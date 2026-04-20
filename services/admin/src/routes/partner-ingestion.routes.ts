import { Router, type NextFunction, type Request, type Response } from 'express';
import { createHash, createHmac, timingSafeEqual, randomUUID, randomBytes } from 'node:crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import express from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { ApiError, badRequest, notFound, unauthorized, validateBody } from '@palisade/core';
import { getAdminConfig } from '../env.js';
import { metrics } from '../metrics.js';

// Secrets Manager client for partner HMAC key resolution (H-6).  One
// instance per process; resolves in the container's region.
const secretsManager = new SecretsManagerClient({
  region: process.env.AWS_REGION ?? 'ap-southeast-2',
});

// Very small in-process cache of partner HMAC keys.  Partner requests are
// rare (batch ingestion, ~N per day) but we don't want to call Secrets
// Manager on every signature verification.  60-second TTL is enough to
// absorb bursts; longer would widen the revocation window.
//
// Cache stores the hex string (not a Buffer) so callers can decode their
// own fresh Buffer and scrub without mutating the cache entry.
const partnerKeyCache = new Map<string, { keyHex: string; expiresAt: number }>();
const PARTNER_KEY_CACHE_TTL_MS = 60_000;

// A stable-lifetime dummy HMAC key used for the unknown-credential /
// unrotated-credential path.  Random per boot so an attacker can't
// precompute signatures that would verify against it, but stable within
// a single process so the dummy HMAC work takes the same code path and
// roughly the same time as a real HMAC-cache hit.  PCI 8.3 / audit N-3:
// closes the timing oracle where an unknown keyId short-circuited before
// we read the body + ran HMAC.
const DUMMY_HMAC_KEY = randomBytes(32);

async function resolvePartnerHmacKey(secretArn: string): Promise<Buffer> {
  const now = Date.now();
  const cached = partnerKeyCache.get(secretArn);
  if (cached && cached.expiresAt > now) {
    return Buffer.from(cached.keyHex, 'hex');
  }

  const resp = await secretsManager.send(
    new GetSecretValueCommand({ SecretId: secretArn }),
  );
  if (typeof resp.SecretString !== 'string') {
    throw new Error(`partner secret ${secretArn} has no SecretString`);
  }
  // Partners sign with hex-decoded key material — same wire format as
  // pre-H-6, just resolved from SM at verification time instead of DB.
  partnerKeyCache.set(secretArn, {
    keyHex: resp.SecretString,
    expiresAt: now + PARTNER_KEY_CACHE_TTL_MS,
  });
  return Buffer.from(resp.SecretString, 'hex');
}

/** Test hook: clear partner key cache between runs. */
export function _resetPartnerKeyCache(): void {
  partnerKeyCache.clear();
}

// ---------------------------------------------------------------------------
// Partner Ingestion — HTTP endpoint partners call to submit embossing
// batches.  NOT behind adminAuth.  Authentication is a custom HMAC-SHA256
// signature scheme (similar to @palisade/service-auth but with explicit partner
// headers and a secret that's hashed at rest, so we can't reuse that
// package directly).
//
// Headers (all required):
//   X-Partner-KeyId:      <keyId>
//   X-Partner-Signature:  <hex HMAC-SHA256>
//   X-Partner-Timestamp:  <unix seconds>
//   X-Partner-TemplateId: <embossingTemplateId>
//   X-Partner-ProgramId:  <programId>
//
// Canonical string signed: `METHOD\nPATH\nTIMESTAMP\nSHA256(body)`
// Replay window: ±60 seconds.
// ---------------------------------------------------------------------------

const router: Router = Router();
const s3 = new S3Client({ region: 'ap-southeast-2' });
const MAX_BATCH_SIZE = 500 * 1024 * 1024; // 500 MB
const SIGNATURE_WINDOW_SECONDS = 60;

interface PartnerRequest extends Request {
  partnerCredential?: {
    id: string;
    keyId: string;
    financialInstitutionId: string;
  };
  rawPartnerBody?: Buffer;
}

// --- HMAC verification middleware ------------------------------------------
//
// Reads the body into a Buffer (needed for the signature hash and later for
// S3 upload), then verifies headers + signature.  On success, attaches the
// verified credential to the request so the handler can use it.

export function partnerHmacMiddleware() {
  return async (req: PartnerRequest, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const keyId = readHeader(req, 'x-partner-keyid');
      const signatureHex = readHeader(req, 'x-partner-signature');
      const timestampStr = readHeader(req, 'x-partner-timestamp');

      if (!keyId || !signatureHex || !timestampStr) {
        metrics().counter('admin.partner_auth.fail', 1, { reason: 'missing_signature' });
        throw unauthorized('missing_signature', 'Missing partner auth headers');
      }
      if (!/^[0-9a-fA-F]+$/.test(signatureHex)) {
        metrics().counter('admin.partner_auth.fail', 1, { reason: 'bad_signature' });
        throw unauthorized('bad_signature', 'Signature must be hex');
      }
      const timestamp = Number.parseInt(timestampStr, 10);
      if (!Number.isFinite(timestamp)) {
        metrics().counter('admin.partner_auth.fail', 1, { reason: 'bad_timestamp' });
        throw unauthorized('bad_timestamp', 'Timestamp is not a number');
      }
      const now = Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > SIGNATURE_WINDOW_SECONDS) {
        metrics().counter('admin.partner_auth.fail', 1, { reason: 'clock_skew' });
        throw unauthorized('clock_skew', 'Timestamp outside replay window');
      }

      // N-3 (timing-oracle closure): take the SAME path for every
      // credential outcome so a remote attacker can't differentiate
      // "unknown keyId", "revoked credential", "unrotated credential",
      // and "bad signature" by response latency.
      //
      // The code below unconditionally:
      //   1. Does the DB lookup (paid regardless of outcome).
      //   2. Reads the request body into memory.
      //   3. Resolves an HMAC key — the real one on a happy credential,
      //      a per-process random `DUMMY_HMAC_KEY` otherwise.  The
      //      dummy path still goes through createHmac() so timing /
      //      allocation patterns mirror the success path.
      //   4. Runs timingSafeEqual on fixed-length inputs.
      // Only after all of that do we branch and throw, using a single
      // generic "bad_signature" error for all non-success paths.
      const cred = await prisma.partnerCredential.findUnique({ where: { keyId } });

      // Buffer the full body regardless — the real path needs it for
      // HMAC + S3; the dummy path needs it so an attacker can't
      // distinguish "unknown key" (short response) from "valid key,
      // bad sig" (post-body response).
      const body = await readBody(req);

      // H-6 remediation: HMAC key lives in Secrets Manager under
      // `cred.secretArn`, not in the DB row.  If a credential predates
      // the migration (secretArn null) we fall back to DUMMY_HMAC_KEY
      // so verification always fails — operators must rotate via
      // /api/admin/partner-credentials to get a new SM-backed key
      // before the partner can sign.
      //
      // ACTIVE + has secretArn → real key.  Anything else (missing,
      // inactive, unrotated) → dummy key that will never match.
      let hmacKey: Buffer = DUMMY_HMAC_KEY;
      const credUsable = cred && cred.status === 'ACTIVE' && cred.secretArn;
      if (credUsable) {
        try {
          hmacKey = await resolvePartnerHmacKey(cred.secretArn!);
        } catch (err) {
          // Don't leak SM error details to the partner.  Fall back to
          // the dummy so the downstream HMAC + compare still runs,
          // maintaining constant-time behaviour on SM failure.
          // eslint-disable-next-line no-console
          console.error(
            `[partner-hmac] failed to fetch key for ${cred.id}: ${err instanceof Error ? err.message : err}`,
          );
          hmacKey = DUMMY_HMAC_KEY;
        }
      }

      const canonical = canonicalString(
        req.method,
        req.originalUrl,
        timestamp,
        body,
      );
      const expected = createHmac('sha256', hmacKey)
        .update(canonical)
        .digest();
      const got = Buffer.from(signatureHex, 'hex');
      // timingSafeEqual requires same length.  `got` can be arbitrary
      // hex; compare against a fixed-length equivalent on mismatch to
      // keep the comparison itself constant-time.
      let sigOk = false;
      if (expected.length === got.length) {
        sigOk = timingSafeEqual(expected, got);
      } else {
        // Still pay the comparison cost on length mismatch to avoid a
        // length-based oracle.
        const pad = Buffer.alloc(expected.length);
        timingSafeEqual(expected, pad);
      }

      // Now — and ONLY now — branch on credential validity + signature.
      if (!credUsable || !sigOk) {
        metrics().counter('admin.partner_auth.fail', 1, { reason: 'bad_signature' });
        throw unauthorized('bad_signature', 'Signature did not verify');
      }
      metrics().counter('admin.partner_auth.ok', 1, { keyId });

      // Record last-used on success.  Non-blocking — we don't want an audit
      // write to fail the request, but we do await so the timestamp is
      // visible immediately in the admin UI.
      await prisma.partnerCredential.update({
        where: { id: cred!.id },
        data: {
          lastUsedAt: new Date(),
          lastUsedIp: req.ip ?? null,
        },
      });

      req.partnerCredential = {
        id: cred!.id,
        keyId: cred!.keyId,
        financialInstitutionId: cred!.financialInstitutionId,
      };
      req.rawPartnerBody = body;
      next();
    } catch (err) {
      next(err);
    }
  };
}

// --- Route ------------------------------------------------------------------
//
// POST /api/partners/embossing-batches
// Headers: X-Partner-KeyId, X-Partner-Signature, X-Partner-Timestamp,
//          X-Partner-TemplateId, X-Partner-ProgramId
// Body: raw batch file bytes (not multipart).
//
// Response: { batchId, status }

router.post('/embossing-batches', async (req: PartnerRequest, res) => {
  const cred = req.partnerCredential;
  const body = req.rawPartnerBody;
  if (!cred || !body) {
    // Impossible-state: middleware sets both on every accepted request.
    throw new ApiError(500, 'ingestion_state', 'partner middleware did not populate request');
  }

  const templateId = readHeader(req, 'x-partner-templateid');
  const programId = readHeader(req, 'x-partner-programid');
  if (!templateId) throw badRequest('missing_template_id', 'X-Partner-TemplateId required');
  if (!programId) throw badRequest('missing_program_id', 'X-Partner-ProgramId required');

  if (body.length === 0) {
    metrics().counter('admin.batch.received', 1, { result: 'empty' });
    throw badRequest('empty_body', 'Batch body is empty');
  }
  if (body.length > MAX_BATCH_SIZE) {
    metrics().counter('admin.batch.received', 1, { result: 'too_large' });
    throw badRequest('file_too_large', 'Batch exceeds 500MB limit');
  }

  const [template, program] = await Promise.all([
    prisma.embossingTemplate.findUnique({ where: { id: templateId } }),
    prisma.program.findUnique({ where: { id: programId } }),
  ]);
  if (!template) throw notFound('template_not_found', 'Template not found');
  if (!program) throw notFound('program_not_found', 'Program not found');

  // Scope check: the template must belong to the same FI that issued the
  // credential.  Prevents a partner from uploading against an FI they don't
  // represent by specifying a borrowed templateId.
  if (template.financialInstitutionId !== cred.financialInstitutionId) {
    metrics().counter('admin.batch.received', 1, { result: 'fi_mismatch' });
    throw unauthorized('template_fi_mismatch', 'Template does not belong to partner FI');
  }
  // And the program must use (or be compatible with) that FI too.  Programs
  // can belong to an FI via Program.financialInstitutionId; enforce it so a
  // partner can't redirect to a program they don't own.
  if (program.financialInstitutionId && program.financialInstitutionId !== cred.financialInstitutionId) {
    metrics().counter('admin.batch.received', 1, { result: 'program_mismatch' });
    throw unauthorized('program_fi_mismatch', 'Program does not belong to partner FI');
  }

  const sha256 = createHash('sha256').update(body).digest('hex');
  const fileName = readHeader(req, 'x-partner-filename') ?? `partner_${Date.now()}.bin`;

  const config = getAdminConfig();
  const bucket = config.EMBOSSING_BUCKET;
  const s3Key = `batches/${programId}/${Date.now()}_${randomUUID()}/${fileName}`;

  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: s3Key,
      Body: body,
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: config.EMBOSSING_KMS_KEY_ARN || undefined,
      ContentType: 'application/octet-stream',
      Metadata: { sha256, programId, templateId, partnerKeyId: cred.keyId },
    }),
  );

  const batch = await prisma.embossingBatch.create({
    data: {
      templateId,
      programId,
      fileName,
      fileSize: body.length,
      sha256,
      s3Bucket: bucket,
      s3Key,
      status: 'RECEIVED',
      uploadedVia: 'API',
      // Partner audit: record the keyId (not cognitoSub — this isn't a human).
      uploadedBy: cred.keyId,
    },
    select: { id: true, status: true, uploadedAt: true },
  });

  metrics().counter('admin.batch.received', 1, { result: 'ok' });
  metrics().gauge('admin.batch.size_bytes', body.length);

  res.status(201).json({ batchId: batch.id, status: batch.status, uploadedAt: batch.uploadedAt });
});

// --- POST /api/partners/cards/mark-sold -------------------------------------
//
// Bulk flip retail cards from SHIPPED → SOLD.  Used when a retailer's POS
// reports a sale.  Scoped to the caller's FI: every cardRef must belong to
// a Card whose program.financialInstitutionId matches the partner credential.
//
// Body (JSON — separate from the binary batch upload route):
//   { "cardRefs": ["kc_ABC...", "kc_DEF..."] }
//
// Response:
//   { updated: ["kc_ABC..."], skipped: ["kc_DEF..."], notFound: [...],
//     wrongFi: [...], notRetail: [...] }
//
// Idempotent: SOLD cards go into `skipped`, not `updated`, so a retry is a
// no-op from the partner's point of view.

const markSoldSchema = z.object({
  cardRefs: z.array(z.string().min(1).max(64)).min(1).max(1000),
});

// express.json() is scoped to this route — /embossing-batches keeps the
// raw-body reader it needs for its signature hash.
router.post(
  '/cards/mark-sold',
  express.json({ limit: '256kb' }),
  validateBody(markSoldSchema),
  async (req: PartnerRequest, res) => {
    const cred = req.partnerCredential;
    if (!cred) throw new ApiError(500, 'ingestion_state', 'partner middleware did not populate request');

    const { cardRefs } = req.body as z.infer<typeof markSoldSchema>;

    const cards = await prisma.card.findMany({
      where: { cardRef: { in: cardRefs } },
      select: {
        id: true,
        cardRef: true,
        retailSaleStatus: true,
        program: {
          select: { programType: true, financialInstitutionId: true },
        },
      },
    });

    const byRef = new Map(cards.map((c) => [c.cardRef, c]));
    const updated: string[] = [];
    const skipped: string[] = [];
    const missing: string[] = [];
    const wrongFi: string[] = [];
    const notRetail: string[] = [];
    const toUpdate: string[] = [];

    for (const ref of cardRefs) {
      const c = byRef.get(ref);
      if (!c) {
        missing.push(ref);
        continue;
      }
      if (c.program?.financialInstitutionId !== cred.financialInstitutionId) {
        // Don't leak whether the card exists — treat both "belongs to
        // another FI" and "belongs to no FI" as access denied.
        wrongFi.push(ref);
        continue;
      }
      if (c.program?.programType !== 'RETAIL') {
        notRetail.push(ref);
        continue;
      }
      if (c.retailSaleStatus === 'SOLD') {
        skipped.push(ref);
        continue;
      }
      toUpdate.push(ref);
    }

    if (toUpdate.length > 0) {
      const now = new Date();
      const result = await prisma.card.updateMany({
        where: { cardRef: { in: toUpdate } },
        data: { retailSaleStatus: 'SOLD', retailSoldAt: now },
      });
      if (result.count !== toUpdate.length) {
        // Some cards raced into SOLD between the read and the write —
        // recompute.  Not an error; just move them to skipped.
        const reread = await prisma.card.findMany({
          where: { cardRef: { in: toUpdate } },
          select: { cardRef: true, retailSaleStatus: true },
        });
        const final = new Map(reread.map((c) => [c.cardRef, c]));
        for (const ref of toUpdate) {
          if (final.get(ref)?.retailSaleStatus === 'SOLD' && !skipped.includes(ref)) {
            updated.push(ref);
          } else {
            skipped.push(ref);
          }
        }
      } else {
        updated.push(...toUpdate);
      }
    }

    res.json({
      updated,
      skipped,
      notFound: missing,
      wrongFi,
      notRetail,
    });
  },
);

// --- Helpers ---------------------------------------------------------------

function readHeader(req: Request, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  if (Array.isArray(v)) return v[0];
  return v;
}

function canonicalString(
  method: string,
  pathAndQuery: string,
  ts: number,
  body: Buffer,
): string {
  const bodyHash = createHash('sha256').update(body).digest('hex');
  return `${method.toUpperCase()}\n${pathAndQuery}\n${ts}\n${bodyHash}`;
}

/**
 * Read the request body into a bounded Buffer.  The partner route accepts a
 * raw binary body (not JSON, not multipart), so we read the stream directly
 * rather than rely on express.json().  Bounded to MAX_BATCH_SIZE so a
 * hostile partner can't OOM the admin service.
 */
async function readBody(req: Request): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_BATCH_SIZE) {
      throw badRequest('file_too_large', 'Batch exceeds 500MB limit');
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

export default router;
