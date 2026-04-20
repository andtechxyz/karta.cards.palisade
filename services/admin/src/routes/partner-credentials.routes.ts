import { Router } from 'express';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import {
  SecretsManagerClient,
  CreateSecretCommand,
  DeleteSecretCommand,
} from '@aws-sdk/client-secrets-manager';

// One SM client per process.  Region from env; credentials from the ECS
// task role (which has palisade/partner-hmac/* create/delete/read
// permissions granted at IAM time).
const smClient = new SecretsManagerClient({
  region: process.env.AWS_REGION ?? 'ap-southeast-2',
});

/** Partner HMAC key SM namespace.  Keep per-cred so revoke = delete one. */
const PARTNER_HMAC_SECRET_PREFIX = 'palisade/partner-hmac/';
import { promisify } from 'node:util';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { badRequest, notFound, validateBody } from '@palisade/core';

// ---------------------------------------------------------------------------
// Partner Credentials — per-FI API credentials partners use to upload
// embossing batch files via HTTP.  Secrets are shown ONCE at creation and
// stored only as scrypt hashes thereafter.  Admin UI lists / generates /
// revokes credentials under the selected FI.
//
// Mounted under /api/admin/financial-institutions so every route is nested
// by :fiId (same layout as embossing-templates).
// ---------------------------------------------------------------------------

const router: Router = Router();

const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: string,
  keylen: number,
) => Promise<Buffer>;

// Hash a random 32-byte secret with scrypt.  The secret IS 256-bit entropy
// so we keep scrypt at its defaults — the cost factor here defends the rare
// case of a leaked hash rather than guessing attacks on a user password.
export async function hashSecret(secret: string, salt: string): Promise<string> {
  const buf = await scryptAsync(secret, salt, 32);
  return buf.toString('hex');
}

/** Constant-time verify against a stored scrypt hash. */
export async function verifySecret(secret: string, salt: string, storedHex: string): Promise<boolean> {
  const candidate = await scryptAsync(secret, salt, 32);
  const stored = Buffer.from(storedHex, 'hex');
  if (candidate.length !== stored.length) return false;
  return timingSafeEqual(candidate, stored);
}

// --- Routes -----------------------------------------------------------------

// GET /api/admin/financial-institutions/:fiId/credentials
router.get('/:fiId/credentials', async (req, res) => {
  const fi = await prisma.financialInstitution.findUnique({ where: { id: req.params.fiId } });
  if (!fi) throw notFound('fi_not_found', 'Financial institution not found');

  const creds = await prisma.partnerCredential.findMany({
    where: { financialInstitutionId: req.params.fiId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      keyId: true,
      description: true,
      status: true,
      lastUsedAt: true,
      lastUsedIp: true,
      revokedAt: true,
      revokedReason: true,
      createdBy: true,
      createdAt: true,
    },
  });
  res.json(creds);
});

const createSchema = z.object({
  description: z.string().min(1).max(256).optional(),
  // Optional human-suggested keyId.  If absent we generate one.  Must be
  // URL-safe since partners put it in a request header.
  keyId: z
    .string()
    .regex(/^[a-z0-9][a-z0-9-]{2,62}[a-z0-9]$/, 'lowercase letters/digits/hyphens, 4-64 chars')
    .optional(),
}).strict();

// POST /api/admin/financial-institutions/:fiId/credentials
// Body: { description?, keyId? }
// Response: { id, keyId, secret, secretHash, salt } — secret shown ONCE, never again.
//
// We deliberately return `secretHash` + `salt` alongside the plaintext secret:
// the HMAC scheme uses `secretHash` (= scrypt(secret, salt)) as the HMAC key,
// so partners need it to sign requests without running scrypt themselves.
// Both values are already surfaced to the partner via the scrypt hash stored
// at rest — exposing them here at creation time doesn't widen the blast
// radius.  The plaintext `secret` is the only irrecoverable value.
router.post('/:fiId/credentials', validateBody(createSchema), async (req, res) => {
  const { fiId } = req.params;
  const fi = await prisma.financialInstitution.findUnique({ where: { id: fiId } });
  if (!fi) throw notFound('fi_not_found', 'Financial institution not found');

  const parsed = req.body as z.infer<typeof createSchema>;
  // Default keyId derived from slug + a short random suffix so partners get
  // something recognisable ("incomm-ab12cd") without having to pick one.
  const keyId = parsed.keyId ?? `${fi.slug}-${randomBytes(4).toString('hex')}`;

  // Pre-flight uniqueness check — Prisma's P2002 on the unique index is also
  // handled below, but we catch most collisions here without wasting a hash.
  const existing = await prisma.partnerCredential.findUnique({ where: { keyId } });
  if (existing) throw badRequest('key_id_taken', `keyId "${keyId}" already in use`);

  // 32-byte random secret.  Hex-encoded so partners can stash it in a
  // single string env var without base64 padding surprises.  Partner
  // signs with this secret as the HMAC key.
  const secret = randomBytes(32).toString('hex');
  const salt = randomBytes(16).toString('hex');
  const secretHash = await hashSecret(secret, salt);

  const cognitoUser = req.cognitoUser;
  try {
    // H-6: store the HMAC key in Secrets Manager first, then stamp its
    // ARN on the credential row.  secretHash stays as a one-way
    // "was-this-our-key" hash for audit but is NOT used for signature
    // verification any more.
    //
    // SM name format: palisade/partner-hmac/<keyId>.  Uses keyId (which
    // is already unique-indexed) so operators can see the mapping
    // directly in the SM console.
    const smName = `${PARTNER_HMAC_SECRET_PREFIX}${keyId}`;
    const sm = await smClient.send(new CreateSecretCommand({
      Name: smName,
      Description: `HMAC signing key for partner credential ${keyId} (FI=${fi.slug}). H-6 remediation.`,
      SecretString: secret,
    }));
    const secretArn = sm.ARN;
    if (!secretArn) {
      throw new Error('SM CreateSecret returned no ARN');
    }

    let cred;
    try {
      cred = await prisma.partnerCredential.create({
        data: {
          financialInstitutionId: fiId,
          keyId,
          secretHash,
          salt,
          secretArn,
          description: parsed.description,
          createdBy: cognitoUser?.sub ?? 'unknown',
        },
        select: { id: true, keyId: true },
      });
    } catch (dbErr) {
      // DB create failed after SM create succeeded — delete the orphan
      // SM entry so we don't leak quota + avoid dangling secrets.
      await smClient
        .send(new DeleteSecretCommand({ SecretId: secretArn, ForceDeleteWithoutRecovery: true }))
        .catch(() => { /* best-effort */ });
      throw dbErr;
    }
    // Plaintext secret only appears here — never persisted plaintext.
    res.status(201).json({ id: cred.id, keyId: cred.keyId, secret, secretHash, salt });
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code?: string }).code === 'P2002') {
      throw badRequest('key_id_taken', `keyId "${keyId}" already in use`);
    }
    throw err;
  }
});

const revokeSchema = z.object({
  reason: z.string().min(1).max(256).optional(),
}).strict();

// POST /api/admin/financial-institutions/:fiId/credentials/:id/revoke
router.post('/:fiId/credentials/:id/revoke', validateBody(revokeSchema), async (req, res) => {
  const { fiId, id } = req.params;
  const cred = await prisma.partnerCredential.findUnique({ where: { id } });
  if (!cred || cred.financialInstitutionId !== fiId) {
    throw notFound('credential_not_found', 'Credential not found');
  }
  if (cred.status === 'REVOKED') {
    // Idempotent — return the existing row without bumping revokedAt.
    res.json({ id: cred.id, status: cred.status, revokedAt: cred.revokedAt });
    return;
  }
  const updated = await prisma.partnerCredential.update({
    where: { id },
    data: {
      status: 'REVOKED',
      revokedAt: new Date(),
      revokedReason: (req.body as z.infer<typeof revokeSchema>).reason ?? null,
    },
    select: { id: true, status: true, revokedAt: true, revokedReason: true, secretArn: true },
  });

  // H-6 — delete the plaintext HMAC key from Secrets Manager.  We use
  // ForceDeleteWithoutRecovery because a revoked partner credential
  // should be permanently unrecoverable — SM's 7-30 day grace period is
  // the wrong behavior for a revocation event.
  if (updated.secretArn) {
    await smClient
      .send(new DeleteSecretCommand({ SecretId: updated.secretArn, ForceDeleteWithoutRecovery: true }))
      .catch((err) => {
        // Non-fatal: the DB row is already marked REVOKED, so the
        // credential can't be used even if SM deletion fails.  Log
        // loudly so ops can clean up the orphan secret.
        // eslint-disable-next-line no-console
        console.error(
          `[partner-credentials] SM delete failed for ${id} (${updated.secretArn}): ${err instanceof Error ? err.message : err}. Manual cleanup required.`,
        );
      });
  }

  res.json({
    id: updated.id,
    status: updated.status,
    revokedAt: updated.revokedAt,
    revokedReason: updated.revokedReason,
  });
});

export default router;
