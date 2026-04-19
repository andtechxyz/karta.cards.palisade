import { Router } from 'express';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
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
  // single string env var without base64 padding surprises.
  const secret = randomBytes(32).toString('hex');
  const salt = randomBytes(16).toString('hex');
  const secretHash = await hashSecret(secret, salt);

  const cognitoUser = req.cognitoUser;
  try {
    const cred = await prisma.partnerCredential.create({
      data: {
        financialInstitutionId: fiId,
        keyId,
        secretHash,
        salt,
        description: parsed.description,
        createdBy: cognitoUser?.sub ?? 'unknown',
      },
      select: { id: true, keyId: true },
    });
    // Plaintext secret only appears here — never persisted.
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
    select: { id: true, status: true, revokedAt: true, revokedReason: true },
  });
  res.json(updated);
});

export default router;
