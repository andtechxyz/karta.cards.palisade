import { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';

// PCI-DSS 3.1: retain CHD (and its derivatives) only as long as necessary.
// Each fn enforces one schema-declared TTL the DB doesn't auto-enforce.
//
// Palisade only owns the card-side ActivationSession purge.  Vault entries,
// retrieval tokens, registration challenges, and transaction TTLs live on
// Vera and are reaped by Vera's copy of @vera/retention.

export async function purgeExpiredActivationSessions(now: Date): Promise<number> {
  // Consumed sessions are kept as the per-card activation audit trail.
  const { count } = await prisma.activationSession.deleteMany({
    where: { expiresAt: { lt: now }, consumedAt: null },
  });
  return count;
}

/**
 * Expire stale ParamRecord rows (PCI DSS 3.1 / CPL LSR 5).
 *
 * ParamRecord carries the entire per-card TLV ParamBundle (all EMV
 * master keys + ICC RSA priv for that card) KMS-wrapped at rest.
 * Once CONSUMED by a successful tap, the row is audit-only — we don't
 * need the ciphertext for any further operation.  Same flow for any
 * READY row that lingers past `expiresAt` (default 30 days, set at
 * prepareParamBundle time in data-prep).
 *
 * Retention policy:
 *   - READY past expiresAt      → EXPIRED + ciphertext zeroed
 *   - CONSUMED past consumedAt
 *     + 7 days                  → EXPIRED + ciphertext zeroed
 *   - REVOKED past revokedAt
 *     + 7 days                  → EXPIRED + ciphertext zeroed
 *
 * Rows are NOT deleted — the per-card status + timestamps stay as an
 * audit trail.  Only the encrypted payload + per-column envelopes get
 * zeroed so the KMS-wrapped key material is gone from the DB.
 *
 * Returns the number of rows scrubbed.
 */
export async function purgeExpiredParamRecords(
  now: Date,
  consumedGracePeriodMs: number = 7 * 24 * 3600_000,
): Promise<number> {
  const consumedCutoff = new Date(now.getTime() - consumedGracePeriodMs);

  // Bulk READY-expired sweep — time-triggered expiry.
  const expiredReady = await prisma.paramRecord.updateMany({
    where: {
      status: 'READY',
      expiresAt: { lt: now },
    },
    data: {
      status: 'EXPIRED',
      bundleEncrypted: Buffer.alloc(0),
      mkAcEncrypted: null,
      mkSmiEncrypted: null,
      mkSmcEncrypted: null,
      iccRsaPrivEncrypted: null,
    },
  });

  // CONSUMED + 7 days grace — the successful tap already happened, so
  // the bundle no longer needs decryptability.  `createdAt` is a rough
  // stand-in for consumedAt which we don't yet track separately
  // (future schema add).
  const expiredConsumed = await prisma.paramRecord.updateMany({
    where: {
      status: 'CONSUMED',
      createdAt: { lt: consumedCutoff },
    },
    data: {
      status: 'EXPIRED',
      bundleEncrypted: Buffer.alloc(0),
      mkAcEncrypted: null,
      mkSmiEncrypted: null,
      mkSmcEncrypted: null,
      iccRsaPrivEncrypted: null,
    },
  });

  // REVOKED + 7 days grace — same rationale.
  const expiredRevoked = await prisma.paramRecord.updateMany({
    where: {
      status: 'REVOKED',
      createdAt: { lt: consumedCutoff },
    },
    data: {
      status: 'EXPIRED',
      bundleEncrypted: Buffer.alloc(0),
      mkAcEncrypted: null,
      mkSmiEncrypted: null,
      mkSmcEncrypted: null,
      iccRsaPrivEncrypted: null,
    },
  });

  return expiredReady.count + expiredConsumed.count + expiredRevoked.count;
}

/**
 * Scrub SCP03 session keys from abandoned CardOpSession rows.
 *
 * CardOpSession.scpState is a JSON blob holding S-ENC / S-MAC / S-RMAC
 * session keys for the duration of a GP admin operation.  The happy path
 * clears scpState on COMPLETE/FAILED via operation-runner.ts.  If the
 * WS dies before the clear path (unexpected throw, network blip,
 * process restart), those keys can sit in DB indefinitely.
 *
 * This purge closes that gap: any CardOpSession older than `keyTtlMs`
 * whose phase is still RUNNING/PLAN_SENT has its scpState set to DbNull.
 * The session row itself is preserved — its apduLog is a durable audit
 * trail that we don't want to lose — only the plaintext key material is
 * scrubbed.  PCI 3.5 / 3.6.4.
 *
 * Default TTL is 30 minutes; a normal card-op finishes in under 60
 * seconds, so this is well outside any legitimate window.
 */
export async function scrubStaleCardOpScpState(
  now: Date,
  keyTtlMs: number = 30 * 60_000,
): Promise<number> {
  const cutoff = new Date(now.getTime() - keyTtlMs);
  // scpState is nullable; use Prisma.DbNull to set it to SQL NULL (vs
  // JsonNull which would write the JSON value `null`).  Prisma
  // distinguishes them.
  // Two passes so we can preserve terminal-state phase labels while still
  // scrubbing their keys.  Audit finding N-4: a crash between
  // operation-runner's terminal write and the scpState clear leaves
  // COMPLETE/FAILED rows with plaintext S-ENC/S-MAC/S-RMAC indefinitely.
  //
  // Pass 1 — stale active sessions: flip to FAILED with reason, scrub keys.
  const active = await prisma.cardOpSession.updateMany({
    where: {
      createdAt: { lt: cutoff },
      phase: { in: ['READY', 'RUNNING'] },
      scpState: { not: Prisma.JsonNull },
    },
    data: {
      scpState: Prisma.DbNull,
      phase: 'FAILED',
      failedAt: now,
      failureReason: 'scpState-expired-by-sweeper',
    },
  });

  // Pass 2 — terminal rows (COMPLETE / FAILED) that still have scpState
  // non-null.  Preserve phase + existing failureReason; only scrub the
  // plaintext key material.  Same TTL cutoff so we don't racing the
  // terminal writer.
  const terminal = await prisma.cardOpSession.updateMany({
    where: {
      createdAt: { lt: cutoff },
      phase: { in: ['COMPLETE', 'FAILED'] },
      scpState: { not: Prisma.JsonNull },
    },
    data: {
      scpState: Prisma.DbNull,
    },
  });

  return active.count + terminal.count;
}
