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
