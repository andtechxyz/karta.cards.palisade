import { prisma, TransactionStatus } from '@palisade/db';

// PCI-DSS 3.1: retain CHD (and its derivatives) only as long as necessary.
// Each fn enforces one schema-declared TTL the DB doesn't auto-enforce.
// VaultAccessLog is deliberately NOT purged here — 10.7 requires 12-month
// retention for audit rows.

/** Written to `Transaction.failureReason` when a PENDING txn past its TTL is
 *  flipped to EXPIRED.  Shared with transaction.service.ts's read-path
 *  expire so the two sources of expiry emit the same sentinel. */
export const TRANSACTION_TTL_ELAPSED_REASON = 'transaction_ttl_elapsed';

export async function purgeExpiredRetrievalTokens(now: Date): Promise<number> {
  // VaultAccessLog.retrievalTokenId is onDelete: SetNull, so audit survives.
  const { count } = await prisma.retrievalToken.deleteMany({
    where: { expiresAt: { lt: now } },
  });
  return count;
}

export async function purgeExpiredRegistrationChallenges(now: Date): Promise<number> {
  // Consumed challenges are deleted inline by finishRegistration; this only
  // reaps abandoned ones.
  const { count } = await prisma.registrationChallenge.deleteMany({
    where: { expiresAt: { lt: now } },
  });
  return count;
}

export async function purgeExpiredActivationSessions(now: Date): Promise<number> {
  // Consumed sessions are kept as the per-card activation audit trail.
  const { count } = await prisma.activationSession.deleteMany({
    where: { expiresAt: { lt: now }, consumedAt: null },
  });
  return count;
}

/** Bypasses the per-row state-machine assertion deliberately: the where-clause
 *  pins the source state to PENDING (a legal origin for EXPIRED), and a
 *  per-row update would race the in-flight auth path. */
export async function expirePendingTransactions(now: Date): Promise<number> {
  const { count } = await prisma.transaction.updateMany({
    where: { status: TransactionStatus.PENDING, expiresAt: { lt: now } },
    data: {
      status: TransactionStatus.EXPIRED,
      failureReason: TRANSACTION_TTL_ELAPSED_REASON,
    },
  });
  return count;
}
