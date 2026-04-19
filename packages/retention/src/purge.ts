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
