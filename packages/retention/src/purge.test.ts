import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@palisade/db', () => ({
  prisma: {
    retrievalToken: { deleteMany: vi.fn() },
    registrationChallenge: { deleteMany: vi.fn() },
    activationSession: { deleteMany: vi.fn() },
    transaction: { updateMany: vi.fn() },
  },
  TransactionStatus: { PENDING: 'PENDING', EXPIRED: 'EXPIRED' },
}));

import { prisma, TransactionStatus } from '@palisade/db';
import {
  purgeExpiredRetrievalTokens,
  purgeExpiredRegistrationChallenges,
  purgeExpiredActivationSessions,
  expirePendingTransactions,
} from './purge.js';

type Mocked<T> = ReturnType<typeof vi.fn> & T;
const mock = {
  retrievalTokenDelete: () =>
    prisma.retrievalToken.deleteMany as unknown as Mocked<typeof prisma.retrievalToken.deleteMany>,
  registrationChallengeDelete: () =>
    prisma.registrationChallenge.deleteMany as unknown as Mocked<
      typeof prisma.registrationChallenge.deleteMany
    >,
  activationSessionDelete: () =>
    prisma.activationSession.deleteMany as unknown as Mocked<
      typeof prisma.activationSession.deleteMany
    >,
  transactionUpdate: () =>
    prisma.transaction.updateMany as unknown as Mocked<typeof prisma.transaction.updateMany>,
};

const NOW = new Date('2026-04-16T12:00:00Z');

beforeEach(() => {
  mock.retrievalTokenDelete().mockReset().mockResolvedValue({ count: 0 } as never);
  mock.registrationChallengeDelete().mockReset().mockResolvedValue({ count: 0 } as never);
  mock.activationSessionDelete().mockReset().mockResolvedValue({ count: 0 } as never);
  mock.transactionUpdate().mockReset().mockResolvedValue({ count: 0 } as never);
});

describe('purgeExpiredRetrievalTokens', () => {
  it('deletes any token with expiresAt < now and returns the count', async () => {
    mock.retrievalTokenDelete().mockResolvedValue({ count: 7 } as never);

    const count = await purgeExpiredRetrievalTokens(NOW);

    expect(count).toBe(7);
    expect(mock.retrievalTokenDelete()).toHaveBeenCalledWith({
      where: { expiresAt: { lt: NOW } },
    });
  });
});

describe('purgeExpiredRegistrationChallenges', () => {
  it('deletes challenges past their TTL', async () => {
    mock.registrationChallengeDelete().mockResolvedValue({ count: 3 } as never);

    const count = await purgeExpiredRegistrationChallenges(NOW);

    expect(count).toBe(3);
    expect(mock.registrationChallengeDelete()).toHaveBeenCalledWith({
      where: { expiresAt: { lt: NOW } },
    });
  });
});

describe('purgeExpiredActivationSessions', () => {
  it('deletes only unconsumed expired sessions (audit trail for consumed ones is retained)', async () => {
    mock.activationSessionDelete().mockResolvedValue({ count: 2 } as never);

    const count = await purgeExpiredActivationSessions(NOW);

    expect(count).toBe(2);
    expect(mock.activationSessionDelete()).toHaveBeenCalledWith({
      where: { expiresAt: { lt: NOW }, consumedAt: null },
    });
  });
});

describe('expirePendingTransactions', () => {
  it('flips PENDING past expiresAt to EXPIRED with the shared failureReason', async () => {
    mock.transactionUpdate().mockResolvedValue({ count: 5 } as never);

    const count = await expirePendingTransactions(NOW);

    expect(count).toBe(5);
    expect(mock.transactionUpdate()).toHaveBeenCalledWith({
      where: { status: TransactionStatus.PENDING, expiresAt: { lt: NOW } },
      data: {
        status: TransactionStatus.EXPIRED,
        failureReason: 'transaction_ttl_elapsed',
      },
    });
  });
});
