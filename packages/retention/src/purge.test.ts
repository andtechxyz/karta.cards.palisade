import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@palisade/db', () => ({
  prisma: {
    activationSession: { deleteMany: vi.fn() },
  },
}));

import { prisma } from '@palisade/db';
import { purgeExpiredActivationSessions } from './purge.js';

type Mocked<T> = ReturnType<typeof vi.fn> & T;
const activationSessionDelete = () =>
  prisma.activationSession.deleteMany as unknown as Mocked<
    typeof prisma.activationSession.deleteMany
  >;

const NOW = new Date('2026-04-16T12:00:00Z');

beforeEach(() => {
  activationSessionDelete().mockReset().mockResolvedValue({ count: 0 } as never);
});

describe('purgeExpiredActivationSessions', () => {
  it('deletes only unconsumed expired sessions (audit trail for consumed ones is retained)', async () => {
    activationSessionDelete().mockResolvedValue({ count: 2 } as never);

    const count = await purgeExpiredActivationSessions(NOW);

    expect(count).toBe(2);
    expect(activationSessionDelete()).toHaveBeenCalledWith({
      where: { expiresAt: { lt: NOW }, consumedAt: null },
    });
  });
});
