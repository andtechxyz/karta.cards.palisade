import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  runReaper,
  formatCountersLine,
  emptyCounters,
  ONE_HOUR_MS,
  THIRTY_DAYS_MS,
  NINETY_DAYS_MS,
  type ReaperPrisma,
} from './reaper-sad-sessions.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Pinned NOW so every time-window assertion is stable.  Picked a wall time
// far from midnight so DST / timezone drift can't flip a boundary.
const NOW = new Date('2026-04-19T12:00:00.000Z');

function oneHourAgo(): Date {
  return new Date(NOW.getTime() - ONE_HOUR_MS);
}
function thirtyDaysAgo(): Date {
  return new Date(NOW.getTime() - THIRTY_DAYS_MS);
}
function ninetyDaysAgo(): Date {
  return new Date(NOW.getTime() - NINETY_DAYS_MS);
}

function mockPrisma(includeCardOp = true): ReaperPrisma {
  const base: ReaperPrisma = {
    sadRecord: {
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
      count: vi.fn().mockResolvedValue(0),
    },
    provisioningSession: {
      updateMany: vi.fn().mockResolvedValue({ count: 0 }),
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
      count: vi.fn().mockResolvedValue(0),
    },
  };
  if (includeCardOp) {
    base.cardOpSession = {
      updateMany: vi.fn().mockResolvedValue({ count: 0 }),
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
      count: vi.fn().mockResolvedValue(0),
    };
  }
  return base;
}

// ---------------------------------------------------------------------------
// Live-mode SQL predicates
// ---------------------------------------------------------------------------

describe('runReaper — live mode WHERE clauses', () => {
  let prisma: ReaperPrisma;

  beforeEach(() => {
    prisma = mockPrisma();
  });

  it('sadRecord.deleteMany: READY + expiresAt < now', async () => {
    await runReaper(prisma, { dryRun: false }, NOW);
    expect(prisma.sadRecord.deleteMany).toHaveBeenCalledWith({
      where: {
        status: 'READY',
        expiresAt: { lt: NOW },
      },
    });
  });

  it('sadRecord.deleteMany: terminal + createdAt < now - 30d', async () => {
    await runReaper(prisma, { dryRun: false }, NOW);
    expect(prisma.sadRecord.deleteMany).toHaveBeenCalledWith({
      where: {
        status: { in: ['CONSUMED', 'REVOKED'] },
        createdAt: { lt: thirtyDaysAgo() },
      },
    });
  });

  it('provisioningSession.updateMany: non-terminal + createdAt < now - 1h', async () => {
    await runReaper(prisma, { dryRun: false }, NOW);
    expect(prisma.provisioningSession.updateMany).toHaveBeenCalledWith({
      where: {
        phase: { notIn: ['COMPLETE', 'FAILED'] },
        createdAt: { lt: oneHourAgo() },
      },
      data: {
        phase: 'EXPIRED',
        failedAt: NOW,
        failureReason: expect.stringContaining('abandoned'),
      },
    });
  });

  it('provisioningSession.deleteMany: terminal + updatedAt < now - 90d', async () => {
    await runReaper(prisma, { dryRun: false }, NOW);
    expect(prisma.provisioningSession.deleteMany).toHaveBeenCalledWith({
      where: {
        phase: { in: ['COMPLETE', 'FAILED'] },
        updatedAt: { lt: ninetyDaysAgo() },
      },
    });
  });

  it('cardOpSession.updateMany: non-terminal + createdAt < now - 1h', async () => {
    await runReaper(prisma, { dryRun: false }, NOW);
    expect(prisma.cardOpSession!.updateMany).toHaveBeenCalledWith({
      where: {
        phase: { notIn: ['COMPLETE', 'FAILED'] },
        createdAt: { lt: oneHourAgo() },
      },
      data: {
        phase: 'EXPIRED',
        failedAt: NOW,
        failureReason: expect.stringContaining('abandoned'),
      },
    });
  });

  it('cardOpSession.deleteMany: terminal + updatedAt < now - 90d', async () => {
    await runReaper(prisma, { dryRun: false }, NOW);
    expect(prisma.cardOpSession!.deleteMany).toHaveBeenCalledWith({
      where: {
        phase: { in: ['COMPLETE', 'FAILED'] },
        updatedAt: { lt: ninetyDaysAgo() },
      },
    });
  });

  it('skips CardOpSession work when the delegate is absent', async () => {
    const noCardOp = mockPrisma(/* includeCardOp */ false);
    const counters = await runReaper(noCardOp, { dryRun: false }, NOW);
    expect(counters.cardOpSessionsAbandonedArchived).toBe(0);
    expect(counters.cardOpSessionsTerminalDeleted).toBe(0);
    // Non-optional work still ran.
    expect(noCardOp.sadRecord.deleteMany).toHaveBeenCalled();
    expect(noCardOp.provisioningSession.updateMany).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Dry-run semantics
// ---------------------------------------------------------------------------

describe('runReaper — dry-run mode', () => {
  it('calls only count(), never a mutating method', async () => {
    const prisma = mockPrisma();
    await runReaper(prisma, { dryRun: true }, NOW);

    expect(prisma.sadRecord.count).toHaveBeenCalledTimes(2);
    expect(prisma.sadRecord.deleteMany).not.toHaveBeenCalled();

    expect(prisma.provisioningSession.count).toHaveBeenCalledTimes(2);
    expect(prisma.provisioningSession.updateMany).not.toHaveBeenCalled();
    expect(prisma.provisioningSession.deleteMany).not.toHaveBeenCalled();

    expect(prisma.cardOpSession!.count).toHaveBeenCalledTimes(2);
    expect(prisma.cardOpSession!.updateMany).not.toHaveBeenCalled();
    expect(prisma.cardOpSession!.deleteMany).not.toHaveBeenCalled();
  });

  it('propagates count() results into counters', async () => {
    const prisma = mockPrisma();
    (prisma.sadRecord.count as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(7) // READY+expired
      .mockResolvedValueOnce(3); // terminal
    (prisma.provisioningSession.count as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(5) // abandoned
      .mockResolvedValueOnce(11); // terminal
    (prisma.cardOpSession!.count as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce(2) // abandoned
      .mockResolvedValueOnce(8); // terminal

    const counters = await runReaper(prisma, { dryRun: true }, NOW);
    expect(counters).toEqual({
      sadRecordsExpiredDeleted: 7,
      sadRecordsTerminalDeleted: 3,
      provisioningSessionsAbandonedArchived: 5,
      provisioningSessionsTerminalDeleted: 11,
      cardOpSessionsAbandonedArchived: 2,
      cardOpSessionsTerminalDeleted: 8,
    });
  });
});

// ---------------------------------------------------------------------------
// Counter propagation in live mode
// ---------------------------------------------------------------------------

describe('runReaper — live mode counter propagation', () => {
  it('returns counts from each mutating call', async () => {
    const prisma = mockPrisma();
    (prisma.sadRecord.deleteMany as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ count: 4 })
      .mockResolvedValueOnce({ count: 9 });
    (prisma.provisioningSession.updateMany as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ count: 6 });
    (prisma.provisioningSession.deleteMany as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ count: 15 });
    (prisma.cardOpSession!.updateMany as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ count: 1 });
    (prisma.cardOpSession!.deleteMany as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ count: 2 });

    const counters = await runReaper(prisma, { dryRun: false }, NOW);
    expect(counters).toEqual({
      sadRecordsExpiredDeleted: 4,
      sadRecordsTerminalDeleted: 9,
      provisioningSessionsAbandonedArchived: 6,
      provisioningSessionsTerminalDeleted: 15,
      cardOpSessionsAbandonedArchived: 1,
      cardOpSessionsTerminalDeleted: 2,
    });
  });
});

// ---------------------------------------------------------------------------
// Log formatting
// ---------------------------------------------------------------------------

describe('formatCountersLine', () => {
  it('emits live-mode line with every counter', () => {
    const counters = {
      sadRecordsExpiredDeleted: 1,
      sadRecordsTerminalDeleted: 2,
      provisioningSessionsAbandonedArchived: 3,
      provisioningSessionsTerminalDeleted: 4,
      cardOpSessionsAbandonedArchived: 5,
      cardOpSessionsTerminalDeleted: 6,
    };
    const line = formatCountersLine(counters, false);
    expect(line).toBe(
      '[reaper] LIVE sad.expired=1 sad.terminal=2 prov.abandoned=3 ' +
      'prov.terminal=4 cardop.abandoned=5 cardop.terminal=6',
    );
  });

  it('emits DRY-RUN marker when dryRun=true', () => {
    const line = formatCountersLine(emptyCounters(), true);
    expect(line).toContain('[reaper] DRY-RUN');
    expect(line).toContain('sad.expired=0');
    expect(line).toContain('cardop.terminal=0');
  });
});

// ---------------------------------------------------------------------------
// Idempotence — second run with empty DB touches nothing extra
// ---------------------------------------------------------------------------

describe('runReaper — idempotence', () => {
  it('a second live-mode run against an empty DB makes no change', async () => {
    const prisma = mockPrisma();
    // First run — all mocks return count: 0
    const first = await runReaper(prisma, { dryRun: false }, NOW);
    expect(first).toEqual(emptyCounters());

    // Count how many mutating calls happened on the first pass.
    const firstCallCount =
      (prisma.sadRecord.deleteMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.provisioningSession.updateMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.provisioningSession.deleteMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.cardOpSession!.updateMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.cardOpSession!.deleteMany as ReturnType<typeof vi.fn>).mock.calls.length;

    // Second run.
    const second = await runReaper(prisma, { dryRun: false }, NOW);
    expect(second).toEqual(emptyCounters());

    // Each pass issues exactly the same set of deleteMany/updateMany
    // calls — the "idempotence" is in the WHERE clause, not in call
    // gating.  The real-DB guarantee: once a run returns 0 across the
    // board, the subsequent run is also 0 unless new data shows up.
    const secondCallCount =
      (prisma.sadRecord.deleteMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.provisioningSession.updateMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.provisioningSession.deleteMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.cardOpSession!.updateMany as ReturnType<typeof vi.fn>).mock.calls.length +
      (prisma.cardOpSession!.deleteMany as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(secondCallCount).toBe(firstCallCount * 2);
  });
});
