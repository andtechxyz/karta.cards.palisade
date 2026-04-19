/**
 * operation-runner dispatch tests — verifies:
 *   - Known ops route to their handler (success/terminal path).
 *   - Phase 3 stub ops emit NOT_IMPLEMENTED and mark CardOpSession FAILED.
 *   - Unknown operation rejects with UNKNOWN_OP.
 *   - APDU audit trail gets populated with cmd+rsp entries and is
 *     flushed to CardOpSession.apduLog on phase transitions.
 *
 * Handler modules are mocked so we don't exercise full SCP03 flow here
 * — that's covered in the per-operation test files.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@palisade/db', () => ({
  prisma: {
    cardOpSession: {
      update: vi.fn().mockResolvedValue({}),
    },
  },
}));

// Stub handlers — individually tested elsewhere.
vi.mock('../operations/list-applets.js', () => ({
  runListApplets: vi.fn().mockResolvedValue({
    type: 'complete',
    applets: [{ aid: 'A0000000625041', lifeCycle: 7, privileges: '00' }],
    packages: [],
  }),
}));
vi.mock('../operations/install-pa.js', () => ({
  runInstallPa: vi.fn().mockResolvedValue({
    type: 'complete',
    packageAid: 'A0000000625041',
    instanceAid: 'A00000006250414C',
  }),
}));
vi.mock('../operations/reset-pa-state.js', () => ({
  runResetPaState: vi.fn().mockResolvedValue({ type: 'complete' }),
}));

import { runOperation } from './operation-runner.js';
import { ApduAuditLogger } from './apdu-audit.js';
import { prisma } from '@palisade/db';
import type { WSMessage } from './messages.js';

const cardOpSessionUpdate = () =>
  prisma.cardOpSession.update as unknown as ReturnType<typeof vi.fn>;

function ctxFor(operation: string) {
  const sent: WSMessage[] = [];
  return {
    session: {
      id: 'cop_1',
      cardId: 'card_1',
      operation,
      initiatedBy: 'admin-sub',
      phase: 'RUNNING',
      createdAt: new Date(),
      updatedAt: new Date(),
      apduLog: null,
      scpState: null,
      completedAt: null,
      failedAt: null,
      failureReason: null,
      card: { id: 'card_1' } as any,
    } as any,
    send: (m: WSMessage) => { sent.push(m); },
    next: vi.fn(),
    sent,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('runOperation dispatch', () => {
  it('list_applets → routes to handler and emits complete', async () => {
    const ctx = ctxFor('list_applets');
    await runOperation(ctx);
    const terminal = ctx.sent[ctx.sent.length - 1];
    expect(terminal.type).toBe('complete');
    expect((terminal as any).applets).toEqual([
      { aid: 'A0000000625041', lifeCycle: 7, privileges: '00' },
    ]);
  });

  it('install_pa → routes to handler and emits complete', async () => {
    const ctx = ctxFor('install_pa');
    await runOperation(ctx);
    expect(ctx.sent[ctx.sent.length - 1].type).toBe('complete');
  });

  it('reset_pa_state → routes to handler and emits complete', async () => {
    const ctx = ctxFor('reset_pa_state');
    await runOperation(ctx);
    expect(ctx.sent[ctx.sent.length - 1].type).toBe('complete');
  });

  it.each([
    ['install_t4t'],
    ['install_receiver'],
    ['uninstall_pa'],
    ['uninstall_t4t'],
    ['uninstall_receiver'],
    ['wipe_card'],
  ])('Phase 3 stub %s emits NOT_IMPLEMENTED', async (op) => {
    const ctx = ctxFor(op);
    await runOperation(ctx);
    const terminal = ctx.sent[ctx.sent.length - 1];
    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('NOT_IMPLEMENTED');
  });

  it('unknown operation emits UNKNOWN_OP', async () => {
    const ctx = ctxFor('detonate');
    await runOperation(ctx);
    const terminal = ctx.sent[ctx.sent.length - 1];
    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('UNKNOWN_OP');
  });
});

describe('runOperation APDU audit log', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('flushes an (initially empty) log immediately on entry', async () => {
    const ctx = ctxFor('list_applets');
    const audit = new ApduAuditLogger(ctx.session.id);
    await runOperation({ ...ctx, audit });

    // First apduLog flush happens on entry — before the handler runs
    // — so CardOpSession.apduLog is written at least once with []
    // even for a synchronous handler.
    const flushCalls = cardOpSessionUpdate().mock.calls
      .filter((c: any[]) => c[0]?.data?.apduLog !== undefined);
    expect(flushCalls.length).toBeGreaterThanOrEqual(1);
  });

  it('records commands + responses and flushes both on terminal transition', async () => {
    // Build a live audit logger and let a mocked handler append entries
    // through it, simulating an SCP03-driven op.
    const ctx = ctxFor('list_applets');
    const audit = new ApduAuditLogger(ctx.session.id);

    const { runListApplets } = await import('../operations/list-applets.js');
    (runListApplets as unknown as ReturnType<typeof vi.fn>)
      .mockImplementationOnce(async (_session: unknown, io: any) => {
        io.audit?.recordCommand('80CAFE00', 'SELECT_ISD');
        io.audit?.recordResponse('6F1A9000', '9000', 'SELECT_ISD');
        return { type: 'complete', applets: [], packages: [] };
      });

    await runOperation({ ...ctx, audit });

    // The in-memory buffer should have both entries.
    const snap = audit.snapshot();
    expect(snap.length).toBeGreaterThanOrEqual(2);
    const cmd = snap.find((e) => e.direction === 'cmd');
    const rsp = snap.find((e) => e.direction === 'rsp');
    expect(cmd?.hex).toBe('80CAFE00');
    expect(rsp?.hex).toBe('6F1A9000');
    expect(rsp?.sw).toBe('9000');

    // And the final flush on COMPLETE must have written the full
    // transcript to CardOpSession.apduLog.  Find the flush call that
    // carried both our entries.
    const finalFlush = cardOpSessionUpdate().mock.calls
      .map((c: any[]) => c[0]?.data?.apduLog)
      .filter((log: unknown): log is Array<Record<string, unknown>> =>
        Array.isArray(log) && log.length >= 2,
      );
    expect(finalFlush.length).toBeGreaterThan(0);
    const latest = finalFlush[finalFlush.length - 1];
    expect(latest.some((e) => e.direction === 'cmd' && e.hex === '80CAFE00')).toBe(true);
    expect(latest.some((e) => e.direction === 'rsp' && e.hex === '6F1A9000')).toBe(true);
  });

  it('flushes on FAILED terminal too', async () => {
    const ctx = ctxFor('list_applets');
    const audit = new ApduAuditLogger(ctx.session.id);

    const { runListApplets } = await import('../operations/list-applets.js');
    (runListApplets as unknown as ReturnType<typeof vi.fn>)
      .mockImplementationOnce(async (_session: unknown, io: any) => {
        io.audit?.recordCommand('00A40400', 'SELECT');
        io.audit?.recordResponse('6A82', '6A82', 'SELECT');
        return { type: 'error', code: 'FILE_NOT_FOUND', message: 'applet missing' };
      });

    await runOperation({ ...ctx, audit });

    // Terminal is 'error' — but the audit should still have been flushed
    // before the FAILED DB update.
    const flushed = cardOpSessionUpdate().mock.calls
      .map((c: any[]) => c[0]?.data?.apduLog)
      .filter((log: unknown): log is Array<Record<string, unknown>> =>
        Array.isArray(log) && log.length >= 1,
      );
    expect(flushed.length).toBeGreaterThan(0);
    const latest = flushed[flushed.length - 1];
    expect(latest.some((e) => e.hex === '00A40400')).toBe(true);
    expect(latest.some((e) => e.hex === '6A82')).toBe(true);
  });
});
