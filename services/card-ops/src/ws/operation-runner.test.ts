/**
 * operation-runner dispatch tests — verifies:
 *   - Known ops route to their handler (success/terminal path).
 *   - Phase 3 stub ops emit NOT_IMPLEMENTED and mark CardOpSession FAILED.
 *   - Unknown operation rejects with UNKNOWN_OP.
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
import type { WSMessage } from './messages.js';

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
