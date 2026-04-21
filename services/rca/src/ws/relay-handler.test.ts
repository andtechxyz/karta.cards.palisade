import { vi, describe, it, expect, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';

// ---------------------------------------------------------------------------
// Mock SessionManager before importing the handler
// ---------------------------------------------------------------------------

const { mockHandleMessage, mockBuildPlanForSession, mockPrismaUpdate, mockPrismaFindUnique } = vi.hoisted(() => ({
  mockHandleMessage: vi.fn(),
  mockBuildPlanForSession: vi.fn(),
  mockPrismaUpdate: vi.fn(),
  mockPrismaFindUnique: vi.fn(),
}));

vi.mock('../services/session-manager.js', () => ({
  SessionManager: vi.fn().mockImplementation(() => ({
    handleMessage: mockHandleMessage,
    buildPlanForSession: mockBuildPlanForSession,
  })),
}));

vi.mock('@palisade/db', () => ({
  prisma: {
    provisioningSession: {
      update: mockPrismaUpdate,
      findUnique: mockPrismaFindUnique,
    },
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { handleRelayConnection } from './relay-handler.js';

// ---------------------------------------------------------------------------
// Mock WebSocket
// ---------------------------------------------------------------------------

class MockWebSocket extends EventEmitter {
  static readonly OPEN = 1;
  readonly OPEN = 1;
  readyState = 1; // OPEN
  sent: string[] = [];
  closeCode?: number;
  closeReason?: string;

  send(data: string) {
    this.sent.push(data);
  }

  close(code?: number, reason?: string) {
    this.closeCode = code;
    this.closeReason = reason;
    this.readyState = 3; // CLOSED
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('handleRelayConnection', () => {
  let ws: MockWebSocket;

  beforeEach(() => {
    vi.clearAllMocks();
    ws = new MockWebSocket();
  });

  it('sends SELECT PA APDU on connect (pa-v1 default when no ChipProfile)', async () => {
    // Card has no ChipProfile → resolver falls back to pa-v1 AID.
    mockPrismaFindUnique.mockResolvedValueOnce({ card: { program: { issuerProfile: null } } });

    await handleRelayConnection(ws as any, 'session_01');

    expect(ws.sent).toHaveLength(1);
    const initial = JSON.parse(ws.sent[0]);
    expect(initial.type).toBe('apdu');
    expect(initial.phase).toBe('select_pa');
    // 00A40400 || Lc=08 || A00000006250414C → 22 hex chars, no Le byte.
    expect(initial.hex).toBe('00A4040008A00000006250414C');
  });

  it('sends SELECT pa-v1 APDU when ChipProfile.provisioningMode=SAD_LEGACY', async () => {
    mockPrismaFindUnique.mockResolvedValueOnce({
      card: {
        program: {
          issuerProfile: { chipProfile: { provisioningMode: 'SAD_LEGACY' } },
        },
      },
    });

    await handleRelayConnection(ws as any, 'session_01');

    const initial = JSON.parse(ws.sent[0]);
    expect(initial.hex).toBe('00A4040008A00000006250414C');
  });

  it('sends SELECT pa-v3 APDU when ChipProfile.provisioningMode=PARAM_BUNDLE', async () => {
    mockPrismaFindUnique.mockResolvedValueOnce({
      card: {
        program: {
          issuerProfile: { chipProfile: { provisioningMode: 'PARAM_BUNDLE' } },
        },
      },
    });

    await handleRelayConnection(ws as any, 'session_01');

    const initial = JSON.parse(ws.sent[0]);
    // 00A40400 || Lc=09 || A0000000625041034C → 9-byte AID.
    expect(initial.hex).toBe('00A4040009A0000000625041034C');
    expect(initial.phase).toBe('select_pa');
  });

  it('parses incoming JSON messages and passes to SessionManager', async () => {
    mockHandleMessage.mockResolvedValue([
      { type: 'apdu', hex: 'AABB', phase: 'scp11_auth', progress: 0.1 },
    ]);

    await handleRelayConnection(ws as any, 'session_01');

    // Clear the initial SELECT PA message
    ws.sent = [];

    // Simulate incoming message
    const incoming = JSON.stringify({ type: 'pa_fci', hex: '6F00' });
    ws.emit('message', Buffer.from(incoming));

    // Allow async handlers to settle
    await vi.waitFor(() => {
      expect(mockHandleMessage).toHaveBeenCalledOnce();
    });

    expect(mockHandleMessage).toHaveBeenCalledWith(
      'session_01',
      { type: 'pa_fci', hex: '6F00' },
    );

    // Response sent back
    expect(ws.sent).toHaveLength(1);
    const resp = JSON.parse(ws.sent[0]);
    expect(resp.type).toBe('apdu');
    expect(resp.hex).toBe('AABB');
  });

  it('closes connection on "complete" response', async () => {
    mockHandleMessage.mockResolvedValue([
      { type: 'complete', proxyCardId: 'pxy_123' },
    ]);

    await handleRelayConnection(ws as any, 'session_01');
    ws.sent = [];

    const incoming = JSON.stringify({ type: 'response', hex: '01', sw: '9000' });
    ws.emit('message', Buffer.from(incoming));

    await vi.waitFor(() => {
      expect(ws.closeCode).toBe(1000);
    });

    expect(ws.closeReason).toBe('Session ended');
  });

  it('closes connection on "error" response', async () => {
    mockHandleMessage.mockResolvedValue([
      { type: 'error', code: 'CARD_ERROR', message: 'Bad SW' },
    ]);

    await handleRelayConnection(ws as any, 'session_01');
    ws.sent = [];

    const incoming = JSON.stringify({ type: 'response', hex: '', sw: '6A82' });
    ws.emit('message', Buffer.from(incoming));

    await vi.waitFor(() => {
      expect(ws.closeCode).toBe(1000);
    });

    expect(ws.closeReason).toBe('Session ended');
  });

  it('sends SERVER_ERROR and closes on exception in message handler', async () => {
    mockHandleMessage.mockRejectedValue(new Error('boom'));

    await handleRelayConnection(ws as any, 'session_01');
    ws.sent = [];

    const incoming = JSON.stringify({ type: 'response', hex: '', sw: '9000' });
    ws.emit('message', Buffer.from(incoming));

    await vi.waitFor(() => {
      expect(ws.sent.length).toBeGreaterThanOrEqual(1);
    });

    const errorMsg = JSON.parse(ws.sent[0]);
    expect(errorMsg.type).toBe('error');
    expect(errorMsg.code).toBe('SERVER_ERROR');
    expect(ws.closeCode).toBe(1011);
  });

  // -------------------------------------------------------------------------
  // Plan mode
  //
  // With planMode: true, the handler must call buildPlanForSession and send
  // the plan JSON on connect instead of the SELECT PA APDU, and transition
  // the session's phase to PLAN_SENT.
  // -------------------------------------------------------------------------

  describe('plan mode', () => {
    it('ships a full plan on connect and marks phase PLAN_SENT', async () => {
      const fakePlan = {
        type: 'plan',
        version: 1,
        steps: [
          { i: 0, apdu: '00A4040008A00000006250414C', phase: 'select_pa', progress: 0.05, expectSw: '9000' },
          { i: 1, apdu: '80E000000101', phase: 'key_generation', progress: 0.25, expectSw: '9000' },
        ],
      };
      mockBuildPlanForSession.mockResolvedValue(fakePlan);
      mockPrismaUpdate.mockResolvedValue({ id: 'session_01', phase: 'PLAN_SENT' });

      await handleRelayConnection(ws as any, 'session_01', { planMode: true });

      expect(mockBuildPlanForSession).toHaveBeenCalledWith('session_01');
      expect(mockPrismaUpdate).toHaveBeenCalledWith({
        where: { id: 'session_01' },
        data: { phase: 'PLAN_SENT' },
      });

      expect(ws.sent).toHaveLength(1);
      const sent = JSON.parse(ws.sent[0]);
      expect(sent.type).toBe('plan');
      expect(sent.version).toBe(1);
      expect(sent.steps).toHaveLength(2);
    });

    it('does NOT send the classical SELECT PA APDU when planMode=true', async () => {
      mockBuildPlanForSession.mockResolvedValue({ type: 'plan', version: 1, steps: [] });
      mockPrismaUpdate.mockResolvedValue({ id: 'session_01' });

      await handleRelayConnection(ws as any, 'session_01', { planMode: true });

      // Only the plan message — no separate APDU.
      expect(ws.sent).toHaveLength(1);
      const sent = JSON.parse(ws.sent[0]);
      expect(sent.type).toBe('plan');
    });

    it('sends PLAN_BUILD_FAILED and closes 1011 if buildPlanForSession throws', async () => {
      mockBuildPlanForSession.mockRejectedValue(new Error('chip profile missing'));

      await handleRelayConnection(ws as any, 'session_01', { planMode: true });

      expect(ws.sent).toHaveLength(1);
      const sent = JSON.parse(ws.sent[0]);
      expect(sent.type).toBe('error');
      expect(sent.code).toBe('PLAN_BUILD_FAILED');
      expect(ws.closeCode).toBe(1011);
      // Phase update should not have happened.
      expect(mockPrismaUpdate).not.toHaveBeenCalled();
    });

    it('routes plan-mode responses back through handleMessage and closes on terminal', async () => {
      mockBuildPlanForSession.mockResolvedValue({ type: 'plan', version: 1, steps: [] });
      mockPrismaUpdate.mockResolvedValue({ id: 'session_01' });
      mockHandleMessage.mockResolvedValue([
        { type: 'complete', proxyCardId: 'pxy_abc' },
      ]);

      await handleRelayConnection(ws as any, 'session_01', { planMode: true });
      ws.sent = []; // clear the initial plan message

      const incoming = JSON.stringify({ type: 'response', i: 4, hex: '', sw: '9000' });
      ws.emit('message', Buffer.from(incoming));

      await vi.waitFor(() => {
        expect(ws.closeCode).toBe(1000);
      });

      expect(mockHandleMessage).toHaveBeenCalledWith(
        'session_01',
        { type: 'response', i: 4, hex: '', sw: '9000' },
      );
      // Plan mode still uses the same complete-message channel.
      const completeMsg = JSON.parse(ws.sent[0]);
      expect(completeMsg.type).toBe('complete');
      expect(completeMsg.proxyCardId).toBe('pxy_abc');
    });
  });
});
