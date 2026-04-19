import { vi, describe, it, expect, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';

// ---------------------------------------------------------------------------
// Mock SessionManager before importing the handler
// ---------------------------------------------------------------------------

const { mockHandleMessage } = vi.hoisted(() => ({
  mockHandleMessage: vi.fn(),
}));

vi.mock('../services/session-manager.js', () => ({
  SessionManager: vi.fn().mockImplementation(() => ({
    handleMessage: mockHandleMessage,
  })),
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

  it('sends SELECT PA APDU on connect', async () => {
    await handleRelayConnection(ws as any, 'session_01');

    expect(ws.sent).toHaveLength(1);
    const initial = JSON.parse(ws.sent[0]);
    expect(initial.type).toBe('apdu');
    expect(initial.phase).toBe('select_pa');
    expect(initial.hex).toContain('00A40400'); // SELECT command
    expect(initial.hex).toContain('A00000006250414C'); // PA AID (Palisade default)
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
});
