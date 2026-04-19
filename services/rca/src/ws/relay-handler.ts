/**
 * WebSocket relay handler for provisioning sessions.
 *
 * Protocol (JSON messages):
 *   Server → App: { type: "apdu", hex, phase, progress }
 *   App → Server: { type: "response", hex, sw }
 *   App → Server: { type: "pa_fci", hex, sw }
 *   Server → App: { type: "complete", proxyCardId }
 *   Server → App: { type: "error", code, message }
 *
 * Ported from palisade-rca/app/api/websocket.py.
 */

import type { WebSocket } from 'ws';
import { SessionManager, type WSMessage } from '../services/session-manager.js';

const sessionManager = new SessionManager();

/**
 * Handle a WebSocket connection for a provisioning session.
 */
export async function handleRelayConnection(
  ws: WebSocket,
  sessionId: string,
): Promise<void> {
  console.log(`[rca-ws] relay connected: session=${sessionId}`);

  ws.on('message', async (raw) => {
    try {
      const message: WSMessage = JSON.parse(raw.toString());

      const responses = await sessionManager.handleMessage(sessionId, message);

      for (const resp of responses) {
        if (ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify(resp));
        }
      }

      // Close on terminal states
      if (responses.some((r) => r.type === 'complete' || r.type === 'error')) {
        ws.close(1000, 'Session ended');
      }
    } catch (err) {
      console.error(`[rca-ws] error in session ${sessionId}:`, err);
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type: 'error',
          code: 'SERVER_ERROR',
          message: 'Internal error during provisioning',
        }));
        ws.close(1011, 'Server error');
      }
    }
  });

  ws.on('close', (code, _reason) => {
    console.log(`[rca-ws] relay closed: session=${sessionId}, code=${code}`);
  });

  ws.on('error', (err) => {
    console.error(`[rca-ws] relay error: session=${sessionId}`, err);
  });

  // Send initial ready message — SELECT the Palisade Provisioning Agent
  // applet by its instance AID.  `A00000006250414C` is the AID the JavaCard
  // converter assigns when building from com.palisade.pa (package AID
  // A0000000625041 + 1-byte module tag 0x4C).  Palisade's own reference
  // perso installs `gp --install pa.cap` with no --create override, so the
  // default module AID is the live instance AID we SELECT here.
  ws.send(JSON.stringify({
    type: 'apdu',
    hex: '00A40400' + '08' + 'A00000006250414C', // SELECT PA by AID
    phase: 'select_pa',
    progress: 0.05,
  }));
}
