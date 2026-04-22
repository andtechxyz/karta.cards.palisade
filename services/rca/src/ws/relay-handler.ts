/**
 * WebSocket relay handler for provisioning sessions.
 *
 * Two protocol modes coexist on the same WS endpoint:
 *
 *   - **Classical** (default): server sends one APDU, waits for the
 *     response, then sends the next.  5 phases, 4 server-to-app
 *     round-trips per tap.  This is what the production mobile builds
 *     speak today.
 *
 *   - **Plan** (opt-in via `?mode=plan`): server pre-computes the entire
 *     5-APDU sequence and ships it on connect as a single `{type:'plan'}`
 *     message.  The phone queues the plan locally and streams responses
 *     back indexed by step.  1 server-to-app message total.  Cuts ~2 s
 *     off the tap on 500 ms-RTT bad-connection scenarios.
 *
 * Protocol (JSON messages):
 *
 *   Classical:
 *     Server → App: { type: "apdu", hex, phase, progress }
 *     App → Server: { type: "pa_fci", hex, sw }       (after SELECT PA)
 *     App → Server: { type: "response", hex, sw }     (subsequent APDUs)
 *
 *   Plan:
 *     Server → App: { type: "plan", version, steps: [{i,apdu,phase,progress,expectSw}, ...] }
 *     App → Server: { type: "response", i, hex, sw }  (one per step)
 *
 *   Shared terminal messages:
 *     Server → App: { type: "complete", proxyCardId }
 *     Server → App: { type: "error", code, message }
 *     App → Server: { type: "error", code, message }
 */

import type { WebSocket } from 'ws';
import { prisma } from '@palisade/db';
import { redactSid } from '@palisade/core';

import { SessionManager, type WSMessage } from '../services/session-manager.js';

const sessionManager = new SessionManager();

export interface RelayOptions {
  /** When true, send a pre-computed plan on connect instead of streaming APDUs. */
  planMode?: boolean;
}

/**
 * Handle a WebSocket connection for a provisioning session.
 *
 * The caller (index.ts) has already validated the sessionId exists and
 * is in INIT phase; we just drive the session from here.
 */
export async function handleRelayConnection(
  ws: WebSocket,
  sessionId: string,
  options: RelayOptions = {},
): Promise<void> {
  const mode = options.planMode ? 'plan' : 'classical';
  console.log(`[rca-ws] relay connected: session=${redactSid(sessionId)}, mode=${mode}`);

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
      console.error(`[rca-ws] error in session ${redactSid(sessionId)}:`, err);
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
    console.log(`[rca-ws] relay closed: session=${redactSid(sessionId)}, code=${code}`);
  });

  ws.on('error', (err) => {
    console.error(`[rca-ws] relay error: session=${redactSid(sessionId)}`, err);
  });

  if (options.planMode) {
    // Plan mode: assemble the full APDU plan and ship it in one message.
    // The phone runs the whole sequence locally against the chip and
    // streams indexed responses back — no server round-trips between
    // steps.  We mark the session PLAN_SENT so `handleMessage` knows to
    // route subsequent `response` messages through the plan-mode
    // handlers (distinguished at runtime by the `i` field on the inbound
    // response).
    try {
      const plan = await sessionManager.buildPlanForSession(sessionId);
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'PLAN_SENT' },
      });
      ws.send(JSON.stringify(plan));
    } catch (err) {
      console.error(`[rca-ws] plan build failed for session ${redactSid(sessionId)}:`, err);
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({
          type: 'error',
          code: 'PLAN_BUILD_FAILED',
          message: 'Could not assemble provisioning plan',
        }));
        ws.close(1011, 'Plan build failed');
      }
      return;
    }
    return;
  }

  // Classical mode: send SELECT PA and let the phase machine drive the
  // rest via pa_fci → GENERATE_KEYS → TRANSFER_SAD | TRANSFER_PARAMS →
  // FINAL_STATUS → CONFIRM.  AID picked based on the Card's
  // ChipProfile.provisioningMode, same toggle that routes data-prep's
  // prepare() and card-ops' install_pa:
  //
  //   SAD_LEGACY   → A00000006250414C   (pa-v1, 8-byte AID)
  //   PARAM_BUNDLE → A0000000625041034C (pa-v3, 9-byte AID — package
  //                  A000000062504103 + module tag 0x4C)
  //
  // Both applets can be resident on the same chip simultaneously during
  // migration — different package AIDs, different instance AIDs, no
  // conflict.  If the lookup fails (no ChipProfile on the Card → Program
  // → IssuerProfile chain), default to pa-v1 to preserve legacy
  // behaviour.
  const selectAid = await resolveSelectPaAid(sessionId);
  // Lc byte = AID length in bytes (8 for pa-v1, 9 for pa-v3).
  const aidBytes = Buffer.from(selectAid, 'hex');
  const lc = aidBytes.length.toString(16).toUpperCase().padStart(2, '0');
  ws.send(JSON.stringify({
    type: 'apdu',
    hex: '00A40400' + lc + selectAid,
    phase: 'select_pa',
    progress: 0.05,
  }));
}

/**
 * Resolve the PA applet AID to SELECT for this session.
 *
 * Chain: ProvisioningSession → Card → Program → IssuerProfile →
 * ChipProfile.provisioningMode.
 *
 * Returns the AID as uppercase hex (no 0x prefix, no delimiters).  The
 * caller prepends CLA/INS/P1/P2/Lc and appends Le=0x00 as needed.
 */
async function resolveSelectPaAid(sessionId: string): Promise<string> {
  const session = await prisma.provisioningSession.findUnique({
    where: { id: sessionId },
    select: {
      card: {
        select: {
          program: {
            select: {
              issuerProfile: {
                select: {
                  chipProfile: { select: { provisioningMode: true } },
                },
              },
            },
          },
        },
      },
    },
  });
  const mode = session?.card?.program?.issuerProfile?.chipProfile?.provisioningMode;
  if (mode === 'PARAM_BUNDLE') {
    // pa-v3 applet AID — package A000000062504103 || 0x4C.
    return 'A0000000625041034C';
  }
  // Default = legacy pa-v1 applet AID.  Covers SAD_LEGACY, null
  // ChipProfile (legacy programs), and any future enum value rca
  // hasn't been taught about yet.
  return 'A00000006250414C';
}
