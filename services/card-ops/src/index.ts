/**
 * card-ops — Admin-operated card management service.
 *
 * Internal service on port 3008.  Exposes:
 *   POST /api/card-ops/register     HMAC-gated S2S — primes a session
 *                                   that activation already created
 *   WS   /api/card-ops/relay/:id    APDU relay driving the chosen
 *                                   GlobalPlatform operation
 *
 * No CORS — the admin WebSocket connects directly to the public ALB
 * path that forwards here; browsers don't hit REST endpoints on this
 * service.
 */

import 'dotenv/config';
import 'express-async-errors';
import { resolveSecretRefs, redactSid } from '@palisade/core';
await resolveSecretRefs();

import { createServer } from 'node:http';
import express from 'express';
import { WebSocketServer } from 'ws';
import { requireSignedRequest, captureRawBody } from '@palisade/service-auth';
import {
  errorMiddleware,
  apiRateLimit,
  requestIdMiddleware,
} from '@palisade/core';
import { prisma } from '@palisade/db';
import { startSweeper, scrubStaleCardOpScpState } from '@palisade/retention';
import { verifyHandoff, HandoffError } from '@palisade/handoff';
import { createCognitoTokenVerifier } from '@palisade/cognito-auth';

import { getCardOpsConfig } from './env.js';
import { createRegisterRouter } from './routes/register.routes.js';
import { handleRelayConnection } from './ws/relay-handler.js';

const config = getCardOpsConfig();
const app = express();
const server = createServer(app);

// Cognito token verifier for WS upgrade auth (PCI DSS 10.2.5 strict
// reading: bind every WS connection to the operator who created the
// session, not just to the session cuid).  Pulls pool ID + client ID
// from the same env defaults the activation service uses, so a single
// Cognito pool covers both ends of the admin → card-ops handoff.
const verifyCognito = createCognitoTokenVerifier({
  userPoolId: process.env.COGNITO_USER_POOL_ID ?? 'ap-southeast-2_Db4d1vpIV',
  clientId: process.env.COGNITO_CLIENT_ID ?? '7pj9230obhsa6h6vrvk9tru7do',
});

app.set('trust proxy', 1);

// PCI DSS 10.x / CPL LSR 8 — correlation ID for cross-service tracing.
app.use(requestIdMiddleware);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'card-ops' });
});

// HMAC-gated REST: only the admin backend forwarding session starts
// reaches this path.  apiRateLimit is defensive — same reasoning as
// rca/index.ts — against hot-loop bugs or a compromised upstream.
const authGate = requireSignedRequest({ keys: config.CARD_OPS_AUTH_KEYS });
app.use(
  '/api/card-ops',
  express.json({ limit: '64kb', verify: captureRawBody }),
  apiRateLimit,
  authGate,
  createRegisterRouter(),
);

app.use(errorMiddleware);

// ---------------------------------------------------------------------------
// WebSocket server for APDU relay
// ---------------------------------------------------------------------------

const wss = new WebSocketServer({ server, path: undefined });

wss.on('connection', async (ws, req) => {
  const match = req.url?.match(/\/api\/card-ops\/relay\/([a-zA-Z0-9_-]+)/);
  if (!match) {
    ws.close(4000, 'Invalid path — expected /api/card-ops/relay/:sessionId');
    return;
  }

  const sessionId = match[1];

  // Parse `?tok=<signed>` from the query.  PCI 8.3.6 / H-8: cuid alone
  // isn't enough auth for a full-auth GP relay channel.  Activation
  // mints the token at card-op creation time; we verify here with the
  // shared WS_TOKEN_SECRET.
  const parsedUrl = new URL(req.url ?? '/', 'http://localhost');
  const tok = parsedUrl.searchParams.get('tok');
  if (!tok) {
    ws.close(4001, 'Missing WS auth token');
    return;
  }
  try {
    const claims = verifyHandoff({
      token: tok,
      secretHex: config.WS_TOKEN_SECRET,
      expectedPurpose: 'provisioning',
      allowedIssuers: ['activation'],
    });
    if (claims.sub !== sessionId) {
      ws.close(4001, 'Token bound to different session');
      return;
    }
  } catch (err) {
    const code = err instanceof HandoffError ? err.code : 'token_verify_failed';
    console.warn(`[card-ops-ws] upgrade rejected for ${redactSid(sessionId)}: ${code}`);
    ws.close(4001, `WS auth failed: ${code}`);
    return;
  }

  // Validate the session: exists, READY (or RUNNING on reconnect-retry),
  // and not expired.  Plus PCI DSS 10.2.5 / Stage C.2 — bind to the
  // specific operator who created the session.  An attacker who somehow
  // exfiltrated wsUrl + tok still can't hijack the session unless they
  // also hold the original operator's Cognito session.
  try {
    const session = await prisma.cardOpSession.findUnique({
      where: { id: sessionId },
    });
    if (!session) {
      ws.close(4001, 'Unknown session');
      return;
    }
    if (session.phase !== 'READY') {
      ws.close(4001, `Session not in READY phase (got ${session.phase})`);
      return;
    }
    const ageMs = Date.now() - session.createdAt.getTime();
    if (ageMs > config.WS_TIMEOUT_SECONDS * 1000) {
      ws.close(4001, 'Session expired');
      return;
    }

    // PCI 10.2.5 — operator identity binding.  ?id_token=<JWT> is
    // required; we verify against the same Cognito pool activation
    // gates with, then assert the connecting user is the one who
    // created this session (session.initiatedBy was stamped at
    // activation's POST /api/admin/card-op/start).  CLI ops tools
    // grab the JWT from `aws cognito-idp admin-initiate-auth` (or
    // the token cache) and append it to the wsUrl before connecting.
    const idToken = parsedUrl.searchParams.get('id_token');
    if (!idToken) {
      console.warn(
        `[card-ops-ws] missing id_token for ${redactSid(sessionId)} — operator identity unverifiable`,
      );
      ws.close(4001, 'Missing id_token query param');
      return;
    }
    const verifyResult = await verifyCognito(idToken);
    if (!verifyResult.ok) {
      console.warn(
        `[card-ops-ws] cognito verify failed for ${redactSid(sessionId)}: ${verifyResult.code}`,
      );
      ws.close(4001, `id_token rejected: ${verifyResult.code}`);
      return;
    }
    if (verifyResult.user.sub !== session.initiatedBy) {
      console.warn(
        `[card-ops-ws] operator mismatch for ${redactSid(sessionId)}: ` +
          `connecting=${redactSid(verifyResult.user.sub)} initiated=${redactSid(session.initiatedBy)}`,
      );
      ws.close(4001, 'Operator does not match session initiator');
      return;
    }
    // Stamp who actually connected onto the audit trail.  This is a
    // separate field from initiatedBy because edge cases exist where
    // the connecting operator could differ (e.g. a future relay-by-
    // proxy mode); for now they're equal by the check above, but the
    // explicit stamp removes ambiguity in audit reads.
    await prisma.cardOpSession.update({
      where: { id: sessionId },
      data: {
        wsConnectedBy: verifyResult.user.sub,
        wsConnectedAt: new Date(),
      },
    });
  } catch (err) {
    console.error('[card-ops-ws] session validation error:', err);
    ws.close(4001, 'Session validation failed');
    return;
  }

  handleRelayConnection(ws, sessionId);
});

// ---------------------------------------------------------------------------
// Retention sweepers — PCI 3.5 / 3.6.4
// ---------------------------------------------------------------------------
// Scrub plaintext SCP03 session keys from orphaned CardOpSession rows.
// Happy path clears them on COMPLETE/FAILED; this catches abandoned
// sessions where the WS died before the clear path ran.
startSweeper({
  name: 'card-op-scp-state',
  intervalMs: 5 * 60_000,
  run: scrubStaleCardOpScpState,
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const port = config.PORT;
server.listen(port, () => {
  console.log(`[card-ops] listening on :${port} (HTTP + WebSocket)`);
});

export default app;
