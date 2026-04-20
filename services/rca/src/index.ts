/**
 * rca — Real-time Card Personalisation Agent (provisioning relay orchestrator).
 *
 * Internal service on port 3007. Exposes a REST endpoint to start sessions
 * and a WebSocket endpoint for APDU relay between the mobile app and the
 * card's Provisioning Agent applet.
 *
 * No CORS — service-to-service only (internal ALB, HMAC-gated).
 */

import 'dotenv/config';
import 'express-async-errors';
import { resolveSecretRefs, redactSid } from '@palisade/core';
// PCI 3.5.1 / 3.6.1 — resolve Secrets Manager refs in env before any
// getConfig() reads process.env.  See packages/core/src/secrets-resolver.ts.
await resolveSecretRefs();

import { createServer } from 'node:http';
import express from 'express';
import { WebSocketServer } from 'ws';
import { requireSignedRequest, captureRawBody } from '@palisade/service-auth';
import { errorMiddleware } from '@palisade/core';
import { prisma } from '@palisade/db';
import { verifyHandoff, HandoffError } from '@palisade/handoff';
import { assertAttestationPinsForMode } from './services/attestation-verifier.js';

import { getRcaConfig } from './env.js';
import { createProvisionRouter } from './routes/provision.routes.js';
import { handleRelayConnection } from './ws/relay-handler.js';

const config = getRcaConfig();

// Boot-time invariant: refuse to start in strict attestation mode while
// the vendor root public-key pins are still placeholders.  Otherwise
// strict mode silently rejects every tap (N-2 from the PCI audit).
assertAttestationPinsForMode(config.PALISADE_ATTESTATION_MODE);

const app = express();
const server = createServer(app);

app.set('trust proxy', 1);

// Health check (unauthenticated)
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'rca' });
});

// HMAC-gated REST endpoint
const authGate = requireSignedRequest({ keys: config.PROVISION_AUTH_KEYS });
app.use(
  '/api/provision',
  express.json({ limit: '64kb', verify: captureRawBody }),
  authGate,
  createProvisionRouter(),
);

app.use(errorMiddleware);

// ---------------------------------------------------------------------------
// WebSocket server for APDU relay
// ---------------------------------------------------------------------------

const wss = new WebSocketServer({
  server,
  path: undefined, // We handle path routing ourselves
});

wss.on('connection', async (ws, req) => {
  // Extract session ID from path: /api/provision/relay/:sessionId
  const match = req.url?.match(/\/api\/provision\/relay\/([a-zA-Z0-9_-]+)/);
  if (!match) {
    ws.close(4000, 'Invalid path — expected /api/provision/relay/:sessionId');
    return;
  }

  const sessionId = match[1];

  // Parse the query string once for all protocol-level feature flags.
  // Today we check:
  //   tok  — WS auth HMAC token (PCI 8.3.6 / H-8).  Mandatory; rejects
  //          upgrade if missing, malformed, expired, or bound to a
  //          different sessionId.
  //   mode — plan-mode (pre-computed APDU sequence).  Optional.
  //
  // The URL constructor needs a base — we're only interested in the
  // query params, so any valid base works.
  const parsedUrl = new URL(req.url ?? '/', 'http://localhost');
  const planMode = parsedUrl.searchParams.get('mode') === 'plan';
  const tok = parsedUrl.searchParams.get('tok');

  // Verify the WS upgrade token BEFORE touching the DB.  Short-circuits
  // DoS by rejecting unauth'd upgrades at the cheapest possible point.
  if (!tok) {
    ws.close(4001, 'Missing WS auth token');
    return;
  }
  try {
    const claims = verifyHandoff({
      token: tok,
      secretHex: config.WS_TOKEN_SECRET,
      expectedPurpose: 'provisioning',
      allowedIssuers: ['rca'],
    });
    if (claims.sub !== sessionId) {
      ws.close(4001, 'Token bound to different session');
      return;
    }
  } catch (err) {
    const code = err instanceof HandoffError ? err.code : 'token_verify_failed';
    console.warn(`[rca-ws] upgrade rejected for ${redactSid(sessionId)}: ${code}`);
    ws.close(4001, `WS auth failed: ${code}`);
    return;
  }

  // Validate the session exists, is in INIT phase, and was created recently.
  try {
    const session = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
    });
    if (!session) {
      ws.close(4001, 'Unknown session');
      return;
    }
    if (session.phase !== 'INIT') {
      ws.close(4001, 'Session not in INIT phase');
      return;
    }
    const ageMs = Date.now() - session.createdAt.getTime();
    if (ageMs > config.WS_TIMEOUT_SECONDS * 1000) {
      ws.close(4001, 'Session expired');
      return;
    }
  } catch (err) {
    console.error('[rca-ws] session validation error:', err);
    ws.close(4001, 'Session validation failed');
    return;
  }

  handleRelayConnection(ws, sessionId, { planMode });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const port = config.PORT;
server.listen(port, () => {
  console.log(`[rca] listening on :${port} (HTTP + WebSocket)`);
});

export default app;
