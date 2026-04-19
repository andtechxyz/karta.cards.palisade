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
import { createServer } from 'node:http';
import express from 'express';
import { WebSocketServer } from 'ws';
import { requireSignedRequest, captureRawBody } from '@palisade/service-auth';
import { errorMiddleware } from '@palisade/core';
import { prisma } from '@palisade/db';

import { getCardOpsConfig } from './env.js';
import { createRegisterRouter } from './routes/register.routes.js';
import { handleRelayConnection } from './ws/relay-handler.js';

const config = getCardOpsConfig();
const app = express();
const server = createServer(app);

app.set('trust proxy', 1);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'card-ops' });
});

const authGate = requireSignedRequest({ keys: config.CARD_OPS_AUTH_KEYS });
app.use(
  '/api/card-ops',
  express.json({ limit: '64kb', verify: captureRawBody }),
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

  // Validate the session: exists, READY (or RUNNING on reconnect-retry),
  // and not expired.  The sessionId itself is the auth token — it's a
  // cuid with 25+ chars of entropy, returned only via activation's
  // Cognito+allowlist-gated /api/admin/card-op/start.
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
  } catch (err) {
    console.error('[card-ops-ws] session validation error:', err);
    ws.close(4001, 'Session validation failed');
    return;
  }

  handleRelayConnection(ws, sessionId);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const port = config.PORT;
server.listen(port, () => {
  console.log(`[card-ops] listening on :${port} (HTTP + WebSocket)`);
});

export default app;
