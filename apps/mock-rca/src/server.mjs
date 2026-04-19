// Mock Palisade RCA middleware for local mobile NFC relay testing.
//
// Emulates two endpoints the real RCA exposes:
//   POST /api/v1/provision/start            — creates a session, returns ws_url
//   WebSocket /api/v1/provision/relay/{id}  — scripted APDU relay
//
// What it does:
//  1. App POSTs { proxy_card_id, activation_token } -> returns { session_id, ws_url }
//  2. App opens WebSocket, sends first "pa_fci" message
//  3. Server walks a scripted sequence of { apdu, phase, progress } messages
//     Each expects a { response, sw } echo from the app (whatever the card returns)
//  4. Server sends { type: "complete", proxy_card_id } at the end
//
// This does NOT do real SCP11 crypto. It's for wiring up the mobile relay loop,
// verifying the WebSocket protocol, and watching APDU exchanges with a real card.
// Point the mobile app at this instead of the real RCA for local testing.
//
// Run: node src/server.mjs
// Default port: 4000 (HTTP + WS on same port via express-like routing)

import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { WebSocketServer } from 'ws';

const PORT = Number(process.env.PORT ?? 4000);
const HOST = process.env.HOST ?? '0.0.0.0';

// In-memory session store: sessionId -> { proxyCardId, createdAt }
const sessions = new Map();

// Scripted APDU sequence — covers the six provisioning phases from
// ~/Documents/Claude Code/Palisade/04-rca-middleware.md.
// Each entry is sent to the app; the app must return the card's response.
// The hex bytes here are representative, not cryptographically valid.
const SCRIPTED_APDUS = [
  // Phase 1: SCP11c — send server ephemeral public key
  { phase: 'scp11_auth', progress: 0.10, apdu: '002A00A841' + '04' + 'AA'.repeat(64) },
  // Phase 2: SSD creation (GP INSTALL for install)
  { phase: 'scp11_auth', progress: 0.25, apdu: '80E60200' + '20' + 'CC'.repeat(32) },
  // Phase 3: Payment applet install
  { phase: 'key_generation', progress: 0.40, apdu: '80E60C00' + '24' + 'DD'.repeat(36) },
  // Phase 3.5a: GENERATE_KEYS
  { phase: 'key_generation', progress: 0.55, apdu: '80E00000' + '11' + '01' + randomHex(16) },
  // Phase 3.5f: TRANSFER_SAD (chained)
  { phase: 'sad_transfer', progress: 0.70, apdu: '80E20100' + 'FF' + 'EE'.repeat(255) },
  { phase: 'sad_transfer', progress: 0.80, apdu: '80E20200' + 'FF' + 'EE'.repeat(255) },
  { phase: 'sad_transfer', progress: 0.90, apdu: '80E20300' + '80' + 'FF'.repeat(128) },
  // Phase 6: final commit
  { phase: 'confirming', progress: 0.98, apdu: '80E40000' + '00' },
];

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ---------------------------------------------------------------------------
// HTTP handler: POST /api/v1/provision/start
// ---------------------------------------------------------------------------
const httpServer = createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/v1/provision/start') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      let payload;
      try {
        payload = JSON.parse(body || '{}');
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'invalid_json' }));
      }

      const { proxy_card_id, activation_token } = payload;
      if (!proxy_card_id) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'missing_proxy_card_id' }));
      }

      const sessionId = randomUUID();
      sessions.set(sessionId, {
        proxyCardId: proxy_card_id,
        activationToken: activation_token,
        createdAt: Date.now(),
      });

      const wsUrl = `ws://${req.headers.host ?? `${HOST}:${PORT}`}/api/v1/provision/relay/${sessionId}`;
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ session_id: sessionId, ws_url: wsUrl }));
      log(`[start] session ${sessionId} for proxy_card ${proxy_card_id}`);
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('mock-rca — Palisade RCA middleware emulator\nPOST /api/v1/provision/start\n');
  }

  res.writeHead(404);
  res.end();
});

// ---------------------------------------------------------------------------
// WebSocket handler: /api/v1/provision/relay/{session_id}
// ---------------------------------------------------------------------------
const wss = new WebSocketServer({ noServer: true });

httpServer.on('upgrade', (req, socket, head) => {
  const match = req.url?.match(/^\/api\/v1\/provision\/relay\/([^/]+)$/);
  if (!match) {
    socket.destroy();
    return;
  }
  const sessionId = match[1];
  if (!sessions.has(sessionId)) {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req, sessionId);
  });
});

wss.on('connection', async (ws, _req, sessionId) => {
  const session = sessions.get(sessionId);
  log(`[relay] WS connected for session ${sessionId}`);

  let step = 0;
  let phase = 'pa_fci'; // waiting for pa_fci first
  let pendingResolve = null;

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      ws.send(JSON.stringify({ type: 'error', code: 'BAD_JSON', message: 'Could not parse message' }));
      return;
    }

    log(`[relay] ← ${msg.type} ${msg.hex ? `(${msg.hex.length / 2}B)` : ''}${msg.sw ? ` sw=${msg.sw}` : ''}`);

    if (msg.type === 'pa_fci') {
      // Kick off the scripted relay
      phase = 'scp11_auth';
      sendNextApdu(ws);
      return;
    }

    if (msg.type === 'response') {
      if (pendingResolve) {
        pendingResolve(msg);
        pendingResolve = null;
      }
      sendNextApdu(ws);
      return;
    }

    if (msg.type === 'error') {
      log(`[relay] app reported error: ${msg.code} ${msg.message}`);
      ws.close();
      return;
    }
  });

  ws.on('close', () => {
    log(`[relay] WS closed for session ${sessionId}`);
    sessions.delete(sessionId);
  });

  ws.on('error', (err) => {
    log(`[relay] WS error: ${err.message}`);
  });

  function sendNextApdu(ws) {
    if (step >= SCRIPTED_APDUS.length) {
      const msg = { type: 'complete', proxy_card_id: session.proxyCardId };
      ws.send(JSON.stringify(msg));
      log(`[relay] → complete`);
      setTimeout(() => ws.close(1000), 100);
      return;
    }
    const next = SCRIPTED_APDUS[step++];
    const msg = {
      type: 'apdu',
      hex: next.apdu.toUpperCase(),
      phase: next.phase,
      progress: next.progress,
    };
    ws.send(JSON.stringify(msg));
    log(`[relay] → apdu phase=${next.phase} progress=${next.progress} (${next.apdu.length / 2}B)`);
  }
});

function log(msg) {
  const time = new Date().toTimeString().slice(0, 8);
  // eslint-disable-next-line no-console
  console.log(`${time} ${msg}`);
}

httpServer.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`\n🧪 mock-rca listening on http://${HOST}:${PORT}`);
  // eslint-disable-next-line no-console
  console.log(`   POST http://${HOST}:${PORT}/api/v1/provision/start`);
  // eslint-disable-next-line no-console
  console.log(`   WS   ws://${HOST}:${PORT}/api/v1/provision/relay/{session_id}\n`);
});
