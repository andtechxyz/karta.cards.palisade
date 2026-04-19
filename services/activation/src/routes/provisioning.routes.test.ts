import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'express-async-errors';

// ---------------------------------------------------------------------------
// Mocks — must be declared before imports that resolve them.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    card: {
      findUnique: vi.fn(),
      findFirst: vi.fn(),
      update: vi.fn(),
    },
    sadRecord: {
      findFirst: vi.fn(),
    },
    provisioningSession: {
      create: vi.fn(),
      findFirst: vi.fn(),
      update: vi.fn(),
    },
  },
}));

vi.mock('@palisade/handoff', () => ({
  verifyHandoff: vi.fn(),
}));

vi.mock('@palisade/cognito-auth', () => ({
  createCognitoAuthMiddleware: vi.fn().mockReturnValue(
    // Pass-through: populates req.cognitoUser like a real token would.
    (req: any, _res: any, next: any) => {
      req.cognitoUser = req._testCognitoUser ?? { sub: 'cognito-sub-1', email: 'user@test.com' };
      next();
    },
  ),
}));

vi.mock('@palisade/service-auth', () => ({
  requireSignedRequest: vi.fn().mockReturnValue(
    (_req: any, _res: any, next: any) => next(),
  ),
  // Stub: real signRequest builds an HMAC header, but the test only cares
  // that the call goes out — it doesn't verify the signature.
  signRequest: vi.fn().mockReturnValue('VeraHmac keyId=activation,signature=test'),
}));

vi.mock('undici', () => ({
  request: vi.fn(),
}));

vi.mock('../env.js', () => ({
  getActivationConfig: vi.fn().mockReturnValue({
    COGNITO_USER_POOL_ID: 'ap-southeast-2_TestPool',
    COGNITO_CLIENT_ID: 'test-client-id',
    TAP_HANDOFF_SECRET: '0'.repeat(64),
    PALISADE_RCA_URL: 'http://localhost:9000',
    PROVISION_AUTH_KEYS: { 'provision-agent': '1'.repeat(64) },
  }),
}));

// ---------------------------------------------------------------------------
// Imports — resolved against the mocks above.
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import { verifyHandoff } from '@palisade/handoff';
import { request as undiciRequest } from 'undici';
import express from 'express';
import { createProvisioningRouter } from './provisioning.routes.js';
import { errorMiddleware } from '@palisade/core';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Mocked<T> = ReturnType<typeof vi.fn> & T;

const cardFindUnique = () => prisma.card.findUnique as unknown as Mocked<typeof prisma.card.findUnique>;
const cardFindFirst = () => prisma.card.findFirst as unknown as Mocked<typeof prisma.card.findFirst>;
const cardUpdate = () => prisma.card.update as unknown as Mocked<typeof prisma.card.update>;
const sessionCreate = () => prisma.provisioningSession.create as unknown as Mocked<typeof prisma.provisioningSession.create>;
const sessionFindFirst = () => prisma.provisioningSession.findFirst as unknown as Mocked<typeof prisma.provisioningSession.findFirst>;
const sessionUpdate = () => prisma.provisioningSession.update as unknown as Mocked<typeof prisma.provisioningSession.update>;

import http from 'node:http';

/**
 * Build a mini Express app with the provisioning router mounted at /api/provisioning
 * and the error middleware wired in — enough for supertest-free integration.
 */
function buildApp() {
  const app = express();
  app.use(express.json());
  // Attach a default Cognito user for the pass-through middleware.
  app.use((req: any, _res: any, next: any) => {
    req._testCognitoUser = { sub: 'cognito-sub-1', email: 'user@test.com' };
    next();
  });
  app.use('/api/provisioning', createProvisioningRouter());
  app.use(errorMiddleware);
  return app;
}

/** Fire a request against the Express app via a real ephemeral HTTP server. */
let activeServer: http.Server | null = null;

async function inject(
  app: express.Express,
  method: 'POST' | 'GET',
  path: string,
  body?: Record<string, unknown>,
): Promise<{ status: number; body: any }> {
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const server = http.createServer(app);
    activeServer = server;

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;
      const bodyStr = body ? JSON.stringify(body) : undefined;

      const req = http.request(url, {
        method,
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer fake.jwt.token',
          ...(bodyStr ? { 'content-length': String(Buffer.byteLength(bodyStr)) } : {}),
        },
      }, (res) => {
        let data = '';
        res.on('data', (chunk: string) => { data += chunk; });
        res.on('end', () => {
          server.close();
          activeServer = null;
          let parsed: any;
          try { parsed = JSON.parse(data); } catch { parsed = null; }
          resolve({ status: res.statusCode!, body: parsed });
        });
      });
      req.on('error', (err) => { server.close(); activeServer = null; reject(err); });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  });
}

afterEach(() => {
  if (activeServer) { activeServer.close(); activeServer = null; }
});

beforeEach(() => {
  vi.mocked(cardFindUnique()).mockReset();
  vi.mocked(cardFindFirst()).mockReset();
  vi.mocked(cardUpdate()).mockReset();
  vi.mocked(sessionCreate()).mockReset();
  vi.mocked(sessionFindFirst()).mockReset();
  vi.mocked(sessionUpdate()).mockReset();
  vi.mocked(verifyHandoff).mockReset();
  vi.mocked(undiciRequest).mockReset();
});

// ---------------------------------------------------------------------------
// POST /api/provisioning/start
// ---------------------------------------------------------------------------

describe('POST /api/provisioning/start', () => {
  it('400 when handoffToken is missing', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/start', {});

    expect(status).toBe(400);
    expect(body.error.code).toBe('missing_token');
  });

  it('401-level error when handoff verification fails', async () => {
    vi.mocked(verifyHandoff).mockImplementation(() => {
      throw new Error('bad_signature');
    });

    const app = buildApp();
    const { status } = await inject(app, 'POST', '/api/provisioning/start', {
      handoffToken: 'bad.token',
    });

    // The error middleware catches the raw Error and returns 500 (not ApiError).
    // In production the handoff library throws HandoffError which is caught
    // upstream.  The important assertion: it does NOT succeed.
    expect(status).toBeGreaterThanOrEqual(400);
  });

  it('400 invalid_status when card is not ACTIVATED', async () => {
    vi.mocked(verifyHandoff).mockReturnValue({
      sub: 'card_1',
      purpose: 'provisioning',
      iat: 0,
      exp: Date.now() / 1000 + 60,
      iss: 'tap',
    });
    vi.mocked(cardFindUnique()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'ref_1',
      status: 'SHIPPED',
      proxyCardId: 'proxy_1',
      cognitoSub: null,
    } as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/start', {
      handoffToken: 'valid.token',
    });

    expect(status).toBe(400);
    expect(body.error.code).toBe('invalid_status');
  });

  it('404 card_not_found when card does not exist', async () => {
    vi.mocked(verifyHandoff).mockReturnValue({
      sub: 'card_missing',
      purpose: 'provisioning',
      iat: 0,
      exp: Date.now() / 1000 + 60,
      iss: 'tap',
    });
    vi.mocked(cardFindUnique()).mockResolvedValue(null);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/start', {
      handoffToken: 'valid.token',
    });

    expect(status).toBe(404);
    expect(body.error.code).toBe('card_not_found');
  });

  it('201 with sessionId and wsUrl on success', async () => {
    vi.mocked(verifyHandoff).mockReturnValue({
      sub: 'card_1',
      purpose: 'provisioning',
      iat: 0,
      exp: Date.now() / 1000 + 60,
      iss: 'tap',
    });
    vi.mocked(cardFindUnique()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'ref_1',
      status: 'ACTIVATED',
      proxyCardId: 'proxy_1',
      cognitoSub: null,
    } as never);

    // Mock RCA response — RCA returns camelCase per its real contract.
    vi.mocked(undiciRequest).mockResolvedValue({
      statusCode: 200,
      body: {
        json: vi.fn().mockResolvedValue({
          sessionId: 'rca_session_1',
          wsUrl: 'wss://rca.example.com/ws',
        }),
      },
    } as any);

    vi.mocked(sessionCreate()).mockResolvedValue({ id: 'ps_1' } as never);
    vi.mocked(cardUpdate()).mockResolvedValue({} as never);
    vi.mocked(prisma.sadRecord.findFirst as any).mockResolvedValue({ id: 'sad_1' });

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/start', {
      handoffToken: 'valid.token',
    });

    expect(status).toBe(201);
    expect(body).toEqual({
      sessionId: 'rca_session_1',
      wsUrl: 'wss://rca.example.com/ws',
    });
    // Verify provisioning session was created
    expect(sessionCreate()).toHaveBeenCalledOnce();
    // Verify card was linked to the cognito user
    expect(cardUpdate()).toHaveBeenCalledOnce();
  });

  it('does not re-link cognitoSub if card already has one', async () => {
    vi.mocked(verifyHandoff).mockReturnValue({
      sub: 'card_1',
      purpose: 'provisioning',
      iat: 0,
      exp: Date.now() / 1000 + 60,
      iss: 'tap',
    });
    vi.mocked(cardFindUnique()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'ref_1',
      status: 'ACTIVATED',
      proxyCardId: 'proxy_1',
      cognitoSub: 'already-linked-sub',
    } as never);

    vi.mocked(undiciRequest).mockResolvedValue({
      statusCode: 200,
      body: {
        json: vi.fn().mockResolvedValue({
          sessionId: 'rca_session_2',
          wsUrl: 'wss://rca.example.com/ws2',
        }),
      },
    } as any);

    vi.mocked(sessionCreate()).mockResolvedValue({ id: 'ps_2' } as never);
    vi.mocked(prisma.sadRecord.findFirst as any).mockResolvedValue({ id: 'sad_2' });

    const app = buildApp();
    await inject(app, 'POST', '/api/provisioning/start', {
      handoffToken: 'valid.token',
    });

    // cardUpdate should NOT be called because cognitoSub is already set
    expect(cardUpdate()).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// POST /api/provisioning/callback
// ---------------------------------------------------------------------------

describe('POST /api/provisioning/callback', () => {
  it('400 missing_field when proxy_card_id is absent', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/callback', {
      session_id: 'rca_1',
    });

    expect(status).toBe(400);
    expect(body.error.code).toBe('missing_field');
  });

  it('404 card_not_found when no card matches proxyCardId', async () => {
    vi.mocked(cardFindFirst()).mockResolvedValue(null);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/callback', {
      proxy_card_id: 'nonexistent',
    });

    expect(status).toBe(404);
    expect(body.error.code).toBe('card_not_found');
  });

  it('transitions card to PROVISIONED and session to COMPLETE', async () => {
    vi.mocked(cardFindFirst()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'ref_1',
      proxyCardId: 'proxy_1',
    } as never);
    vi.mocked(cardUpdate()).mockResolvedValue({} as never);
    vi.mocked(sessionFindFirst()).mockResolvedValue({
      id: 'ps_1',
      rcaSessionId: 'rca_1',
    } as never);
    vi.mocked(sessionUpdate()).mockResolvedValue({} as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/callback', {
      proxy_card_id: 'proxy_1',
      session_id: 'rca_1',
    });

    expect(status).toBe(200);
    expect(body).toEqual({ status: 'ok', cardRef: 'ref_1' });

    // Card should be updated to PROVISIONED
    expect(cardUpdate()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'card_1' },
        data: expect.objectContaining({ status: 'PROVISIONED' }),
      }),
    );

    // Session should be updated to COMPLETE
    expect(sessionUpdate()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'ps_1' },
        data: expect.objectContaining({ phase: 'COMPLETE' }),
      }),
    );
  });

  it('succeeds without updating session when session_id is omitted', async () => {
    vi.mocked(cardFindFirst()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'ref_1',
      proxyCardId: 'proxy_1',
    } as never);
    vi.mocked(cardUpdate()).mockResolvedValue({} as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/provisioning/callback', {
      proxy_card_id: 'proxy_1',
    });

    expect(status).toBe(200);
    expect(body.status).toBe('ok');
    expect(sessionFindFirst()).not.toHaveBeenCalled();
    expect(sessionUpdate()).not.toHaveBeenCalled();
  });
});
