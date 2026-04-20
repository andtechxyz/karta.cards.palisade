import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'express-async-errors';
import http from 'node:http';
import express from 'express';

// ---------------------------------------------------------------------------
// Mocks — must be declared before imports that resolve them.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    card: {
      findUnique: vi.fn(),
    },
    cardOpSession: {
      create: vi.fn(),
      update: vi.fn(),
    },
  },
}));

vi.mock('@palisade/cognito-auth', () => ({
  createCognitoAuthMiddleware: vi.fn().mockReturnValue(
    (req: any, _res: any, next: any) => {
      req.cognitoUser = req._testCognitoUser ?? {
        sub: 'admin-sub-1',
        email: 'admin@karta.cards',
        groups: ['admin'],
      };
      next();
    },
  ),
}));

vi.mock('@palisade/admin-config', () => ({
  getAdminEmails: vi.fn().mockReturnValue(['admin@karta.cards']),
}));

vi.mock('@palisade/service-auth', () => ({
  signRequest: vi.fn().mockReturnValue('VeraHmac keyId=activation,ts=0,sig=deadbeef'),
}));

vi.mock('undici', () => ({
  request: vi.fn(),
}));

vi.mock('../env.js', () => ({
  getActivationConfig: vi.fn().mockReturnValue({
    COGNITO_USER_POOL_ID: 'ap-southeast-2_TestPool',
    COGNITO_CLIENT_ID: 'test-client-id',
    CARD_OPS_URL: 'http://card-ops:3009',
    CARD_OPS_PUBLIC_WS_BASE: 'wss://manage.karta.cards',
    SERVICE_AUTH_CARD_OPS_SECRET: '0'.repeat(64),
    WS_TOKEN_SECRET: '1'.repeat(32) + '2'.repeat(32),
    WS_TIMEOUT_SECONDS: 60,
  }),
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import { request as undiciRequest } from 'undici';
import { errorMiddleware } from '@palisade/core';
import { createCardOpRouter } from './card-op.routes.js';

type Mocked<T> = ReturnType<typeof vi.fn> & T;
const cardFindUnique = () => prisma.card.findUnique as unknown as Mocked<typeof prisma.card.findUnique>;
const sessionCreate = () => (prisma as any).cardOpSession.create as ReturnType<typeof vi.fn>;
const sessionUpdate = () => (prisma as any).cardOpSession.update as ReturnType<typeof vi.fn>;

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/admin/card-op', createCardOpRouter());
  app.use(errorMiddleware);
  return app;
}

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
        res.on('data', (chunk) => { data += chunk; });
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
  vi.mocked(sessionCreate()).mockReset();
  vi.mocked(sessionUpdate()).mockReset();
  vi.mocked(undiciRequest).mockReset();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('POST /api/admin/card-op/start', () => {
  it('400 validation_failed when body is empty', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/card-op/start', {});

    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('400 validation_failed for unknown operation', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/card-op/start', {
      operation: 'detonate',
      cardRef: 'cr_1',
    });

    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('400 validation_failed when cardRef is missing', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/card-op/start', {
      operation: 'list_applets',
    });

    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('404 card_not_found when card does not exist', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue(null);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/card-op/start', {
      operation: 'list_applets',
      cardRef: 'cr_missing',
    });

    expect(status).toBe(404);
    expect(body.error.code).toBe('card_not_found');
  });

  it('201 with sessionId + wsUrl on success, creates session, S2S registers', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'cr_1',
    } as never);
    vi.mocked(sessionCreate()).mockResolvedValue({
      id: 'cop_1',
      cardId: 'card_1',
      operation: 'list_applets',
    } as never);
    vi.mocked(undiciRequest).mockResolvedValue({
      statusCode: 200,
      body: {
        json: vi.fn().mockResolvedValue({ ok: true, wsPath: '/api/card-ops/relay/cop_1' }),
      },
    } as any);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/card-op/start', {
      operation: 'list_applets',
      cardRef: 'cr_1',
    });

    expect(status).toBe(201);
    expect(body.sessionId).toBe('cop_1');
    // PCI 8.3.6 / H-8: wsUrl now carries a signed `?tok=` HMAC token so
    // the WS upgrade auth isn't solely the cuid.  Assert the PATH prefix
    // is right and that the token parameter is present + structurally valid.
    expect(body.wsUrl).toMatch(
      /^wss:\/\/manage\.karta\.cards\/api\/card-ops\/relay\/cop_1\?tok=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
    );

    // Session row created with the right initiator + phase
    expect(sessionCreate()).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          cardId: 'card_1',
          operation: 'list_applets',
          initiatedBy: 'admin-sub-1',
          phase: 'READY',
        }),
      }),
    );
    // S2S register call fired
    expect(undiciRequest).toHaveBeenCalledOnce();
  });

  it('500 card_ops_error and marks session FAILED when S2S returns 5xx', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'cr_1',
    } as never);
    vi.mocked(sessionCreate()).mockResolvedValue({ id: 'cop_1' } as never);
    vi.mocked(sessionUpdate()).mockResolvedValue({} as never);
    vi.mocked(undiciRequest).mockResolvedValue({
      statusCode: 503,
      body: { text: vi.fn().mockResolvedValue('upstream down') },
    } as any);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/card-op/start', {
      operation: 'install_pa',
      cardRef: 'cr_1',
    });

    expect(status).toBe(500);
    expect(body.error.code).toBe('card_ops_error');
    // Session marked FAILED
    expect(sessionUpdate()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'cop_1' },
        data: expect.objectContaining({ phase: 'FAILED' }),
      }),
    );
  });

  it('accepts every operation listed in the spec', async () => {
    const ops = [
      'list_applets',
      'install_pa',
      'install_t4t',
      'install_receiver',
      'install_payment_applet',
      'personalise_payment_applet',
      'reset_pa_state',
      'uninstall_pa',
      'uninstall_t4t',
      'uninstall_receiver',
      'wipe_card',
    ];

    for (const op of ops) {
      vi.mocked(cardFindUnique()).mockResolvedValue({
        id: 'card_1',
        cardRef: 'cr_1',
      } as never);
      vi.mocked(sessionCreate()).mockResolvedValue({ id: `cop_${op}` } as never);
      vi.mocked(undiciRequest).mockResolvedValue({
        statusCode: 200,
        body: { json: vi.fn().mockResolvedValue({ ok: true, wsPath: `/api/card-ops/relay/cop_${op}` }) },
      } as any);

      const app = buildApp();
      const { status } = await inject(app, 'POST', '/api/admin/card-op/start', {
        operation: op,
        cardRef: 'cr_1',
      });
      expect(status, `op ${op}`).toBe(201);
    }
  });
});
