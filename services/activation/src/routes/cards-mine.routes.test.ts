import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'express-async-errors';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    card: {
      findMany: vi.fn(),
      findFirst: vi.fn(),
    },
  },
}));

vi.mock('@palisade/cognito-auth', () => ({
  createCognitoAuthMiddleware: vi.fn().mockReturnValue(
    (req: any, _res: any, next: any) => {
      // If the test sets _testCognitoUser=null, simulate "no auth" by
      // returning 401 the same way the real middleware does.
      if (req._testCognitoUser === null) {
        _res.status(401).json({ error: 'missing_token', message: 'Authorization Bearer token required' });
        return;
      }
      req.cognitoUser = req._testCognitoUser ?? { sub: 'cognito-sub-1', email: 'user@test.com' };
      next();
    },
  ),
}));

vi.mock('../env.js', () => ({
  getActivationConfig: vi.fn().mockReturnValue({
    COGNITO_USER_POOL_ID: 'ap-southeast-2_TestPool',
    COGNITO_CLIENT_ID: 'test-client-id',
  }),
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import http from 'node:http';
import { prisma } from '@palisade/db';
import express from 'express';
import { createCardsMineRouter } from './cards-mine.routes.js';
import { errorMiddleware } from '@palisade/core';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Mocked<T> = ReturnType<typeof vi.fn> & T;

const cardFindMany = () => prisma.card.findMany as unknown as Mocked<typeof prisma.card.findMany>;
const cardFindFirst = () => prisma.card.findFirst as unknown as Mocked<typeof prisma.card.findFirst>;

function buildApp(opts?: { cognitoUser?: { sub: string; email?: string } | null }) {
  const app = express();
  app.use(express.json());
  // Inject test Cognito user for the pass-through mock middleware to pick up.
  app.use((req: any, _res: any, next: any) => {
    req._testCognitoUser = opts?.cognitoUser !== undefined ? opts.cognitoUser : { sub: 'cognito-sub-1', email: 'user@test.com' };
    next();
  });
  app.use('/api/cards/mine', createCardsMineRouter());
  app.use(errorMiddleware);
  return app;
}

let activeServer: http.Server | null = null;

async function inject(
  app: express.Express,
  method: 'GET' | 'POST',
  path: string,
): Promise<{ status: number; body: any }> {
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const server = http.createServer(app);
    activeServer = server;

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;

      http.get(url, { method, headers: { authorization: 'Bearer fake' } }, (res) => {
        let data = '';
        res.on('data', (chunk: string) => { data += chunk; });
        res.on('end', () => {
          server.close();
          activeServer = null;
          let parsed: any;
          try { parsed = JSON.parse(data); } catch { parsed = null; }
          resolve({ status: res.statusCode!, body: parsed });
        });
      }).on('error', (err) => {
        server.close();
        activeServer = null;
        reject(err);
      });
    });
  });
}

afterEach(() => {
  if (activeServer) { activeServer.close(); activeServer = null; }
});

beforeEach(() => {
  vi.mocked(cardFindMany()).mockReset();
  vi.mocked(cardFindFirst()).mockReset();
});

// ---------------------------------------------------------------------------
// GET /api/cards/mine
// ---------------------------------------------------------------------------

describe('GET /api/cards/mine', () => {
  it('401 when Cognito auth is absent', async () => {
    const app = buildApp({ cognitoUser: null });
    const { status, body } = await inject(app, 'GET', '/api/cards/mine');

    expect(status).toBe(401);
    expect(body.error).toBe('missing_token');
  });

  it('returns cards belonging to the authenticated user', async () => {
    vi.mocked(cardFindMany()).mockResolvedValue([
      {
        id: 'card_1',
        cardRef: 'ref_1',
        status: 'ACTIVATED',
        panLast4: '4242',
        cardholderName: 'Test User',
        panExpiryMonth: '12',
        panExpiryYear: '28',
        program: { name: 'Test Program' },
        credentials: [],
      },
    ] as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/cards/mine');

    expect(status).toBe(200);
    expect(body).toHaveLength(1);
    expect(body[0]).toEqual({
      id: 'card_1',
      cardRef: 'ref_1',
      status: 'ACTIVATED',
      panLast4: '4242',
      cardholderName: 'Test User',
      panExpiryMonth: '12',
      panExpiryYear: '28',
      programName: 'Test Program',
      financialInstitutionName: null,
      credentials: [],
    });

    // Verify the query used the correct cognitoSub
    expect(cardFindMany()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { cognitoSub: 'cognito-sub-1' },
      }),
    );
  });

  it('returns empty array when user has no cards', async () => {
    vi.mocked(cardFindMany()).mockResolvedValue([] as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/cards/mine');

    expect(status).toBe(200);
    expect(body).toEqual([]);
  });

  it('returns null for missing vault/program fields', async () => {
    vi.mocked(cardFindMany()).mockResolvedValue([
      {
        id: 'card_2',
        cardRef: 'ref_2',
        status: 'SHIPPED',
        panLast4: null,
        cardholderName: null,
        panExpiryMonth: null,
        panExpiryYear: null,
        program: null,
        credentials: [],
      },
    ] as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/cards/mine');

    expect(status).toBe(200);
    expect(body[0].panLast4).toBeNull();
    expect(body[0].cardholderName).toBeNull();
    expect(body[0].programName).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// GET /api/cards/mine/:cardId
// ---------------------------------------------------------------------------

describe('GET /api/cards/mine/:cardId', () => {
  it('returns the card when it belongs to the user', async () => {
    vi.mocked(cardFindFirst()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'ref_1',
      status: 'ACTIVATED',
      panLast4: '4242',
      cardholderName: 'Test',
      panExpiryMonth: '01',
      panExpiryYear: '30',
      program: { name: 'Prog A' },
      credentials: [{ id: 'cred_1', kind: 'PLATFORM', deviceName: 'iPhone', createdAt: '2025-01-01' }],
    } as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/cards/mine/card_1');

    expect(status).toBe(200);
    expect(body.id).toBe('card_1');
    expect(body.panLast4).toBe('4242');
    expect(body.programName).toBe('Prog A');
    expect(body.credentials).toHaveLength(1);

    // Verify the query used both cardId and cognitoSub
    expect(cardFindFirst()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'card_1', cognitoSub: 'cognito-sub-1' },
      }),
    );
  });

  it('404 when card belongs to a different user (findFirst returns null)', async () => {
    vi.mocked(cardFindFirst()).mockResolvedValue(null);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/cards/mine/card_other');

    expect(status).toBe(404);
    expect(body.error.code).toBe('card_not_found');
  });

  it('404 when card does not exist at all', async () => {
    vi.mocked(cardFindFirst()).mockResolvedValue(null);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/cards/mine/card_nonexistent');

    expect(status).toBe(404);
    expect(body.error.code).toBe('card_not_found');
  });
});
