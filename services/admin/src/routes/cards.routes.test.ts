import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'express-async-errors';

// ---------------------------------------------------------------------------
// Mocks — Prisma surface this router touches.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    card: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    webAuthnCredential: {
      findFirst: vi.fn(),
      findUnique: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      delete: vi.fn(),
    },
  },
}));

import { prisma } from '@palisade/db';
import express from 'express';
import http from 'node:http';
import cardsRouter from './cards.routes.js';
import { errorMiddleware } from '@palisade/core';

// ---------------------------------------------------------------------------
// Test harness — mounts the router and runs HTTP against an ephemeral server.
// Same pattern as provisioning.routes.test.ts so the two stay aligned.
// ---------------------------------------------------------------------------

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/cards', cardsRouter);
  app.use(errorMiddleware);
  return app;
}

let activeServer: http.Server | null = null;

async function inject(
  app: express.Express,
  method: string,
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
          ...(bodyStr ? { 'content-length': String(Buffer.byteLength(bodyStr)) } : {}),
        },
      }, (res) => {
        let data = '';
        res.on('data', (c: string) => { data += c; });
        res.on('end', () => {
          server.close();
          activeServer = null;
          let parsed: any = null;
          try { parsed = data ? JSON.parse(data) : null; } catch { parsed = data; }
          resolve({ status: res.statusCode!, body: parsed });
        });
      });
      req.on('error', (e) => { server.close(); activeServer = null; reject(e); });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  });
}

afterEach(() => {
  if (activeServer) { activeServer.close(); activeServer = null; }
});

beforeEach(() => {
  vi.resetAllMocks();
});

// Compact accessors for the mocked surface.
const cardFindUnique = () => prisma.card.findUnique as unknown as ReturnType<typeof vi.fn>;
const credFindFirst = () => prisma.webAuthnCredential.findFirst as unknown as ReturnType<typeof vi.fn>;
const credFindUnique = () => prisma.webAuthnCredential.findUnique as unknown as ReturnType<typeof vi.fn>;
const credFindMany = () => prisma.webAuthnCredential.findMany as unknown as ReturnType<typeof vi.fn>;
const credCreate = () => prisma.webAuthnCredential.create as unknown as ReturnType<typeof vi.fn>;
const credDelete = () => prisma.webAuthnCredential.delete as unknown as ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// POST /api/cards/:cardRef/credentials  (pre-register a FIDO credential)
// ---------------------------------------------------------------------------

describe('POST /:cardRef/credentials', () => {
  const VALID_BODY = {
    credentialId: 'AAECAwQFBgcICQoLDA0ODw',
    publicKey: 'pAEDAzkBACBYIBfgEHRkBQ-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    transports: ['nfc'],
    deviceName: 'Pre-registered (perso)',
  };

  it('creates a preregistered credential and returns 201', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1', status: 'SHIPPED' });
    credFindFirst().mockResolvedValueOnce(null);
    credCreate().mockResolvedValueOnce({
      id: 'cred_1',
      credentialId: VALID_BODY.credentialId,
      deviceName: VALID_BODY.deviceName,
      transports: VALID_BODY.transports,
      createdAt: new Date('2026-04-18T00:00:00Z'),
    });

    const res = await inject(buildApp(), 'POST', '/api/cards/abc/credentials', VALID_BODY);

    expect(res.status).toBe(201);
    expect(res.body.id).toBe('cred_1');
    expect(credCreate()).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        cardId: 'card_1',
        preregistered: true,
        kind: 'CROSS_PLATFORM',
        credentialId: VALID_BODY.credentialId,
      }),
    }));
  });

  it('rejects when card is missing (404)', async () => {
    cardFindUnique().mockResolvedValueOnce(null);
    const res = await inject(buildApp(), 'POST', '/api/cards/missing/credentials', VALID_BODY);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('card_not_found');
  });

  it('rejects when card is not SHIPPED (409)', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1', status: 'ACTIVATED' });
    const res = await inject(buildApp(), 'POST', '/api/cards/abc/credentials', VALID_BODY);
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('card_not_shipped');
  });

  it('rejects double pre-registration (409)', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1', status: 'SHIPPED' });
    credFindFirst().mockResolvedValueOnce({ id: 'existing_cred' });
    const res = await inject(buildApp(), 'POST', '/api/cards/abc/credentials', VALID_BODY);
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('preregistered_already_exists');
  });

  it('translates Prisma P2002 to credential_id_taken (409)', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1', status: 'SHIPPED' });
    credFindFirst().mockResolvedValueOnce(null);
    const { Prisma } = await import('@prisma/client');
    credCreate().mockRejectedValueOnce(
      new Prisma.PrismaClientKnownRequestError('unique constraint', {
        code: 'P2002', clientVersion: '5.22', meta: { target: ['credentialId'] },
      }),
    );
    const res = await inject(buildApp(), 'POST', '/api/cards/abc/credentials', VALID_BODY);
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('credential_id_taken');
  });

  it('rejects malformed credentialId (400)', async () => {
    const res = await inject(buildApp(), 'POST', '/api/cards/abc/credentials', {
      ...VALID_BODY, credentialId: 'has spaces and !!! not base64url',
    });
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// GET /api/cards/:cardRef/credentials
// ---------------------------------------------------------------------------

describe('GET /:cardRef/credentials', () => {
  it('returns the credentials in createdAt-desc order', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1' });
    credFindMany().mockResolvedValueOnce([
      { id: 'c2', preregistered: true, createdAt: new Date(), kind: 'CROSS_PLATFORM' },
      { id: 'c1', preregistered: false, createdAt: new Date(), kind: 'CROSS_PLATFORM' },
    ]);
    const res = await inject(buildApp(), 'GET', '/api/cards/abc/credentials');
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].preregistered).toBe(true);
  });

  it('404 when card missing', async () => {
    cardFindUnique().mockResolvedValueOnce(null);
    const res = await inject(buildApp(), 'GET', '/api/cards/missing/credentials');
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// DELETE /api/cards/:cardRef/credentials/:credId
// ---------------------------------------------------------------------------

describe('DELETE /:cardRef/credentials/:credId', () => {
  it('204s on success', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1' });
    credFindUnique().mockResolvedValueOnce({ id: 'cred_1', cardId: 'card_1', preregistered: true });
    credDelete().mockResolvedValueOnce({});
    const res = await inject(buildApp(), 'DELETE', '/api/cards/abc/credentials/cred_1');
    expect(res.status).toBe(204);
    expect(credDelete()).toHaveBeenCalledWith({ where: { id: 'cred_1' } });
  });

  it('404 when credential is on a different card (scope check)', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1' });
    credFindUnique().mockResolvedValueOnce({ id: 'cred_1', cardId: 'OTHER_card', preregistered: true });
    const res = await inject(buildApp(), 'DELETE', '/api/cards/abc/credentials/cred_1');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('credential_not_found');
  });

  it('400 when trying to delete a non-preregistered credential', async () => {
    cardFindUnique().mockResolvedValueOnce({ id: 'card_1' });
    credFindUnique().mockResolvedValueOnce({ id: 'cred_1', cardId: 'card_1', preregistered: false });
    const res = await inject(buildApp(), 'DELETE', '/api/cards/abc/credentials/cred_1');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('not_preregistered');
  });
});
