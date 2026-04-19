import { describe, it, expect, vi, beforeEach } from 'vitest';
import 'express-async-errors';
import express from 'express';
import http from 'node:http';
import { createHash, createHmac } from 'node:crypto';

// ---------------------------------------------------------------------------
// Mocks — declared before imports that resolve them.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    card: {
      findUnique: vi.fn(),
    },
    webAuthnCredential: {
      findMany: vi.fn(),
      findFirst: vi.fn(),
      create: vi.fn(),
      updateMany: vi.fn(),
    },
  },
  CredentialKind: {
    PLATFORM: 'PLATFORM',
    CROSS_PLATFORM: 'CROSS_PLATFORM',
  },
}));

// ---------------------------------------------------------------------------
// Imports — resolved against the mocks above.
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import { errorMiddleware } from '@palisade/core';
import {
  captureRawBody,
  requireSignedRequest,
  signRequest,
} from '@palisade/service-auth';
import { createWebAuthnRouters } from './webauthn-credentials.routes.js';

type Mocked<T> = ReturnType<typeof vi.fn> & T;
const cardFindUnique = () =>
  prisma.card.findUnique as unknown as Mocked<typeof prisma.card.findUnique>;
const credFindMany = () =>
  prisma.webAuthnCredential.findMany as unknown as Mocked<
    typeof prisma.webAuthnCredential.findMany
  >;
const credFindFirst = () =>
  prisma.webAuthnCredential.findFirst as unknown as Mocked<
    typeof prisma.webAuthnCredential.findFirst
  >;
const credCreate = () =>
  prisma.webAuthnCredential.create as unknown as Mocked<
    typeof prisma.webAuthnCredential.create
  >;
const credUpdateMany = () =>
  prisma.webAuthnCredential.updateMany as unknown as Mocked<
    typeof prisma.webAuthnCredential.updateMany
  >;

const PAY_SECRET = 'f'.repeat(64);
const PAY_AUTH_KEYS = { pay: PAY_SECRET };

function buildApp() {
  const app = express();
  const payGate = requireSignedRequest({ keys: PAY_AUTH_KEYS });
  const routers = createWebAuthnRouters(payGate);
  app.use(
    '/api/cards',
    express.json({ limit: '64kb', verify: captureRawBody }),
    routers.cardScoped,
  );
  app.use(
    '/api/webauthn-credentials',
    express.json({ limit: '64kb', verify: captureRawBody }),
    routers.credentialScoped,
  );
  app.use(errorMiddleware);
  return app;
}

/** Start a short-lived HTTP server around the app; returns a `{ url, close }`. */
async function serve(
  app: express.Express,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const addr = server.address();
  if (typeof addr !== 'object' || addr === null) throw new Error('no address');
  const url = `http://127.0.0.1:${addr.port}`;
  return {
    url,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function sign(method: string, pathAndQuery: string, body: Buffer = Buffer.alloc(0)): string {
  return signRequest({
    method,
    pathAndQuery,
    body,
    keyId: 'pay',
    secret: PAY_SECRET,
  });
}

async function request(
  method: string,
  url: string,
  opts: { headers?: Record<string, string>; body?: unknown } = {},
): Promise<{ status: number; body: unknown }> {
  const init: RequestInit = { method };
  if (opts.body !== undefined) {
    init.body = JSON.stringify(opts.body);
    init.headers = { 'content-type': 'application/json', ...(opts.headers ?? {}) };
  } else {
    init.headers = opts.headers;
  }
  const res = await fetch(url, init);
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

const sampleCred = {
  id: 'cred_row_1',
  credentialId: 'KH_abc123',
  publicKey: 'pk_base64url',
  counter: 5n,
  deviceName: 'iPhone 16',
  kind: 'PLATFORM',
  createdAt: new Date('2026-04-01T12:00:00.000Z'),
  lastUsedAt: new Date('2026-04-15T08:30:00.000Z'),
};

beforeEach(() => {
  vi.mocked(cardFindUnique()).mockReset();
  vi.mocked(credFindMany()).mockReset();
  vi.mocked(credFindFirst()).mockReset();
  vi.mocked(credCreate()).mockReset();
  vi.mocked(credUpdateMany()).mockReset();
});

// ---------------------------------------------------------------------------
// GET /api/cards/:cardId/webauthn-credentials
// ---------------------------------------------------------------------------

describe('GET /api/cards/:cardId/webauthn-credentials', () => {
  it('returns 200 with the credential array for an existing card', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue({ id: 'card_1' } as never);
    vi.mocked(credFindMany()).mockResolvedValue([sampleCred] as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/webauthn-credentials';
      const res = await request('GET', `${url}${path}`, {
        headers: { authorization: sign('GET', path) },
      });
      expect(res.status).toBe(200);
      expect(res.body).toEqual([
        {
          id: 'cred_row_1',
          credentialId: 'KH_abc123',
          publicKey: 'pk_base64url',
          signCounter: '5',
          deviceName: 'iPhone 16',
          kind: 'PLATFORM',
          createdAt: '2026-04-01T12:00:00.000Z',
          lastUsedAt: '2026-04-15T08:30:00.000Z',
        },
      ]);

      const call = vi.mocked(credFindMany()).mock.calls[0]![0]!;
      expect(call.where).toEqual({ cardId: 'card_1' });
    } finally {
      await close();
    }
  });

  it('returns an empty array when the card has no credentials', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue({ id: 'card_1' } as never);
    vi.mocked(credFindMany()).mockResolvedValue([] as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/webauthn-credentials';
      const res = await request('GET', `${url}${path}`, {
        headers: { authorization: sign('GET', path) },
      });
      expect(res.status).toBe(200);
      expect(res.body).toEqual([]);
    } finally {
      await close();
    }
  });

  it('returns 404 when the cardId is unknown', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue(null);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_missing/webauthn-credentials';
      const res = await request('GET', `${url}${path}`, {
        headers: { authorization: sign('GET', path) },
      });
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({ error: { code: 'card_not_found' } });
      expect(credFindMany()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 401 when unsigned', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/webauthn-credentials';
      const res = await request('GET', `${url}${path}`);
      expect(res.status).toBe(401);
      expect(cardFindUnique()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});

// ---------------------------------------------------------------------------
// POST /api/cards/:cardId/webauthn-credentials
// ---------------------------------------------------------------------------

describe('POST /api/cards/:cardId/webauthn-credentials', () => {
  it('creates a new credential and returns 201', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue({ id: 'card_1' } as never);
    vi.mocked(credCreate()).mockResolvedValue(sampleCred as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/webauthn-credentials';
      const body = {
        credentialId: 'KH_abc123',
        publicKey: 'pk_base64url',
        signCounter: 5,
        deviceName: 'iPhone 16',
        kind: 'PLATFORM',
      };
      const raw = Buffer.from(JSON.stringify(body));
      const res = await request('POST', `${url}${path}`, {
        headers: { authorization: sign('POST', path, raw) },
        body,
      });
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject({
        id: 'cred_row_1',
        credentialId: 'KH_abc123',
        signCounter: '5',
        kind: 'PLATFORM',
      });

      const createCall = vi.mocked(credCreate()).mock.calls[0]![0]!;
      expect(createCall.data).toMatchObject({
        cardId: 'card_1',
        credentialId: 'KH_abc123',
        publicKey: 'pk_base64url',
        counter: 5n,
        deviceName: 'iPhone 16',
        kind: 'PLATFORM',
      });
    } finally {
      await close();
    }
  });

  it('returns 404 when the cardId is unknown', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue(null);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_missing/webauthn-credentials';
      const body = {
        credentialId: 'KH_abc123',
        publicKey: 'pk_base64url',
        signCounter: 0,
        kind: 'CROSS_PLATFORM',
      };
      const raw = Buffer.from(JSON.stringify(body));
      const res = await request('POST', `${url}${path}`, {
        headers: { authorization: sign('POST', path, raw) },
        body,
      });
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({ error: { code: 'card_not_found' } });
      expect(credCreate()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 400 when the body fails Zod validation', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/webauthn-credentials';
      // Missing credentialId + bad kind.
      const body = { publicKey: 'pk', signCounter: 0, kind: 'BOGUS' };
      const raw = Buffer.from(JSON.stringify(body));
      const res = await request('POST', `${url}${path}`, {
        headers: { authorization: sign('POST', path, raw) },
        body,
      });
      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({ error: { code: 'validation_failed' } });
      expect(cardFindUnique()).not.toHaveBeenCalled();
      expect(credCreate()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 401 when unsigned', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/webauthn-credentials';
      const body = {
        credentialId: 'KH_abc123',
        publicKey: 'pk',
        signCounter: 0,
        kind: 'PLATFORM',
      };
      const res = await request('POST', `${url}${path}`, { body });
      expect(res.status).toBe(401);
      expect(credCreate()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});

// ---------------------------------------------------------------------------
// GET /api/webauthn-credentials/:credentialId
// ---------------------------------------------------------------------------

describe('GET /api/webauthn-credentials/:credentialId', () => {
  it('returns 200 with the credential row', async () => {
    vi.mocked(credFindFirst()).mockResolvedValue(sampleCred as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/webauthn-credentials/KH_abc123';
      const res = await request('GET', `${url}${path}`, {
        headers: { authorization: sign('GET', path) },
      });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        id: 'cred_row_1',
        credentialId: 'KH_abc123',
        signCounter: '5',
        kind: 'PLATFORM',
      });

      const call = vi.mocked(credFindFirst()).mock.calls[0]![0]!;
      expect(call.where).toEqual({ credentialId: 'KH_abc123' });
    } finally {
      await close();
    }
  });

  it('returns 404 when the credential is unknown', async () => {
    vi.mocked(credFindFirst()).mockResolvedValue(null);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/webauthn-credentials/KH_missing';
      const res = await request('GET', `${url}${path}`, {
        headers: { authorization: sign('GET', path) },
      });
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({ error: { code: 'credential_not_found' } });
    } finally {
      await close();
    }
  });

  it('returns 401 when unsigned', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/webauthn-credentials/KH_abc123';
      const res = await request('GET', `${url}${path}`);
      expect(res.status).toBe(401);
      expect(credFindFirst()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});

// ---------------------------------------------------------------------------
// PATCH /api/webauthn-credentials/:credentialId/counter
// ---------------------------------------------------------------------------

describe('PATCH /api/webauthn-credentials/:credentialId/counter', () => {
  it('returns 200 with the new signCounter + lastUsedAt', async () => {
    vi.mocked(credUpdateMany()).mockResolvedValue({ count: 1 } as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/webauthn-credentials/KH_abc123/counter';
      const body = { signCounter: 42 };
      const raw = Buffer.from(JSON.stringify(body));
      const res = await request('PATCH', `${url}${path}`, {
        headers: { authorization: sign('PATCH', path, raw) },
        body,
      });
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ signCounter: '42' });
      expect((res.body as { lastUsedAt: string }).lastUsedAt).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );

      const updateCall = vi.mocked(credUpdateMany()).mock.calls[0]![0]!;
      expect(updateCall.where).toEqual({ credentialId: 'KH_abc123' });
      expect(updateCall.data).toMatchObject({ counter: 42n });
      expect((updateCall.data as { lastUsedAt: Date }).lastUsedAt).toBeInstanceOf(Date);
    } finally {
      await close();
    }
  });

  it('returns 404 when the credential is unknown', async () => {
    vi.mocked(credUpdateMany()).mockResolvedValue({ count: 0 } as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/webauthn-credentials/KH_missing/counter';
      const body = { signCounter: 1 };
      const raw = Buffer.from(JSON.stringify(body));
      const res = await request('PATCH', `${url}${path}`, {
        headers: { authorization: sign('PATCH', path, raw) },
        body,
      });
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({ error: { code: 'credential_not_found' } });
    } finally {
      await close();
    }
  });

  it('returns 400 when signCounter is missing', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/webauthn-credentials/KH_abc123/counter';
      const body = {};
      const raw = Buffer.from(JSON.stringify(body));
      const res = await request('PATCH', `${url}${path}`, {
        headers: { authorization: sign('PATCH', path, raw) },
        body,
      });
      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({ error: { code: 'validation_failed' } });
      expect(credUpdateMany()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 401 when unsigned', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/webauthn-credentials/KH_abc123/counter';
      const body = { signCounter: 42 };
      const res = await request('PATCH', `${url}${path}`, { body });
      expect(res.status).toBe(401);
      expect(credUpdateMany()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});

// Suppress unused-import warnings.
void createHash;
void createHmac;
