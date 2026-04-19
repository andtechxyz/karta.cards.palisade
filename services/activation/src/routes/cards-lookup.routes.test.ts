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
      updateMany: vi.fn(),
    },
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
import { createCardsPayRouter } from './cards-lookup.routes.js';

type Mocked<T> = ReturnType<typeof vi.fn> & T;
const cardFindUnique = () =>
  prisma.card.findUnique as unknown as Mocked<typeof prisma.card.findUnique>;
const cardUpdateMany = () =>
  prisma.card.updateMany as unknown as Mocked<typeof prisma.card.updateMany>;

const PAY_SECRET = 'f'.repeat(64);
const PAY_AUTH_KEYS = { pay: PAY_SECRET };

function buildApp() {
  const app = express();
  const payGate = requireSignedRequest({ keys: PAY_AUTH_KEYS });
  app.use(
    '/api/cards',
    express.json({ limit: '64kb', verify: captureRawBody }),
    createCardsPayRouter(payGate),
  );
  app.use(errorMiddleware);
  return app;
}

/** Start a short-lived HTTP server around the app; returns a `{ url, close }`. */
async function serve(app: express.Express): Promise<{ url: string; close: () => Promise<void> }> {
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

function makeSignedHeader(
  method: string,
  pathAndQuery: string,
  body: Buffer = Buffer.alloc(0),
): string {
  return signRequest({
    method,
    pathAndQuery,
    body,
    keyId: 'pay',
    secret: PAY_SECRET,
  });
}

/** Thin fetch wrapper that doesn't need undici/supertest.  Returns status+body. */
async function request(
  method: string,
  url: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(url, { method, headers });
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

beforeEach(() => {
  vi.mocked(cardFindUnique()).mockReset();
  vi.mocked(cardUpdateMany()).mockReset();
});

describe('GET /api/cards/lookup/:cardId', () => {
  it('returns 200 with the full lookup shape for an existing card', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue({
      id: 'card_1',
      cardRef: 'cardref_abc',
      status: 'ACTIVATED',
      programId: 'prog_plat_aud',
      retailSaleStatus: null,
      chipSerial: 'JCOP5_00A1B2C3',
      panLast4: '4242',
      panBin: '411111',
      cardholderName: 'Jane Doe',
    } as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/lookup/card_1';
      const res = await request('GET', `${url}${path}`, {
        authorization: makeSignedHeader('GET', path),
      });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        id: 'card_1',
        cardRef: 'cardref_abc',
        status: 'ACTIVATED',
        programId: 'prog_plat_aud',
        retailSaleStatus: null,
        chipSerial: 'JCOP5_00A1B2C3',
        panLast4: '4242',
        panBin: '411111',
        cardholderName: 'Jane Doe',
      });

      // Verify the Prisma select went out with the full projection — keeps
      // the response shape in lockstep with whatever pay expects.
      const call = vi.mocked(cardFindUnique()).mock.calls[0]![0]!;
      expect(call.where).toEqual({ id: 'card_1' });
      expect(call.select).toEqual({
        id: true,
        cardRef: true,
        status: true,
        programId: true,
        retailSaleStatus: true,
        chipSerial: true,
        panLast4: true,
        panBin: true,
        cardholderName: true,
      });
    } finally {
      await close();
    }
  });

  it('returns 404 card_not_found when the cardId is unknown', async () => {
    vi.mocked(cardFindUnique()).mockResolvedValue(null);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/lookup/card_missing';
      const res = await request('GET', `${url}${path}`, {
        authorization: makeSignedHeader('GET', path),
      });
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({
        error: { code: 'card_not_found' },
      });
    } finally {
      await close();
    }
  });

  it('returns 401 when the request is unsigned', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/lookup/card_1';
      const res = await request('GET', `${url}${path}`);
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({
        error: { code: 'missing_auth' },
      });
      // Prisma is never reached when the HMAC gate rejects the request.
      expect(cardFindUnique()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 401 when signed with an unknown keyId', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/lookup/card_1';
      // Sign with a keyId that isn't in PAY_AUTH_KEYS.
      const bogus = signRequest({
        method: 'GET',
        pathAndQuery: path,
        body: Buffer.alloc(0),
        keyId: 'bogus',
        secret: PAY_SECRET,
      });
      const res = await request('GET', `${url}${path}`, { authorization: bogus });
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: { code: 'unknown_key' } });
      expect(cardFindUnique()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 401 when the signature does not match the body hash', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/lookup/card_1';
      // Sign a different path to force a bad signature for the actual path.
      const mismatched = signRequest({
        method: 'GET',
        pathAndQuery: '/api/cards/lookup/card_999',
        body: Buffer.alloc(0),
        keyId: 'pay',
        secret: PAY_SECRET,
      });
      const res = await request('GET', `${url}${path}`, { authorization: mismatched });
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: { code: 'bad_signature' } });
      expect(cardFindUnique()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});

describe('PATCH /api/cards/:cardId/atc-increment', () => {
  it('returns 200 with the new ATC value after atomic increment', async () => {
    vi.mocked(cardUpdateMany()).mockResolvedValue({ count: 1 } as never);
    vi.mocked(cardFindUnique()).mockResolvedValue({ atc: 7 } as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/atc-increment';
      const res = await request('PATCH', `${url}${path}`, {
        authorization: makeSignedHeader('PATCH', path),
      });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ atc: 7 });

      // Verify the Prisma call used the atomic increment operator.
      const updateCall = vi.mocked(cardUpdateMany()).mock.calls[0]![0]!;
      expect(updateCall.where).toEqual({ id: 'card_1' });
      expect(updateCall.data).toEqual({ atc: { increment: 1 } });
    } finally {
      await close();
    }
  });

  it('returns 404 card_not_found when the cardId is unknown', async () => {
    vi.mocked(cardUpdateMany()).mockResolvedValue({ count: 0 } as never);

    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_missing/atc-increment';
      const res = await request('PATCH', `${url}${path}`, {
        authorization: makeSignedHeader('PATCH', path),
      });
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({
        error: { code: 'card_not_found' },
      });
      // findUnique never runs when the update turned up nothing.
      expect(cardFindUnique()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 401 when the request is unsigned', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/atc-increment';
      const res = await request('PATCH', `${url}${path}`);
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({
        error: { code: 'missing_auth' },
      });
      expect(cardUpdateMany()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });

  it('returns 401 when signed with a bad signature', async () => {
    const app = buildApp();
    const { url, close } = await serve(app);
    try {
      const path = '/api/cards/card_1/atc-increment';
      // Sign with the wrong method to force bad_signature.
      const mismatched = signRequest({
        method: 'GET',
        pathAndQuery: path,
        body: Buffer.alloc(0),
        keyId: 'pay',
        secret: PAY_SECRET,
      });
      const res = await request('PATCH', `${url}${path}`, { authorization: mismatched });
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: { code: 'bad_signature' } });
      expect(cardUpdateMany()).not.toHaveBeenCalled();
    } finally {
      await close();
    }
  });
});

// Suppress unused-import warnings in environments where the CMAC helpers aren't
// referenced directly (they're used by signRequest above).
void createHash;
void createHmac;
