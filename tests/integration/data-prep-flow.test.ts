/**
 * Integration tests for the Data Prep service HTTP layer.
 *
 * Builds the Express app from the same route/middleware modules used by
 * services/data-prep/src/index.ts.  Prisma and AWS SDK are mocked.
 * HMAC auth uses real signRequest() with the test secrets from tests/setup.ts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import type { Express } from 'express';
import 'express-async-errors';
import { signRequest, captureRawBody, requireSignedRequest } from '@palisade/service-auth';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockPrisma = vi.hoisted(() => ({
  issuerProfile: {
    findUnique: vi.fn(),
  },
  sadRecord: {
    create: vi.fn(),
    findUnique: vi.fn(),
    update: vi.fn(),
  },
  card: {
    update: vi.fn(),
  },
}));
vi.mock('@palisade/db', () => ({ prisma: mockPrisma }));

// AWS SDK
vi.mock('@aws-sdk/client-kms', () => ({
  KMSClient: vi.fn().mockImplementation(() => ({
    send: vi.fn().mockResolvedValue({
      CiphertextBlob: Buffer.from('encrypted-test-data'),
      Plaintext: Buffer.from('decrypted-test-data'),
    }),
  })),
  EncryptCommand: vi.fn(),
  DecryptCommand: vi.fn(),
}));

// Mock the DataPrepService to avoid real AWS calls
vi.mock('../../services/data-prep/src/services/data-prep.service.js', () => ({
  DataPrepService: vi.fn().mockImplementation(() => ({
    prepareCard: vi.fn().mockResolvedValue({
      proxyCardId: 'pxy_test123',
      sadRecordId: 'sad-rec-1',
      status: 'READY',
    }),
  })),
}));

// Mock serve-frontend and rate limiters
vi.mock('@palisade/core', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    serveFrontend: vi.fn(),
    authRateLimit: (_req: any, _res: any, next: any) => next(),
    apiRateLimit: (_req: any, _res: any, next: any) => next(),
  };
});

// ---------------------------------------------------------------------------
// Constants from tests/setup.ts
// ---------------------------------------------------------------------------

const PROVISION_AUTH_KEYS: Record<string, string> = {
  'provision-agent': '8'.repeat(64),
};

// ---------------------------------------------------------------------------
// Build app
// ---------------------------------------------------------------------------

import { errorMiddleware } from '@palisade/core';
import { createDataPrepRouter } from '../../services/data-prep/src/routes/data-prep.routes.js';

function buildApp(): Express {
  const app = express();
  app.set('trust proxy', 1);

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'data-prep' });
  });

  const authGate = requireSignedRequest({ keys: PROVISION_AUTH_KEYS });
  app.use(
    '/api/data-prep',
    express.json({ limit: '64kb', verify: captureRawBody }),
    authGate,
    createDataPrepRouter(),
  );

  app.use(errorMiddleware);
  return app;
}

/** Sign a JSON body for the given path using the 'provision-agent' key. */
function signedHeaders(
  method: string,
  path: string,
  body: object | undefined = undefined,
  keyId = 'provision-agent',
): Record<string, string> {
  const bodyBuf = body ? Buffer.from(JSON.stringify(body), 'utf8') : Buffer.alloc(0);
  const authorization = signRequest({
    method,
    pathAndQuery: path,
    body: bodyBuf,
    keyId,
    secret: PROVISION_AUTH_KEYS[keyId],
  });
  return { authorization };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Data Prep service — integration', () => {
  let app: Express;

  beforeEach(() => {
    vi.clearAllMocks();
    app = buildApp();
  });

  // ---- Health ----
  describe('GET /api/health', () => {
    it('returns 200', async () => {
      const res = await request(app).get('/api/health');
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ ok: true, service: 'data-prep' });
    });
  });

  // ---- Prepare: auth gate ----
  describe('POST /api/data-prep/prepare', () => {
    const preparePath = '/api/data-prep/prepare';
    const prepareBody = {
      cardId: 'card-1',
      pan: '4242424242424242',
      expiryYymm: '2812',
      programId: 'test-program',
    };

    it('rejects without HMAC', async () => {
      const res = await request(app)
        .post(preparePath)
        .set('content-type', 'application/json')
        .send(prepareBody);
      expect(res.status).toBe(401);
    });

    it('returns 201 with HMAC + valid body', async () => {
      const headers = signedHeaders('POST', preparePath, prepareBody);
      const res = await request(app)
        .post(preparePath)
        .set(headers)
        .send(prepareBody);
      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('proxyCardId');
    });
  });

  // ---- SAD retrieval ----
  describe('GET /api/data-prep/sad/:proxyCardId', () => {
    const sadPath = '/api/data-prep/sad/pxy_test123';

    it('returns 200 with encrypted SAD for known proxyCardId', async () => {
      mockPrisma.sadRecord.findUnique.mockResolvedValue({
        id: 'sad-rec-1',
        proxyCardId: 'pxy_test123',
        cardId: 'card-1',
        sadEncrypted: Buffer.from('test-sad-data'),
        sadKeyVersion: 1,
        chipSerial: 'CS001',
        status: 'READY',
        expiresAt: new Date(Date.now() + 86400_000),
      });

      const headers = signedHeaders('GET', sadPath);
      const res = await request(app)
        .get(sadPath)
        .set(headers);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('proxyCardId', 'pxy_test123');
      expect(res.body).toHaveProperty('sadEncrypted');
      expect(res.body).toHaveProperty('status', 'READY');
    });

    it('returns 404 for unknown proxyCardId', async () => {
      mockPrisma.sadRecord.findUnique.mockResolvedValue(null);

      const unknownPath = '/api/data-prep/sad/unknown';
      const headers = signedHeaders('GET', unknownPath);
      const res = await request(app)
        .get(unknownPath)
        .set(headers);
      expect(res.status).toBe(404);
    });
  });

  // ---- SAD revocation ----
  describe('DELETE /api/data-prep/sad/:proxyCardId', () => {
    it('returns 200 with status REVOKED', async () => {
      const deletePath = '/api/data-prep/sad/pxy_test123';
      mockPrisma.sadRecord.findUnique.mockResolvedValue({
        id: 'sad-rec-1',
        proxyCardId: 'pxy_test123',
        status: 'READY',
      });
      mockPrisma.sadRecord.update.mockResolvedValue({
        id: 'sad-rec-1',
        proxyCardId: 'pxy_test123',
        status: 'REVOKED',
      });

      const headers = signedHeaders('DELETE', deletePath);
      const res = await request(app)
        .delete(deletePath)
        .set(headers);
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({
        proxyCardId: 'pxy_test123',
        status: 'REVOKED',
      });
    });
  });
});
