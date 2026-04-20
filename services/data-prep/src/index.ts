/**
 * data-prep — EMV SAD preparation service.
 *
 * Internal, HMAC-gated. Derives EMV keys via AWS Payment Cryptography,
 * builds TLV/DGI structures, encrypts and stores the SAD blob.
 *
 * Port 3006. No CORS — service-to-service only (internal ALB, HMAC-gated).
 */

import 'dotenv/config';
import 'express-async-errors';
import { resolveSecretRefs } from '@palisade/core';
await resolveSecretRefs();

import express from 'express';
import { requireSignedRequest, captureRawBody } from '@palisade/service-auth';
import { errorMiddleware } from '@palisade/core';

import { getDataPrepConfig } from './env.js';
import { createDataPrepRouter } from './routes/data-prep.routes.js';

const config = getDataPrepConfig();
const app = express();

app.set('trust proxy', 1);

// Health check (unauthenticated — ALB needs it)
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'data-prep' });
});

// HMAC gate on all /api/data-prep routes
const authGate = requireSignedRequest({ keys: config.PROVISION_AUTH_KEYS });
app.use(
  '/api/data-prep',
  express.json({ limit: '64kb', verify: captureRawBody }),
  authGate,
  createDataPrepRouter(),
);

app.use(errorMiddleware);

const port = config.PORT;
app.listen(port, () => {
  console.log(`[data-prep] listening on :${port}`);
});

export default app;
