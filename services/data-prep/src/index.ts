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
import {
  purgeExpiredParamRecords,
  startSweeper,
} from '@palisade/retention';

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

// PCI DSS 3.1 / CPL LSR 5 — ParamRecord retention reaper.
// Zeros the bundleEncrypted + per-field envelope columns on rows past
// their TTL (READY+expiresAt or CONSUMED/REVOKED + 7 days grace).
// Row itself stays as an audit trail; only the key material leaves.
// 5-minute cadence — these rows are not time-sensitive, the ECS
// task already handles request traffic at full throughput, and
// hourly would leave a long tail of consumed rows with live keys.
startSweeper({
  name: 'param-records',
  intervalMs: 5 * 60_000,
  run: purgeExpiredParamRecords,
});

const port = config.PORT;
app.listen(port, () => {
  console.log(`[data-prep] listening on :${port}`);
});

export default app;
