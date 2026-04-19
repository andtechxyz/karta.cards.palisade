import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { errorMiddleware, serveFrontend, authRateLimit, apiRateLimit } from '@palisade/core';
import { captureRawBody, requireSignedRequest } from '@palisade/service-auth';
import { purgeExpiredActivationSessions, startSweeper } from '@palisade/retention';
import { getActivationConfig } from './env.js';
import activationRouter from './routes/activation.routes.js';
import cardsRouter from './routes/cards.routes.js';
import cardsLookupRouter from './routes/cards-lookup.routes.js';
import { createProvisioningRouter } from './routes/provisioning.routes.js';
import { createCardsMineRouter } from './routes/cards-mine.routes.js';
import { createCardOpRouter } from './routes/card-op.routes.js';

const config = getActivationConfig();
const app = express();

app.use(helmet());
app.use(cors({ origin: config.CORS_ORIGINS, credentials: false }));
app.set('trust proxy', 1);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'activation' });
});

// JSON parsing is per-route-group so the HMAC surface gets captureRawBody
// while public activation routes skip the per-request Buffer copy.
app.use('/api/activation', express.json({ limit: '64kb' }), authRateLimit, activationRouter);

// --- Mobile card list (Cognito-authed, no HMAC) ---
// Mounted before /api/cards so the HMAC gate on /api/cards doesn't intercept.
app.use('/api/cards/mine',
  express.json({ limit: '64kb' }),
  apiRateLimit,
  createCardsMineRouter(),
);

// --- Cross-repo card lookup (pay-service-authed, HMAC) ---
// Mounted BEFORE /api/cards so the more-specific /api/cards/lookup prefix
// catches ahead of the provisioning-authed /api/cards mount.  Keyed off
// a separate PAY_AUTH_KEYS map so rotating pay's secret doesn't disturb the
// provisioning-agent / batch-processor callers.
const payGate = requireSignedRequest({ keys: config.PAY_AUTH_KEYS });
app.use('/api/cards/lookup',
  express.json({ limit: '64kb', verify: captureRawBody }),
  payGate,
  cardsLookupRouter,
);

const provisionGate = requireSignedRequest({ keys: config.PROVISION_AUTH_KEYS });
app.use('/api/cards',
  express.json({ limit: '64kb', verify: captureRawBody }),
  provisionGate,
  cardsRouter,
);

// --- Mobile provisioning ---
// /start uses Cognito JWT auth (inside the router).
// /callback uses HMAC (requireSignedRequest) — called by the RCA service.
// captureRawBody is needed so the HMAC gate on /callback can hash-check.
app.use('/api/provisioning',
  express.json({ limit: '64kb', verify: captureRawBody }),
  authRateLimit,
  createProvisioningRouter(),
);

// --- Admin card-ops initiation ---
// Cognito-gated (admin group + email allowlist).  Router creates a
// CardOpSession, calls card-ops for S2S register, and returns the
// WebSocket URL the admin client should connect to.
app.use('/api/admin/card-op',
  express.json({ limit: '64kb' }),
  apiRateLimit,
  createCardOpRouter(),
);

serveFrontend(app, import.meta.url);
app.use(errorMiddleware);

// PCI-DSS 3.1.  Consumed sessions stay as the per-card activation audit trail.
startSweeper({
  name: 'activation-sessions',
  intervalMs: 60_000,
  run: purgeExpiredActivationSessions,
});

app.listen(config.PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[activation] listening on :${config.PORT}`);
});
