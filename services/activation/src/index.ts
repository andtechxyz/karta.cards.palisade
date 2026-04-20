import 'express-async-errors';
import { resolveSecretRefs } from '@palisade/core';
// PCI 3.5.1 / 3.6.1 — C-3 from the audit: resolve any env vars whose
// values are Secrets Manager references (arn:aws:secretsmanager:... or
// secretsmanager:<name>) to their plaintext BEFORE any getConfig() hits
// process.env.  Values that aren't references are left alone so dev .env
// files with plaintext still work.  TLA suspends module evaluation until
// resolution completes.
await resolveSecretRefs();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { errorMiddleware, serveFrontend, authRateLimit, apiRateLimit } from '@palisade/core';
import { captureRawBody, requireSignedRequest } from '@palisade/service-auth';
import { purgeExpiredActivationSessions, startSweeper } from '@palisade/retention';
import { getActivationConfig } from './env.js';
import activationRouter from './routes/activation.routes.js';
import cardsRouter from './routes/cards.routes.js';
import { createCardsPayRouter } from './routes/cards-lookup.routes.js';
import { createWebAuthnRouters } from './routes/webauthn-credentials.routes.js';
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

// --- Cross-repo pay endpoints (pay-service-authed, HMAC) ---
// Mounted BEFORE the provisioning /api/cards mount so pay's specific routes
// (/lookup/:cardId, /:cardId/atc-increment, /:cardId/webauthn-credentials)
// catch ahead of the provisioning-authed mount.  The pay gate is attached
// PER-ROUTE inside the factories so non-matching requests (e.g.
// POST /api/cards/register for the provisioning caller) fall through to the
// provisioning router without being rejected at the HMAC gate.  Keyed off a
// separate PAY_AUTH_KEYS map so rotating pay's secret doesn't disturb the
// provisioning-agent / batch-processor callers.
const payGate = requireSignedRequest({ keys: config.PAY_AUTH_KEYS });
const webAuthnRouters = createWebAuthnRouters(payGate);
// Pay-gated WebAuthn routes carry credential enumeration + counter-update
// surfaces.  Rate-limit at the tighter authRateLimit so a compromised pay
// secret doesn't give an attacker unbounded WebAuthn reads.  PCI 8.3.6.
app.use('/api/cards',
  express.json({ limit: '64kb', verify: captureRawBody }),
  apiRateLimit,
  createCardsPayRouter(payGate),
  webAuthnRouters.cardScoped,
);
app.use('/api/webauthn-credentials',
  express.json({ limit: '64kb', verify: captureRawBody }),
  apiRateLimit,
  webAuthnRouters.credentialScoped,
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
// Cognito-gated (admin group + email allowlist).  Admin-privileged endpoint
// that returns a WS URL usable for GP ops — use the tighter authRateLimit
// so credential-stuffing an admin JWT can't also spray card-op starts.
// PCI 8.3.6.
app.use('/api/admin/card-op',
  express.json({ limit: '64kb' }),
  authRateLimit,
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
