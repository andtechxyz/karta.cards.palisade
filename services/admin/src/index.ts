import 'express-async-errors';
import { resolveSecretRefs } from '@palisade/core';
await resolveSecretRefs();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { errorMiddleware, serveFrontend, apiRateLimit, requestIdMiddleware } from '@palisade/core';
import { createCognitoAuthMiddleware } from '@palisade/cognito-auth';
import { getAdminConfig } from './env.js';
import programsRouter from './routes/programs.routes.js';
import cardsRouter from './routes/cards.routes.js';
import provisioningRouter from './routes/provisioning.routes.js';
import micrositesRouter from './routes/microsites.routes.js';
import financialInstitutionsRouter from './routes/financial-institutions.routes.js';
import embossingTemplatesRouter from './routes/embossing-templates.routes.js';
import embossingBatchesRouter from './routes/embossing-batches.routes.js';
import partnerCredentialsRouter from './routes/partner-credentials.routes.js';
import partnerIngestionRouter, { partnerHmacMiddleware } from './routes/partner-ingestion.routes.js';
import issuerProfilesRouter from './routes/issuer-profiles.routes.js';
import chipProfilesRouter from './routes/chip-profiles.routes.js';
import capabilitiesRouter from './routes/capabilities.routes.js';

const config = getAdminConfig();
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      'connect-src': ["'self'", 'https://cognito-idp.ap-southeast-2.amazonaws.com'],
    },
  },
}));
app.use(cors({ origin: config.CORS_ORIGINS, credentials: false, allowedHeaders: ['content-type', 'authorization'] }));
app.set('trust proxy', 1);

// PCI DSS 10.x / CPL LSR 8 — correlation ID for cross-service tracing.
app.use(requestIdMiddleware);

app.use(express.json({ limit: '64kb' }));

// Prod path-prefix normalisation.  The shared admin SPA (Vera-owned) calls
// Palisade under /palisade-api/* — Vera's Vite dev proxy rewrites it to
// /api/*, but AWS ALB listener rules can't rewrite paths.  Rewriting at the
// request layer keeps every route declaration below on /api/* and works
// uniformly in dev (post-Vite) and prod (raw from ALB).
app.use((req, _res, next) => {
  if (req.url.startsWith('/palisade-api/')) {
    req.url = '/api' + req.url.slice('/palisade-api'.length);
  } else if (req.url === '/palisade-api') {
    req.url = '/api';
  }
  next();
});

// Health is the ALB probe — must answer without auth.
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'admin' });
});

// Capability probe — unauthenticated, parity with Vera admin.
app.use('/api/capabilities', capabilitiesRouter);

// Rate limit all API routes before auth checks.
app.use('/api', apiRateLimit);

// Cognito JWT with 'admin' group membership required.
// MFA is enforced at the Cognito pool level — the JWT is only issued after
// password + TOTP.  Group check gates access to admin-only resources.
const adminAuth = createCognitoAuthMiddleware({
  userPoolId: config.COGNITO_USER_POOL_ID,
  clientId: config.COGNITO_CLIENT_ID,
  requiredGroup: 'admin',
});
app.use('/api/programs', adminAuth, programsRouter);
app.use('/api/cards', adminAuth, cardsRouter);
app.use('/api/admin/financial-institutions', adminAuth, financialInstitutionsRouter);
// Embossing template CRUD sits under the same FI path prefix, nested by :fiId.
app.use('/api/admin/financial-institutions', adminAuth, embossingTemplatesRouter);
// Partner credential management (Cognito-gated — admin UI only)
app.use('/api/admin/financial-institutions', adminAuth, partnerCredentialsRouter);
// Partner ingestion endpoint (HMAC-authenticated — partner's secret, NOT Cognito).
// Mounted OUTSIDE /api/admin so adminAuth doesn't intercept partner calls.
app.use('/api/partners', partnerHmacMiddleware(), partnerIngestionRouter);
// Issuer + Chip profile CRUD — full-fidelity (ARNs, EMV constants, DGIs).
// Mounted outside /api/admin so the paths are /api/issuer-profiles
// and /api/chip-profiles.  The older minimal variants inside
// provisioning.routes.ts remain for now and will be retired once the
// frontend migrations settle.
app.use('/api/issuer-profiles', adminAuth, issuerProfilesRouter);
app.use('/api/chip-profiles', adminAuth, chipProfilesRouter);
app.use('/api/admin', adminAuth, provisioningRouter);
// Microsite uploads handle their own multipart body parsing (no global
// express.json() interference) and must sit on /api/admin/programs/...
app.use('/api/admin', adminAuth, micrositesRouter);
// Embossing batches — program-scoped multipart uploads, same pattern as microsites.
app.use('/api/admin/programs', adminAuth, embossingBatchesRouter);

serveFrontend(app, import.meta.url);
app.use(errorMiddleware);

app.listen(config.PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[admin] listening on :${config.PORT}`);
});
