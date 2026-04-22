import 'express-async-errors';
import { resolveSecretRefs } from '@palisade/core';
// PCI 3.5.1 / 3.6.1 — resolve any Secrets Manager references in env
// before env.ts consumers read process.env.  See packages/core/src/
// secrets-resolver.ts for the contract.
await resolveSecretRefs();

import express from 'express';
import { errorMiddleware, authRateLimit, requestIdMiddleware } from '@palisade/core';
import { getTapConfig } from './env.js';
import sunTapRouter from './routes/sun-tap.routes.js';
import postActivationTapRouter from './routes/post-activation-tap.routes.js';
import tapVerifyRouter from './routes/tap-verify.routes.js';

const config = getTapConfig();
const app = express();

// No CORS — tap handles NFC redirects only (GET → 302).  No browser fetch calls.
app.set('trust proxy', 1);

// PCI DSS 10.x / CPL LSR 8 — correlation ID for cross-service tracing.
// Mount FIRST so every downstream handler + log emits req.requestId.
app.use(requestIdMiddleware);

app.use(express.json({ limit: '64kb' }));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'tap' });
});

// Apple App Site Association — Universal Links for tap.karta.cards.
// Chip emits https://tap.karta.cards/<urlCode>?e=&m= after activation,
// which iOS routes to the Palisade app via this file.
// Served as application/json, no file extension, publicly cacheable.
// Team ID 39GT4WXF5C; supports current + previous bundle IDs during migration.
app.get('/.well-known/apple-app-site-association', (_req, res) => {
  res.type('application/json').json({
    applinks: {
      apps: [],
      details: [
        {
          appIDs: [
            '39GT4WXF5C.cards.karta.palisade',
            '39GT4WXF5C.com.mobile.karta.cards',
          ],
          components: [
            { '/': '/*' },
          ],
        },
      ],
    },
  });
});

// SUN-tap — mounted at root because the URL baked into the NFC chip has
// no /api prefix.  Rate-limit to prevent replay brute-force.
app.use('/activate', authRateLimit);
app.use('/tap', authRateLimit);
app.use('/', sunTapRouter);
// Post-activation SUN-tap — /tap/:cardRef, used by cards whose NDEF URL
// has been rewritten after activation.  Minted handoff tokens always carry
// purpose='provisioning' regardless of card state.
app.use('/', postActivationTapRouter);

// Mobile-app SUN verify — POST /api/tap/verify/:urlCode for cardRef-less
// chip URLs (mobile.karta.cards/t/<urlCode>?e=&m=).  Rate-limited to guard
// against PICC/MAC enumeration.
app.use('/api/tap', authRateLimit, tapVerifyRouter);

app.use(errorMiddleware);

app.listen(config.PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[tap] listening on :${config.PORT}`);
});
