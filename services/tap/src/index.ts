import 'express-async-errors';
import express from 'express';
import { errorMiddleware, authRateLimit } from '@palisade/core';
import { getTapConfig } from './env.js';
import sunTapRouter from './routes/sun-tap.routes.js';
import postActivationTapRouter from './routes/post-activation-tap.routes.js';
import tapVerifyRouter from './routes/tap-verify.routes.js';

const config = getTapConfig();
const app = express();

// No CORS — tap handles NFC redirects only (GET → 302).  No browser fetch calls.
app.set('trust proxy', 1);

app.use(express.json({ limit: '64kb' }));

// TEMP debug logger — remove once tap test passes.  Logs every request's
// method/path/body-shape so we can see what the mobile app is actually
// sending vs what the routes expect.
app.use((req, _res, next) => {
  try {
    const bodyKeys = req.body && typeof req.body === 'object' ? Object.keys(req.body) : [];
    console.log(`[req] ${req.method} ${req.originalUrl} body-keys=[${bodyKeys.join(',')}] ct=${req.get('content-type') ?? ''}`);
  } catch {
    // don't block on logging failures
  }
  next();
});

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
