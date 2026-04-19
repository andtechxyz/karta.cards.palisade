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

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'tap' });
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
