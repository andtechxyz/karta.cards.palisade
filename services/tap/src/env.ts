import { defineEnv, baseEnvShape, cardFieldCryptoEnvShape } from '@palisade/core';
import { z } from 'zod';

const { get: getTapConfig, reset: _resetTapConfig } = defineEnv({
  ...baseEnvShape,
  ...cardFieldCryptoEnvShape,
  PORT: z.coerce.number().int().positive().default(3001),
  TAP_HANDOFF_SECRET: z.string().min(32),
  ACTIVATION_URL: z.string().url(),
  MOBILE_APP_URL: z.string().url().default('https://app.karta.cards'),
  // Base host for per-program microsites.  RETAIL cards in SHIPPED state
  // land here directly (no handoff, no activation) until they're marked
  // SOLD; other flows hit it only after successful activation.
  MICROSITE_CDN_URL: z.string().url().default('https://microsite.karta.cards'),
});

export { getTapConfig, _resetTapConfig };
