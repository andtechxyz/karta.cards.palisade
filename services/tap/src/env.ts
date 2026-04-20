import {
  defineEnv,
  baseEnvShape,
  cardFieldCryptoEnvShape,
  sdmKeyDerivationEnvShape,
  hexKey,
} from '@palisade/core';
import { z } from 'zod';

import type { SdmBackend } from '@palisade/sdm-keys';
export type { SdmBackend };

const { get: getTapConfig, reset: _resetTapConfig } = defineEnv({
  ...baseEnvShape,
  ...cardFieldCryptoEnvShape,
  ...sdmKeyDerivationEnvShape,
  PORT: z.coerce.number().int().positive().default(3001),
  // 32-byte (64 hex chars) HMAC-SHA256 key for handoff tokens.  Hex-only —
  // Buffer.from(hex,'hex') silently truncates non-hex input so a plain
  // password would produce a weak/empty key.
  TAP_HANDOFF_SECRET: hexKey(32),
  ACTIVATION_URL: z.string().url(),
  MOBILE_APP_URL: z.string().url().default('https://app.karta.cards'),
  // Base host for per-program microsites.  RETAIL cards in SHIPPED state
  // land here directly (no handoff, no activation) until they're marked
  // SOLD; other flows hit it only after successful activation.
  MICROSITE_CDN_URL: z.string().url().default('https://microsite.karta.cards'),
});

export { getTapConfig, _resetTapConfig };
export { assertSdmEnv } from '@palisade/core';
