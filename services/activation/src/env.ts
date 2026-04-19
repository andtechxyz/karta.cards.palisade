import {
  defineEnv,
  baseEnvShape,
  cardFieldCryptoEnvShape,
  sdmKeyDerivationEnvShape,
  authKeysJson,
  hexKey,
  originList,
} from '@palisade/core';
import { z } from 'zod';

const { get: getActivationConfig, reset: _resetActivationConfig } = defineEnv({
  ...baseEnvShape,
  ...cardFieldCryptoEnvShape,
  ...sdmKeyDerivationEnvShape,
  CORS_ORIGINS: originList,
  // Separate from vault's SERVICE_AUTH_KEYS — both services share one .env in
  // dev; different caller sets need different key maps.
  PROVISION_AUTH_KEYS: authKeysJson,
  // Activation is the only service that fingerprints UIDs (for collision
  // detection at register time).  Declared inline — no shared fragment.
  CARD_UID_FINGERPRINT_KEY: hexKey(32),
  PORT: z.coerce.number().int().positive().default(3002),
  TAP_HANDOFF_SECRET: z.string().min(32),
  PAY_URL: z.string().url().default('https://pay.karta.cards'),
  VAULT_SERVICE_URL: z.string().url().default('http://localhost:3004'),
  // Shared secret for HMAC-signed vault calls; must appear verbatim in the
  // vault service's SERVICE_AUTH_KEYS['activation'].
  SERVICE_AUTH_ACTIVATION_SECRET: hexKey(32),
  DATA_PREP_SERVICE_URL: z.string().url().default('http://localhost:3006'),
  SERVICE_AUTH_PROVISIONING_SECRET: hexKey(32).default('0'.repeat(64)),
  // Palisade RCA endpoint for mobile provisioning
  PALISADE_RCA_URL: z.string().url().optional(),
  // AWS Cognito — mobile app JWT verification
  COGNITO_USER_POOL_ID: z.string().default('ap-southeast-2_Db4d1vpIV'),
  COGNITO_CLIENT_ID: z.string().default('7pj9230obhsa6h6vrvk9tru7do'),
  // Base URL of the per-program microsite CDN.  Activation builds a redirect
  // target against this host when the card's program has a microsite live.
  MICROSITE_CDN_URL: z.string().url().default('https://microsite.karta.cards'),
});

export { getActivationConfig, _resetActivationConfig };
