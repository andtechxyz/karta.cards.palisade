import { defineEnv, baseEnvShape, authKeysJson } from '@palisade/core';
import { z } from 'zod';

const { get: getCardOpsConfig, reset: _resetCardOpsConfig } = defineEnv({
  ...baseEnvShape,

  PORT: z.coerce.number().default(3009),

  // HMAC auth keys for inbound S2S (activation → card-ops /register).
  CARD_OPS_AUTH_KEYS: authKeysJson,

  // How long a CardOpSession is valid between creation and WS connect.
  WS_TIMEOUT_SECONDS: z.coerce.number().default(60),

  // Public origin the admin client connects its WebSocket to.  When
  // unset we fall back to the inbound request host — fine for dev,
  // broken in prod (the admin client would get an unreachable URL).
  CARD_OPS_PUBLIC_WS_BASE: z.string().url().optional(),

  // Directory containing CAP files shipped with the build.  Overridable
  // for tests; defaults to `services/card-ops/cap-files/` relative to
  // the compiled dist (i.e. alongside the built service).
  CAP_FILES_DIR: z.string().default(''),

  // GP master key for SCP03 — a 3-key set (ENC / MAC / DEK) delivered
  // as JSON, each key as 32 hex chars (16 raw bytes, AES-128).  Example:
  //   {"enc":"404142...","mac":"404142...","dek":"404142..."}
  // Defaults to the GP test key (40..4F) so local dev works against a
  // virgin JCOP sample card without config.
  //
  // This is the **test-keys fallback** — used when
  // CARD_OPS_USE_TEST_KEYS is set OR the card's IssuerProfile has no
  // gp{Enc,Mac,Dek}KeyArn populated.  Production must set
  // CARD_OPS_USE_TEST_KEYS='' and populate the ARNs per IssuerProfile.
  GP_MASTER_KEY: z.string().default(
    JSON.stringify({
      enc: '404142434445464748494A4B4C4D4E4F',
      mac: '404142434445464748494A4B4C4D4E4F',
      dek: '404142434445464748494A4B4C4D4E4F',
    }),
  ),

  // Bypass the per-card IssuerProfile ARN lookup and return the
  // GP_MASTER_KEY (default: GP test keys) for every card.  Set to '1'
  // in dev to use sample-card-friendly keys; leave unset in
  // staging/production so a missing ARN is a loud warning rather than
  // silent key reuse.
  CARD_OPS_USE_TEST_KEYS: z.string().optional(),

  // KMS key ARN for decrypting SadRecord.sadEncrypted.  Used by the
  // personalise_payment_applet op to resolve the plaintext DGI blob
  // that then gets streamed to the payment applet via STORE DATA.
  //
  // Empty string = dev mode (AES-128-ECB via @palisade/emv's
  // decryptSadDev).  Production sets this to the same ARN as
  // data-prep / rca so decrypts round-trip across services.
  KMS_SAD_KEY_ARN: z.string().default(''),
});

export { getCardOpsConfig, _resetCardOpsConfig };
