import { defineEnv, baseEnvShape, authKeysJson } from '@palisade/core';
import { z } from 'zod';

const { get: _getCardOpsConfigRaw, reset: _resetCardOpsConfig } = defineEnv({
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

  // Shared HMAC key for verifying the WS upgrade token minted by
  // activation.  PCI 8.3.6 / H-8.  Activation signs with the same key.
  // 64 hex chars (32 bytes).
  WS_TOKEN_SECRET: z.string().regex(/^[0-9a-fA-F]{64}$/, 'WS_TOKEN_SECRET must be 64 hex chars (32 bytes)'),

  // TEMPORARY escape hatch for Stage C.2 rollout — when set to '1',
  // the WS upgrade handler skips the Cognito JWT validation that
  // requires `?id_token=<JWT>` matching session.initiatedBy.
  //
  // Defaults UNSET (= validation enforced).  CLI ops tools that
  // pre-date the JWT requirement should append the token to wsUrl;
  // this flag exists only to keep them limping while operators
  // update their tooling.
  //
  // PCI DSS 10.2.5 — setting this in production weakens operator
  // attribution from "Cognito-verified" to "session-cuid trusted",
  // which is the pre-Stage-C.2 baseline.  The card-ops process
  // logs a loud warning at startup AND on every WS connect that
  // bypasses validation, so the gap is visible in CloudWatch.
  // Remove from env (and delete this branch) once all clients
  // pass id_token.
  ALLOW_UNAUTHENTICATED_WS: z.string().optional(),

  // --- Patent C16/C23: Issuer CA KMS key ARN for per-card attestation
  // material minting during install-pa perso.  Direct-imports
  // issueCardCert + makeKmsIssuerSigner from @palisade/data-prep so
  // card-ops owns the kms:Sign call (simpler than an HTTP round trip
  // and keeps the attestation private scalar from ever touching the
  // wire between services).
  //
  // Empty default keeps dev installs working — install-pa sees the
  // empty ARN, skips the 3 STORE_ATTESTATION APDUs, and completes
  // normally.  The card will then fail strict-mode verification at
  // tap time with a clear 'cardCert missing' warning, which is the
  // signal to set the ARN and re-run install-pa.
  KMS_ATTESTATION_ISSUER_ARN: z.string().default(''),
  // AWS region for KMS.  Separate from the base AWS_REGION so card-ops
  // could hypothetically sign against a key in a different region than
  // its PC region.  In practice they share ap-southeast-2.
  AWS_REGION: z.string().default('ap-southeast-2'),

  // Prototype toggle — which PA CAP file to install by default when the
  // install_pa operation does not receive an explicit capKey in the
  // session params.
  //
  //   'pa'    → legacy pa.cap (INS_TRANSFER_SAD, server-computed DGIs).
  //             This is the production default and what every existing
  //             card in the field runs.
  //   'pa-v3' → prototype pa-v3.cap (INS_TRANSFER_PARAMS, chip-computed
  //             DGIs via ECDH-wrapped ParamBundle).  Dual-mode applet —
  //             still accepts legacy SAD for cards whose server
  //             provisioning path hasn't migrated yet.
  //
  // Per-session override: POST /api/sessions body may include
  //   { opType: 'install_pa', params: { capKey: 'pa-v3' } }
  // which beats this default.  The env var is the "my whole fleet is
  // ready to migrate" switch; the params field is "this one card is a
  // prototype trial".
  CARD_OPS_DEFAULT_PA_CAP: z.enum(['pa', 'pa-v3']).default('pa'),
});

// Wrap the raw config getter with a production guard that refuses to boot
// with GP test keys or CARD_OPS_USE_TEST_KEYS=1 still set.  PCI 3.6.1 /
// 6.4.3 — test keys must never authenticate production cards.
const GP_TEST_KEY_BYTES = '404142434445464748494A4B4C4D4E4F';
function getCardOpsConfig(): ReturnType<typeof _getCardOpsConfigRaw> {
  const cfg = _getCardOpsConfigRaw();
  if (process.env.NODE_ENV === 'production') {
    if (cfg.CARD_OPS_USE_TEST_KEYS) {
      throw new Error(
        'CARD_OPS_USE_TEST_KEYS=1 is forbidden in production.  Leave it unset so the per-FI GP key ARNs are resolved per card.',
      );
    }
    try {
      const parsed = JSON.parse(cfg.GP_MASTER_KEY);
      const usingTest =
        (parsed.enc ?? '').toUpperCase() === GP_TEST_KEY_BYTES ||
        (parsed.mac ?? '').toUpperCase() === GP_TEST_KEY_BYTES ||
        (parsed.dek ?? '').toUpperCase() === GP_TEST_KEY_BYTES;
      if (usingTest) {
        throw new Error(
          'GP_MASTER_KEY contains the well-known GlobalPlatform test key (40..4F).  Production must set per-FI ARNs on IssuerProfile; GP_MASTER_KEY is dev-only.',
        );
      }
    } catch (parseErr) {
      // GP_MASTER_KEY should still be valid JSON even in prod (the
      // schema default is JSON-shaped).  Re-throw parse errors; the
      // testKey branch throws its own message.
      if (parseErr instanceof SyntaxError) {
        throw new Error('GP_MASTER_KEY is not valid JSON');
      }
      throw parseErr;
    }
  }
  return cfg;
}

export { getCardOpsConfig, _resetCardOpsConfig };
