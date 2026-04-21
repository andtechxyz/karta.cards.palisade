import {
  defineEnv,
  baseEnvShape,
  authKeysJson,
  assertProdRequiredEnv,
} from '@palisade/core';
import { z } from 'zod';

// Dev fallback constants kept at module scope so zod's `.default(...)` and
// the prod-required assertion below always agree on what "the dev value" is.
// If someone changes either side in isolation the prod check silently stops
// firing, so the single source of truth lives here.
const DATA_PREP_DEV_URL = 'http://localhost:3006';
const ACTIVATION_CALLBACK_DEV_URL = 'http://localhost:3002';
const CALLBACK_HMAC_DEV_SECRET = '0'.repeat(64);

const { get: _getRcaConfigRaw, reset: _resetRcaConfigRaw } = defineEnv({
  ...baseEnvShape,

  PORT: z.coerce.number().default(3007),

  // HMAC auth — who can call us
  PROVISION_AUTH_KEYS: authKeysJson,

  // Data-prep service URL (internal ALB).  Localhost default is for
  // `pnpm dev`; production MUST override via task def with the internal
  // ALB DNS (e.g. http://data-prep.palisade.internal:3006).  Enforced
  // by assertProdRequiredEnv below.
  DATA_PREP_SERVICE_URL: z.string().url().default(DATA_PREP_DEV_URL),

  // Callback URL for notifying activation service on completion.  Same
  // prod-override rules as DATA_PREP_SERVICE_URL.
  ACTIVATION_CALLBACK_URL: z.string().url().default(ACTIVATION_CALLBACK_DEV_URL),

  // HMAC secret for signing callbacks.  Default is 64 zero chars — a
  // key an attacker could generate offline, so callback integrity is
  // effectively off in dev.  Prod MUST provide a real 32-byte hex
  // secret from Secrets Manager (palisade/CALLBACK_HMAC_SECRET).
  CALLBACK_HMAC_SECRET: z.string().min(1).default(CALLBACK_HMAC_DEV_SECRET),

  // WebSocket reconnect timeout
  WS_TIMEOUT_SECONDS: z.coerce.number().default(30),

  // Publicly-reachable origin the mobile app should connect its WebSocket to.
  // RCA itself runs on an internal ALB; the WS endpoint is exposed via
  // CloudFront → public ALB → palisade-rca (path-routed under mobile.karta.cards
  // /api/provision/*).  When unset, fall back to the inbound request host —
  // OK for local dev, would hand the phone an unreachable URL in prod.
  RCA_PUBLIC_WS_BASE: z.string().url().optional(),

  // --- SAD decryption ------------------------------------------------------
  // RCA reads SadRecord.sadEncrypted and passes the decrypted bytes to the
  // PA applet as part of TRANSFER_SAD.  Must match what the data-prep
  // service used to encrypt the blob — different sadKeyVersion values
  // select between regimes:
  //   0 → KMS CiphertextBlob, decrypted via KMS_SAD_KEY_ARN
  //   1 → AES-128-ECB under DEV_SAD_MASTER_KEY (dev/e2e)
  //
  // KMS_SAD_KEY_ARN is optional; when empty, only dev-mode ciphertexts
  // (sadKeyVersion=1) can be decrypted — which is the case for the
  // e2e_fi_2590 fixture today.
  KMS_SAD_KEY_ARN: z.string().default(''),
  AWS_REGION: z.string().default('ap-southeast-2'),

  // --- Dev-only fallback ---------------------------------------------------
  // When set to "1", buildPlanForSession allows the minimal-SAD path
  // (one DGI 0x0101 / TLV 0x50 "PALISADE" + placeholder metadata) when
  // the IssuerProfile is incomplete.  Intended solely for the e2e_fi_2590
  // skeleton profile that still exists in the dev DB.  Emits a prominent
  // warning every time it fires so it never goes unnoticed.  Prod
  // deployments MUST leave this unset — RCA throws
  // issuer_profile_incomplete if it is.
  RCA_ALLOW_MINIMAL_SAD: z.enum(['0', '1']).default('0'),

  // --- Attestation mode (patent claim C16/C23) ----------------------------
  // strict     — require non-empty attestation cert chain from the PA that
  //              validates to a pinned vendor root (NXP JCOP 5 or Infineon
  //              Secora).  Refuse to ship TRANSFER_SAD if verification
  //              fails.  Required for PCI/patent compliance.
  // permissive — stub mode: accept everything, log a warning banner.  Used
  //              until karta-se applet v1 ships real attestation output.
  // Default is `permissive` for backward compatibility during rollout; a
  // karta-se v1 deployment should flip this to `strict` via ECS task def.
  PALISADE_ATTESTATION_MODE: z.enum(['strict', 'permissive']).default('permissive'),

  // --- ParamBundle prototype flag (patent C17/C22) -----------------------
  // Master kill-switch for the chip-computed-DGI prototype path.
  //   '0' (default): every provisioning session uses the legacy TRANSFER_SAD
  //                  flow, regardless of Card.paramRecordId.  Prototype code
  //                  is physically deployed but unreachable — safe to ship
  //                  to prod without risk to existing fleet.
  //   '1':           sessions whose Card has a non-null paramRecordId route
  //                  through the TRANSFER_PARAMS path (ECDH-wrapped
  //                  parameter bundle sent to pa-v3 applet).  Legacy cards
  //                  (paramRecordId = null) keep using TRANSFER_SAD
  //                  unconditionally — both paths coexist at runtime.
  // Flip to '1' only on the ECS task def servicing prototype cards; keep at
  // '0' (default) on the main production fleet until graduation.
  RCA_ENABLE_PARAM_BUNDLE: z.enum(['0', '1']).default('0'),

  // --- WS upgrade auth token (patent C3 / PCI 8.3.6) ---------------------
  // HMAC-SHA256 key for the short-lived token appended to wsUrl.  Signer
  // and verifier share the same key; mobile clients round-trip it
  // verbatim from /api/provision/start to the WS upgrade.  64-char hex
  // (32 bytes) — read from Secrets Manager (palisade/WS_TOKEN_SECRET).
  //
  // TTL matches WS_TIMEOUT_SECONDS so a leaked wsUrl is only attackable
  // inside the same window the server would have accepted the cuid alone
  // — after that, both the cuid-age check AND the token-exp check reject.
  WS_TOKEN_SECRET: z.string().regex(/^[0-9a-fA-F]{64}$/, 'WS_TOKEN_SECRET must be 64 hex chars (32 bytes)'),
});

// Single-flight guard — assertProdRequiredEnv emits one warning line per
// fallback-active field in dev.  Firing it every time getRcaConfig() is
// called would bury those warnings under thousands of lines of spam
// (getRcaConfig is called per-request in some paths).  We run the check
// exactly once per process and cache the resolved config.
let _prodEnvChecked = false;

/**
 * Resolve the rca config and — on first call — run the production
 * required-env check.  In prod, missing/unsafe values throw here with a
 * single message listing every offending field at once.  In dev/test,
 * a single warning per fallback-active field is printed to stderr.
 */
export function getRcaConfig() {
  const cfg = _getRcaConfigRaw();
  if (!_prodEnvChecked) {
    assertProdRequiredEnv(cfg.NODE_ENV, [
      {
        name: 'KMS_SAD_KEY_ARN',
        value: cfg.KMS_SAD_KEY_ARN,
        devFallback: '',
        // 'none'/'dev' are sentinel values that mean "no KMS key, use
        // the AES-128-ECB stub" (Secrets Manager rejects zero-length
        // strings so the operator has to store SOMETHING — see
        // commit cde5f8d).  Prod must have a real ARN, not a sentinel.
        fallbackSentinels: ['none', 'dev'],
        description:
          'AWS Payment Cryptography key ARN for SAD blob decryption. ' +
          'Without it rca can only read AES-128-ECB dev ciphertexts — ' +
          'prod SadRecords encrypted under KMS will fail to decrypt.',
      },
      {
        name: 'RCA_PUBLIC_WS_BASE',
        value: cfg.RCA_PUBLIC_WS_BASE,
        // Declared `.optional()` — no zod default — so undefined IS the fallback.
        devFallback: undefined,
        description:
          'Publicly-reachable WebSocket origin handed back to the mobile ' +
          'app in /api/provision/start.  Falling back to the inbound ' +
          'request host breaks behind ALB/CloudFront (phone gets the ' +
          'internal DNS name).  Must be https://palisade.karta.cards in prod.',
      },
      {
        name: 'CALLBACK_HMAC_SECRET',
        value: cfg.CALLBACK_HMAC_SECRET,
        devFallback: CALLBACK_HMAC_DEV_SECRET,
        description:
          'HMAC-SHA256 key for signing provisioning-complete callbacks ' +
          'to the activation service.  Default is 64 zero chars — any ' +
          'attacker who can reach the activation endpoint can forge ' +
          'completions.  Pull from Secrets Manager (palisade/CALLBACK_HMAC_SECRET).',
      },
      {
        name: 'DATA_PREP_SERVICE_URL',
        value: cfg.DATA_PREP_SERVICE_URL,
        devFallback: DATA_PREP_DEV_URL,
        description:
          'Internal ALB DNS for the data-prep service.  Leaving it at ' +
          'localhost in a Fargate task means rca tries to reach data-prep ' +
          'on its own loopback — no such service listens there.',
        rejectLocalhostInProd: true,
      },
      {
        name: 'ACTIVATION_CALLBACK_URL',
        value: cfg.ACTIVATION_CALLBACK_URL,
        devFallback: ACTIVATION_CALLBACK_DEV_URL,
        description:
          'Internal ALB DNS for the activation service, used when rca ' +
          'notifies activation that a card just finished provisioning. ' +
          'Localhost default would silently drop the completion callback.',
        rejectLocalhostInProd: true,
      },
    ]);
    _prodEnvChecked = true;
  }
  return cfg;
}

/** Reset the cached config — test hook, clears the prod-check single-flight too. */
export function _resetRcaConfig(): void {
  _resetRcaConfigRaw();
  _prodEnvChecked = false;
}
