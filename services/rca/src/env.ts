import { defineEnv, baseEnvShape, authKeysJson } from '@palisade/core';
import { z } from 'zod';

const { get: getRcaConfig, reset: _resetRcaConfig } = defineEnv({
  ...baseEnvShape,

  PORT: z.coerce.number().default(3007),

  // HMAC auth — who can call us
  PROVISION_AUTH_KEYS: authKeysJson,

  // Data-prep service URL (internal ALB)
  DATA_PREP_SERVICE_URL: z.string().url().default('http://localhost:3006'),

  // Callback URL for notifying activation service on completion
  ACTIVATION_CALLBACK_URL: z.string().url().default('http://localhost:3002'),

  // HMAC secret for signing callbacks
  CALLBACK_HMAC_SECRET: z.string().min(1).default('0'.repeat(64)),

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

export { getRcaConfig, _resetRcaConfig };
