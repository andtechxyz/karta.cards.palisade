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
});

export { getRcaConfig, _resetRcaConfig };
