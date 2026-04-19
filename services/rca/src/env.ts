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
});

export { getRcaConfig, _resetRcaConfig };
