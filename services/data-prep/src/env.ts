import { defineEnv, baseEnvShape, authKeysJson } from '@palisade/core';
import { z } from 'zod';

const { get: getDataPrepConfig, reset: _resetDataPrepConfig } = defineEnv({
  ...baseEnvShape,

  PORT: z.coerce.number().default(3006),

  // HMAC auth — who can call us (activation, admin)
  PROVISION_AUTH_KEYS: authKeysJson,

  // AWS region for Payment Cryptography and KMS
  AWS_REGION: z.string().default('ap-southeast-2'),

  // KMS key for encrypting SAD blobs at rest
  KMS_SAD_KEY_ARN: z.string().default(''),

  // SAD record TTL in days
  SAD_TTL_DAYS: z.coerce.number().int().positive().default(30),

  // Mock the EMV key derivation (skip AWS Payment Cryptography).  Returns
  // deterministic fake iCVV + mock key ARNs.  Useful for E2E testing
  // before real PC keys are provisioned, or in staging/dev where paying
  // ~$4/day for 4 HSM keys isn't justified.  NEVER set true in prod —
  // the mock iCVV won't authorise against issuer systems.
  DATA_PREP_MOCK_EMV: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
});

export { getDataPrepConfig, _resetDataPrepConfig };
