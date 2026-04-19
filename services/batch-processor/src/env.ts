import { defineEnv, baseEnvShape, hexKey } from '@palisade/core';
import { z } from 'zod';

const { get: getBatchConfig, reset: _resetBatchConfig } = defineEnv({
  ...baseEnvShape,

  PORT: z.coerce.number().int().positive().default(3008),

  // AWS region for S3 + KMS
  AWS_REGION: z.string().default('ap-southeast-2'),

  // Encrypted template key (matches admin service)
  EMBOSSING_KEY_V1: hexKey(32),
  EMBOSSING_KEY_ACTIVE_VERSION: z.coerce.number().int().positive().default(1),

  // S3 bucket holding encrypted batch files
  EMBOSSING_BUCKET: z.string().default('karta-embossing-files-600743178530'),

  // Activation service for routing parsed records through registerCard
  ACTIVATION_SERVICE_URL: z.string().url().default('http://localhost:3002'),

  // HMAC secret for calling activation.  Must match activation's
  // PROVISION_AUTH_KEYS['batch-processor'] entry.
  SERVICE_AUTH_BATCH_PROCESSOR_SECRET: hexKey(32),

  // How often to scan for RECEIVED batches
  POLL_INTERVAL_MS: z.coerce.number().int().positive().default(30000),
});

export { getBatchConfig, _resetBatchConfig };
