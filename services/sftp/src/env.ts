import { defineEnv, baseEnvShape } from '@palisade/core';
import { z } from 'zod';

const { get: getSftpConfig, reset: _resetSftpConfig } = defineEnv({
  ...baseEnvShape,

  AWS_REGION: z.string().default('ap-southeast-2'),

  // S3 bucket + optional KMS key for uploaded batches — must match admin /
  // batch-processor so the pipeline writes and reads the same store.
  EMBOSSING_BUCKET: z.string().default('karta-embossing-files-600743178530'),
  EMBOSSING_KMS_KEY_ARN: z.string().optional(),

  // Root of SFTP user home dirs — one subdir per chrooted user.
  SFTP_HOME_BASE: z.string().default('/home'),

  // How often to scan for new files.  Partners typically upload a few files
  // per day, so 30s is plenty.
  SFTP_POLL_INTERVAL_MS: z.coerce.number().int().positive().default(30000),

  // Stability window — we only ingest a file once its size + mtime have been
  // unchanged for this long.  Protects against reading a file mid-upload
  // (e.g. a 500MB partner batch arriving over a slow link).
  SFTP_STABILITY_MS: z.coerce.number().int().positive().default(15000),
});

export { getSftpConfig, _resetSftpConfig };
