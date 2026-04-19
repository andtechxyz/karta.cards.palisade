import { defineEnv, baseEnvShape, authKeysJson } from '@palisade/core';
import { z } from 'zod';

import type { UdkBackend } from './services/udk-deriver.js';
export type { UdkBackend };

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

  // Per-card EMV UDK derivation backend:
  //   hsm    - AWS Payment Cryptography.  Requires real IMK ARNs.  Prod.
  //   local  - Real EMV Method A in Node crypto using dev IMKs derived from
  //            DEV_UDK_ROOT_SEED via HKDF.  Cryptographically valid, but the
  //            root seed lives in app memory — dev only.
  //   mock   - sha256-based fakes, structurally valid, cryptographically
  //            meaningless.  For unit tests.
  //
  // Default is empty so resolveUdkBackend() can fall back to the legacy
  // DATA_PREP_MOCK_EMV toggle for one release cycle.
  DATA_PREP_UDK_BACKEND: z.enum(['hsm', 'local', 'mock', '']).default(''),

  // Deprecated legacy toggle.  Maps "true" → mock, "false" → hsm when
  // DATA_PREP_UDK_BACKEND is unset.  Kept so the prod secret
  // `palisade/DATA_PREP_MOCK_EMV=false` keeps selecting the hsm backend while
  // infra catches up with the rename.
  DATA_PREP_MOCK_EMV: z.enum(['true', 'false', '']).default(''),

  // Root seed for the local UdkDeriver backend.  Ignored unless
  // DATA_PREP_UDK_BACKEND resolves to 'local'.  Must decode to exactly 32
  // bytes.  Rotate freely in dev (changes MK + iCVV for every card).
  DEV_UDK_ROOT_SEED: z.string().default(''),
});

/**
 * Resolve the effective UDK backend.  Precedence:
 *   1. DATA_PREP_UDK_BACKEND if explicitly set
 *   2. DATA_PREP_MOCK_EMV=true  → 'mock'
 *   3. DATA_PREP_MOCK_EMV=false → 'hsm'
 *   4. Default                   → 'hsm'
 *
 * Also enforces that 'local' has a 32-byte DEV_UDK_ROOT_SEED.
 */
export function resolveUdkBackend(cfg: ReturnType<typeof getDataPrepConfig>): UdkBackend {
  let backend: UdkBackend;
  if (cfg.DATA_PREP_UDK_BACKEND) {
    backend = cfg.DATA_PREP_UDK_BACKEND;
  } else if (cfg.DATA_PREP_MOCK_EMV === 'true') {
    backend = 'mock';
  } else {
    backend = 'hsm';
  }

  if (backend === 'local') {
    if (!cfg.DEV_UDK_ROOT_SEED || !/^[0-9a-fA-F]{64}$/.test(cfg.DEV_UDK_ROOT_SEED)) {
      throw new Error(
        "DATA_PREP_UDK_BACKEND='local' requires DEV_UDK_ROOT_SEED to be a " +
          '32-byte hex string (64 hex chars)',
      );
    }
  }

  return backend;
}

export { getDataPrepConfig, _resetDataPrepConfig };
