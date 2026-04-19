/**
 * Load the GP static keys for SCP03 from the service config.
 *
 * In Phase 2 we read from env (GP_MASTER_KEY) — a single issuer-wide
 * key set, which is fine while we're only talking to developer cards.
 * In production this will pull a per-card set from the same KMS/vault
 * store the existing perso flow uses.  Interface already returns the
 * set opaquely, so that swap is a two-line change.
 *
 * Env shape (JSON):
 *   { "enc": "<32 hex chars>", "mac": "<32 hex chars>", "dek": "<32 hex chars>" }
 */

import type { StaticKeys } from './scp03.js';
import { getCardOpsConfig } from '../env.js';

let cached: StaticKeys | null = null;

export function getGpStaticKeys(
  /** Optional override — future per-card lookup will hang off cardId. */
  _cardId?: string,
): StaticKeys {
  if (cached) return cached;

  const raw = getCardOpsConfig().GP_MASTER_KEY;
  let parsed: { enc?: string; mac?: string; dek?: string };
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('GP_MASTER_KEY is not valid JSON');
  }
  if (!parsed.enc || !parsed.mac || !parsed.dek) {
    throw new Error('GP_MASTER_KEY must have enc, mac, dek fields');
  }

  const toBuf = (hex: string, label: string): Buffer => {
    if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
      throw new Error(`GP_MASTER_KEY.${label} must be 32 hex chars (16 bytes)`);
    }
    return Buffer.from(hex, 'hex');
  };

  cached = {
    enc: toBuf(parsed.enc, 'enc'),
    mac: toBuf(parsed.mac, 'mac'),
    dek: toBuf(parsed.dek, 'dek'),
  };
  return cached;
}

// Test-only: flush the cache between runs.
export function _resetGpStaticKeysCache(): void {
  cached = null;
}
