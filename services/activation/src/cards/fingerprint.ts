import crypto from 'node:crypto';
import { getActivationConfig } from '../env.js';

/**
 * Deterministic per-card fingerprint of a PICC UID, for unique-lookup and
 * duplicate-registration prevention without storing plaintext UID.
 *
 *   fingerprint = HMAC-SHA256(CARD_UID_FINGERPRINT_KEY, "uid:" || lowercase(uid))
 *
 * Scoped to activation only; the vault PAN fingerprint uses a different key.
 */
export function fingerprintUid(uidHex: string): string {
  const normalised = uidHex.replace(/[\s-]/g, '').toLowerCase();
  const key = Buffer.from(getActivationConfig().CARD_UID_FINGERPRINT_KEY, 'hex');
  return crypto
    .createHmac('sha256', key)
    .update('uid:')
    .update(normalised)
    .digest('hex');
}
