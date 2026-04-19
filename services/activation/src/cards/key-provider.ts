import { EnvKeyProvider, type KeyProvider } from '@palisade/core';
import { getActivationConfig } from '../env.js';

// -----------------------------------------------------------------------------
// Activation-service-local KeyProvider — wraps the CARD_FIELD_DEK keyspace
// used to encrypt Card.uidEncrypted and the two SDM read keys.
//
// Tap service uses the same keyspace (to decrypt SDM keys for SUN verify);
// vault service does NOT — its PAN DEK is a separate keyspace entirely
// (PCI-DSS 3.5/3.6 — keys scoped to the data they protect).
// -----------------------------------------------------------------------------

let _kp: EnvKeyProvider | null = null;

export function getCardFieldKeyProvider(): KeyProvider {
  if (!_kp) {
    const config = getActivationConfig();
    _kp = new EnvKeyProvider({
      activeVersion: config.CARD_FIELD_DEK_ACTIVE_VERSION,
      keys: { 1: config.CARD_FIELD_DEK_V1 },
    });
  }
  return _kp;
}

/** Test hook — reset the cached provider after env changes. */
export function _resetCardFieldKeyProvider(): void {
  _kp = null;
}
