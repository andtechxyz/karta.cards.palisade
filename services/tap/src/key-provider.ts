import { EnvKeyProvider, type KeyProvider } from '@palisade/core';
import { getTapConfig } from './env.js';

// -----------------------------------------------------------------------------
// Tap-service-local KeyProvider — wraps the CARD_FIELD_DEK keyspace used to
// decrypt the two SDM read keys on each SUN tap.  Activation writes these
// ciphertexts; tap reads them.  Same keyspace, different service boundary.
// -----------------------------------------------------------------------------

let _kp: EnvKeyProvider | null = null;

export function getCardFieldKeyProvider(): KeyProvider {
  if (!_kp) {
    const config = getTapConfig();
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
