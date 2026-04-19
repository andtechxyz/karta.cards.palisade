import { aesCmac } from './cmac.js';
import { SC_SDMENC, SC_SDMMAC, SCT_1, SKL_128 } from './constants.js';

// Per-tap session key derivation per AN14683 p.5-6.
//
//   SV             = UID(7) | SDMReadCounter(3, LSB-first)         // 10B
//   session_vector = SC(2) | SCT_1(2) | SKL_128(2) | SV(10)         // 16B
//   session_key    = AES-CMAC(sdmFileReadKey, session_vector)       // 16B
//
// We derive both the ENC and MAC session keys here even though only `mac` is
// needed for SDMMAC verification — having both available keeps the door open
// for SDM-encrypted file data (`?c=...`) without rewriting this module.

function deriveSessionKey128(
  master: Buffer,
  uid: Buffer,
  sdmReadCounter: Buffer,
  sessionConstant: Buffer,
): Buffer {
  if (uid.length !== 7) throw new Error('UID must be 7 bytes');
  if (sdmReadCounter.length !== 3) {
    throw new Error('SDM read counter must be 3 bytes (LSB-first)');
  }
  const sv = Buffer.concat([uid, sdmReadCounter]);
  const sessionVector = Buffer.concat([sessionConstant, SCT_1, SKL_128, sv]);
  return aesCmac(master, sessionVector);
}

export interface SessionKeys {
  enc: Buffer;
  mac: Buffer;
}

export function deriveSessionKeys(
  sdmFileReadKey: Buffer,
  uid: Buffer,
  sdmReadCounter: Buffer,
): SessionKeys {
  return {
    enc: deriveSessionKey128(sdmFileReadKey, uid, sdmReadCounter, SC_SDMENC),
    mac: deriveSessionKey128(sdmFileReadKey, uid, sdmReadCounter, SC_SDMMAC),
  };
}
