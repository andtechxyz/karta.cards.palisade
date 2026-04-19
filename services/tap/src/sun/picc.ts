import { createDecipheriv } from 'node:crypto';
import { PICC_DATA_TAG } from './constants.js';

// PICC (Proximity Integrated Circuit Card) data decryption per AN14683 p.5.
//
// The card emits a 16-byte AES-CBC ciphertext under the per-card SDM
// meta-read key with a zero IV.  Plaintext layout:
//
//   [tag(1) | UID(7) | SDMReadCounter(3, LSB-first) | padding(5)]
//
// `tag` MUST equal PICC_DATA_TAG (0xC7) on a valid decrypt; any other value
// means the wrong key was used or the ciphertext was tampered with.

const ZERO_IV = Buffer.alloc(16);

export interface PiccData {
  /** First plaintext byte; equals PICC_DATA_TAG (0xC7) on a valid decrypt. */
  tag: number;
  /** 7-byte PICC UID. */
  uid: Buffer;
  /** 3-byte SDM read counter, LSB-first (as it appears on the wire). */
  sdmReadCounter: Buffer;
  /** Counter parsed as an integer for ordinary comparisons. */
  counter: number;
  /** Trailing 5 bytes (random padding from the card). */
  padding: Buffer;
  /** True iff `tag === PICC_DATA_TAG`. */
  valid: boolean;
}

export function decryptPiccData(
  sdmMetaReadKey: Buffer,
  encryptedPiccHex: string,
): PiccData {
  if (sdmMetaReadKey.length !== 16) {
    throw new Error('SDM meta-read key must be 16 bytes');
  }
  const enc = Buffer.from(encryptedPiccHex, 'hex');
  if (enc.length !== 16) {
    throw new Error(`Encrypted PICC data must be 16 bytes (got ${enc.length})`);
  }

  const decipher = createDecipheriv('aes-128-cbc', sdmMetaReadKey, ZERO_IV);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([decipher.update(enc), decipher.final()]);

  const tag = decrypted[0];
  // .subarray() returns a view; copy so callers can't mutate the decrypted buffer
  // through these handles after we've returned.
  const uid = Buffer.from(decrypted.subarray(1, 8));
  const sdmReadCounter = Buffer.from(decrypted.subarray(8, 11));
  const padding = Buffer.from(decrypted.subarray(11, 16));
  const counter = sdmReadCounter.readUIntLE(0, 3);

  return {
    tag,
    uid,
    sdmReadCounter,
    counter,
    padding,
    valid: tag === PICC_DATA_TAG,
  };
}
