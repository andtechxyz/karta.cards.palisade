import crypto from 'node:crypto';
import type { KeyProvider } from './key-provider.js';

// -----------------------------------------------------------------------------
// AES-256-GCM wrapper.
//
// Ciphertext format (single base64 string):
//   [1-byte version prefix][12-byte IV][N-byte ciphertext][16-byte tag]
//
// The leading 0x01 tag lets us evolve the envelope later without breaking
// existing entries.  The key version is stored separately on the row that
// holds the ciphertext — that's what the KeyProvider dereferences.
//
// The caller always passes the KeyProvider explicitly: there is no global
// default because the vault PAN keyspace and the card-field keyspace must
// not share a root (PCI-DSS 3.5/3.6).
// -----------------------------------------------------------------------------

const ENVELOPE_VERSION = 0x01;
const IV_LEN = 12;
const TAG_LEN = 16;

export interface EncryptedPayload {
  /** base64 of envelope | iv | ciphertext | tag */
  ciphertext: string;
  /** Key version used. */
  keyVersion: number;
}

export function encrypt(plaintext: string, kp: KeyProvider): EncryptedPayload {
  const key = kp.getKey(kp.activeVersion);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope = Buffer.concat([Buffer.from([ENVELOPE_VERSION]), iv, ct, tag]);
  return {
    ciphertext: envelope.toString('base64'),
    keyVersion: kp.activeVersion,
  };
}

export function decrypt(payload: EncryptedPayload, kp: KeyProvider): string {
  const key = kp.getKey(payload.keyVersion);
  const buf = Buffer.from(payload.ciphertext, 'base64');
  if (buf.length < 1 + IV_LEN + TAG_LEN) {
    throw new Error('ciphertext too short');
  }
  const ver = buf[0];
  if (ver !== ENVELOPE_VERSION) {
    throw new Error(`unknown envelope version: ${ver}`);
  }
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  const ct = buf.subarray(1 + IV_LEN, buf.length - TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString('utf8');
}
