import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { deriveSessionKeys } from './sessionKeys.js';
import {
  computeSdmmac,
  extractSdmmacInput,
  verifySdmmac,
  verifySunUrl,
} from './verify.js';

// End-to-end SUN URL verifier tests.
//
// We synthesize an encrypted PICC + matching CMAC under known keys, glue it
// into a URL of the same shape the physical card emits, and assert the
// verifier accepts it — and rejects mutations.

const META_KEY = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const FILE_KEY = Buffer.from('ffeeddccbbaa99887766554433221100', 'hex');
const UID = Buffer.from('04A3B2C1D2E380', 'hex');
const COUNTER = 7;

/** 3-byte LSB-first counter, matching what decryptPiccData returns. */
function counterBytes(n: number): Buffer {
  const b = Buffer.alloc(3);
  b.writeUIntLE(n, 0, 3);
  return b;
}

/** Compose the 16-byte PICC plaintext block per AN14683 §2.5.2. */
function buildPiccPlaintext(uid: Buffer, counter: number): Buffer {
  // PICCDataTag (1) | UID (7) | SDMReadCtr LE (3) | random padding (5)
  const buf = Buffer.alloc(16);
  buf[0] = 0xc7; // tag for "UID + counter" present
  uid.copy(buf, 1, 0, 7);
  buf.writeUIntLE(counter, 8, 3);
  // bytes 11..15 left as zero padding — verifier ignores them
  return buf;
}

function encryptPicc(metaKey: Buffer, plaintext: Buffer): string {
  // AES-128-CBC, zero IV, no padding (NXP convention).
  const cipher = crypto.createCipheriv('aes-128-cbc', metaKey, Buffer.alloc(16));
  cipher.setAutoPadding(false);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return ct.toString('hex').toUpperCase();
}

function buildSunUrl(host: string, path: string, piccHex: string, fileKey: Buffer): string {
  // Compose URL minus the &m= value, then derive the MAC over that prefix.
  const prefix = `https://${host}${path}?e=${piccHex}&m=`;
  const macInput = extractSdmmacInput(prefix);
  const { mac: macSessionKey } = deriveSessionKeys(fileKey, UID, counterBytes(COUNTER));
  const macHex = computeSdmmac(macSessionKey, macInput).toString('hex').toUpperCase();
  return `${prefix}${macHex}`;
}

describe('verifySunUrl — end-to-end with synthesized vectors', () => {
  const piccHex = encryptPicc(META_KEY, buildPiccPlaintext(UID, COUNTER));
  const url = buildSunUrl('pay.karta.cards', '/activate/test-001', piccHex, FILE_KEY);

  it('accepts a URL whose PICC + MAC are consistent with the keys', () => {
    const r = verifySunUrl({ url, sdmMetaReadKey: META_KEY, sdmFileReadKey: FILE_KEY });
    expect(r.valid).toBe(true);
    if (r.valid) {
      expect(r.uidHex).toBe('04A3B2C1D2E380');
      expect(r.counter).toBe(COUNTER);
    }
  });

  it('rejects a tampered MAC', () => {
    const bad = url.slice(0, -2) + (url.slice(-2) === '00' ? 'ff' : '00');
    const r = verifySunUrl({ url: bad, sdmMetaReadKey: META_KEY, sdmFileReadKey: FILE_KEY });
    expect(r.valid).toBe(false);
  });

  it('rejects a wrong meta-read key', () => {
    const wrong = Buffer.alloc(16, 0x42);
    const r = verifySunUrl({ url, sdmMetaReadKey: wrong, sdmFileReadKey: FILE_KEY });
    expect(r.valid).toBe(false);
  });

  it('rejects a missing &m= parameter', () => {
    const noMac = `https://pay.karta.cards/activate/test-001?e=${piccHex}`;
    const r = verifySunUrl({ url: noMac, sdmMetaReadKey: META_KEY, sdmFileReadKey: FILE_KEY });
    expect(r.valid).toBe(false);
  });
});

describe('extractSdmmacInput', () => {
  it('strips the scheme and stops at &m=', () => {
    const url = 'https://pay.karta.cards/activate/abc?e=DEADBEEF&m=ABCDEF';
    expect(extractSdmmacInput(url).toString('ascii')).toBe(
      'pay.karta.cards/activate/abc?e=DEADBEEF&m=',
    );
  });

  it('throws when &m= is missing', () => {
    expect(() => extractSdmmacInput('https://x/y?e=AA')).toThrow(/&m=/);
  });
});

describe('verifySdmmac', () => {
  it('accepts the canonical 8-byte truncation', () => {
    const key = Buffer.alloc(16, 0x01);
    const msg = Buffer.from('hello', 'ascii');
    const expected = computeSdmmac(key, msg).toString('hex');
    expect(verifySdmmac(key, msg, expected)).toBe(true);
  });

  it('rejects wrong-length input rather than throwing', () => {
    const key = Buffer.alloc(16, 0x01);
    expect(verifySdmmac(key, Buffer.from('x'), 'aabb')).toBe(false);
  });
});
