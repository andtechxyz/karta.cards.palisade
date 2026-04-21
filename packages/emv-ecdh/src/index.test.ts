/**
 * Tests for @palisade/emv-ecdh.
 *
 * Three kinds of coverage:
 *
 *   1. HKDF-SHA256 against RFC 5869 test case #1 — proves our HKDF
 *      matches the standard, which the PA v3 applet must also implement
 *      byte-identically for interop.
 *   2. ECDH + HKDF + AES-CBC + HMAC-SHA256 round-trip — server wraps,
 *      "chip" (simulated by test keypair) unwraps back to the original
 *      bytes.  Tampered wire bytes must fail unwrap.
 *   3. Wire-format parse/serialize round-trip.
 */

import { describe, it, expect } from 'vitest';
import {
  hkdfSha256,
  wrapParamBundle,
  unwrapParamBundle,
  wrapParamBundleDeterministic,
  serializeWrappedBundle,
  parseWireBundle,
  generateTestKeypair,
  ECDH_PROTOCOL,
} from './index.js';

describe('hkdfSha256 — RFC 5869 compliance', () => {
  it('matches RFC 5869 test case 1', () => {
    const ikm = Buffer.from('0b'.repeat(22), 'hex');
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
    const L = 42;
    const expected = Buffer.from(
      '3cb25f25faacd57a90434f64d0362f2a' +
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
        '34007208d5b887185865',
      'hex',
    );

    const okm = hkdfSha256(ikm, salt, info, L);
    expect(okm.equals(expected)).toBe(true);
  });

  it('matches RFC 5869 test case 2 (longer inputs)', () => {
    const ikm = Buffer.from(
      '000102030405060708090a0b0c0d0e0f' +
        '101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f' +
        '303132333435363738393a3b3c3d3e3f' +
        '404142434445464748494a4b4c4d4e4f',
      'hex',
    );
    const salt = Buffer.from(
      '606162636465666768696a6b6c6d6e6f' +
        '707172737475767778797a7b7c7d7e7f' +
        '808182838485868788898a8b8c8d8e8f' +
        '909192939495969798999a9b9c9d9e9f' +
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      'hex',
    );
    const info = Buffer.from(
      'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      'hex',
    );
    const L = 82;
    const expected = Buffer.from(
      'b11e398dc80327a1c8e7f78c596a4934' +
        '4f012eda2d4efad8a050cc4c19afa97c' +
        '59045a99cac7827271cb41c65e590e09' +
        'da3275600c2f09b8367793a9aca3db71' +
        'cc30c58179ec3e87c14c01d5c1f3434f' +
        '1d87',
      'hex',
    );

    const okm = hkdfSha256(ikm, salt, info, L);
    expect(okm.equals(expected)).toBe(true);
  });

  it('throws on absurd output length', () => {
    expect(() => hkdfSha256(Buffer.alloc(32), Buffer.alloc(0), Buffer.alloc(0), 10_000)).toThrow(
      /exceeds HKDF max/,
    );
  });
});

describe('wrap / unwrap — round-trip (AES-CBC + HMAC-SHA256)', () => {
  it('wraps a ParamBundle and the chip can unwrap it', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.from('DEADBEEFCAFEBABE0102030405060708', 'hex');

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'test-session-01',
    });

    expect(wrapped.serverEphemeralPub.length).toBe(ECDH_PROTOCOL.SEC1_UNCOMPRESSED_LEN);
    expect(wrapped.serverEphemeralPub[0]).toBe(0x04);
    expect(wrapped.iv.length).toBe(ECDH_PROTOCOL.AES_IV_LEN);
    expect(wrapped.tag.length).toBe(ECDH_PROTOCOL.HMAC_TAG_LEN);
    // AES-CBC PKCS#7 pads a 16-byte plaintext to 32 bytes (full pad block).
    expect(wrapped.ciphertext.length).toBe(32);

    const unwrapped = unwrapParamBundle({
      ...wrapped,
      chipPriv: chip.priv,
      sessionId: 'test-session-01',
    });

    expect(unwrapped.equals(plaintext)).toBe(true);
  });

  it('handles larger bundles (240-byte typical ParamBundle)', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.alloc(240);
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = (i * 17 + 3) & 0xff;

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'long-session-id-with-cuid-v2-shape-01234567',
    });

    const unwrapped = unwrapParamBundle({
      ...wrapped,
      chipPriv: chip.priv,
      sessionId: 'long-session-id-with-cuid-v2-shape-01234567',
    });

    expect(unwrapped.equals(plaintext)).toBe(true);
  });

  it('fails unwrap when sessionId does not match (HKDF info binding)', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.from('11'.repeat(32), 'hex');

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'session-A',
    });

    expect(() =>
      unwrapParamBundle({
        ...wrapped,
        chipPriv: chip.priv,
        sessionId: 'session-B', // different sessionId → different HKDF output
      }),
    ).toThrow();
  });

  it('fails unwrap when ciphertext is tampered (HMAC tag mismatch)', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.from('22'.repeat(32), 'hex');

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'session-X',
    });

    // Flip one byte in the middle of the ciphertext.
    const tamperedCiphertext = Buffer.from(wrapped.ciphertext);
    tamperedCiphertext[tamperedCiphertext.length >> 1] ^= 0x01;

    expect(() =>
      unwrapParamBundle({
        ...wrapped,
        ciphertext: tamperedCiphertext,
        chipPriv: chip.priv,
        sessionId: 'session-X',
      }),
    ).toThrow(/HMAC tag verification failed/);
  });

  it('fails unwrap when tag itself is tampered', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.from('33'.repeat(32), 'hex');

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'session-Y',
    });

    const tamperedTag = Buffer.from(wrapped.tag);
    tamperedTag[0] ^= 0x01;

    expect(() =>
      unwrapParamBundle({
        ...wrapped,
        tag: tamperedTag,
        chipPriv: chip.priv,
        sessionId: 'session-Y',
      }),
    ).toThrow(/HMAC tag verification failed/);
  });

  it('fails unwrap when chipPriv is wrong (ECDH shared differs)', () => {
    const chipA = generateTestKeypair();
    const chipB = generateTestKeypair();
    const plaintext = Buffer.from('44'.repeat(32), 'hex');

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chipA.pubUncompressed,
      plaintext,
      sessionId: 'session-K',
    });

    expect(() =>
      unwrapParamBundle({
        ...wrapped,
        chipPriv: chipB.priv, // wrong chip's privkey
        sessionId: 'session-K',
      }),
    ).toThrow();
  });

  it('fresh wrap produces different ciphertext each call (forward secrecy via ephemeral)', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.from('55'.repeat(32), 'hex');

    const w1 = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'same-session',
    });
    const w2 = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'same-session',
    });

    expect(w1.serverEphemeralPub.equals(w2.serverEphemeralPub)).toBe(false);
    expect(w1.ciphertext.equals(w2.ciphertext)).toBe(false);

    const p1 = unwrapParamBundle({ ...w1, chipPriv: chip.priv, sessionId: 'same-session' });
    const p2 = unwrapParamBundle({ ...w2, chipPriv: chip.priv, sessionId: 'same-session' });
    expect(p1.equals(plaintext)).toBe(true);
    expect(p2.equals(plaintext)).toBe(true);
  });

  it('handles plaintext not aligned to block boundary (PKCS#7 pad adds up to 16 B)', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.from('ABCDE', 'hex'); // 2.5 bytes, weird but valid

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'pad-test',
    });
    // After PKCS#7 padding, CT length = 16 (one full block).
    expect(wrapped.ciphertext.length).toBe(16);

    const unwrapped = unwrapParamBundle({
      ...wrapped,
      chipPriv: chip.priv,
      sessionId: 'pad-test',
    });
    expect(unwrapped.equals(plaintext)).toBe(true);
  });
});

describe('wrapParamBundleDeterministic — reproducible test vectors', () => {
  it('same inputs produce same wire bytes', () => {
    const chip = generateTestKeypair();
    const serverEphemeralPriv = Buffer.from('aa'.repeat(32), 'hex');
    const plaintext = Buffer.from('DEADBEEF', 'hex');

    const w1 = wrapParamBundleDeterministic({
      chipPubUncompressed: chip.pubUncompressed,
      serverEphemeralPriv,
      plaintext,
      sessionId: 'fixed-session',
    });
    const w2 = wrapParamBundleDeterministic({
      chipPubUncompressed: chip.pubUncompressed,
      serverEphemeralPriv,
      plaintext,
      sessionId: 'fixed-session',
    });

    expect(w1.serverEphemeralPub.equals(w2.serverEphemeralPub)).toBe(true);
    expect(w1.iv.equals(w2.iv)).toBe(true);
    expect(w1.ciphertext.equals(w2.ciphertext)).toBe(true);
    expect(w1.tag.equals(w2.tag)).toBe(true);
  });

  it('deterministic-wrapped bundle still unwraps correctly', () => {
    const chip = generateTestKeypair();
    const serverEphemeralPriv = Buffer.from('bb'.repeat(32), 'hex');
    const plaintext = Buffer.from('1234567890ABCDEF', 'hex');

    const wrapped = wrapParamBundleDeterministic({
      chipPubUncompressed: chip.pubUncompressed,
      serverEphemeralPriv,
      plaintext,
      sessionId: 'det-session',
    });

    const unwrapped = unwrapParamBundle({
      ...wrapped,
      chipPriv: chip.priv,
      sessionId: 'det-session',
    });

    expect(unwrapped.equals(plaintext)).toBe(true);
  });
});

describe('wire format serialization', () => {
  it('serialize / parse round-trip', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.alloc(64, 0x55);

    const wrapped = wrapParamBundle({
      chipPubUncompressed: chip.pubUncompressed,
      plaintext,
      sessionId: 'serde-test',
    });

    const wire = serializeWrappedBundle(wrapped);

    // Expected length: 65 (pubkey) + 16 (iv) + 64 (ct, exact block
    // alignment — still gets full-block PKCS#7 pad, so 80) + 16 (tag)
    // = 65 + 16 + 80 + 16 = 177
    expect(wire.length).toBe(177);

    const parsed = parseWireBundle(wire);

    expect(parsed.serverEphemeralPub.equals(wrapped.serverEphemeralPub)).toBe(true);
    expect(parsed.iv.equals(wrapped.iv)).toBe(true);
    expect(parsed.ciphertext.equals(wrapped.ciphertext)).toBe(true);
    expect(parsed.tag.equals(wrapped.tag)).toBe(true);
  });

  it('parseWireBundle rejects wire blobs shorter than header+tag', () => {
    // 65 + 16 + 16 = 97 minimum (zero-length ciphertext) — but zero CT
    // also isn't allowed, so any blob under 97+16 is rejected.
    expect(() => parseWireBundle(Buffer.alloc(96))).toThrow(/too short/);
  });

  it('parseWireBundle rejects ciphertext length not aligned to 16', () => {
    // 65 + 16 + 17 + 16 = 114 bytes, CT length 17 (not % 16)
    const badWire = Buffer.alloc(114);
    badWire[0] = 0x04; // start with SEC1 marker (not that it matters for length check)
    expect(() => parseWireBundle(badWire)).toThrow(/multiple of/);
  });
});
