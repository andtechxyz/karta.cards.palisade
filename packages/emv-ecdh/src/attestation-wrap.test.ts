import { describe, it, expect } from 'vitest';
import { createECDH } from 'node:crypto';

import {
  wrapAttestationBundle,
  unwrapParamBundle,
  parseWireBundle,
  ATTEST_TLV_TAG_PRIV,
  ATTEST_TLV_TAG_CERT,
  ATTEST_TLV_TAG_CPLC,
} from './index.js';

/**
 * Generate a bootstrap keypair that mimics what the applet would
 * emit from GET_ATTESTATION_BOOTSTRAP_PUBKEY.  Returns both halves
 * so tests can round-trip wrap → unwrap and verify byte parity
 * with the unwrapped inner plaintext.
 */
function bootstrapKeypair(): { pub: Buffer; priv: Buffer } {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  // createECDH's Buffer-returning overloads — need explicit casts for
  // TS's strict mode (the runtime shape is always Buffer when no
  // encoding is passed).
  return {
    pub: ecdh.getPublicKey() as unknown as Buffer,
    priv: ecdh.getPrivateKey() as unknown as Buffer,
  };
}

describe('wrapAttestationBundle', () => {
  it('round-trips priv + cardCert + cplc through the ECDH envelope', () => {
    const { pub, priv } = bootstrapKeypair();
    const scalar = Buffer.alloc(32, 0xAB);
    const cardCert = Buffer.concat([
      Buffer.alloc(65, 0x04),  // fake SEC1 pubkey
      Buffer.alloc(42, 0xCD),  // fake CPLC
      Buffer.from('3045022100' + '11'.repeat(32) + '022000' + '22'.repeat(31), 'hex'),
    ]);
    const cplc = Buffer.alloc(42, 0xCD);

    const wire = wrapAttestationBundle({
      bootstrapPubUncompressed: pub,
      sessionId: 'session_test_wrap_1',
      cardAttestPrivRaw: scalar,
      cardCert,
      cplc,
    });

    // Sanity: serialized wire has the ECDH envelope shape.
    const wrapped = parseWireBundle(wire);
    expect(wrapped.serverEphemeralPub.length).toBe(65);
    expect(wrapped.serverEphemeralPub[0]).toBe(0x04);
    expect(wrapped.iv.length).toBe(16);
    expect(wrapped.tag.length).toBe(16);
    expect(wrapped.ciphertext.length).toBeGreaterThan(0);

    // Unwrap with the bootstrap priv (what the applet does on-chip).
    const inner = unwrapParamBundle({
      serverEphemeralPub: wrapped.serverEphemeralPub,
      iv: wrapped.iv,
      ciphertext: wrapped.ciphertext,
      tag: wrapped.tag,
      chipPriv: priv,
      sessionId: 'session_test_wrap_1',
    });

    // Inner is a TLV of three entries: 0x01 priv, 0x02 cert, 0x03 cplc.
    // Parse inline — no helper needed for 3 entries.
    expect(inner[0]).toBe(ATTEST_TLV_TAG_PRIV);
    const privLen = inner[1];
    expect(privLen).toBe(32);
    const parsedPriv = inner.subarray(2, 2 + privLen);
    expect(parsedPriv.equals(scalar)).toBe(true);

    const certTagOff = 2 + privLen;
    expect(inner[certTagOff]).toBe(ATTEST_TLV_TAG_CERT);
    const certLen = inner[certTagOff + 1];
    expect(certLen).toBe(cardCert.length);
    const parsedCert = inner.subarray(certTagOff + 2, certTagOff + 2 + certLen);
    expect(parsedCert.equals(cardCert)).toBe(true);

    const cplcTagOff = certTagOff + 2 + certLen;
    expect(inner[cplcTagOff]).toBe(ATTEST_TLV_TAG_CPLC);
    const cplcLen = inner[cplcTagOff + 1];
    expect(cplcLen).toBe(42);
    const parsedCplc = inner.subarray(cplcTagOff + 2, cplcTagOff + 2 + cplcLen);
    expect(parsedCplc.equals(cplc)).toBe(true);
  });

  it('rejects a tampered ciphertext (HMAC tag mismatch)', () => {
    const { pub, priv } = bootstrapKeypair();
    const wire = wrapAttestationBundle({
      bootstrapPubUncompressed: pub,
      sessionId: 'session_tamper',
      cardAttestPrivRaw: Buffer.alloc(32, 0xEE),
      cardCert: Buffer.alloc(170, 0x99),
      cplc: Buffer.alloc(42, 0xFE),
    });
    const wrapped = parseWireBundle(wire);
    // Flip a bit inside the ciphertext — HMAC should catch it.
    const tampered = Buffer.from(wrapped.ciphertext);
    tampered[0] ^= 0x01;

    expect(() =>
      unwrapParamBundle({
        serverEphemeralPub: wrapped.serverEphemeralPub,
        iv: wrapped.iv,
        ciphertext: tampered,
        tag: wrapped.tag,
        chipPriv: priv,
        sessionId: 'session_tamper',
      }),
    ).toThrowError(/hmac|tag/i);
  });

  it('rejects invalid bootstrap pubkey shape', () => {
    const cardCert = Buffer.alloc(170, 0x01);
    const cplc = Buffer.alloc(42, 0xCC);
    const scalar = Buffer.alloc(32, 0xAA);

    // Wrong length
    expect(() =>
      wrapAttestationBundle({
        bootstrapPubUncompressed: Buffer.alloc(32, 0x04),
        sessionId: 's1',
        cardAttestPrivRaw: scalar,
        cardCert,
        cplc,
      }),
    ).toThrowError(/bootstrapPubUncompressed must be 65 bytes/);

    // Right length, wrong marker byte
    const bad = Buffer.alloc(65, 0x02);
    expect(() =>
      wrapAttestationBundle({
        bootstrapPubUncompressed: bad,
        sessionId: 's1',
        cardAttestPrivRaw: scalar,
        cardCert,
        cplc,
      }),
    ).toThrowError(/0x04/);
  });

  it('rejects wrong-sized priv scalar or cplc', () => {
    const { pub } = bootstrapKeypair();
    const cardCert = Buffer.alloc(170, 0x01);
    const cplc = Buffer.alloc(42, 0xCC);

    expect(() =>
      wrapAttestationBundle({
        bootstrapPubUncompressed: pub,
        sessionId: 's1',
        cardAttestPrivRaw: Buffer.alloc(31, 0xAA), // too short
        cardCert,
        cplc,
      }),
    ).toThrowError(/cardAttestPrivRaw must be 32 bytes/);

    expect(() =>
      wrapAttestationBundle({
        bootstrapPubUncompressed: pub,
        sessionId: 's1',
        cardAttestPrivRaw: Buffer.alloc(32, 0xAA),
        cardCert,
        cplc: Buffer.alloc(41, 0xCC), // too short
      }),
    ).toThrowError(/cplc must be 42 bytes/);
  });
});
