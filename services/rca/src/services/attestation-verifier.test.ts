import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import {
  AttestationVerifier,
  STUB_MODE_WARNING,
  ICC_PUBKEY_LEN,
  CPLC_LEN,
  verifyAttestationSignature,
  type AttestationExtractResult,
} from './attestation-verifier.js';

/** Build an extract result for the verifier unit tests. */
function mkExtract(
  attestation: Buffer,
  certChain: Buffer = Buffer.alloc(0),
): AttestationExtractResult {
  return {
    iccPubkey: Buffer.alloc(ICC_PUBKEY_LEN, 0x04),
    attestation,
    cplc: Buffer.alloc(CPLC_LEN, 0xcc),
    certChain,
  };
}

describe('AttestationVerifier.extract', () => {
  it('splits a well-formed response into pubkey(65) + attestation(var) + cplc(42)', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const sig = Buffer.from('3045022100' + 'AA'.repeat(32) + '022000' + 'BB'.repeat(30), 'hex');
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const full = Buffer.concat([pub, sig, cplc]);

    const { iccPubkey, attestation, cplc: cplcOut, certChain } = AttestationVerifier.extract(full);

    expect(iccPubkey.length).toBe(ICC_PUBKEY_LEN);
    expect(iccPubkey.equals(pub)).toBe(true);
    expect(attestation.length).toBe(sig.length);
    expect(attestation.equals(sig)).toBe(true);
    expect(cplcOut.length).toBe(CPLC_LEN);
    expect(cplcOut.equals(cplc)).toBe(true);
    // No cert chain in legacy layout.
    expect(certChain.length).toBe(0);
  });

  it('handles the typical 72-byte attestation signature length', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const sig = Buffer.alloc(72, 0x30);
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const full = Buffer.concat([pub, sig, cplc]);

    const { attestation } = AttestationVerifier.extract(full);
    expect(attestation.length).toBe(72);
  });

  it('returns empty attestation when the response is exactly pubkey + cplc', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const full = Buffer.concat([pub, cplc]);

    const { iccPubkey, attestation, cplc: cplcOut } = AttestationVerifier.extract(full);
    expect(iccPubkey.length).toBe(ICC_PUBKEY_LEN);
    expect(attestation.length).toBe(0);
    expect(cplcOut.length).toBe(CPLC_LEN);
  });

  it('tolerates a truncated buffer: short response → partial pubkey, empty trailers', () => {
    const truncated = Buffer.alloc(40, 0xEE);
    const { iccPubkey, attestation, cplc } = AttestationVerifier.extract(truncated);
    expect(iccPubkey.length).toBe(40);
    expect(attestation.length).toBe(0);
    expect(cplc.length).toBe(0);
  });

  it('tolerates a buffer that has pubkey + a short attestation but no full CPLC', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const partial = Buffer.alloc(20, 0xAA);
    const full = Buffer.concat([pub, partial]);

    const { iccPubkey, attestation, cplc } = AttestationVerifier.extract(full);
    expect(iccPubkey.length).toBe(ICC_PUBKEY_LEN);
    expect(attestation.length).toBe(20);
    expect(cplc.length).toBe(0);
  });

  it('splits pubkey(65) + sig(var) + cplc(42) + chainLen(2) + chain(var)', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const sig = Buffer.from('3045022100' + 'AA'.repeat(32) + '022000' + 'BB'.repeat(30), 'hex');
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const chain = Buffer.from('3082010A' + '00'.repeat(262), 'hex'); // a 266-byte "cert"-shaped buffer
    const chainLen = Buffer.alloc(2);
    chainLen.writeUInt16BE(chain.length);
    const full = Buffer.concat([pub, sig, cplc, chainLen, chain]);

    const out = AttestationVerifier.extract(full);
    expect(out.iccPubkey.equals(pub)).toBe(true);
    expect(out.attestation.equals(sig)).toBe(true);
    expect(out.cplc.equals(cplc)).toBe(true);
    expect(out.certChain.equals(chain)).toBe(true);
  });
});

describe('AttestationVerifier.verify (permissive mode)', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    logSpy.mockRestore();
  });

  it('defaults to permissive mode — always returns ok=true with a warning', () => {
    expect(AttestationVerifier.verify(mkExtract(Buffer.alloc(72, 0xAA)))).toMatchObject({
      ok: true,
    });
    expect(AttestationVerifier.verify(mkExtract(Buffer.alloc(0)))).toMatchObject({
      ok: true,
    });
    expect(AttestationVerifier.verify(mkExtract(Buffer.from('DEADBEEF', 'hex')))).toMatchObject({
      ok: true,
    });
  });

  it('emits the STUB_MODE_WARNING banner on every permissive-mode call', () => {
    AttestationVerifier.verify(mkExtract(Buffer.alloc(0)));
    AttestationVerifier.verify(mkExtract(Buffer.alloc(10)));
    AttestationVerifier.verify(mkExtract(Buffer.alloc(72)));

    expect(warnSpy).toHaveBeenCalledTimes(3);
    for (const call of warnSpy.mock.calls) {
      expect(call[0]).toBe(STUB_MODE_WARNING);
    }
  });

  it('logs a 16-byte sample of the attestation bytes so logs stay small', () => {
    const sig = Buffer.from('30450221' + '00'.repeat(60), 'hex');
    AttestationVerifier.verify(mkExtract(sig));

    expect(logSpy).toHaveBeenCalledTimes(1);
    const logged = logSpy.mock.calls[0][0] as string;
    expect(logged).toContain(`attLen=${sig.length}`);
    const prefix = sig.subarray(0, 16).toString('hex').toUpperCase();
    expect(logged).toContain(`first16=${prefix}`);
  });
});

describe('AttestationVerifier.verify (strict mode)', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    vi.restoreAllMocks();
  });

  it('rejects empty cert chain in strict mode', () => {
    const r = AttestationVerifier.verify(mkExtract(Buffer.alloc(72)), 'strict');
    expect(r.ok).toBe(false);
    expect(r.warning).toContain('non-empty attestation cert chain');
  });

  it('rejects malformed attestation (empty sig or bad CPLC length)', () => {
    const r1 = AttestationVerifier.verify(
      {
        iccPubkey: Buffer.alloc(ICC_PUBKEY_LEN, 0x04),
        attestation: Buffer.alloc(0),
        cplc: Buffer.alloc(CPLC_LEN, 0xcc),
        certChain: Buffer.from('aabb', 'hex'),
      },
      'strict',
    );
    expect(r1.ok).toBe(false);

    const r2 = AttestationVerifier.verify(
      {
        iccPubkey: Buffer.alloc(ICC_PUBKEY_LEN, 0x04),
        attestation: Buffer.alloc(72, 0x30),
        cplc: Buffer.alloc(10, 0xcc),
        certChain: Buffer.from('aabb', 'hex'),
      },
      'strict',
    );
    expect(r2.ok).toBe(false);
  });

  it('rejects when cert chain bytes do not parse as DER certs', () => {
    const r = AttestationVerifier.verify(
      mkExtract(Buffer.alloc(72, 0x30), Buffer.from('deadbeef', 'hex')),
      'strict',
    );
    expect(r.ok).toBe(false);
    expect(r.warning).toMatch(/could not parse/);
  });
});

// ---------------------------------------------------------------------------
// verifyAttestationSignature — signature-verify unit tests
// ---------------------------------------------------------------------------
//
// The full strict-mode verify() path also walks a cert chain to a pinned
// vendor root.  Synthesising an X.509 chain in tests requires a library
// (node-forge / @peculiar/x509) we don't take as a dep for this alone,
// so the chain-walk path is exercised only via the negative-path tests
// above ("malformed DER", "empty chain").  The SIGNATURE VERIFY portion
// — the actual ECDSA over (iccPubkey || cplc) — is what distinguishes
// a genuine chip attestation from a replay, so we cover it in isolation
// here with an in-memory P-256 keypair playing the role of the leaf.

describe('verifyAttestationSignature', () => {
  it('accepts a real ECDSA-SHA256 signature over (iccPubkey || cplc)', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const signer = createSign('SHA256');
    signer.update(Buffer.concat([iccPubkey, cplc]));
    const sig = signer.sign(privateKey);

    expect(verifyAttestationSignature(iccPubkey, cplc, sig, publicKey)).toBe(true);
  });

  it('rejects a signature over the wrong message', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const signer = createSign('SHA256');
    signer.update(Buffer.from('OTHER MESSAGE'));
    const sig = signer.sign(privateKey);

    expect(verifyAttestationSignature(iccPubkey, cplc, sig, publicKey)).toBe(false);
  });

  it('rejects a signature from the wrong key', () => {
    const kpSigner = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const kpVerifier = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const signer = createSign('SHA256');
    signer.update(Buffer.concat([iccPubkey, cplc]));
    const sig = signer.sign(kpSigner.privateKey);

    // Signed with kpSigner but verifying against kpVerifier — must fail.
    expect(verifyAttestationSignature(iccPubkey, cplc, sig, kpVerifier.publicKey)).toBe(false);
  });

  it('rejects a bit-flipped signature', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const signer = createSign('SHA256');
    signer.update(Buffer.concat([iccPubkey, cplc]));
    const sig = Buffer.from(signer.sign(privateKey));
    // Flip a byte deep in the signature payload.
    sig[Math.floor(sig.length / 2)] ^= 0x01;

    expect(verifyAttestationSignature(iccPubkey, cplc, sig, publicKey)).toBe(false);
  });

  it('returns false (not throws) on structurally-invalid DER signature', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    // 72 bytes of 0x00 — not a valid DER ECDSA signature.
    const bogusSig = Buffer.alloc(72, 0x00);

    expect(() =>
      verifyAttestationSignature(iccPubkey, cplc, bogusSig, publicKey),
    ).not.toThrow();
    expect(verifyAttestationSignature(iccPubkey, cplc, bogusSig, publicKey)).toBe(false);
  });
});
