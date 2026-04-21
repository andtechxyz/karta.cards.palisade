/**
 * Tests for the post-Option-A attestation verifier.  No X.509 — compact
 * binary certs only.  Fixtures are built from real P-256 keypairs so
 * every ECDSA path is exercised against node:crypto, not mocked.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createPrivateKey,
  createSign,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';
import {
  AttestationVerifier,
  STUB_MODE_WARNING,
  ICC_PUBKEY_LEN,
  SEC1_UNCOMPRESSED_LEN,
  CPLC_LEN,
  ISSUER_ID_LEN,
  assertAttestationConfigForMode,
  verifyAttestationSignature,
  type AttestationExtractResult,
  type AttestationVerifierConfig,
} from './attestation-verifier.js';

// ---------------------------------------------------------------------------
// Fixture helpers — build real compact certs from real P-256 keys so the
// strict-mode verify path exercises the full Root → Issuer → Card → attest
// chain end-to-end.
// ---------------------------------------------------------------------------

interface Keypair {
  priv: KeyObject;
  pub: KeyObject;
  /** 65-byte SEC1 uncompressed: 0x04 || X || Y. */
  pubRaw: Buffer;
}

function newKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  // SPKI tail = raw 65-byte SEC1 point.
  const pubRaw = spki.subarray(spki.length - SEC1_UNCOMPRESSED_LEN);
  return { priv: privateKey, pub: publicKey, pubRaw };
}

function signDer(priv: KeyObject, msg: Buffer): Buffer {
  const s = createSign('SHA256');
  s.update(msg);
  return s.sign(priv);
}

function buildIssuerCertBlob(root: Keypair, issuer: Keypair, issuerId: number): Buffer {
  const idBuf = Buffer.alloc(ISSUER_ID_LEN);
  idBuf.writeUInt32BE(issuerId);
  const body = Buffer.concat([issuer.pubRaw, idBuf]);
  const sig = signDer(root.priv, body);
  return Buffer.concat([body, sig]);
}

function buildCardCertBlob(issuer: Keypair, card: Keypair, cplc: Buffer): Buffer {
  if (cplc.length !== CPLC_LEN) throw new Error(`cplc must be ${CPLC_LEN} bytes`);
  const body = Buffer.concat([card.pubRaw, cplc]);
  const sig = signDer(issuer.priv, body);
  return Buffer.concat([body, sig]);
}

function buildKeygenResponse(
  icc: Keypair,
  card: Keypair,
  cplc: Buffer,
  cardCert: Buffer,
): Buffer {
  // attestSig is signed by the per-card attestation key (card.priv) over
  // (iccPubkey || cplc) — i.e. the card attests this session's ephemeral pubkey.
  const attestSig = signDer(card.priv, Buffer.concat([icc.pubRaw, cplc]));
  return Buffer.concat([icc.pubRaw, attestSig, cardCert]);
}

/** Build a complete config + response pair.  Every test that needs the full
 *  chain starts here so fixture drift stays confined to one place. */
function buildChainFixture() {
  const root = newKeypair();
  const issuer = newKeypair();
  const card = newKeypair();
  const icc = newKeypair();
  const cplc = Buffer.alloc(CPLC_LEN, 0xAB);
  const issuerCert = buildIssuerCertBlob(root, issuer, /*issuerId=*/ 42);
  const cardCert = buildCardCertBlob(issuer, card, cplc);
  const keygenResponse = buildKeygenResponse(icc, card, cplc, cardCert);
  const config: AttestationVerifierConfig = {
    rootPubkey: root.pubRaw,
    issuerCert,
  };
  return { root, issuer, card, icc, cplc, config, keygenResponse };
}

/** Build a minimal AttestationExtractResult for permissive-mode tests. */
function mkExtract(attestSig: Buffer, cardCert: Buffer = Buffer.alloc(0)): AttestationExtractResult {
  return {
    iccPubkey: Buffer.alloc(ICC_PUBKEY_LEN, 0x04),
    attestSig,
    attestation: attestSig,
    cardCert,
    certChain: cardCert,
    cplc: Buffer.alloc(CPLC_LEN, 0xcc),
  };
}

// ---------------------------------------------------------------------------

describe('AttestationVerifier.extract', () => {
  it('splits a well-formed response into iccPubkey / attestSig / cardCert', () => {
    const { keygenResponse, icc, card, cplc } = buildChainFixture();

    const out = AttestationVerifier.extract(keygenResponse);

    expect(out.iccPubkey.equals(icc.pubRaw)).toBe(true);
    // attestSig is DER ECDSA — 68..72 bytes for P-256
    expect(out.attestSig.length).toBeGreaterThanOrEqual(68);
    expect(out.attestSig.length).toBeLessThanOrEqual(72);
    expect(out.attestSig[0]).toBe(0x30);
    // cardCert = card_pubkey(65) || cplc(42) || sig(DER)
    expect(out.cardCert.length).toBeGreaterThanOrEqual(65 + 42 + 68);
    expect(out.cardCert.subarray(0, 65).equals(card.pubRaw)).toBe(true);
    expect(out.cardCert.subarray(65, 107).equals(cplc)).toBe(true);
    // Convenience CPLC peeled out of the card cert body
    expect(out.cplc.equals(cplc)).toBe(true);
    // Back-compat aliases
    expect(out.attestation).toBe(out.attestSig);
    expect(out.certChain).toBe(out.cardCert);
  });

  it('returns empty fields for an empty response', () => {
    const out = AttestationVerifier.extract(Buffer.alloc(0));
    expect(out.iccPubkey.length).toBe(0);
    expect(out.attestSig.length).toBe(0);
    expect(out.cardCert.length).toBe(0);
    expect(out.cplc.length).toBe(0);
  });

  it('tolerates a truncated buffer: partial pubkey, empty trailers', () => {
    const truncated = Buffer.alloc(40, 0xEE);
    const out = AttestationVerifier.extract(truncated);
    expect(out.iccPubkey.length).toBe(40);
    expect(out.attestSig.length).toBe(0);
    expect(out.cardCert.length).toBe(0);
  });

  it('gives back a cardCert of raw bytes when attestSig DER is malformed', () => {
    // pubkey + non-DER trailer — attestSig parse fails, trailer lands as cardCert
    const pub = Buffer.alloc(SEC1_UNCOMPRESSED_LEN, 0x04);
    const trailer = Buffer.from('DEADBEEF', 'hex');
    const out = AttestationVerifier.extract(Buffer.concat([pub, trailer]));
    expect(out.attestSig.length).toBe(0);
    expect(out.cardCert.equals(trailer)).toBe(true);
  });
});

// ---------------------------------------------------------------------------

describe('AttestationVerifier.verify — permissive mode', () => {
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

  it('defaults to permissive and always returns ok=true', () => {
    expect(AttestationVerifier.verify(mkExtract(Buffer.alloc(72, 0xAA)))).toMatchObject({ ok: true });
    expect(AttestationVerifier.verify(mkExtract(Buffer.alloc(0)))).toMatchObject({ ok: true });
  });

  it('emits STUB_MODE_WARNING on every permissive call', () => {
    AttestationVerifier.verify(mkExtract(Buffer.alloc(0)));
    AttestationVerifier.verify(mkExtract(Buffer.alloc(72)));
    expect(warnSpy).toHaveBeenCalledTimes(2);
    for (const call of warnSpy.mock.calls) {
      expect(call[0]).toBe(STUB_MODE_WARNING);
    }
  });

  it('logs a 16-byte sample so CloudWatch logs stay small', () => {
    const sig = Buffer.from('30450221' + '00'.repeat(60), 'hex');
    AttestationVerifier.verify(mkExtract(sig));
    const logged = logSpy.mock.calls[0][0] as string;
    expect(logged).toContain(`sigLen=${sig.length}`);
    expect(logged).toContain(sig.subarray(0, 16).toString('hex').toUpperCase());
  });
});

// ---------------------------------------------------------------------------

describe('AttestationVerifier.verify — strict mode', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    vi.restoreAllMocks();
  });

  it('accepts a well-formed end-to-end chain (Root → Issuer → Card → attest)', () => {
    const { keygenResponse, config } = buildChainFixture();
    const extracted = AttestationVerifier.extract(keygenResponse);
    const r = AttestationVerifier.verify(extracted, 'strict', config);
    expect(r.ok).toBe(true);
    expect(r.issuerId).toBe(42);
  });

  it('requires a config in strict mode', () => {
    const { keygenResponse } = buildChainFixture();
    const extracted = AttestationVerifier.extract(keygenResponse);
    const r = AttestationVerifier.verify(extracted, 'strict'); // no config
    expect(r.ok).toBe(false);
    expect(r.warning).toMatch(/requires AttestationVerifierConfig/);
  });

  it('rejects when root pubkey is malformed (not 65 bytes SEC1)', () => {
    const { keygenResponse, config } = buildChainFixture();
    const extracted = AttestationVerifier.extract(keygenResponse);
    const bad: AttestationVerifierConfig = {
      ...config,
      rootPubkey: Buffer.alloc(64, 0x04), // wrong length
    };
    const r = AttestationVerifier.verify(extracted, 'strict', bad);
    expect(r.ok).toBe(false);
    expect(r.warning).toMatch(/rootPubkey malformed/);
  });

  it('rejects a forged issuer cert (signed by the wrong root)', () => {
    const { keygenResponse } = buildChainFixture();
    const attackerRoot = newKeypair();
    const issuer = newKeypair();
    const forgedIssuer = buildIssuerCertBlob(attackerRoot, issuer, 1);
    // Feed the real pinned root but an attacker-signed issuer cert
    const config: AttestationVerifierConfig = {
      rootPubkey: newKeypair().pubRaw, // the pinned root is a different root still
      issuerCert: forgedIssuer,
    };
    const extracted = AttestationVerifier.extract(keygenResponse);
    const r = AttestationVerifier.verify(extracted, 'strict', config);
    expect(r.ok).toBe(false);
    expect(r.warning).toMatch(/issuer cert signature does not verify/);
  });

  it('rejects a card cert signed by an attacker posing as the issuer', () => {
    const { root, icc, cplc, config } = buildChainFixture();
    const attackerIssuer = newKeypair();
    const card = newKeypair();
    const rogueCardCert = buildCardCertBlob(attackerIssuer, card, cplc);
    const response = buildKeygenResponse(icc, card, cplc, rogueCardCert);

    // config still pins the real root + real issuer cert
    void root;
    const extracted = AttestationVerifier.extract(response);
    const r = AttestationVerifier.verify(extracted, 'strict', config);
    expect(r.ok).toBe(false);
    expect(r.warning).toMatch(/card cert signature does not verify/);
    expect(r.issuerId).toBe(42); // issuer parse succeeded before card cert failed
  });

  it('rejects an attestSig that was signed over a different iccPubkey', () => {
    // Build a full chain then swap iccPubkey bytes at the head of the
    // response — attestSig now covers bytes that no longer match.
    const { keygenResponse, config } = buildChainFixture();
    const tampered = Buffer.from(keygenResponse);
    tampered[0] = 0x04; // keep SEC1 prefix
    tampered[1] ^= 0xFF; // flip one X coord byte
    const extracted = AttestationVerifier.extract(tampered);
    const r = AttestationVerifier.verify(extracted, 'strict', config);
    expect(r.ok).toBe(false);
    expect(r.warning).toMatch(/attestation signature does not verify/);
  });

  it('rejects a bit-flipped attestSig', () => {
    const { keygenResponse, config } = buildChainFixture();
    const tampered = Buffer.from(keygenResponse);
    // Flip a byte in the middle of the attestSig (starts at offset 65, ~70 bytes long)
    tampered[65 + 20] ^= 0x01;
    const extracted = AttestationVerifier.extract(tampered);
    const r = AttestationVerifier.verify(extracted, 'strict', config);
    expect(r.ok).toBe(false);
  });

  it('rejects a truncated issuer cert', () => {
    const { keygenResponse, config } = buildChainFixture();
    const truncated: AttestationVerifierConfig = {
      ...config,
      issuerCert: config.issuerCert.subarray(0, 60), // chop mid-payload
    };
    const extracted = AttestationVerifier.extract(keygenResponse);
    const r = AttestationVerifier.verify(extracted, 'strict', truncated);
    expect(r.ok).toBe(false);
    expect(r.warning).toMatch(/malformed issuerCert/);
  });
});

// ---------------------------------------------------------------------------

describe('assertAttestationConfigForMode', () => {
  it('does nothing in permissive mode regardless of config', () => {
    expect(() =>
      assertAttestationConfigForMode('permissive', {
        KARTA_ATTESTATION_ROOT_PUBKEY: undefined,
        KARTA_ATTESTATION_ISSUER_CERT: undefined,
      }),
    ).not.toThrow();
  });

  it('throws when strict mode is set with no root pubkey', () => {
    expect(() =>
      assertAttestationConfigForMode('strict', {
        KARTA_ATTESTATION_ROOT_PUBKEY: '',
        KARTA_ATTESTATION_ISSUER_CERT: 'aa'.repeat(140),
      }),
    ).toThrow(/KARTA_ATTESTATION_ROOT_PUBKEY/);
  });

  it('throws when root pubkey is wrong length', () => {
    expect(() =>
      assertAttestationConfigForMode('strict', {
        KARTA_ATTESTATION_ROOT_PUBKEY: 'aa'.repeat(32), // 64 hex = 32 bytes, not 65
        KARTA_ATTESTATION_ISSUER_CERT: 'aa'.repeat(140),
      }),
    ).toThrow(/65-byte SEC1/);
  });

  it('throws when root pubkey lacks the 0x04 SEC1 prefix', () => {
    expect(() =>
      assertAttestationConfigForMode('strict', {
        KARTA_ATTESTATION_ROOT_PUBKEY: '02' + 'aa'.repeat(64),
        KARTA_ATTESTATION_ISSUER_CERT: 'aa'.repeat(140),
      }),
    ).toThrow(/leading byte 0x04/);
  });

  it('throws on all-zero root pubkey (placeholder sentinel)', () => {
    expect(() =>
      assertAttestationConfigForMode('strict', {
        KARTA_ATTESTATION_ROOT_PUBKEY: '00'.repeat(65),
        KARTA_ATTESTATION_ISSUER_CERT: 'aa'.repeat(140),
      }),
    ).toThrow(/all zeros/);
  });

  it('throws on truncated issuer cert blob', () => {
    expect(() =>
      assertAttestationConfigForMode('strict', {
        KARTA_ATTESTATION_ROOT_PUBKEY: '04' + 'aa'.repeat(64),
        KARTA_ATTESTATION_ISSUER_CERT: 'aa'.repeat(50), // way too short
      }),
    ).toThrow(/truncated/);
  });

  it('passes with shape-correct config', () => {
    expect(() =>
      assertAttestationConfigForMode('strict', {
        KARTA_ATTESTATION_ROOT_PUBKEY: '04' + 'aa'.repeat(64),
        KARTA_ATTESTATION_ISSUER_CERT: 'aa'.repeat(140),
      }),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// verifyAttestationSignature — the leaf-level ECDSA helper, exercised
// independently so a regression in this single helper is easy to locate.

describe('verifyAttestationSignature', () => {
  // Prevent unused import lint hit when fixture helpers don't reference it.
  void createPrivateKey;

  it('accepts a real ECDSA-SHA256 over (iccPubkey || cplc)', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const sig = signDer(privateKey, Buffer.concat([iccPubkey, cplc]));
    expect(verifyAttestationSignature(iccPubkey, cplc, sig, publicKey)).toBe(true);
  });

  it('rejects a signature over the wrong message', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const sig = signDer(privateKey, Buffer.from('SOME OTHER BYTES'));
    expect(verifyAttestationSignature(iccPubkey, cplc, sig, publicKey)).toBe(false);
  });

  it('rejects a signature from the wrong key', () => {
    const signerKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const verifierKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const sig = signDer(signerKp.privateKey, Buffer.concat([iccPubkey, cplc]));
    expect(verifyAttestationSignature(iccPubkey, cplc, sig, verifierKp.publicKey)).toBe(false);
  });

  it('rejects a bit-flipped signature', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const sig = Buffer.from(signDer(privateKey, Buffer.concat([iccPubkey, cplc])));
    sig[Math.floor(sig.length / 2)] ^= 0x01;
    expect(verifyAttestationSignature(iccPubkey, cplc, sig, publicKey)).toBe(false);
  });

  it('returns false on structurally-invalid DER (does not throw)', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const iccPubkey = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const bogus = Buffer.alloc(72, 0x00);
    expect(() => verifyAttestationSignature(iccPubkey, cplc, bogus, publicKey)).not.toThrow();
    expect(verifyAttestationSignature(iccPubkey, cplc, bogus, publicKey)).toBe(false);
  });
});
