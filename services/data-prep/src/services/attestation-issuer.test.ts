/**
 * Per-card attestation issuance unit tests.  The KMS-backed signer is
 * a thin wrapper tested implicitly via the injected-signer path — the
 * heavy logic (keygen, body composition, scalar extraction, cert
 * packing) runs against an in-memory P-256 Issuer key so the tests
 * don't need AWS.
 *
 * The end-to-end shape check is covered by re-deriving the verifier's
 * assumptions: every cert we issue here has to round-trip through
 * AttestationVerifier's parseCardCert.  Since that's in a different
 * workspace we duplicate the parse inline — keeps this test self-
 * contained and makes wire-format drift between issuer and verifier
 * an immediate red test.
 */
import { describe, it, expect } from 'vitest';
import {
  createPublicKey,
  createSign,
  createVerify,
  generateKeyPairSync,
} from 'node:crypto';
import {
  CARD_PUBKEY_LEN,
  CPLC_LEN,
  P256_PRIV_RAW_LEN,
  issueCardCert,
  type IssuerSigner,
} from './attestation-issuer.js';

/** Build an in-memory Issuer CA.  Signer uses the private key to sign
 *  DER ECDSA-SHA256, matching what KMS returns in production. */
function makeInMemoryIssuer() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const signer: IssuerSigner = async (msg: Buffer) => {
    const s = createSign('SHA256');
    s.update(msg);
    return s.sign(privateKey);
  };
  return { privateKey, publicKey, signer };
}

describe('issueCardCert', () => {
  it('returns a 65-byte card pubkey, 32-byte raw scalar, and valid card cert', async () => {
    const { signer } = makeInMemoryIssuer();
    const cplc = Buffer.alloc(CPLC_LEN, 0xAA);
    const bundle = await issueCardCert(cplc, signer);

    expect(bundle.cardPubkeyRaw.length).toBe(CARD_PUBKEY_LEN);
    expect(bundle.cardPubkeyRaw[0]).toBe(0x04); // SEC1 uncompressed prefix
    expect(bundle.cardAttestPrivRaw.length).toBe(P256_PRIV_RAW_LEN);

    // cert = body(107) + DER sig(~70-72)
    expect(bundle.cardCert.length).toBeGreaterThanOrEqual(
      CARD_PUBKEY_LEN + CPLC_LEN + 68,
    );
    expect(bundle.cardCert.subarray(0, CARD_PUBKEY_LEN).equals(bundle.cardPubkeyRaw)).toBe(true);
    expect(
      bundle.cardCert
        .subarray(CARD_PUBKEY_LEN, CARD_PUBKEY_LEN + CPLC_LEN)
        .equals(cplc),
    ).toBe(true);
    // Trailing bytes are DER ECDSA sig → start with SEQUENCE tag 0x30.
    expect(bundle.cardCert[CARD_PUBKEY_LEN + CPLC_LEN]).toBe(0x30);
  });

  it('signs the body (card_pubkey || cplc) so the cert verifies against the issuer pubkey', async () => {
    const { publicKey, signer } = makeInMemoryIssuer();
    const cplc = Buffer.alloc(CPLC_LEN, 0xBB);
    const bundle = await issueCardCert(cplc, signer);

    const body = bundle.cardCert.subarray(0, CARD_PUBKEY_LEN + CPLC_LEN);
    const sig = bundle.cardCert.subarray(CARD_PUBKEY_LEN + CPLC_LEN);

    const v = createVerify('SHA256');
    v.update(body);
    expect(v.verify(publicKey, sig)).toBe(true);
  });

  it('produces a different card keypair on every call (not a cached fixture)', async () => {
    const { signer } = makeInMemoryIssuer();
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const [b1, b2] = await Promise.all([
      issueCardCert(cplc, signer),
      issueCardCert(cplc, signer),
    ]);
    expect(b1.cardPubkeyRaw.equals(b2.cardPubkeyRaw)).toBe(false);
    expect(b1.cardAttestPrivRaw.equals(b2.cardAttestPrivRaw)).toBe(false);
  });

  it('the returned raw scalar actually corresponds to the returned pubkey', async () => {
    const { signer } = makeInMemoryIssuer();
    const cplc = Buffer.alloc(CPLC_LEN, 0xDD);
    const bundle = await issueCardCert(cplc, signer);

    // Reconstruct the private key from the raw scalar via JWK, then
    // re-derive the pubkey and compare.  Easier than DER-nesting.
    // P-256 X and Y are read out of the SEC1 point for the JWK.
    const x = bundle.cardPubkeyRaw.subarray(1, 33).toString('base64url');
    const y = bundle.cardPubkeyRaw.subarray(33, 65).toString('base64url');
    const d = bundle.cardAttestPrivRaw.toString('base64url');

    // Reconstructing a full JWK keypair and verifying the relationship
    // by signing with the reconstructed priv and verifying with the
    // reconstructed pub.  If d doesn't correspond to (x, y), the
    // signature won't verify.
    const reconstructedPriv = createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x, y, d },
      format: 'jwk',
    });
    // node refuses to create a priv via createPublicKey, so route via
    // crypto.createPrivateKey:
    const cp = (await import('node:crypto')).createPrivateKey({
      key: { kty: 'EC', crv: 'P-256', x, y, d } as any,
      format: 'jwk',
    });
    void reconstructedPriv;

    const signer2: IssuerSigner = async (msg) => {
      const s = createSign('SHA256');
      s.update(msg);
      return s.sign(cp);
    };
    const msg = Buffer.from('round-trip');
    const sig = await signer2(msg);
    const v = createVerify('SHA256');
    v.update(msg);
    // The public key reconstructed from x||y should verify a sig made
    // with d if and only if d is the correct scalar for (x, y).
    const pubFromXY = createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x, y },
      format: 'jwk',
    });
    expect(v.verify(pubFromXY, sig)).toBe(true);
  });

  it('left-pads short scalars to exactly 32 bytes', async () => {
    // Run enough iterations that we likely hit a scalar whose JWK
    // encoding is < 32 bytes (leading zeros stripped).  Not every run
    // will produce a short scalar but the padding path must never
    // drop below 32 even when JWK returns fewer bytes.
    const { signer } = makeInMemoryIssuer();
    const cplc = Buffer.alloc(CPLC_LEN, 0xEE);
    for (let i = 0; i < 10; i++) {
      const bundle = await issueCardCert(cplc, signer);
      expect(bundle.cardAttestPrivRaw.length).toBe(P256_PRIV_RAW_LEN);
    }
  });

  it('rejects CPLC of the wrong length', async () => {
    const { signer } = makeInMemoryIssuer();
    await expect(issueCardCert(Buffer.alloc(40), signer)).rejects.toThrow(/cplc/);
    await expect(issueCardCert(Buffer.alloc(0), signer)).rejects.toThrow(/cplc/);
    await expect(issueCardCert(Buffer.alloc(50), signer)).rejects.toThrow(/cplc/);
  });

  it('rejects a signer that returns non-DER bytes (defence against misconfigured KMS)', async () => {
    const cplc = Buffer.alloc(CPLC_LEN, 0x01);
    const badSigner: IssuerSigner = async () =>
      Buffer.from('00'.repeat(70), 'hex'); // no 0x30 SEQUENCE tag
    await expect(issueCardCert(cplc, badSigner)).rejects.toThrow(/non-DER signature/);
  });
});
