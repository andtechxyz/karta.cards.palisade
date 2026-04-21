/**
 * Per-card attestation issuance — mints the materials that go into
 * STORE DATA DGI A001 + DGI A002 during personalisation.
 *
 * For every card data-prep provisions we:
 *   1. Generate a fresh P-256 attestation keypair in memory.
 *   2. Sign a compact card cert body (card_pubkey || cplc) with the
 *      Issuer CA — `alias/palisade-attestation-issuer` in KMS.
 *   3. Return the raw 32-byte private scalar + the signed cert blob.
 *      Caller (prepareParamBundle) writes the scalar into DGI A001
 *      and the cert blob into DGI A002 of the STORE DATA packet.
 *
 * The applet, at GENERATE_KEYS time, uses this key to sign
 * (iccPubkey || cplc) — that attests the ephemeral session pubkey
 * against the chip's identity.  The server verifier walks the
 * Root → Issuer → Card cert chain to confirm authenticity (see
 * services/rca/src/services/attestation-verifier.ts).
 *
 * Cert format (Option A — no X.509):
 *
 *   cardCert = card_pubkey(65) || cplc(42) || sig(DER ECDSA-SHA256)
 *   Signed body = card_pubkey || cplc (first 107 bytes)
 *   sig is the Issuer CA's signature over that body.
 *
 * The Issuer CA itself is authenticated to the verifier via a
 * separate issuer cert blob pinned in rca's env (KARTA_
 * ATTESTATION_ISSUER_CERT); that blob is signed by the Root CA
 * and carries the Issuer CA pubkey + a 4-byte issuer_id.  All
 * three layers (Root → Issuer → Card) use this same compact
 * format.  There is NO X.509 involvement anywhere in the chain.
 */

import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import {
  KMSClient,
  SignCommand,
  type SigningAlgorithmSpec,
} from '@aws-sdk/client-kms';

export const CARD_PUBKEY_LEN = 65 as const;
export const CPLC_LEN = 42 as const;
/** Raw P-256 private scalar width. */
export const P256_PRIV_RAW_LEN = 32 as const;

/**
 * Signer abstraction.  Takes the body bytes to sign, returns a DER
 * ECDSA-SHA256 signature.  Real implementations call KMS; tests
 * inject an in-memory P-256 key so mocking AWS is unnecessary.
 */
export type IssuerSigner = (body: Buffer) => Promise<Buffer>;

export interface CardAttestationBundle {
  /** 32-byte raw P-256 private scalar — goes into STORE DATA DGI A001.
   *  The applet loads this via ECPrivateKey.setS() at perso time. */
  cardAttestPrivRaw: Buffer;
  /** Card cert blob — goes into STORE DATA DGI A002.  Format:
   *  `card_pubkey(65) || cplc(42) || sig(DER)`. */
  cardCert: Buffer;
  /** The 65-byte SEC1 card pubkey — surfaced for observability /
   *  logging.  Already embedded in `cardCert`. */
  cardPubkeyRaw: Buffer;
}

/**
 * Build a real KMS-backed signer for the live path.  In unit tests
 * prefer {@link makeInMemorySigner} — it's decoupled from AWS and
 * runs in <1 ms per call.
 */
export function makeKmsIssuerSigner(
  kmsKeyArn: string,
  region: string,
): IssuerSigner {
  const client = new KMSClient({ region });
  return async (body) => {
    const res = await client.send(
      new SignCommand({
        KeyId: kmsKeyArn,
        Message: body,
        MessageType: 'RAW',
        SigningAlgorithm: 'ECDSA_SHA_256' satisfies SigningAlgorithmSpec,
      }),
    );
    if (!res.Signature) {
      throw new Error(`KMS.Sign returned no signature for key ${kmsKeyArn}`);
    }
    // res.Signature is Uint8Array; Buffer.from() is a zero-copy view.
    return Buffer.from(res.Signature);
  };
}

/**
 * Issue a per-card attestation cert.  Generates a fresh P-256 keypair,
 * composes the cert body `(card_pubkey || cplc)`, signs it via the
 * provided signer, and returns the materials ready for DGI packing.
 *
 * The generated private key never leaves memory longer than the call —
 * it's exported to raw bytes and returned to the caller, which is
 * expected to fold it into STORE DATA and then scrub its own buffer.
 *
 * @throws when `cplc` is not exactly 42 bytes.
 */
export async function issueCardCert(
  cplc: Buffer,
  signer: IssuerSigner,
): Promise<CardAttestationBundle> {
  if (cplc.length !== CPLC_LEN) {
    throw new Error(
      `attestation-issuer: cplc must be ${CPLC_LEN} bytes (got ${cplc.length})`,
    );
  }

  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  const cardPubkeyRaw = extractSec1Uncompressed(publicKey);
  const cardAttestPrivRaw = extractP256Scalar(privateKey);

  const body = Buffer.concat([cardPubkeyRaw, cplc]);
  const sig = await signer(body);
  if (sig[0] !== 0x30) {
    throw new Error(
      `attestation-issuer: signer returned non-DER signature ` +
        `(first byte ${sig[0]?.toString(16) ?? 'undef'}); expected 0x30`,
    );
  }

  const cardCert = Buffer.concat([body, sig]);
  return { cardAttestPrivRaw, cardCert, cardPubkeyRaw };
}

// ---------------------------------------------------------------------------
// Key-export helpers
// ---------------------------------------------------------------------------

/**
 * Extract a raw 65-byte SEC1 uncompressed P-256 point from a Node
 * KeyObject.  The SPKI DER encoding always ends with the raw point
 * (the BIT STRING tail), so we just slice the last 65 bytes off.
 */
function extractSec1Uncompressed(pub: KeyObject): Buffer {
  const spki = pub.export({ format: 'der', type: 'spki' }) as Buffer;
  const tail = spki.subarray(spki.length - CARD_PUBKEY_LEN);
  if (tail[0] !== 0x04) {
    throw new Error(
      'extractSec1Uncompressed: SPKI tail does not start with 0x04',
    );
  }
  return tail;
}

/**
 * Extract the raw 32-byte P-256 private scalar `d` from a Node
 * KeyObject.  Uses the JWK export path because PKCS#8 parsing is
 * nested ASN.1 and we don't want an ASN.1 dep just for this — JWK's
 * `d` field is the base64url-encoded scalar.  Left-pads shorter
 * scalars with zeros so the returned buffer is always exactly 32
 * bytes (JWK strips leading zeros; downstream STORE DATA expects
 * fixed width).
 */
function extractP256Scalar(priv: KeyObject): Buffer {
  const jwk = priv.export({ format: 'jwk' }) as { d?: string };
  if (!jwk.d) {
    throw new Error('extractP256Scalar: JWK export has no `d` scalar');
  }
  const raw = Buffer.from(jwk.d, 'base64url');
  if (raw.length === P256_PRIV_RAW_LEN) return raw;
  if (raw.length > P256_PRIV_RAW_LEN) {
    // Shouldn't happen for P-256 — scalar fits in 32 bytes.
    throw new Error(
      `extractP256Scalar: scalar is ${raw.length} bytes, exceeds 32`,
    );
  }
  // Left-pad with zeros to the full 32-byte width.
  const padded = Buffer.alloc(P256_PRIV_RAW_LEN);
  raw.copy(padded, P256_PRIV_RAW_LEN - raw.length);
  return padded;
}
