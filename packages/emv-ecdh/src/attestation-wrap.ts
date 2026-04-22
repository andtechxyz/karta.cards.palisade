/**
 * Attestation-bundle wrapping for remote personalisation.
 *
 * PCI CPL LSR 6 closure: under remote-operations Palisade has no
 * CP-PSR-audited perso terminal to contain the raw P-256 private
 * scalar we load into the card's IssuerAttestation.  This helper
 * wraps the (priv, cardCert, cplc) triple under the same ECDH/HKDF/
 * AES-128-CBC/HMAC-SHA256 envelope format the applet's
 * EcdhUnwrapper already consumes for TRANSFER_PARAMS, so the wire
 * between the cloud service and the chip never carries the
 * plaintext private scalar.
 *
 * Wire format (outer) — delegated to {@link wrapParamBundle} +
 * {@link serializeWrappedBundle}:
 *   server_pub(65) || nonce(12) || ciphertext || hmac_tag(16)
 *
 * Inner plaintext — TLV with single-byte tag + single-byte length
 * (all fields are under 255 bytes).  Tag space overlaps with
 * STORE_ATTESTATION P1 values for human-readability:
 *   0x01 <32>     — P-256 private scalar (raw, big-endian, zero-padded)
 *   0x02 <var>    — card cert blob: card_pubkey(65) || cplc(42) || sig(DER)
 *   0x03 <42>     — CPLC (copy of the bytes inside cardCert, for
 *                   applet-side convenience: lets
 *                   IssuerAttestation.loadCplc run before cardCert
 *                   is parsed, should sequencing ever matter)
 *
 * Applet side (pending CAP rebuild per
 * docs/runbooks/attestation-priv-wrapping.md):
 *   INS_STORE_ATTESTATION P1=0x81 body = the wrapped blob
 *   applet delegates to IssuerAttestation.unwrapAndLoad which
 *   reuses EcdhUnwrapper against the one-shot bootstrap keypair
 *   emitted at initOnce.
 */

import {
  wrapParamBundle,
  serializeWrappedBundle,
} from './index.js';

/** SEC1 uncompressed P-256 point: 0x04 || X(32) || Y(32).
 *  Duplicated locally because index.ts keeps it module-private. */
const SEC1_UNCOMPRESSED_LEN = 65 as const;
export const ATTEST_PRIV_SCALAR_LEN = 32 as const;
export const ATTEST_CPLC_LEN = 42 as const;

export const ATTEST_TLV_TAG_PRIV = 0x01 as const;
export const ATTEST_TLV_TAG_CERT = 0x02 as const;
export const ATTEST_TLV_TAG_CPLC = 0x03 as const;

export interface WrapAttestationBundleInput {
  /**
   * 65-byte SEC1 uncompressed bootstrap pubkey emitted by the applet
   * at GET_ATTESTATION_BOOTSTRAP_PUBKEY (INS=0xE4).  One-shot per
   * install — applet scrubs the matching private half immediately
   * after STORE_ATTESTATION_SEALED succeeds.
   */
  bootstrapPubUncompressed: Buffer;
  /**
   * Stable install-session identifier.  Mixed into HKDF info so the
   * sealed blob is session-bound — a blob captured from a prior
   * install can't replay against a new one.
   */
  sessionId: string;
  /** 32-byte raw P-256 private scalar from issueCardCert. */
  cardAttestPrivRaw: Buffer;
  /** Card cert blob from issueCardCert: card_pubkey || cplc || sig. */
  cardCert: Buffer;
  /** 42-byte CPLC (duplicated vs cardCert-embedded — see module doc). */
  cplc: Buffer;
}

/**
 * Build the inner TLV.  Compact single-byte-tag + single-byte-length
 * form — matches the applet's own TLV parser shape.  Each field
 * length is bounded by design (priv 32 / cplc 42 / cardCert ~179)
 * so no extended-length encoding is needed.
 */
function buildInnerTlv(input: WrapAttestationBundleInput): Buffer {
  if (input.cardAttestPrivRaw.length !== ATTEST_PRIV_SCALAR_LEN) {
    throw new Error(
      `wrapAttestationBundle: cardAttestPrivRaw must be ${ATTEST_PRIV_SCALAR_LEN} bytes, got ${input.cardAttestPrivRaw.length}`,
    );
  }
  if (input.cplc.length !== ATTEST_CPLC_LEN) {
    throw new Error(
      `wrapAttestationBundle: cplc must be ${ATTEST_CPLC_LEN} bytes, got ${input.cplc.length}`,
    );
  }
  if (input.cardCert.length === 0 || input.cardCert.length > 0xff) {
    throw new Error(
      `wrapAttestationBundle: cardCert length must be 1..255 bytes, got ${input.cardCert.length}`,
    );
  }
  const parts: Buffer[] = [];
  // priv
  parts.push(Buffer.from([ATTEST_TLV_TAG_PRIV, input.cardAttestPrivRaw.length]));
  parts.push(input.cardAttestPrivRaw);
  // cert
  parts.push(Buffer.from([ATTEST_TLV_TAG_CERT, input.cardCert.length]));
  parts.push(input.cardCert);
  // cplc
  parts.push(Buffer.from([ATTEST_TLV_TAG_CPLC, input.cplc.length]));
  parts.push(input.cplc);
  return Buffer.concat(parts);
}

/**
 * Wrap the attestation bundle via the existing ECDH envelope format.
 * Returns the wire body ready to hand as the APDU payload of
 * `STORE_ATTESTATION P1=0x81`.
 *
 * The caller MUST scrub its copy of `cardAttestPrivRaw` after
 * passing it in (the wrap copies the bytes into an intermediate
 * ciphertext buffer; the original Buffer is safe to zero once this
 * function returns).
 */
export function wrapAttestationBundle(input: WrapAttestationBundleInput): Buffer {
  if (input.bootstrapPubUncompressed.length !== SEC1_UNCOMPRESSED_LEN) {
    throw new Error(
      `wrapAttestationBundle: bootstrapPubUncompressed must be ${SEC1_UNCOMPRESSED_LEN} bytes, got ${input.bootstrapPubUncompressed.length}`,
    );
  }
  if (input.bootstrapPubUncompressed[0] !== 0x04) {
    throw new Error(
      'wrapAttestationBundle: bootstrapPubUncompressed must start with 0x04 (SEC1 uncompressed marker)',
    );
  }

  const plaintext = buildInnerTlv(input);
  const wrapped = wrapParamBundle({
    chipPubUncompressed: input.bootstrapPubUncompressed,
    plaintext,
    sessionId: input.sessionId,
  });
  // Scrub the inner plaintext buffer before returning — best-effort
  // defence against Buffer reuse in the JS runtime.  The wrapped
  // ciphertext already holds what the applet needs.
  plaintext.fill(0);
  return serializeWrappedBundle(wrapped);
}
