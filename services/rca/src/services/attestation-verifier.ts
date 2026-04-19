/**
 * Chip attestation verifier — currently STUB MODE.
 *
 * The PA applet's GENERATE_KEYS response is
 *   ICC_PubKey(65) || Attest_Sig(var) || CPLC(42)
 * where Attest_Sig is a DER-encoded ECDSA-SHA-256 signature over
 *   W(65) || CPLC(42)
 * signed by the vendor-provisioned attestation key burned into the secure
 * element at manufacture (NXP JCOP 5 / Infineon Secora Pay).  Real
 * verification requires:
 *
 *   1. Auto-detect vendor from the attestation cert chain (TODO — PA
 *      currently returns an empty cert chain, so we can't tell NXP apart
 *      from Infineon at the wire level yet).
 *   2. Validate the cert chain up to the vendor root (baked into the RCA
 *      at build time — NXP JCOP 5 root + Infineon Secora root).
 *   3. Verify the ECDSA signature over (pubkey || CPLC) using the leaf
 *      cert's public key.
 *   4. If verification passes, continue.  If it fails, the RCA should
 *      refuse to ship TRANSFER_SAD (protocol checkpoint mechanism — not
 *      implemented yet; see plan-builder.ts for the deferred
 *      `checkpointAfter` plan field).
 *
 * Today: we extract the bytes, persist them on ProvisioningSession for
 * offline analysis, and log a prominent stub-mode warning.  We never
 * reject.  This matches the palisade-rca Python reference (see
 * 04-rca-middleware.md line 107: "If attestation fails: set flag,
 * continue provisioning, investigate offline").
 *
 * DO NOT let this file's `verify()` grow into a silent pass-through with
 * more plumbing around it — that's the failure mode that ships a broken
 * attestation check.  Every caller must still read the `warning` field
 * and know this is not a real verdict.
 */

/** Stub-mode banner the verifier prints on every verify() call. */
export const STUB_MODE_WARNING =
  '[attestation] STUB MODE: accepting all chips; implement NXP/Infineon ' +
  'cert chain validation before prod launch';

/**
 * Layout constants for the PA applet's GENERATE_KEYS response.
 *
 *   ICC_PubKey: 65 bytes — uncompressed SEC1 ECC P-256 point
 *                          (0x04 || X[32] || Y[32])
 *   Attest_Sig: ~70-72 bytes DER-encoded ECDSA-SHA-256, variable length.
 *               We derive it as "everything between the pubkey and CPLC"
 *               rather than hard-coding a length — DER-encoded ECDSA
 *               signatures swing between 70 and 72 bytes depending on
 *               whether the r/s halves need the high-bit padding byte.
 *   CPLC:       42 bytes — ISO 7816-4 Card Production Life Cycle data
 *               (NXP) or equivalent chip ID (Infineon).
 *
 * TODO(attestation): Validate the 42-byte CPLC length against a freshly
 * captured Palisade PA trace once we can run the applet against real
 * JCOP 5 silicon; the java source defines CPLC as 42 bytes today but
 * production silicon sometimes returns CPLC with ISO7816 tag 0x9F 0x7F
 * wrapping (4 extra bytes).
 */
export const ICC_PUBKEY_LEN = 65 as const;
export const CPLC_LEN = 42 as const;

export type AttestationVendor = 'nxp' | 'infineon' | 'unknown';

export interface AttestationExtractResult {
  /** 65-byte uncompressed SEC1 ICC public key (0x04 || X || Y). */
  iccPubkey: Buffer;
  /** Variable-length DER ECDSA-SHA-256 signature over (pubkey || CPLC). */
  attestation: Buffer;
  /** 42-byte CPLC / hardware identifier. */
  cplc: Buffer;
}

export interface AttestationVerifyResult {
  /** True iff verification passed.  In stub mode: always true. */
  ok: boolean;
  /**
   * Human-readable warning/reason string.  In stub mode this carries the
   * STUB_MODE_WARNING text so callers can surface it even if they treat
   * `ok` as authoritative.
   */
  warning?: string;
}

/**
 * AttestationVerifier — wraps the extract + verify operations so callers
 * don't manually slice the GENERATE_KEYS response (history: two bugs
 * landed from off-by-one slicing — this class exists partly to prevent
 * recurrence).
 */
export class AttestationVerifier {
  /**
   * Split a raw GENERATE_KEYS response buffer into its three components.
   *
   * Length assumptions:
   *   - Total length ≥ 65 + 42 = 107 bytes.
   *   - The attestation signature is "everything in the middle" — we
   *     intentionally DO NOT hard-code a length here because DER
   *     ECDSA-P256 signatures fluctuate 70-72 bytes and we've already
   *     been bitten by assuming a fixed size.
   *
   * Short buffers are tolerated (returning empty attestation / zeroed
   * CPLC) rather than throwing — keygen sometimes fails silently on bad
   * NFC, and we still want the session audit to capture whatever bytes
   * we did receive.
   */
  static extract(keygenResponse: Buffer): AttestationExtractResult {
    const iccPubkey = keygenResponse.subarray(
      0,
      Math.min(ICC_PUBKEY_LEN, keygenResponse.length),
    );

    let attestation: Buffer;
    let cplc: Buffer;

    if (keygenResponse.length >= ICC_PUBKEY_LEN + CPLC_LEN) {
      // Standard case: pubkey(65) || att_sig(var) || cplc(42)
      cplc = keygenResponse.subarray(keygenResponse.length - CPLC_LEN);
      attestation = keygenResponse.subarray(
        ICC_PUBKEY_LEN,
        keygenResponse.length - CPLC_LEN,
      );
    } else if (keygenResponse.length > ICC_PUBKEY_LEN) {
      // Degraded case: pubkey + partial trailer.  Treat remainder as
      // attestation; CPLC unknown.
      attestation = keygenResponse.subarray(ICC_PUBKEY_LEN);
      cplc = Buffer.alloc(0);
    } else {
      attestation = Buffer.alloc(0);
      cplc = Buffer.alloc(0);
    }

    return { iccPubkey, attestation, cplc };
  }

  /**
   * Verify an attestation signature.
   *
   * STUB MODE: always returns `{ok: true}` with a warning.  The vendor
   * argument is accepted for API stability — once real verification
   * lands we'll auto-detect from the cert chain and dispatch to the
   * right vendor root.  For now we log a sample of the bytes (first 16
   * only to avoid flooding logs on every keygen) and emit the stub-mode
   * banner.
   */
  static verify(
    attestation: Buffer,
    vendor: AttestationVendor,
  ): AttestationVerifyResult {
    const sample = attestation.subarray(0, Math.min(16, attestation.length));
    console.log(
      `[attestation] extract: vendor=${vendor} len=${attestation.length} ` +
      `first16=${sample.toString('hex').toUpperCase() || '(empty)'}`,
    );
    console.warn(STUB_MODE_WARNING);
    return {
      ok: true,
      warning: 'attestation verification not yet implemented',
    };
  }
}
