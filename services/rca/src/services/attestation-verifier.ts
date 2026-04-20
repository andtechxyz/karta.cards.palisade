/**
 * Chip attestation verifier — real ECDSA verification against vendor root.
 *
 * Patent claims C16 + C23: the chip emits a per-instrument attestation
 * (ECDSA-SHA-256 signature over pubkey||CPLC) signed by the factory-burned
 * attestation key.  This module verifies the signature against the vendor
 * (NXP JCOP 5 / Infineon Secora) root CA that's pinned at build time.
 *
 * The PA applet's GENERATE_KEYS response is
 *   ICC_PubKey(65) || Attest_Sig(var) || CPLC(42) || CertChain(var)?
 * where:
 *   ICC_PubKey : 65 bytes uncompressed SEC1 P-256 point (0x04 || X || Y)
 *   Attest_Sig : DER-encoded ECDSA-SHA-256 signature (70-72 bytes typical)
 *                over the bytes (ICC_PubKey || CPLC)
 *   CPLC       : 42 bytes (NXP Card Production Life Cycle)
 *   CertChain  : optional.  If present, TLV-encoded DER X.509 chain, leaf
 *                first, root last.  Currently the applet returns 0 bytes
 *                (C16 gap — see /Users/danderson/Documents/Claude Code/
 *                Palisade/palisade-pa/src/com/palisade/pa/NxpAttestation.java).
 *
 * Two operating modes:
 *   - strict    : cert chain MUST be present, chain MUST validate to the
 *                 pinned vendor root, signature MUST verify.  Any failure
 *                 returns {ok:false} — callers refuse to continue
 *                 provisioning.  Required for PCI/patent compliance.
 *   - permissive: legacy stub behaviour — accept everything, log warning.
 *                 Used until karta-se applet v1 ships real attestation
 *                 output.
 *
 * Mode is controlled by `PALISADE_ATTESTATION_MODE` env var on the RCA
 * service.  Default is `permissive` for backward compatibility during
 * rollout; production deployments should flip to `strict` once the
 * applet is rebuilt.
 */

import { createVerify, createPublicKey, X509Certificate, type KeyObject } from 'node:crypto';

/** Stub-mode banner printed when PALISADE_ATTESTATION_MODE=permissive. */
export const STUB_MODE_WARNING =
  '[attestation] PERMISSIVE MODE: accepting chips without real cert-chain ' +
  'validation.  Set PALISADE_ATTESTATION_MODE=strict once karta-se v1 is deployed.';

export const ICC_PUBKEY_LEN = 65 as const;
export const CPLC_LEN = 42 as const;

export type AttestationVendor = 'nxp' | 'infineon' | 'unknown';
export type AttestationMode = 'strict' | 'permissive';

export interface AttestationExtractResult {
  /** 65-byte uncompressed SEC1 ICC public key (0x04 || X || Y). */
  iccPubkey: Buffer;
  /** Variable-length DER ECDSA-SHA-256 signature over (pubkey || CPLC). */
  attestation: Buffer;
  /** 42-byte CPLC / hardware identifier. */
  cplc: Buffer;
  /**
   * Optional cert chain (leaf-first), TLV-encoded as concatenated DER
   * certificates.  Empty until karta-se v1 lands.  When non-empty, strict
   * mode will validate chain → vendor root.
   */
  certChain: Buffer;
}

export interface AttestationVerifyResult {
  /** True iff verification passed.  In permissive stub mode: always true. */
  ok: boolean;
  /** Human-readable reason/warning string. */
  warning?: string;
  /** Detected vendor (when cert chain present). */
  vendor?: AttestationVendor;
}

// -----------------------------------------------------------------------------
// Vendor root CA pins
// -----------------------------------------------------------------------------
//
// These are PLACEHOLDERS — the real NXP JCOP 5 attestation root and
// Infineon Secora root will be pinned here after the vendor documentation
// review.  The format is raw SEC1 uncompressed public key bytes for the
// root CA's signing key (P-256).  Build-time pinning prevents a compromised
// PKI from minting cards into our fleet.
//
// When updating: get the root cert from the vendor's dev portal, extract
// the SubjectPublicKey (the 65-byte P-256 point), and paste as hex.
//
// PLACEHOLDER VALUES — will be replaced with real vendor root public keys
// once we have access to the attestation infrastructure.  Strict-mode
// verification against these placeholders will FAIL — that's intentional
// until the real pins are in place.
const NXP_ROOT_P256_PUBKEY_HEX =
  '00'.repeat(65); // TODO: replace with real NXP JCOP 5 attestation root pubkey
const INFINEON_ROOT_P256_PUBKEY_HEX =
  '00'.repeat(65); // TODO: replace with real Infineon Secora attestation root pubkey

// Vendor OID prefixes in the leaf cert's Subject or Issuer DN.  Used to
// auto-detect which vendor root to verify against.  Reserved for future
// OID-based detection (today we fall back to substring match on the DN);
// the constants are kept so the real pin values can be committed alongside
// them when the vendor cert chain arrives.
//   NXP PEN       = 1.3.6.1.4.1.26743
//   Infineon PEN  = 1.3.6.1.4.1.341

// -----------------------------------------------------------------------------
// Extract
// -----------------------------------------------------------------------------

export class AttestationVerifier {
  /**
   * Split a raw GENERATE_KEYS response buffer into its four components.
   *
   * Layout: pubkey(65) || attest_sig(var) || cplc(42) || cert_chain(var)
   *
   * Without an explicit length prefix on the variable-length attest_sig,
   * we locate CPLC by counting backwards from a known-length trailer.
   * When the cert chain is non-empty, it comes AFTER the CPLC (with a
   * 2-byte length prefix).
   *
   * Short buffers are tolerated (returning empty components) rather than
   * throwing — keygen sometimes fails silently on bad NFC and we still
   * want to capture whatever bytes we did receive for offline analysis.
   */
  static extract(keygenResponse: Buffer): AttestationExtractResult {
    const iccPubkey = keygenResponse.subarray(
      0,
      Math.min(ICC_PUBKEY_LEN, keygenResponse.length),
    );

    let attestation: Buffer;
    let cplc: Buffer;
    let certChain: Buffer = Buffer.alloc(0);

    if (keygenResponse.length < ICC_PUBKEY_LEN) {
      // Response too short even for a pubkey — return what we have.
      return {
        iccPubkey,
        attestation: Buffer.alloc(0),
        cplc: Buffer.alloc(0),
        certChain: Buffer.alloc(0),
      };
    }

    if (keygenResponse.length < ICC_PUBKEY_LEN + CPLC_LEN) {
      // Degraded: pubkey + partial trailer.  Treat remainder as sig.
      return {
        iccPubkey,
        attestation: keygenResponse.subarray(ICC_PUBKEY_LEN),
        cplc: Buffer.alloc(0),
        certChain: Buffer.alloc(0),
      };
    }

    // Full trailer present.  Two layouts to consider:
    //   v1 (legacy):  pubkey(65) | sig(var) | cplc(42)
    //   v2 (future):  pubkey(65) | sig(var) | cplc(42) | chainLen(2 BE) | chain(N)
    //
    // Peek the last 2 bytes as a candidate chainLen; v2 is accepted only
    // when that length fits cleanly inside the trailer AND the implied
    // signature length is within the DER ECDSA-P256 expected range
    // (64-80 bytes — never exactly 72, but close).  Anything else falls
    // back to v1 parsing.
    const total = keygenResponse.length;
    const candidateChainLen = total >= 2 ? keygenResponse.readUInt16BE(total - 2) : 0;
    const v2SigLen = total - ICC_PUBKEY_LEN - CPLC_LEN - 2 - candidateChainLen;
    const v2Plausible =
      candidateChainLen > 0 &&
      v2SigLen >= 60 &&
      v2SigLen <= 80 &&
      total >= ICC_PUBKEY_LEN + CPLC_LEN + 2 + candidateChainLen;

    if (v2Plausible) {
      // v2 layout.  But chainLen is at the END of the buffer (after chain
      // bytes), so read it the right way:
      //   pubkey | sig | cplc | chain | chainLen(2, big-endian)
      //
      // Wait — re-derive.  The applet writes chainLen BEFORE the chain
      // bytes to let the parser know how much to expect.  Our candidate
      // reader above was wrong; fix here.
    }

    // Reset and re-parse with the correct v2 layout:
    //   pubkey(65) | sig(var) | cplc(42) | chainLen(2 BE) | chain(N)
    //
    // To find the boundary we scan from the RIGHT assuming chainLen sits
    // exactly after cplc (byte positions total - N - 2 .. total - N - 1
    // where N = chain length).  Fast path: search for a plausible chainLen
    // that makes the arithmetic work out.
    //
    // For response sizes in the 65+60+42 (=167) to 65+80+42+2+N (=~2k)
    // range, there's only ever zero or one valid (chainLen, sigLen) pair.
    // Prefer the v2 pair when it exists; fall back to v1 otherwise.
    const v1SigLen = total - ICC_PUBKEY_LEN - CPLC_LEN;
    let parsedV2 = false;
    if (total > ICC_PUBKEY_LEN + CPLC_LEN + 2) {
      // Potential v2.  chainLen is 2 bytes at (ICC_PUBKEY_LEN + sig + cplc).
      // Sig length must be in a plausible DER ECDSA-P256 range.  Iterate
      // candidate chainLens — the correct one makes sigLen valid.
      for (let n = 1; n < total - ICC_PUBKEY_LEN - CPLC_LEN - 2; n++) {
        const sigLen = total - ICC_PUBKEY_LEN - CPLC_LEN - 2 - n;
        if (sigLen < 60 || sigLen > 80) continue;
        const chainLenOff = ICC_PUBKEY_LEN + sigLen + CPLC_LEN;
        const readLen = keygenResponse.readUInt16BE(chainLenOff);
        if (readLen === n) {
          attestation = keygenResponse.subarray(ICC_PUBKEY_LEN, ICC_PUBKEY_LEN + sigLen);
          cplc = keygenResponse.subarray(
            ICC_PUBKEY_LEN + sigLen,
            ICC_PUBKEY_LEN + sigLen + CPLC_LEN,
          );
          certChain = keygenResponse.subarray(
            chainLenOff + 2,
            chainLenOff + 2 + n,
          );
          parsedV2 = true;
          break;
        }
      }
    }

    if (!parsedV2) {
      // v1 layout — sig occupies everything between pubkey and trailing cplc.
      attestation = keygenResponse.subarray(
        ICC_PUBKEY_LEN,
        ICC_PUBKEY_LEN + v1SigLen,
      );
      cplc = keygenResponse.subarray(ICC_PUBKEY_LEN + v1SigLen);
    }

    return { iccPubkey, attestation: attestation!, cplc: cplc!, certChain };
  }

  /**
   * Verify an attestation signature.  Behavior depends on mode:
   *
   *   strict     — require non-empty cert chain + signature that verifies
   *                against the pinned vendor root.  Returns {ok:false} on
   *                any failure; caller must refuse to continue provisioning.
   *   permissive — legacy stub.  Always returns {ok:true} with a warning.
   *                Used until karta-se v1 ships real attestation output.
   */
  static verify(
    extract: AttestationExtractResult,
    mode: AttestationMode = 'permissive',
  ): AttestationVerifyResult {
    if (mode === 'permissive') {
      // Keep the old stub behaviour — accepts everything, logs warning.
      const sample = extract.attestation.subarray(
        0,
        Math.min(16, extract.attestation.length),
      );
      // eslint-disable-next-line no-console
      console.log(
        `[attestation] extract: attLen=${extract.attestation.length} ` +
          `cplcLen=${extract.cplc.length} chainLen=${extract.certChain.length} ` +
          `first16=${sample.toString('hex').toUpperCase() || '(empty)'}`,
      );
      // eslint-disable-next-line no-console
      console.warn(STUB_MODE_WARNING);
      return {
        ok: true,
        warning: 'attestation verification in permissive mode',
      };
    }

    // === STRICT MODE ===
    if (extract.certChain.length === 0) {
      return {
        ok: false,
        warning:
          'strict mode requires a non-empty attestation cert chain; ' +
          'the PA applet returned none (karta-se v1 must include cert chain in GENERATE_KEYS response)',
      };
    }
    if (extract.attestation.length === 0 || extract.cplc.length !== CPLC_LEN) {
      return {
        ok: false,
        warning: `malformed attestation: sigLen=${extract.attestation.length} cplcLen=${extract.cplc.length}`,
      };
    }

    // 1. Parse cert chain (leaf-first) — split concatenated DER.
    const certs = splitDerChain(extract.certChain);
    if (certs.length === 0) {
      return { ok: false, warning: 'could not parse any certs from chain' };
    }

    const leaf = certs[0];
    const vendor = detectVendor(leaf);
    const rootPubkey = pinnedRootPubkey(vendor);
    if (!rootPubkey) {
      return {
        ok: false,
        warning: `unknown vendor for leaf cert (issuer=${leaf.issuer}); no pinned root`,
        vendor,
      };
    }

    // 2. Validate chain → pinned root.  Walks leaf → intermediate → ... →
    //    top-of-chain, verifying each cert's signature with the next's
    //    public key.  The final cert in the chain must be signed by the
    //    pinned root.
    const chainOk = verifyCertChainToRoot(certs, rootPubkey);
    if (!chainOk.ok) {
      return {
        ok: false,
        warning: `cert chain invalid: ${chainOk.reason}`,
        vendor,
      };
    }

    // 3. Verify the attestation signature over (pubkey || CPLC) with the
    //    leaf's public key.
    const signed = Buffer.concat([extract.iccPubkey, extract.cplc]);
    const leafKey = createPublicKey(leaf.publicKey.export({ format: 'der', type: 'spki' }));
    const v = createVerify('SHA256');
    v.update(signed);
    const sigOk = v.verify(leafKey, extract.attestation);

    if (!sigOk) {
      return {
        ok: false,
        warning: 'attestation ECDSA signature does not verify against leaf cert',
        vendor,
      };
    }

    return { ok: true, vendor };
  }
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

/** Parse a concatenated DER cert chain into X509Certificate objects. */
function splitDerChain(chain: Buffer): X509Certificate[] {
  const certs: X509Certificate[] = [];
  let off = 0;
  while (off < chain.length) {
    // DER SEQUENCE tag = 0x30, then length.
    if (chain[off] !== 0x30) break;
    const lenByte = chain[off + 1];
    let len: number;
    let hdr: number;
    if ((lenByte & 0x80) === 0) {
      len = lenByte;
      hdr = 2;
    } else {
      const lenOfLen = lenByte & 0x7f;
      if (lenOfLen < 1 || lenOfLen > 4) break;
      len = 0;
      for (let i = 0; i < lenOfLen; i++) {
        len = (len << 8) | chain[off + 2 + i];
      }
      hdr = 2 + lenOfLen;
    }
    const total = hdr + len;
    if (off + total > chain.length) break;
    try {
      const certDer = chain.subarray(off, off + total);
      certs.push(new X509Certificate(certDer));
    } catch {
      // Corrupt cert — stop parsing here.
      break;
    }
    off += total;
  }
  return certs;
}

/** Auto-detect vendor from leaf cert DN. */
function detectVendor(leaf: X509Certificate): AttestationVendor {
  const subject = leaf.subject.toLowerCase();
  const issuer = leaf.issuer.toLowerCase();
  const haystack = subject + ' ' + issuer;
  if (haystack.includes('nxp')) return 'nxp';
  if (haystack.includes('infineon')) return 'infineon';
  // Fall back to PEN OID lookup on extensions if available.
  return 'unknown';
}

/** Return the pinned P-256 public key for a vendor, or null if unknown. */
function pinnedRootPubkey(vendor: AttestationVendor): KeyObject | null {
  let hex: string;
  switch (vendor) {
    case 'nxp':
      hex = NXP_ROOT_P256_PUBKEY_HEX;
      break;
    case 'infineon':
      hex = INFINEON_ROOT_P256_PUBKEY_HEX;
      break;
    default:
      return null;
  }
  if (/^0+$/.test(hex)) {
    // Placeholder not yet replaced — return null so strict mode rejects.
    return null;
  }
  try {
    // Wrap raw 65-byte SEC1 point in an SPKI structure by letting node
    // parse it via the pem path.  For placeholders this won't run; real
    // pins come in a future commit alongside vendor root certs.
    const spki = rawPointToSpkiDer(Buffer.from(hex, 'hex'));
    return createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

/**
 * Wrap a raw 65-byte SEC1 P-256 public point into the minimal SPKI DER
 * envelope so node:crypto can import it.  Used for pinning vendor roots.
 */
function rawPointToSpkiDer(rawPoint: Buffer): Buffer {
  if (rawPoint.length !== 65 || rawPoint[0] !== 0x04) {
    throw new Error('expected 65-byte uncompressed SEC1 P-256 point');
  }
  // SPKI for P-256:
  //   SEQUENCE {
  //     SEQUENCE { OID 1.2.840.10045.2.1 ecPublicKey, OID 1.2.840.10045.3.1.7 P-256 },
  //     BIT STRING { 0x00 || raw 65-byte point }
  //   }
  const algIdent = Buffer.from(
    '3013' + // SEQUENCE length 0x13
    '0607' + '2a8648ce3d0201' + // OID ecPublicKey
    '0608' + '2a8648ce3d030107', // OID P-256
    'hex',
  );
  const bitString = Buffer.concat([
    Buffer.from([0x03, rawPoint.length + 1, 0x00]),
    rawPoint,
  ]);
  const inner = Buffer.concat([algIdent, bitString]);
  return Buffer.concat([
    Buffer.from([0x30, 0x81, inner.length]),
    inner,
  ]);
}

/**
 * Walk a leaf-first cert chain verifying each cert's signature with the
 * next cert's public key, until the top-of-chain is reached, then verify
 * the top-of-chain is signed by the pinned root (or IS the pinned root).
 */
function verifyCertChainToRoot(
  certs: X509Certificate[],
  rootPubkey: KeyObject,
): { ok: true } | { ok: false; reason: string } {
  // Validate sig of cert[i] using cert[i+1].publicKey.
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i].verify(certs[i + 1].publicKey)) {
      return { ok: false, reason: `cert[${i}] signature does not verify with cert[${i + 1}] pubkey` };
    }
  }
  // Verify the top-of-chain against the pinned root.
  const top = certs[certs.length - 1];
  if (!top.verify(rootPubkey)) {
    return {
      ok: false,
      reason: 'top-of-chain cert does not verify against pinned vendor root',
    };
  }
  // Check dates.
  const now = new Date();
  for (const c of certs) {
    const validFrom = new Date(c.validFrom);
    const validTo = new Date(c.validTo);
    if (now < validFrom || now > validTo) {
      return { ok: false, reason: `cert outside validity window (${c.subject})` };
    }
  }
  return { ok: true };
}
