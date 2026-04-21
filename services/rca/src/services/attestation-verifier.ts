/**
 * Chip attestation verifier — issuer-controlled PKI (Option A: compact
 * binary certs, no X.509).
 *
 * Patent claims C16 + C23: the chip emits a per-instrument attestation
 * (ECDSA-SHA256 signature over iccPubkey || CPLC) signed by a per-card
 * attestation key.  That per-card key is provisioned during personalisation
 * along with an Issuer-CA-signed card cert; the Issuer CA in turn is signed
 * by the Karta Root CA whose public key is pinned at boot time from
 * `palisade/KARTA_ATTESTATION_ROOT_PUBKEY`.  No vendor (NXP/Infineon)
 * relationship is required — we own the root, so we control the policy.
 *
 * Chain of trust at verification time:
 *
 *   Root CA pubkey (pinned in env)
 *       │  signs
 *       ▼
 *   Issuer CA cert blob (stored in env; loaded once at boot)
 *       │  signs
 *       ▼
 *   Card cert blob (returned by card at GENERATE_KEYS; loaded into
 *   the card during perso via STORE DATA DGI A002)
 *       │  holds card_pubkey, which verifies
 *       ▼
 *   Attestation signature over (iccPubkey || CPLC)
 *
 * GENERATE_KEYS response layout (what the applet returns):
 *
 *   iccPubkey  (65 B)   0x04 || X || Y  — ephemeral session pubkey
 *   attestSig  (var)    DER ECDSA-SHA256 over (iccPubkey || cplc)
 *   cardCert   (var)    card_pubkey[65] || cplc[42] || sig[DER]
 *                         signed by Issuer CA over (card_pubkey || cplc)
 *
 * Issuer cert blob layout (in env / Secrets Manager):
 *
 *   issuer_pubkey (65 B)   0x04 || X || Y
 *   issuer_id     (4 B)    big-endian uint32; lets us rotate
 *                          issuer CAs without touching the root
 *   sig           (var)    DER ECDSA-SHA256 over (issuer_pubkey || issuer_id)
 *                          signed by Root CA
 *
 * Two operating modes:
 *
 *   - strict     : all three signature layers must verify.  Any failure
 *                  returns {ok:false}; the caller refuses to continue
 *                  provisioning.  Required for PCI/patent compliance.
 *
 *   - permissive : accept everything.  Logs a warning but doesn't verify.
 *                  For rollout windows where not every card in the fleet
 *                  has been re-personalised with an attestation cert yet.
 *
 * Mode is controlled by PALISADE_ATTESTATION_MODE.  Flip to strict only
 * once every card in the live fleet has been re-personalised — otherwise
 * strict mode rejects every tap.
 */

import { createPublicKey, createVerify, type KeyObject } from 'node:crypto';

// -----------------------------------------------------------------------------
// Wire-format constants
// -----------------------------------------------------------------------------

/** SEC1 uncompressed P-256 point: 0x04 || X(32) || Y(32) = 65 bytes. */
export const SEC1_UNCOMPRESSED_LEN = 65 as const;
/** NXP Card Production Life Cycle — fixed-length chip identity blob. */
export const CPLC_LEN = 42 as const;
/** Issuer CA identifier width — allows up to 2^32 rotating issuer CAs. */
export const ISSUER_ID_LEN = 4 as const;

/** Minimum plausible DER ECDSA-P256 signature length (short r and s). */
const MIN_DER_SIG_LEN = 68 as const;
/** Max plausible DER ECDSA-P256 signature length (full r and s with leading 0x00). */
const MAX_DER_SIG_LEN = 72 as const;

// Kept as an alias to the SEC1 length because downstream code (session-manager)
// writes an `iccPubkey` field sized against this constant.
export const ICC_PUBKEY_LEN = SEC1_UNCOMPRESSED_LEN;

export const STUB_MODE_WARNING =
  '[attestation] PERMISSIVE MODE: accepting chips without chain validation. ' +
  'Set PALISADE_ATTESTATION_MODE=strict once every live card carries an ' +
  'issuer-CA-signed attestation cert.';

export type AttestationMode = 'strict' | 'permissive';

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/**
 * Components extracted from the raw GENERATE_KEYS response.  Field names
 * preserved from the v1 interface so DB columns (iccPublicKey, attestation)
 * don't need migration; `certChain` is retained as an alias of `cardCert`
 * so the call sites that persist it can keep their field name.
 */
export interface AttestationExtractResult {
  iccPubkey: Buffer;
  /** DER ECDSA-SHA256 signature over (iccPubkey || cplc), produced by the
   *  card's per-card attestation key.  Legacy alias: `attestation`. */
  attestSig: Buffer;
  /** Alias of `attestSig` — existing DB column name is `attestation`. */
  attestation: Buffer;
  /** Per-card attestation cert blob emitted by the card.  Format:
   *   card_pubkey(65) || cplc(42) || sig(DER)
   *  where sig is the Issuer CA's signature over (card_pubkey || cplc). */
  cardCert: Buffer;
  /** Alias of `cardCert` for call sites that still say `certChain`. */
  certChain: Buffer;
  /** 42-byte CPLC, peeled out of the card cert body if parseable. */
  cplc: Buffer;
}

export interface AttestationVerifyResult {
  ok: boolean;
  warning?: string;
  /** 4-byte uint32 issuer id from the issuer cert, when verification
   *  reaches that far.  Useful for per-issuer CloudWatch dimensions. */
  issuerId?: number;
}

/**
 * Boot-time attestation config — pulled from env/Secrets Manager and passed
 * into strict-mode verification.  Keeping this outside the AttestationVerifier
 * class means tests can inject synthetic roots without touching process.env.
 */
export interface AttestationVerifierConfig {
  /** 65-byte uncompressed SEC1 P-256 Root CA public key. */
  rootPubkey: Buffer;
  /** Issuer cert blob — issuer_pubkey(65) || issuer_id(4) || sig(DER). */
  issuerCert: Buffer;
}

// -----------------------------------------------------------------------------
// Boot-time config gate
// -----------------------------------------------------------------------------

/**
 * Refuse to run in strict mode when the Karta root pubkey / issuer cert
 * inputs are missing or obviously wrong-shape.  Called once from
 * services/rca/src/index.ts at boot.
 *
 * Not a full signature check — that would require importing the crypto
 * key at startup.  Just enough to make "strict mode with nothing
 * configured" fail loudly instead of silently rejecting every tap.
 */
export function assertAttestationConfigForMode(
  mode: AttestationMode,
  cfg: {
    KARTA_ATTESTATION_ROOT_PUBKEY?: string;
    KARTA_ATTESTATION_ISSUER_CERT?: string;
  },
): void {
  if (mode !== 'strict') return;

  const rootHex = cfg.KARTA_ATTESTATION_ROOT_PUBKEY ?? '';
  const issuerHex = cfg.KARTA_ATTESTATION_ISSUER_CERT ?? '';

  if (!rootHex || !/^[0-9a-fA-F]+$/.test(rootHex) || rootHex.length !== 130) {
    throw new Error(
      'PALISADE_ATTESTATION_MODE=strict requires KARTA_ATTESTATION_ROOT_PUBKEY ' +
        'to be a 65-byte SEC1 uncompressed P-256 point (130 hex chars, leading 04). ' +
        `Got len=${rootHex.length}.`,
    );
  }
  // Placeholder check runs BEFORE the SEC1-prefix check so an all-zero
  // sentinel (the legacy "not yet configured" convention) surfaces as
  // "all zeros" rather than the vaguer "missing 0x04 prefix".
  if (/^0+$/.test(rootHex)) {
    throw new Error(
      'KARTA_ATTESTATION_ROOT_PUBKEY is all zeros — strict mode would reject every ' +
        'tap.  Set the real Root CA public key before flipping strict.',
    );
  }
  if (!rootHex.toLowerCase().startsWith('04')) {
    throw new Error(
      'KARTA_ATTESTATION_ROOT_PUBKEY must be uncompressed SEC1 (leading byte 0x04). ' +
        `Got leading bytes ${rootHex.slice(0, 2)}.`,
    );
  }

  if (!issuerHex || !/^[0-9a-fA-F]+$/.test(issuerHex)) {
    throw new Error(
      'PALISADE_ATTESTATION_MODE=strict requires KARTA_ATTESTATION_ISSUER_CERT ' +
        'to be a hex-encoded issuer cert blob (issuer_pubkey[65] || issuer_id[4] || sig).',
    );
  }
  // Smallest plausible issuer cert: 65 + 4 + 68 = 137 bytes = 274 hex chars.
  if (issuerHex.length < 274) {
    throw new Error(
      `KARTA_ATTESTATION_ISSUER_CERT looks truncated: ${issuerHex.length} hex chars ` +
        `(need at least 274 for the minimal 137-byte issuer cert).`,
    );
  }
}

// Back-compat alias for the old name — boot code imports this.
export const assertAttestationPinsForMode = assertAttestationConfigForMode;

// -----------------------------------------------------------------------------
// Extract
// -----------------------------------------------------------------------------

export class AttestationVerifier {
  /**
   * Split a raw GENERATE_KEYS response into its three components.
   *
   * Layout: iccPubkey(65) || attestSig(DER) || cardCert(var)
   *
   * Parsing strategy: iccPubkey is fixed-width; attestSig starts with DER
   * SEQUENCE (0x30 LL) so its length is self-describing; cardCert is the
   * remainder.  Tolerates short buffers (returns empty fields) so a
   * mid-tap NFC dropout still yields something we can log / debug with.
   */
  static extract(keygenResponse: Buffer): AttestationExtractResult {
    const empty = Buffer.alloc(0);
    const result: AttestationExtractResult = {
      iccPubkey: empty,
      attestSig: empty,
      attestation: empty,
      cardCert: empty,
      certChain: empty,
      cplc: empty,
    };

    if (keygenResponse.length === 0) return result;

    const iccPubkey = keygenResponse.subarray(
      0,
      Math.min(SEC1_UNCOMPRESSED_LEN, keygenResponse.length),
    );
    result.iccPubkey = iccPubkey;

    if (keygenResponse.length <= SEC1_UNCOMPRESSED_LEN) return result;

    // Read DER SEQUENCE length for attestSig.  Short-form (< 128) length
    // is one byte; long-form (0x81 LL) is two; longer forms (0x82+) don't
    // happen for ECDSA-P256 sigs so we reject anything else as a malformed
    // trailer and hand the remainder off as an opaque cardCert field for
    // offline analysis.
    let attestSigLen = 0;
    let attestSigBodyOff = 0;
    const tag = keygenResponse[SEC1_UNCOMPRESSED_LEN];
    const lenByte = keygenResponse[SEC1_UNCOMPRESSED_LEN + 1];
    if (tag === 0x30 && lenByte !== undefined) {
      if ((lenByte & 0x80) === 0) {
        attestSigLen = 2 + lenByte; // hdr(2) + body
        attestSigBodyOff = SEC1_UNCOMPRESSED_LEN;
      } else if (lenByte === 0x81) {
        const real = keygenResponse[SEC1_UNCOMPRESSED_LEN + 2];
        if (real !== undefined) {
          attestSigLen = 3 + real;
          attestSigBodyOff = SEC1_UNCOMPRESSED_LEN;
        }
      }
    }

    if (
      attestSigLen < MIN_DER_SIG_LEN ||
      attestSigLen > MAX_DER_SIG_LEN ||
      attestSigBodyOff + attestSigLen > keygenResponse.length
    ) {
      // Can't carve a plausible attestSig — give the post-pubkey bytes
      // back as cardCert for debug.  Strict-mode verify will then
      // reject on the empty attestSig.
      result.cardCert = keygenResponse.subarray(SEC1_UNCOMPRESSED_LEN);
      result.certChain = result.cardCert;
      return result;
    }

    result.attestSig = keygenResponse.subarray(
      attestSigBodyOff,
      attestSigBodyOff + attestSigLen,
    );
    result.attestation = result.attestSig;

    const cardCertOff = attestSigBodyOff + attestSigLen;
    result.cardCert = keygenResponse.subarray(cardCertOff);
    result.certChain = result.cardCert;

    // Pull CPLC out of the card cert body if long enough.
    if (result.cardCert.length >= SEC1_UNCOMPRESSED_LEN + CPLC_LEN) {
      result.cplc = result.cardCert.subarray(
        SEC1_UNCOMPRESSED_LEN,
        SEC1_UNCOMPRESSED_LEN + CPLC_LEN,
      );
    }

    return result;
  }

  /**
   * Verify an extracted attestation.  Strict mode walks the full chain:
   * Root → Issuer → Card → iccPubkey.  Permissive mode accepts anything
   * (prints a warning).
   *
   * `config` is only consulted in strict mode.  Callers in permissive
   * mode may pass `undefined`.
   */
  static verify(
    extract: AttestationExtractResult,
    mode: AttestationMode = 'permissive',
    config?: AttestationVerifierConfig,
  ): AttestationVerifyResult {
    if (mode === 'permissive') {
      const sample = extract.attestSig.subarray(
        0,
        Math.min(16, extract.attestSig.length),
      );
      // eslint-disable-next-line no-console
      console.log(
        `[attestation] extract: sigLen=${extract.attestSig.length} ` +
          `cardCertLen=${extract.cardCert.length} cplcLen=${extract.cplc.length} ` +
          `first16=${sample.toString('hex').toUpperCase() || '(empty)'}`,
      );
      // eslint-disable-next-line no-console
      console.warn(STUB_MODE_WARNING);
      return { ok: true, warning: 'attestation verification in permissive mode' };
    }

    // === STRICT MODE ===
    if (!config) {
      return {
        ok: false,
        warning:
          'strict mode requires AttestationVerifierConfig (rootPubkey + issuerCert); ' +
          'none provided',
      };
    }
    if (config.rootPubkey.length !== SEC1_UNCOMPRESSED_LEN || config.rootPubkey[0] !== 0x04) {
      return { ok: false, warning: 'rootPubkey malformed (expected 65-byte uncompressed SEC1)' };
    }

    // 1. Verify the issuer cert was signed by the Root CA.  Do this every
    //    time rather than caching the result — boot-time caching invites
    //    the "what if the env changed mid-process" bug class, and the
    //    three ECDSA verifies combined are <1 ms even on t3.micro.
    const issuerParsed = parseIssuerCert(config.issuerCert);
    if (!issuerParsed.ok) {
      return { ok: false, warning: `malformed issuerCert: ${issuerParsed.reason}` };
    }
    const rootKey = sec1PointToKeyObject(config.rootPubkey);
    if (!rootKey) {
      return { ok: false, warning: 'could not import rootPubkey' };
    }
    if (!verifySigOverBody(issuerParsed.body, issuerParsed.sig, rootKey)) {
      return { ok: false, warning: 'issuer cert signature does not verify against Root CA' };
    }
    const issuerId = issuerParsed.issuerId;
    const issuerKey = sec1PointToKeyObject(issuerParsed.issuerPubkey);
    if (!issuerKey) {
      return { ok: false, warning: 'could not import issuer pubkey from cert', issuerId };
    }

    // 2. Verify the card cert was signed by the Issuer CA.
    const cardParsed = parseCardCert(extract.cardCert);
    if (!cardParsed.ok) {
      return {
        ok: false,
        warning: `malformed cardCert: ${cardParsed.reason}`,
        issuerId,
      };
    }
    if (!verifySigOverBody(cardParsed.body, cardParsed.sig, issuerKey)) {
      return {
        ok: false,
        warning: 'card cert signature does not verify against Issuer CA',
        issuerId,
      };
    }

    // 3. Card cert must bind this session's CPLC.  The cpls we carved out
    //    of cardCert in extract() must equal cardParsed.cplc — they come
    //    from the same bytes, so this is a tautology check that guards
    //    against future refactors silently desyncing the two readers.
    if (!extract.cplc.equals(cardParsed.cplc)) {
      return {
        ok: false,
        warning: 'extract.cplc does not match cardCert.cplc (internal parser desync)',
        issuerId,
      };
    }

    // 4. Verify the attestation signature over (iccPubkey || cplc) with
    //    the card's pubkey from the card cert.  This is the actual
    //    binding from card identity to this session's ephemeral pubkey.
    if (extract.attestSig.length < MIN_DER_SIG_LEN) {
      return {
        ok: false,
        warning: `attestSig too short: ${extract.attestSig.length} bytes`,
        issuerId,
      };
    }
    const cardKey = sec1PointToKeyObject(cardParsed.cardPubkey);
    if (!cardKey) {
      return { ok: false, warning: 'could not import card pubkey from cert', issuerId };
    }
    const signed = Buffer.concat([extract.iccPubkey, extract.cplc]);
    if (!verifySigOverBody(signed, extract.attestSig, cardKey)) {
      return {
        ok: false,
        warning: 'attestation signature does not verify against card cert pubkey',
        issuerId,
      };
    }

    return { ok: true, issuerId };
  }
}

/**
 * Low-level ECDSA-SHA256 verify over an arbitrary message.  Exported so
 * unit tests can exercise the signature path without building full cert
 * blobs; production callers funnel through verify() above.
 */
export function verifyAttestationSignature(
  iccPubkey: Buffer,
  cplc: Buffer,
  attestation: Buffer,
  leafPubkey: KeyObject,
): boolean {
  const signed = Buffer.concat([iccPubkey, cplc]);
  return verifySigOverBody(signed, attestation, leafPubkey);
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

type ParsedIssuerCert =
  | { ok: true; body: Buffer; issuerPubkey: Buffer; issuerId: number; sig: Buffer }
  | { ok: false; reason: string };

type ParsedCardCert =
  | { ok: true; body: Buffer; cardPubkey: Buffer; cplc: Buffer; sig: Buffer }
  | { ok: false; reason: string };

/**
 * Issuer cert layout: issuer_pubkey(65) || issuer_id(4) || sig(DER).
 * The signed body is `issuer_pubkey || issuer_id` (first 69 bytes).
 */
function parseIssuerCert(blob: Buffer): ParsedIssuerCert {
  const bodyLen = SEC1_UNCOMPRESSED_LEN + ISSUER_ID_LEN;
  if (blob.length < bodyLen + MIN_DER_SIG_LEN) {
    return { ok: false, reason: `blob too short: ${blob.length} bytes` };
  }
  const body = blob.subarray(0, bodyLen);
  const issuerPubkey = body.subarray(0, SEC1_UNCOMPRESSED_LEN);
  if (issuerPubkey[0] !== 0x04) {
    return { ok: false, reason: 'issuer_pubkey missing 0x04 SEC1 prefix' };
  }
  const issuerId = body.readUInt32BE(SEC1_UNCOMPRESSED_LEN);
  const sig = blob.subarray(bodyLen);
  if (sig[0] !== 0x30) {
    return { ok: false, reason: `sig not DER SEQUENCE (first byte ${sig[0].toString(16)})` };
  }
  return { ok: true, body, issuerPubkey, issuerId, sig };
}

/**
 * Card cert layout: card_pubkey(65) || cplc(42) || sig(DER).
 * The signed body is `card_pubkey || cplc` (first 107 bytes).
 */
function parseCardCert(blob: Buffer): ParsedCardCert {
  const bodyLen = SEC1_UNCOMPRESSED_LEN + CPLC_LEN;
  if (blob.length < bodyLen + MIN_DER_SIG_LEN) {
    return { ok: false, reason: `blob too short: ${blob.length} bytes` };
  }
  const body = blob.subarray(0, bodyLen);
  const cardPubkey = body.subarray(0, SEC1_UNCOMPRESSED_LEN);
  if (cardPubkey[0] !== 0x04) {
    return { ok: false, reason: 'card_pubkey missing 0x04 SEC1 prefix' };
  }
  const cplc = body.subarray(SEC1_UNCOMPRESSED_LEN, bodyLen);
  const sig = blob.subarray(bodyLen);
  if (sig[0] !== 0x30) {
    return { ok: false, reason: `sig not DER SEQUENCE (first byte ${sig[0].toString(16)})` };
  }
  return { ok: true, body, cardPubkey, cplc, sig };
}

/** Wrap a raw 65-byte SEC1 P-256 point into a node KeyObject for verify. */
function sec1PointToKeyObject(rawPoint: Buffer): KeyObject | null {
  try {
    const spki = rawPointToSpkiDer(rawPoint);
    return createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

/**
 * Wrap a raw 65-byte SEC1 P-256 public point into the minimal SPKI DER
 * envelope so node:crypto can import it without going through PEM.
 * Same byte-math as EMV Book 2 §5.9 Table 7 SPKI encoding.
 */
function rawPointToSpkiDer(rawPoint: Buffer): Buffer {
  if (rawPoint.length !== SEC1_UNCOMPRESSED_LEN || rawPoint[0] !== 0x04) {
    throw new Error('expected 65-byte uncompressed SEC1 P-256 point (0x04 || X || Y)');
  }
  // SPKI:
  //   SEQUENCE {
  //     SEQUENCE { OID ecPublicKey(1.2.840.10045.2.1), OID P-256(1.2.840.10045.3.1.7) },
  //     BIT STRING { 0x00 || raw 65-byte point }
  //   }
  const algIdent = Buffer.from(
    '3013' +
      '0607' + '2a8648ce3d0201' +
      '0608' + '2a8648ce3d030107',
    'hex',
  );
  const bitString = Buffer.concat([
    Buffer.from([0x03, rawPoint.length + 1, 0x00]),
    rawPoint,
  ]);
  const inner = Buffer.concat([algIdent, bitString]);
  return Buffer.concat([Buffer.from([0x30, 0x81, inner.length]), inner]);
}

/** Single-shot ECDSA-SHA256 verify; returns false on any structural error. */
function verifySigOverBody(
  body: Buffer,
  sig: Buffer,
  pubkey: KeyObject,
): boolean {
  const v = createVerify('SHA256');
  v.update(body);
  try {
    return v.verify(pubkey, sig);
  } catch {
    // createVerify throws on malformed DER — treat as rejection.
    return false;
  }
}
