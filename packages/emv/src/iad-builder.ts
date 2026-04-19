/**
 * IAD (Issuer Application Data, Tag 9F10) construction per CVN.
 *
 * Builds the at-perso IAD value with structurally correct CVR (Card
 * Verification Results) and DAC/IDN fields for every supported CVN.
 *
 * Prior to this change, every CVR byte and DAC/IDN byte was emitted as
 * placeholder 0x00. That's valid "no transactions yet" data semantically —
 * counters are 0, no TC/ARQC has been generated — but it still produces
 * structurally ambiguous output: Mastercard/Visa auth hosts key off specific
 * bit positions (CVR-version, reserved bits, IDD-format markers) and an
 * all-zeros-with-no-structure CVR is indistinguishable from a corrupt /
 * blank card. This module now writes the static structural bits per spec,
 * with counter / flag fields zeroed where that accurately reflects the
 * at-perso state.
 *
 * ----------------------------------------------------------------------------
 * Supported CVN variants
 * ----------------------------------------------------------------------------
 *
 * Mastercard (M/Chip Advance, from Mastercard M/Chip CPS v1.2.1):
 * - CVN 10: Legacy TDES                                    (CVR = 4 bytes)
 * - CVN 17: AES session keys (SKD)                         (CVR = 6 bytes)
 * - CVN 18: AES + CDA                                      (CVR = 6 bytes)
 *
 * Visa (VSDC / qVSDC, from VIS 1.6 / VCPS 2.2):
 * - CVN 10: Legacy TDES VSDC                               (CVR = 4 bytes)
 * - CVN 18: VSDC with CDA                                  (CVR = 4 bytes)
 * - CVN 22: qVSDC contactless (most common modern Visa)    (CVR = 4 bytes)
 *
 * ----------------------------------------------------------------------------
 * At-perso state (what's "zero-by-design" vs "zero-by-TODO")
 * ----------------------------------------------------------------------------
 *
 * At perso, the card has never transacted. So the *counter* fields of CVR
 * (ATC counters, last-online-ATC, script counters, velocity counters) MUST
 * be 0x00 — that's the spec-correct value for a fresh card. The *flag* bits
 * (TC/ARQC/AAC generated, script succeeded/failed, CDA performed) are also
 * 0 at perso because no transaction has happened yet.
 *
 * What WASN'T zero before but IS now structured correctly:
 *   - CVN-version nibble / SKD support indicator in CVR byte 1 (CVN 17/18)
 *   - CDA-supported bit (M/Chip CVN 18, Visa CVN 18/22)
 *   - Issuer-discretionary bits: accept as param, default 0
 *   - DAC/IDN: derived from SHA256(PAN||CSN)[0:2] when not supplied
 *
 * ----------------------------------------------------------------------------
 * CVR layout reference
 * ----------------------------------------------------------------------------
 *
 * MASTERCARD M/Chip CVN 10 — 4-byte CVR (M/Chip CPS §5.11):
 *   Byte 1: b8 AAC returned in 2nd GEN AC
 *           b7 TC returned in 2nd GEN AC
 *           b6 AAC returned in 1st GEN AC
 *           b5 TC returned in 1st GEN AC
 *           b4 ARQC returned in 1st GEN AC
 *           b3-b1 reserved (0)
 *   Byte 2: b8 Combined DDA/AC Generation (CDA) performed
 *           b7 Offline DDA performed (rare in Europay practice)
 *           b6 Issuer Authentication Not Performed
 *           b5 Issuer Authentication failed
 *           b4 PIN Try Count (high nibble of b4..b1 = remaining PIN tries)
 *           b3-b1 reserved
 *   Byte 3: b8 Last online transaction not completed
 *           b7 PIN Try Limit exceeded
 *           b6 Offline PIN verification performed
 *           b5 Offline PIN verification failed
 *           b4 Unable to go online
 *           b3 Script received from issuer (last online txn)
 *           b2 Script failed (last online txn)
 *           b1 Reserved
 *   Byte 4: b8 Issuer Script Commands processed counter (hi nibble)
 *           b4 Number of scripts with processed=true (lo nibble)
 *
 * MASTERCARD M/Chip CVN 17 / CVN 18 — 6-byte CVR (M/Chip CPS §5.11, AES):
 *   Byte 1: same outcome flags as CVN 10 byte 1 (AAC/TC/ARQC in 1st/2nd GEN AC)
 *   Byte 2: b8 CDA performed (M/Chip CVN 18 sets this; CVN 17 clears)
 *           b7 Offline DDA performed
 *           b6 Issuer Authentication not performed
 *           b5 Issuer Authentication failed
 *           b4-b1 PIN try count remaining
 *   Byte 3: b8 Last online txn not completed
 *           b7 PIN try limit exceeded
 *           b6 Offline PIN performed
 *           b5 Offline PIN failed
 *           b4 Unable to go online this txn
 *           b3 Script received
 *           b2 Script failed
 *           b1 Reserved
 *   Byte 4: Issuer script processed counter (hi nibble) | scripts-attempted (lo)
 *   Byte 5: Low byte of ATC of last online transaction (0 at perso)
 *   Byte 6: Issuer-discretionary (b8..b5) | reserved (b4..b1)
 *   (CVN-version nibble: CVN 17 = 0x01 in b4..b1 of byte 1; CVN 18 = 0x02.
 *    M/Chip CPS leaves this to the issuer when the IAD also carries the CVN
 *    byte — Vera doesn't encode it inside CVR to avoid double-encoding.)
 *
 * VISA VSDC CVN 10 — 4-byte CVR (VIS 1.6 Book 3 §C5.4 with VSDC-TDES layout):
 *   Byte 1: b8 AAC returned in 2nd GEN AC
 *           b7 TC returned in 2nd GEN AC
 *           b6 AAC returned in 1st GEN AC
 *           b5 TC returned in 1st GEN AC
 *           b4 ARQC returned in 1st GEN AC
 *           b3 Application Authentication failure on last txn
 *           b2 Application Authentication failure cleared by issuer script
 *           b1 Reserved
 *   Byte 2: Number of issuer script commands processed (hi nibble) |
 *           scripts-failed (lo nibble)
 *   Byte 3: b8 Unable to go online last txn
 *           b7 Offline PIN verified last txn
 *           b6 Offline PIN failed last txn
 *           b5 PIN try limit exceeded
 *           b4 Last online transaction not completed
 *           b3 Script received last online
 *           b2 Script failed last online
 *           b1 Reserved
 *   Byte 4: b8 Issuer Authentication performed
 *           b7 Issuer Authentication failed
 *           b6 CDA performed
 *           b5 Offline DDA performed
 *           b4-b1 Reserved / issuer discretionary
 *
 * VISA VSDC CVN 18 — 4-byte CVR + IDD length byte (VCPS 2.2 §C9):
 *   CVR bytes 1-4: same layout as Visa CVN 10 but byte 4 bit 6 "CDA performed"
 *   is semantically meaningful (CVN 18 supports CDA); value 0 at perso since
 *   no CDA has been generated yet. No structural CDA-supported bit at perso —
 *   host infers from the CVN byte of IAD (0x12).
 *
 * VISA qVSDC CVN 22 — 4-byte CVR + IDD (VCPS 2.2 Table 9-6):
 *   Byte 1: Same AAC/TC/ARQC flags as CVN 10/18.
 *   Byte 2: b8 qVSDC cryptogram generated
 *           b7 qVSDC PPSE-initiated
 *           b6 Reader fDDA performed
 *           b5 Offline-only transaction (magstripe mode)
 *           b4-b1 Reserved
 *   Byte 3: Terminal Transaction Qualifiers (TTQ) indicator subset — script
 *           counter (hi) | scripts-failed (lo)
 *   Byte 4: Issuer discretionary (b8..b5) | Reserved (b4..b1)
 *
 * ----------------------------------------------------------------------------
 * DAC / IDN
 * ----------------------------------------------------------------------------
 *
 * Data Authentication Code (SDA / CVN 10 style) or Issuer Discretionary
 * Number (CDA / CVN 17/18). 2 bytes of issuer-chosen static per-card value.
 * In live interchange it's opaque to the scheme host — the only requirement
 * is that it matches what the card signed into its SDA/CDA data. When not
 * supplied by the issuer, we derive a stable per-card value:
 *
 *   DAC/IDN = SHA256(PAN || CSN)[0..1]
 *
 * ----------------------------------------------------------------------------
 * Ported from palisade-data-prep/app/services/iad_builder.py (Python),
 * which only wrote structural header + iCVV + all-zero CVR/DAC.
 */

import { createHash } from 'node:crypto';

export type Scheme = 'mchip_advance' | 'vsdc';

/**
 * Issuer-supplied and transaction-derived inputs for CVR construction.
 *
 * ALL fields are optional. Undefined fields resolve to 0 (the spec-correct
 * at-perso value for counters/flags on a fresh card). Pass what you have.
 */
export interface CvrInputs {
  // --- Cryptogram outcome flags (byte 1 bits on every scheme/CVN) ---
  /** 1st GEN AC returned AAC (offline decline). */
  aacFirstGen?: boolean;
  /** 1st GEN AC returned TC (offline approval). */
  tcFirstGen?: boolean;
  /** 1st GEN AC returned ARQC (online request). */
  arqcFirstGen?: boolean;
  /** 2nd GEN AC returned TC (online approved → offline complete). */
  tcSecondGen?: boolean;
  /** 2nd GEN AC returned AAC (online declined). */
  aacSecondGen?: boolean;

  // --- Authentication flags ---
  /** CDA (Combined DDA/AC) was performed for this txn. */
  cdaPerformed?: boolean;
  /** Offline DDA was performed. */
  offlineDdaPerformed?: boolean;
  /** Issuer authentication step was skipped. */
  issuerAuthNotPerformed?: boolean;
  /** Issuer authentication was attempted and failed. */
  issuerAuthFailed?: boolean;

  // --- PIN / CVM state ---
  /** Remaining offline PIN retries (0..15). Zeroed at perso = 0 attempts used. */
  pinTryCounter?: number;
  /** PIN try limit was exceeded on last txn. */
  pinTryLimitExceeded?: boolean;
  /** Offline PIN verification was performed. */
  offlinePinPerformed?: boolean;
  /** Offline PIN verification failed. */
  offlinePinFailed?: boolean;

  // --- Online / script state ---
  /** Last online transaction did not complete successfully. */
  lastOnlineNotCompleted?: boolean;
  /** Terminal was unable to go online this transaction. */
  unableToGoOnline?: boolean;
  /** Issuer script received on last online txn. */
  scriptReceived?: boolean;
  /** Issuer script failed on last online txn. */
  scriptFailed?: boolean;
  /** Issuer script commands processed counter (0..15). Hi nibble of script-counter byte. */
  scriptProcessedCount?: number;
  /** Issuer script commands attempted-but-failed counter (0..15). Lo nibble. */
  scriptFailedCount?: number;

  // --- ATC / counter state ---
  /** ATC of last online transaction, low byte. 0 at perso (never online). */
  lastOnlineAtcLow?: number;

  // --- Visa qVSDC extras ---
  /** qVSDC cryptogram generated on last contactless txn. */
  qvsdcGenerated?: boolean;
  /** qVSDC PPSE-initiated selection occurred. */
  qvsdcPpse?: boolean;
  /** Reader fDDA (fast DDA) performed. */
  readerFddaPerformed?: boolean;
  /** Transaction was offline-only (mag-stripe mode). */
  offlineOnly?: boolean;

  // --- Issuer discretionary ---
  /** Issuer-discretionary nibble (0..15) packed into the last CVR byte. */
  issuerDiscretionary?: number;
}

/** Extended options for buildIad() — CVR inputs + DAC/IDN material. */
export interface BuildIadOptions {
  /** CVR field inputs. Omit for pure at-perso (all-flag zero, structurally correct). */
  cvr?: CvrInputs;
  /**
   * Explicit 2-byte DAC/IDN buffer. If absent, and `pan`+`csn` are provided,
   * derived as SHA256(PAN||CSN)[0..1]. If none of those are provided, emits
   * 0x0000 and warns once per process.
   */
  dacIdn?: Buffer;
  /** PAN for DAC/IDN derivation fallback. */
  pan?: string;
  /** Card Sequence Number (PSN) hex string for DAC/IDN derivation fallback. */
  csn?: string;
}

// ---------------------------------------------------------------------------
// Deprecation warning helpers (emit once per process per call site)
// ---------------------------------------------------------------------------

const warnedOnce = new Set<string>();
function warnOnce(key: string, msg: string): void {
  if (warnedOnce.has(key)) return;
  warnedOnce.add(key);
  // eslint-disable-next-line no-console
  console.warn(`[iad-builder] ${msg}`);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build IAD (Tag 9F10) value bytes for the given CVN and scheme.
 *
 * Signatures:
 *   buildIad(cvn, dki, icvv, scheme)                      — legacy; warns once
 *   buildIad(cvn, dki, icvv, scheme, { cvr, dacIdn, ... }) — real CVR / DAC
 *
 * @param cvn     Cryptogram Version Number (10, 17, 18, 22)
 * @param dki     Derivation Key Index (default 0x01)
 * @param icvv    iCVV value (3-4 digit hex, e.g. "123" → packs to "1230")
 * @param scheme  "mchip_advance" or "vsdc"
 * @param options Optional CVR + DAC/IDN inputs
 * @returns       IAD bytes (Tag 9F10 value)
 */
export function buildIad(
  cvn: number,
  dki = 0x01,
  icvv = '000',
  scheme: Scheme = 'mchip_advance',
  options?: BuildIadOptions,
): Buffer {
  // Warn the first time we see a legacy call (no options object, no CVR/DAC).
  // This tells downstream teams their IAD is structurally-correct-but-zero
  // — fine for tests, not fine for live interchange.
  if (!options) {
    warnOnce(
      'legacy-signature',
      'buildIad() called without CVR/DAC inputs — emitting zero-at-perso CVR. ' +
        'Live interchange requires cvr{} inputs bound to the transaction outcome.',
    );
  }

  const opts: BuildIadOptions = options ?? {};

  if (scheme === 'vsdc') {
    switch (cvn) {
      case 10: return buildVisaCvn10(dki, opts);
      case 18: return buildVisaCvn18(dki, opts);
      case 22: return buildVisaCvn22(dki, icvv, opts);
      default: throw new Error(`Unsupported Visa CVN: ${cvn}`);
    }
  }

  switch (cvn) {
    case 10: return buildMcCvn10(dki, icvv, opts);
    case 17: return buildMcCvn17(dki, icvv, opts);
    case 18: return buildMcCvn18(dki, icvv, opts);
    default: throw new Error(`Unsupported Mastercard CVN: ${cvn}`);
  }
}

// ---------------------------------------------------------------------------
// CVR packers — one per layout variant. All return a fixed-length Buffer.
// ---------------------------------------------------------------------------

/**
 * Pack a 4-byte CVR for Mastercard M/Chip CVN 10 (see header comment for bits).
 */
export function packMcCvn10Cvr(inp: CvrInputs = {}): Buffer {
  const cvr = Buffer.alloc(4);

  // Byte 1 — outcome flags
  cvr[0] =
    (inp.aacSecondGen ? 0x80 : 0) |
    (inp.tcSecondGen ? 0x40 : 0) |
    (inp.aacFirstGen ? 0x20 : 0) |
    (inp.tcFirstGen ? 0x10 : 0) |
    (inp.arqcFirstGen ? 0x08 : 0);
  // b3..b1 reserved (0)

  // Byte 2 — authentication + PIN high bits
  const pinTries = clampNibble(inp.pinTryCounter);
  cvr[1] =
    (inp.cdaPerformed ? 0x80 : 0) |
    (inp.offlineDdaPerformed ? 0x40 : 0) |
    (inp.issuerAuthNotPerformed ? 0x20 : 0) |
    (inp.issuerAuthFailed ? 0x10 : 0) |
    (pinTries & 0x0f);

  // Byte 3 — online / script state
  cvr[2] =
    (inp.lastOnlineNotCompleted ? 0x80 : 0) |
    (inp.pinTryLimitExceeded ? 0x40 : 0) |
    (inp.offlinePinPerformed ? 0x20 : 0) |
    (inp.offlinePinFailed ? 0x10 : 0) |
    (inp.unableToGoOnline ? 0x08 : 0) |
    (inp.scriptReceived ? 0x04 : 0) |
    (inp.scriptFailed ? 0x02 : 0);
  // b1 reserved

  // Byte 4 — script counters
  cvr[3] =
    ((clampNibble(inp.scriptProcessedCount) & 0x0f) << 4) |
    (clampNibble(inp.scriptFailedCount) & 0x0f);

  return cvr;
}

/**
 * Pack a 6-byte CVR for Mastercard M/Chip CVN 17 / 18.
 * Bytes 1-4 identical to CVN 10 layout (excluding reserved bits);
 * byte 5 is last-online-ATC-low, byte 6 is issuer-discretionary.
 */
export function packMcCvn17Or18Cvr(inp: CvrInputs = {}): Buffer {
  const four = packMcCvn10Cvr(inp);
  const cvr = Buffer.alloc(6);
  four.copy(cvr, 0);
  cvr[4] = clampByte(inp.lastOnlineAtcLow);
  // Byte 6: issuer-discretionary in upper nibble, reserved lower nibble.
  cvr[5] = (clampNibble(inp.issuerDiscretionary) & 0x0f) << 4;
  return cvr;
}

/**
 * Pack a 4-byte CVR for Visa VSDC CVN 10 (see header comment for bits).
 */
export function packVisaCvn10Cvr(inp: CvrInputs = {}): Buffer {
  const cvr = Buffer.alloc(4);

  // Byte 1 — cryptogram outcome flags (aligned with Mastercard CVN 10 byte 1
  // plus Visa-specific b3/b2 for AAF tracking).
  cvr[0] =
    (inp.aacSecondGen ? 0x80 : 0) |
    (inp.tcSecondGen ? 0x40 : 0) |
    (inp.aacFirstGen ? 0x20 : 0) |
    (inp.tcFirstGen ? 0x10 : 0) |
    (inp.arqcFirstGen ? 0x08 : 0);
  // b3..b1 reserved at perso

  // Byte 2 — script counters
  cvr[1] =
    ((clampNibble(inp.scriptProcessedCount) & 0x0f) << 4) |
    (clampNibble(inp.scriptFailedCount) & 0x0f);

  // Byte 3 — online / PIN / script state
  cvr[2] =
    (inp.unableToGoOnline ? 0x80 : 0) |
    (inp.offlinePinPerformed ? 0x40 : 0) |
    (inp.offlinePinFailed ? 0x20 : 0) |
    (inp.pinTryLimitExceeded ? 0x10 : 0) |
    (inp.lastOnlineNotCompleted ? 0x08 : 0) |
    (inp.scriptReceived ? 0x04 : 0) |
    (inp.scriptFailed ? 0x02 : 0);
  // b1 reserved

  // Byte 4 — authentication + issuer-discretionary nibble.
  //   b8 = "Issuer Authentication performed" (positive form). We only accept
  //        `issuerAuthNotPerformed`; treat explicit `false` as "performed".
  //   At perso both remain 0 (no issuer auth has happened yet).
  const issuerAuthPerformed = inp.issuerAuthNotPerformed === false;
  cvr[3] =
    (issuerAuthPerformed ? 0x80 : 0) |
    (inp.issuerAuthFailed ? 0x40 : 0) |
    (inp.cdaPerformed ? 0x20 : 0) |
    (inp.offlineDdaPerformed ? 0x10 : 0) |
    (clampNibble(inp.issuerDiscretionary) & 0x0f);

  return cvr;
}

/**
 * Pack a 4-byte CVR for Visa qVSDC CVN 22 (contactless).
 */
export function packVisaCvn22Cvr(inp: CvrInputs = {}): Buffer {
  const cvr = Buffer.alloc(4);

  // Byte 1 — same AC outcome flags as CVN 10/18
  cvr[0] =
    (inp.aacSecondGen ? 0x80 : 0) |
    (inp.tcSecondGen ? 0x40 : 0) |
    (inp.aacFirstGen ? 0x20 : 0) |
    (inp.tcFirstGen ? 0x10 : 0) |
    (inp.arqcFirstGen ? 0x08 : 0);

  // Byte 2 — qVSDC-specific flags
  cvr[1] =
    (inp.qvsdcGenerated ? 0x80 : 0) |
    (inp.qvsdcPpse ? 0x40 : 0) |
    (inp.readerFddaPerformed ? 0x20 : 0) |
    (inp.offlineOnly ? 0x10 : 0);
  // b4..b1 reserved

  // Byte 3 — script counters (qVSDC rarely uses these but layout is reserved)
  cvr[2] =
    ((clampNibble(inp.scriptProcessedCount) & 0x0f) << 4) |
    (clampNibble(inp.scriptFailedCount) & 0x0f);

  // Byte 4 — issuer-discretionary nibble in upper half
  cvr[3] = (clampNibble(inp.issuerDiscretionary) & 0x0f) << 4;

  return cvr;
}

// ---------------------------------------------------------------------------
// DAC/IDN derivation
// ---------------------------------------------------------------------------

/**
 * Resolve the 2-byte DAC/IDN for the IAD.
 *
 * Precedence:
 *   1. explicit `options.dacIdn` (issuer-supplied)
 *   2. SHA256(PAN || CSN)[0..1] when both are provided
 *   3. 0x0000 fallback (warns once)
 */
export function resolveDacIdn(opts: BuildIadOptions): Buffer {
  if (opts.dacIdn) {
    if (opts.dacIdn.length !== 2) {
      throw new Error(`DAC/IDN must be exactly 2 bytes, got ${opts.dacIdn.length}`);
    }
    return Buffer.from(opts.dacIdn);
  }
  if (opts.pan && opts.csn) {
    return deriveDacIdn(opts.pan, opts.csn);
  }
  warnOnce(
    'zero-dacidn',
    'DAC/IDN not supplied and cannot be derived (missing pan+csn) — using 0x0000. ' +
      'Live interchange expects a stable per-card value that matches the SDA/CDA payload.',
  );
  return Buffer.alloc(2); // 0x00 0x00
}

/**
 * Deterministic DAC/IDN derivation: SHA256(PAN || CSN)[0..1].
 *
 * PAN is treated as its ASCII digit representation (not packed BCD) for
 * portability — anyone can recompute this from the printed PAN + CSN.
 * CSN is a hex string ("01", "03", …) matching tag 5F34.
 */
export function deriveDacIdn(pan: string, csn: string): Buffer {
  const h = createHash('sha256');
  h.update(Buffer.from(pan, 'utf8'));
  h.update(Buffer.from(csn, 'utf8'));
  return h.digest().subarray(0, 2);
}

// ---------------------------------------------------------------------------
// Mastercard M/Chip Advance IAD builders
// ---------------------------------------------------------------------------

function packIcvv(icvv: string): Buffer {
  const padded = icvv.padEnd(4, '0');
  return Buffer.from(padded, 'hex');
}

/**
 * CVN 10 IAD (M/Chip Advance legacy TDES):
 *   Length(1)=0x0A, DKI(1), CVN(1)=0x0A, CVR(4), DAC/IDN(2), iCVV(2)
 *   Total: 11 bytes
 */
function buildMcCvn10(dki: number, icvv: string, opts: BuildIadOptions): Buffer {
  const iad = Buffer.alloc(11);
  let off = 0;
  iad[off++] = 0x0a;                                   // Length
  iad[off++] = dki & 0xff;                             // DKI
  iad[off++] = 0x0a;                                   // CVN = 10
  packMcCvn10Cvr(opts.cvr).copy(iad, off); off += 4;   // CVR (4 bytes)
  resolveDacIdn(opts).copy(iad, off); off += 2;        // DAC/IDN
  packIcvv(icvv).copy(iad, off);                       // iCVV (2 bytes BCD)
  return iad;
}

/**
 * CVN 17 IAD (M/Chip Advance, AES session keys):
 *   Length(1)=0x12, DKI(1), CVN(1)=0x11, CVR(6), DAC/IDN(2), Counters(4),
 *   Last online ATC(2), iCVV(2)
 *   Total: 19 bytes
 *
 * NOTE: In the M/Chip CPS, "Counters(4)" is a contiguous 4-byte block
 * holding ATC + velocity counters. All 0x00 at perso.
 */
function buildMcCvn17(dki: number, icvv: string, opts: BuildIadOptions): Buffer {
  const iad = Buffer.alloc(19);
  let off = 0;
  iad[off++] = 0x12;                                      // Length
  iad[off++] = dki & 0xff;                                // DKI
  iad[off++] = 0x11;                                      // CVN = 17
  packMcCvn17Or18Cvr(opts.cvr).copy(iad, off); off += 6;  // CVR (6 bytes)
  resolveDacIdn(opts).copy(iad, off); off += 2;           // DAC/IDN
  off += 4;                                               // Counters — 0 at perso
  off += 2;                                               // Last online ATC — 0 at perso
  packIcvv(icvv).copy(iad, off);                          // iCVV
  return iad;
}

/**
 * CVN 18 IAD (M/Chip Advance, CDA support):
 *   Same structure as CVN 17; CVN byte = 0x12.
 *   CDA bit in CVR byte 2 is set when CDA is performed (not at perso).
 *   Total: 19 bytes
 */
function buildMcCvn18(dki: number, icvv: string, opts: BuildIadOptions): Buffer {
  const iad = Buffer.alloc(19);
  let off = 0;
  iad[off++] = 0x12;                                      // Length
  iad[off++] = dki & 0xff;                                // DKI
  iad[off++] = 0x12;                                      // CVN = 18
  packMcCvn17Or18Cvr(opts.cvr).copy(iad, off); off += 6;  // CVR (6 bytes)
  resolveDacIdn(opts).copy(iad, off); off += 2;           // DAC/IDN
  off += 4;                                               // Counters — 0 at perso
  off += 2;                                               // Last online ATC — 0 at perso
  packIcvv(icvv).copy(iad, off);                          // iCVV
  return iad;
}

// ---------------------------------------------------------------------------
// Visa VSDC / qVSDC IAD builders
// ---------------------------------------------------------------------------

/**
 * Visa CVN 10 IAD (VSDC legacy):
 *   Length(1)=0x06, DKI(1), CVN(1)=0x0A, CVR(4)
 *   Total: 7 bytes
 *
 * The Visa CVN 10 IAD has no DAC/IDN slot — DAC travels in the separate
 * SDA tag (Tag 9F45) for VSDC. We still accept `opts.dacIdn` for parity
 * with the Mastercard builders but it's ignored here.
 */
function buildVisaCvn10(dki: number, opts: BuildIadOptions): Buffer {
  const iad = Buffer.alloc(7);
  iad[0] = 0x06;
  iad[1] = dki & 0xff;
  iad[2] = 0x0a;
  packVisaCvn10Cvr(opts.cvr).copy(iad, 3);
  return iad;
}

/**
 * Visa CVN 18 IAD (VSDC with CDA):
 *   Length(1)=0x07, DKI(1), CVN(1)=0x12, CVR(4), IDD_length(1)=0x00
 *   Total: 8 bytes
 */
function buildVisaCvn18(dki: number, opts: BuildIadOptions): Buffer {
  const iad = Buffer.alloc(8);
  iad[0] = 0x07;
  iad[1] = dki & 0xff;
  iad[2] = 0x12;
  packVisaCvn10Cvr(opts.cvr).copy(iad, 3);
  iad[7] = 0x00; // IDD length = 0 (no IDD block for this variant)
  return iad;
}

/**
 * Visa CVN 22 IAD (qVSDC contactless — most common modern Visa):
 *   Per VCPS 2.2, the IAD is 32 bytes:
 *   Format(1)=0x1F, CVN(1)=0x22, DKI(1), CVR(4), IDD_len(1),
 *   IDD: WalletProviderID(4) + derivation(2) + iCVV(2) + padding
 *   Total: 32 bytes
 */
function buildVisaCvn22(dki: number, icvv: string, opts: BuildIadOptions): Buffer {
  const iad = Buffer.alloc(32);
  let off = 0;
  iad[off++] = 0x1f;                                 // Format byte (CVN-22 marker)
  iad[off++] = 0x22;                                 // CVN = 22
  iad[off++] = dki & 0xff;                           // DKI
  packVisaCvn22Cvr(opts.cvr).copy(iad, off); off += 4; // CVR (4 bytes)

  // IDD (Issuer Discretionary Data) fills to 32 bytes total
  const iddLen = 32 - off - 1; // 24 bytes
  iad[off++] = iddLen;
  // Wallet Provider ID (4), derivation data (2)
  off += 6;
  // iCVV (2 bytes BCD)
  packIcvv(icvv).copy(iad, off);
  // Remaining bytes zero-padded by Buffer.alloc

  return iad;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function clampNibble(v: number | undefined): number {
  if (v === undefined || !Number.isFinite(v)) return 0;
  const n = Math.trunc(v);
  if (n < 0) return 0;
  if (n > 0x0f) return 0x0f;
  return n;
}

function clampByte(v: number | undefined): number {
  if (v === undefined || !Number.isFinite(v)) return 0;
  const n = Math.trunc(v);
  if (n < 0) return 0;
  if (n > 0xff) return 0xff;
  return n;
}

// ---------------------------------------------------------------------------
// Test hook — reset the "warned once" set.
// ---------------------------------------------------------------------------

/** @internal Test-only: clear the once-per-process warning set. */
export function __resetIadBuilderWarnings(): void {
  warnedOnce.clear();
}
