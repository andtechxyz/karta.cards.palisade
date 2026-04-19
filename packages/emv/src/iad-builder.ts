/**
 * IAD (Issuer Application Data, Tag 9F10) construction per CVN.
 *
 * Builds the correct IAD format based on Cryptogram Version Number:
 *
 * Mastercard (M/Chip Advance):
 * - CVN 10: Legacy TDES
 * - CVN 17: AES session keys
 * - CVN 18: AES with CDA support
 *
 * Visa (VSDC / qVSDC):
 * - CVN 10: Legacy TDES (Visa VSDC)
 * - CVN 18: VSDC with CDA
 * - CVN 22: qVSDC contactless (most common modern Visa)
 *
 * Ported from palisade-data-prep/app/services/iad_builder.py.
 */

export type Scheme = 'mchip_advance' | 'vsdc';

/**
 * Build IAD (Tag 9F10) value bytes for the given CVN and scheme.
 *
 * @param cvn   Cryptogram Version Number (10, 17, 18, 22)
 * @param dki   Derivation Key Index (default 0x01)
 * @param icvv  iCVV value (3 digits string, e.g. "123")
 * @param scheme "mchip_advance" or "vsdc"
 * @returns IAD bytes (Tag 9F10 value)
 */
export function buildIad(cvn: number, dki = 0x01, icvv = '000', scheme: Scheme = 'mchip_advance'): Buffer {
  if (scheme === 'vsdc') {
    switch (cvn) {
      case 10: return buildVisaCvn10(dki);
      case 18: return buildVisaCvn18(dki);
      case 22: return buildVisaCvn22(dki, icvv);
      default: throw new Error(`Unsupported Visa CVN: ${cvn}`);
    }
  }

  // Mastercard
  switch (cvn) {
    case 10: return buildMcCvn10(dki, icvv);
    case 17: return buildMcCvn17(dki, icvv);
    case 18: return buildMcCvn18(dki, icvv);
    default: throw new Error(`Unsupported Mastercard CVN: ${cvn}`);
  }
}

// ---------------------------------------------------------------------------
// Mastercard M/Chip Advance
// ---------------------------------------------------------------------------

function packIcvv(icvv: string): Buffer {
  const padded = icvv.padEnd(4, '0');
  return Buffer.from(padded, 'hex');
}

/**
 * CVN 10 IAD (M/Chip Advance legacy):
 *   Length(1)=0x0A, DKI(1), CVN(1)=0x0A, CVR(4), DAC/IDN(2), iCVV(2)
 *   Total: 11 bytes
 */
function buildMcCvn10(dki: number, icvv: string): Buffer {
  const iad = Buffer.alloc(11);
  let off = 0;
  iad[off++] = 0x0a;             // Length
  iad[off++] = dki & 0xff;       // DKI
  iad[off++] = 0x0a;             // CVN = 10
  off += 4;                      // CVR placeholder (4 bytes zeros)
  off += 2;                      // DAC/IDN placeholder
  packIcvv(icvv).copy(iad, off); // iCVV (2 bytes BCD)
  return iad;
}

/**
 * CVN 17 IAD (M/Chip Advance, AES session keys):
 *   Length(1)=0x12, DKI(1), CVN(1)=0x11, CVR(6), DAC/IDN(2), Counters(4),
 *   Last online ATC(2), iCVV(2)
 *   Total: 19 bytes
 */
function buildMcCvn17(dki: number, icvv: string): Buffer {
  const iad = Buffer.alloc(19);
  let off = 0;
  iad[off++] = 0x12;             // Length
  iad[off++] = dki & 0xff;       // DKI
  iad[off++] = 0x11;             // CVN = 17
  off += 6;                      // CVR placeholder (6 bytes)
  off += 2;                      // DAC/IDN placeholder
  off += 4;                      // Counters / crypto capabilities
  off += 2;                      // Last online ATC
  packIcvv(icvv).copy(iad, off); // iCVV
  return iad;
}

/**
 * CVN 18 IAD (M/Chip Advance, CDA support):
 *   Same structure as CVN 17 but CVN byte = 0x12.
 *   CDA bit set in CVR when CDA is active.
 *   Total: 19 bytes
 */
function buildMcCvn18(dki: number, icvv: string): Buffer {
  const iad = Buffer.alloc(19);
  let off = 0;
  iad[off++] = 0x12;             // Length
  iad[off++] = dki & 0xff;       // DKI
  iad[off++] = 0x12;             // CVN = 18
  off += 6;                      // CVR placeholder
  off += 2;                      // DAC/IDN placeholder
  off += 4;                      // Counters
  off += 2;                      // Last online ATC
  packIcvv(icvv).copy(iad, off); // iCVV
  return iad;
}

// ---------------------------------------------------------------------------
// Visa VSDC / qVSDC
// ---------------------------------------------------------------------------

/**
 * Visa CVN 10 IAD (VSDC legacy):
 *   Length(1)=0x06, DKI(1), CVN(1)=0x0A, CVR(4)
 *   Total: 7 bytes
 */
function buildVisaCvn10(dki: number): Buffer {
  const iad = Buffer.alloc(7);
  iad[0] = 0x06;
  iad[1] = dki & 0xff;
  iad[2] = 0x0a;
  // CVR placeholder (4 bytes zeros)
  return iad;
}

/**
 * Visa CVN 18 IAD (VSDC with CDA):
 *   Length(1)=0x07, DKI(1), CVN(1)=0x12, CVR(4), IDD_length(1)=0x00
 *   Total: 8 bytes
 */
function buildVisaCvn18(dki: number): Buffer {
  const iad = Buffer.alloc(8);
  iad[0] = 0x07;
  iad[1] = dki & 0xff;
  iad[2] = 0x12;
  // CVR placeholder (4 bytes zeros)
  iad[7] = 0x00; // IDD length
  return iad;
}

/**
 * Visa CVN 22 IAD (qVSDC contactless — most common modern Visa):
 *   Per VCPS 2.2, the IAD is 32 bytes:
 *   Format(1)=0x1F, CVN(1)=0x22, DKI(1), CVR(4), IDD_len(1),
 *   IDD: WalletProviderID(4) + derivation(2) + iCVV(2) + padding
 *   Total: 32 bytes
 */
function buildVisaCvn22(dki: number, icvv: string): Buffer {
  const iad = Buffer.alloc(32);
  let off = 0;
  iad[off++] = 0x1f;             // Format byte (indicates CVN 22)
  iad[off++] = 0x22;             // CVN = 22
  iad[off++] = dki & 0xff;       // DKI
  off += 4;                      // CVR placeholder

  // IDD (Issuer Discretionary Data) — fills to 32 bytes total
  const iddLen = 32 - off - 1;   // 24 bytes
  iad[off++] = iddLen;
  // Wallet Provider ID (4), derivation data (2)
  off += 6;
  // iCVV (2 bytes BCD)
  packIcvv(icvv).copy(iad, off);
  // Remaining bytes are zero-padded (Buffer.alloc does this)

  return iad;
}
