/**
 * ParamBundle builder — replaces SADBuilder for the C17/C22 prototype.
 *
 * Instead of shipping a fully-built DGI/TLV image to the chip, we ship
 * a compact parameter bundle.  The PA v3 applet receives the bundle,
 * parses it, and assembles the DGIs inline before committing to NVM.
 *
 * WIRE FORMAT
 * -----------
 *
 * The bundle is a flat TLV stream using single-byte tags (0x01..0x7F)
 * and BER-short-form lengths (< 0x80).  Any field that exceeds the
 * short-form limit (128+ bytes) is rejected — ParamBundle size is
 * capped so the whole encrypted blob fits in one extended APDU.
 *
 * Tag conventions (ASCII-ish for readability in a hex dump):
 *
 *   ID     Name                        Len
 *   ----   --------------------------  ---
 *   0x01   PAN (BCD, F-padded)         8-10
 *   0x02   PSN (BCD)                   1
 *   0x03   Expiry YYMM (BCD, BE)       2
 *   0x04   Effective YYMM (BCD, BE)    2
 *   0x05   Service code (BCD)          2
 *   0x06   Scheme byte                 1      (0x01 = MChip, 0x02 = VSDC)
 *   0x07   CVN byte                    1      (0x12 = CVN 18)
 *   0x08   AID                         5-16
 *   0x09   MK-AC                       16
 *   0x0A   MK-SMI                      16
 *   0x0B   MK-SMC                      16
 *   0x0C   AIP                         2
 *   0x0D   AFL                         4-n
 *   0x0E   AUC                         2
 *   0x0F   IAC-Default                 5
 *   0x10   IAC-Denial                  5
 *   0x11   IAC-Online                  5
 *   0x12   CVM List                    10-252
 *   0x13   Bank ID (BE uint32)         4
 *   0x14   Program ID (BE uint32)      4
 *   0x15   Post-provision URL          <= 64
 *   0x16   ICC RSA priv key (PKCS#1)   128
 *   0x17   ICC PK Certificate          1-244  (server-signed 9F46)
 *   0x18   App label (ASCII)           <= 16
 *   0x19   App preferred name (ASCII)  <= 16
 *   0x1A   App version number          2
 *   0x1B   Currency code               2
 *   0x1C   Currency exponent           1
 *   0x1D   Country code                2
 *   0x1E   iCVV (for Track 2)          3
 *   0x1F   Issuer PK exponent          1-3
 *   0x20   Issuer PK certificate       >= 128
 *   0x21   Issuer PK remainder         0-n
 *   0x22   CA PK index                 1
 *
 * Fields marked required below are the minimum the PA v3 applet must
 * see to produce a valid MChip CVN 18 perso image.  Optional fields
 * fall back to scheme defaults baked into the applet.
 *
 * MIRROR ON THE APPLET SIDE
 * -------------------------
 *
 * applets/pa/.../ParamBundleParser.java implements the parser.  Tag
 * ranges 0x01..0x7F use single-byte tags; lengths use BER-short-form
 * (< 0x80) exclusively — no 0x81/0x82 extended lengths.  This keeps
 * the applet parser tight (one byte tag, one byte length, no
 * branching).
 *
 * Any change to tag numbers, lengths, or ordering expectations must
 * be mirrored in the applet in the same commit.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ---------------------------------------------------------------------------
// Tag constants — single source of truth, re-used by parser/builder/tests
// ---------------------------------------------------------------------------

export const ParamTag = {
  PAN: 0x01,
  PSN: 0x02,
  EXPIRY: 0x03,
  EFFECTIVE: 0x04,
  SERVICE_CODE: 0x05,
  SCHEME: 0x06,
  CVN: 0x07,
  AID: 0x08,
  MK_AC: 0x09,
  MK_SMI: 0x0a,
  MK_SMC: 0x0b,
  AIP: 0x0c,
  AFL: 0x0d,
  AUC: 0x0e,
  IAC_DEFAULT: 0x0f,
  IAC_DENIAL: 0x10,
  IAC_ONLINE: 0x11,
  CVM_LIST: 0x12,
  BANK_ID: 0x13,
  PROG_ID: 0x14,
  POST_PROVISION_URL: 0x15,
  ICC_RSA_PRIV: 0x16,
  ICC_PK_CERT: 0x17,
  APP_LABEL: 0x18,
  APP_PREFERRED_NAME: 0x19,
  APP_VERSION: 0x1a,
  CURRENCY_CODE: 0x1b,
  CURRENCY_EXPONENT: 0x1c,
  COUNTRY_CODE: 0x1d,
  ICVV: 0x1e,
  ISSUER_PK_EXP: 0x1f,
  ISSUER_PK_CERT: 0x20,
  ISSUER_PK_REMAINDER: 0x21,
  CA_PK_INDEX: 0x22,
} as const;

export type ParamTagValue = (typeof ParamTag)[keyof typeof ParamTag];

/**
 * Max size for any single field.  The applet parser accepts BER
 * short-form (len < 0x80, 1 byte) and BER long-form 0x81 (1 length
 * byte, up to 255).  0x82 (2 length bytes, up to 65535) is NOT
 * supported — keeps the applet parser tight, and no single
 * ParamBundle field should exceed 255 bytes.
 *
 * Fields that are structurally larger (e.g. ICC RSA priv at 128 bytes
 * for a 1024-bit key) use 0x81 long-form automatically.
 */
export const MAX_FIELD_LEN = 0xff; // 255

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

export interface ParamBundleInput {
  /** Full PAN, digit string.  F-padded by the builder. */
  pan: string;
  /** PAN Sequence Number, 2-digit string. */
  psn: string;
  /** Application Expiry Date, YYMM. */
  expiryYymm: string;
  /** Application Effective Date, YYMM. */
  effectiveYymm: string;
  /** Service code, 3-digit string. */
  serviceCode: string;
  /** Scheme: 'mchip' | 'vsdc' (prototype supports mchip only). */
  scheme: 'mchip' | 'vsdc';
  /** Card Verification Number (MChip CVN 10/17/18, Visa CVN 10/18/22). */
  cvn: number;
  /** Application ID (e.g. A0000000041010 for MC-EMV). */
  aid: Buffer;

  /** 16-byte master key for Application Cryptogram derivation. */
  mkAc: Buffer;
  /** 16-byte master key for Secure Messaging Integrity. */
  mkSmi: Buffer;
  /** 16-byte master key for Secure Messaging Confidentiality. */
  mkSmc: Buffer;

  /** 2-byte Application Interchange Profile. */
  aip: Buffer;
  /** Application File Locator (var length, multiple of 4). */
  afl: Buffer;
  /** 2-byte Application Usage Control. */
  auc: Buffer;
  /** 5-byte Issuer Action Code - Default. */
  iacDefault: Buffer;
  /** 5-byte Issuer Action Code - Denial. */
  iacDenial: Buffer;
  /** 5-byte Issuer Action Code - Online. */
  iacOnline: Buffer;
  /** Card Verification Method List. */
  cvmList: Buffer;

  /** 4-byte big-endian bank identifier. */
  bankId: number;
  /** 4-byte big-endian program identifier. */
  progId: number;
  /** Hostname for post-provisioning URL, ≤ 64 bytes ASCII. */
  postProvisionUrl: string;

  /** PKCS#1 DER-encoded ICC RSA private key (1024-bit CRT form typical). */
  iccRsaPriv: Buffer;
  /** Server-signed ICC PK Certificate (Tag 9F46). */
  iccPkCert: Buffer;

  /** Issuer PK Exponent (Tag 9F32), typically 1 or 3 bytes. */
  issuerPkExp: Buffer;
  /** Issuer PK Certificate (Tag 90). */
  issuerPkCert: Buffer;
  /** Optional Issuer PK Remainder (Tag 92). */
  issuerPkRemainder?: Buffer;
  /** CA PK Index (Tag 8F), 1 byte. */
  caPkIndex: Buffer;

  /** Optional: application label (e.g. "MASTERCARD"). */
  appLabel?: string;
  /** Optional: app preferred name. */
  appPreferredName?: string;
  /** 2-byte app version number. */
  appVersion: Buffer;
  /** 2-byte currency code. */
  currencyCode: Buffer;
  /** 1-byte currency exponent. */
  currencyExponent: Buffer;
  /** 2-byte country code. */
  countryCode: Buffer;
  /** 3-byte iCVV (used in Track 2 synthesis). */
  icvv: Buffer;
}

/**
 * Build the flat TLV ParamBundle bytes.  Deterministic given the same
 * input — tag emission order is fixed (ascending tag number) so two
 * servers building the same bundle produce byte-identical output.
 *
 * Applet-side parser is order-agnostic (walks TLVs, stores by tag),
 * but fixing the order keeps byte-parity tests simple.
 */
export function buildParamBundle(input: ParamBundleInput): Buffer {
  const parts: Array<{ tag: number; value: Buffer }> = [];

  const push = (tag: number, value: Buffer): void => {
    if (value.length > MAX_FIELD_LEN) {
      throw new Error(
        `param-bundle: tag 0x${tag.toString(16)} is ${value.length} bytes, exceeds MAX_FIELD_LEN=${MAX_FIELD_LEN}`,
      );
    }
    parts.push({ tag, value });
  };

  // --- Required fields ----------------------------------------------------
  push(ParamTag.PAN, encodePan(input.pan));
  push(ParamTag.PSN, encodeBcdField(input.psn, 2));
  push(ParamTag.EXPIRY, encodeBcdField(input.expiryYymm, 4));
  push(ParamTag.EFFECTIVE, encodeBcdField(input.effectiveYymm, 4));
  // Service code is 3 digits; BCD requires even nibbles, so we pad
  // to 4 nibbles (2 bytes) with a leading zero.  Simulator + applet
  // strip the leading zero on decode.
  push(ParamTag.SERVICE_CODE, encodeBcdField(input.serviceCode, 4));
  push(ParamTag.SCHEME, Buffer.from([schemeByte(input.scheme)]));
  push(ParamTag.CVN, Buffer.from([input.cvn & 0xff]));
  push(ParamTag.AID, input.aid);
  push(ParamTag.MK_AC, validateLen('MK_AC', input.mkAc, 16));
  push(ParamTag.MK_SMI, validateLen('MK_SMI', input.mkSmi, 16));
  push(ParamTag.MK_SMC, validateLen('MK_SMC', input.mkSmc, 16));
  push(ParamTag.AIP, validateLen('AIP', input.aip, 2));
  push(ParamTag.AFL, input.afl);
  push(ParamTag.AUC, validateLen('AUC', input.auc, 2));
  push(ParamTag.IAC_DEFAULT, validateLen('IAC_DEFAULT', input.iacDefault, 5));
  push(ParamTag.IAC_DENIAL, validateLen('IAC_DENIAL', input.iacDenial, 5));
  push(ParamTag.IAC_ONLINE, validateLen('IAC_ONLINE', input.iacOnline, 5));
  push(ParamTag.CVM_LIST, input.cvmList);
  push(ParamTag.BANK_ID, u32be(input.bankId));
  push(ParamTag.PROG_ID, u32be(input.progId));
  push(ParamTag.POST_PROVISION_URL, Buffer.from(input.postProvisionUrl, 'ascii'));
  push(ParamTag.ICC_RSA_PRIV, input.iccRsaPriv);
  push(ParamTag.ICC_PK_CERT, input.iccPkCert);
  push(ParamTag.APP_VERSION, validateLen('APP_VERSION', input.appVersion, 2));
  push(ParamTag.CURRENCY_CODE, validateLen('CURRENCY_CODE', input.currencyCode, 2));
  push(ParamTag.CURRENCY_EXPONENT, validateLen('CURRENCY_EXPONENT', input.currencyExponent, 1));
  push(ParamTag.COUNTRY_CODE, validateLen('COUNTRY_CODE', input.countryCode, 2));
  push(ParamTag.ICVV, validateLen('ICVV', input.icvv, 3));
  push(ParamTag.ISSUER_PK_EXP, input.issuerPkExp);
  push(ParamTag.ISSUER_PK_CERT, input.issuerPkCert);
  if (input.issuerPkRemainder && input.issuerPkRemainder.length > 0) {
    push(ParamTag.ISSUER_PK_REMAINDER, input.issuerPkRemainder);
  }
  push(ParamTag.CA_PK_INDEX, validateLen('CA_PK_INDEX', input.caPkIndex, 1));

  // --- Optional fields ---------------------------------------------------
  if (input.appLabel) push(ParamTag.APP_LABEL, Buffer.from(input.appLabel, 'ascii'));
  if (input.appPreferredName) {
    push(ParamTag.APP_PREFERRED_NAME, Buffer.from(input.appPreferredName, 'ascii'));
  }

  // Sort by tag for deterministic output.  Applet parser doesn't care
  // about order, but tests do.
  parts.sort((a, b) => a.tag - b.tag);

  const chunks: Buffer[] = [];
  for (const { tag, value } of parts) {
    chunks.push(Buffer.from([tag]));
    chunks.push(encodeLen(value.length));
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

/**
 * BER length encoder.  Short form if <0x80 (one byte); long-form 0x81
 * for 128-255.  0x82 not supported — MAX_FIELD_LEN caps at 255.
 */
function encodeLen(len: number): Buffer {
  if (len < 0) throw new Error(`param-bundle: length cannot be negative: ${len}`);
  if (len < 0x80) return Buffer.from([len]);
  if (len <= 0xff) return Buffer.from([0x81, len]);
  throw new Error(`param-bundle: length ${len} exceeds MAX_FIELD_LEN=${MAX_FIELD_LEN}`);
}

/**
 * Parse a flat ParamBundle back into a Map<tag, Buffer>.  Used by the
 * byte-parity tests (we implement the applet's parser in TS and
 * run it against the same bundle) and by any debugging tooling.
 */
export function parseParamBundle(data: Buffer): Map<number, Buffer> {
  const out = new Map<number, Buffer>();
  let off = 0;
  while (off < data.length) {
    if (off + 2 > data.length) {
      throw new Error(`param-bundle: truncated at offset ${off}`);
    }
    const tag = data[off];
    off += 1;

    // Length: short-form (< 0x80, one byte) or long-form 0x81
    // (one length byte, up to 255).  0x82+ not supported.
    const lenByte = data[off];
    let len: number;
    if (lenByte < 0x80) {
      len = lenByte;
      off += 1;
    } else if (lenByte === 0x81) {
      if (off + 1 >= data.length) {
        throw new Error(`param-bundle: truncated 0x81 length at offset ${off}`);
      }
      len = data[off + 1];
      off += 2;
    } else {
      throw new Error(
        `param-bundle: tag 0x${tag.toString(16)} uses unsupported length byte 0x${lenByte.toString(16)} (expected <0x80 or 0x81)`,
      );
    }

    if (off + len > data.length) {
      throw new Error(
        `param-bundle: tag 0x${tag.toString(16)} overruns buffer (len=${len}, remaining=${data.length - off})`,
      );
    }
    if (out.has(tag)) {
      throw new Error(`param-bundle: duplicate tag 0x${tag.toString(16)}`);
    }
    out.set(tag, Buffer.from(data.subarray(off, off + len)));
    off += len;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function schemeByte(scheme: 'mchip' | 'vsdc'): number {
  switch (scheme) {
    case 'mchip':
      return 0x01;
    case 'vsdc':
      return 0x02;
    default: {
      const _exhaustive: never = scheme;
      throw new Error(`unknown scheme: ${_exhaustive}`);
    }
  }
}

function u32be(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function validateLen(name: string, b: Buffer, expected: number): Buffer {
  if (b.length !== expected) {
    throw new Error(`param-bundle: ${name} expected ${expected} bytes, got ${b.length}`);
  }
  return b;
}

/**
 * Encode a PAN digit-string as BCD, F-padded to even nibble count.
 * e.g. "12345678901234567"  (17 digits) → 0x12, 0x34, 0x56, 0x78, 0x90,
 * 0x12, 0x34, 0x56, 0x7F (9 bytes).
 */
function encodePan(panDigits: string): Buffer {
  if (!/^\d{12,19}$/.test(panDigits)) {
    throw new Error(`param-bundle: PAN must be 12-19 digits, got "${panDigits}"`);
  }
  let hex = panDigits;
  if (hex.length % 2 !== 0) hex += 'F';
  return Buffer.from(hex, 'hex');
}

/**
 * Encode a decimal digit-string as big-endian BCD, padded to `nibbles`
 * nibbles with leading zeros.
 */
function encodeBcdField(digits: string, nibbles: number): Buffer {
  if (!/^\d+$/.test(digits)) {
    throw new Error(`param-bundle: expected digits, got "${digits}"`);
  }
  if (digits.length > nibbles) {
    throw new Error(`param-bundle: "${digits}" has more digits than fits in ${nibbles} nibbles`);
  }
  const padded = digits.padStart(nibbles, '0');
  return Buffer.from(padded, 'hex');
}

// ---------------------------------------------------------------------------
// Known-answer vector exporter for the JavaCard dev
// ---------------------------------------------------------------------------

/**
 * Emit a deterministic reference ParamBundle from a fixed input — used
 * to hand a byte-parity goldens file to the JavaCard dev so their
 * applet parser is validated independently of our server.
 *
 * The input here is intentionally a "simplest valid MChip CVN 18
 * card" — if your implementation can round-trip this bundle, it
 * handles the real cases.
 */
export function referenceBundleForJcDev(): Buffer {
  return buildParamBundle({
    pan: '5413339800000003',
    psn: '01',
    expiryYymm: '3012',
    effectiveYymm: '2505',
    serviceCode: '201',
    scheme: 'mchip',
    cvn: 0x12,
    aid: Buffer.from('A0000000041010', 'hex'),
    mkAc: Buffer.alloc(16, 0xaa),
    mkSmi: Buffer.alloc(16, 0xbb),
    mkSmc: Buffer.alloc(16, 0xcc),
    aip: Buffer.from('3900', 'hex'),
    afl: Buffer.from('08010100', 'hex'),
    auc: Buffer.from('FF00', 'hex'),
    iacDefault: Buffer.from('0000000000', 'hex'),
    iacDenial: Buffer.from('0000000000', 'hex'),
    iacOnline: Buffer.from('F470C4A800', 'hex'),
    cvmList: Buffer.from(
      '000000000000000042031E031F03000000',
      'hex',
    ),
    bankId: 0x00545490,
    progId: 0x00000001,
    postProvisionUrl: 'tap.karta.cards',
    iccRsaPriv: Buffer.alloc(128, 0x11),
    iccPkCert: Buffer.alloc(100, 0x22),
    issuerPkExp: Buffer.from('03', 'hex'),
    issuerPkCert: Buffer.alloc(112, 0x33),
    caPkIndex: Buffer.from('F5', 'hex'),
    appLabel: 'MASTERCARD',
    appVersion: Buffer.from('0002', 'hex'),
    currencyCode: Buffer.from('0840', 'hex'),
    currencyExponent: Buffer.from('02', 'hex'),
    countryCode: Buffer.from('0840', 'hex'),
    icvv: Buffer.from('000123', 'hex'),
  });
}

/**
 * Load a golden ParamBundle from disk — used by the byte-parity tests.
 * Call sites pass a relative path from packages/emv/src/.
 */
export function loadGoldenBundle(relPath: string): Buffer {
  const here = dirname(fileURLToPath(import.meta.url));
  return readFileSync(join(here, relPath));
}
