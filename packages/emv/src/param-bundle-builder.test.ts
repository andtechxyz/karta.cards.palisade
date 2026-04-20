/**
 * Tests for the ParamBundle builder + parser (server-side only).
 *
 * Byte-parity between ParamBundle→simulatedChipBuild and the legacy
 * SADBuilder is covered by a separate byte-parity test — see
 * scheme-mchip.test.ts.
 */

import { describe, it, expect } from 'vitest';
import {
  ParamTag,
  MAX_FIELD_LEN,
  buildParamBundle,
  parseParamBundle,
  referenceBundleForJcDev,
  type ParamBundleInput,
} from './param-bundle-builder.js';

const BASELINE: ParamBundleInput = {
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
  cvmList: Buffer.from('000000000000000042031E031F03000000', 'hex'),
  bankId: 0x00545490,
  progId: 0x00000001,
  postProvisionUrl: 'tap.karta.cards',
  iccRsaPriv: Buffer.alloc(126, 0x11),
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
};

describe('buildParamBundle / parseParamBundle round-trip', () => {
  it('round-trips all required fields', () => {
    const wire = buildParamBundle(BASELINE);
    const parsed = parseParamBundle(wire);

    // Spot-check a few fields.
    expect(parsed.get(ParamTag.PAN)?.toString('hex').toUpperCase()).toBe('5413339800000003');
    expect(parsed.get(ParamTag.SCHEME)?.[0]).toBe(0x01);
    expect(parsed.get(ParamTag.CVN)?.[0]).toBe(0x12);
    expect(parsed.get(ParamTag.MK_AC)?.length).toBe(16);
    expect(parsed.get(ParamTag.ICC_RSA_PRIV)?.length).toBe(126);
    expect(parsed.get(ParamTag.POST_PROVISION_URL)?.toString('ascii')).toBe(
      'tap.karta.cards',
    );
    expect(parsed.get(ParamTag.APP_LABEL)?.toString('ascii')).toBe('MASTERCARD');
  });

  it('emits tags in ascending order (deterministic)', () => {
    const wire = buildParamBundle(BASELINE);
    // Walk the TLVs and assert tag bytes are monotonically increasing.
    let prevTag = -1;
    let off = 0;
    while (off < wire.length) {
      const tag = wire[off];
      expect(tag).toBeGreaterThan(prevTag);
      prevTag = tag;
      const len = wire[off + 1];
      off += 2 + len;
    }
  });

  it('same input produces byte-identical output (determinism)', () => {
    const w1 = buildParamBundle(BASELINE);
    const w2 = buildParamBundle(BASELINE);
    expect(w1.equals(w2)).toBe(true);
  });

  it('omits optional appLabel when absent', () => {
    const { appLabel, ...rest } = BASELINE;
    void appLabel;
    const wire = buildParamBundle(rest);
    const parsed = parseParamBundle(wire);
    expect(parsed.has(ParamTag.APP_LABEL)).toBe(false);
  });

  it('emits ISSUER_PK_REMAINDER only when non-empty', () => {
    const withRem: ParamBundleInput = {
      ...BASELINE,
      issuerPkRemainder: Buffer.from('DEADBEEF', 'hex'),
    };
    const withoutRem: ParamBundleInput = {
      ...BASELINE,
      issuerPkRemainder: Buffer.alloc(0),
    };

    expect(parseParamBundle(buildParamBundle(withRem)).has(ParamTag.ISSUER_PK_REMAINDER)).toBe(true);
    expect(parseParamBundle(buildParamBundle(withoutRem)).has(ParamTag.ISSUER_PK_REMAINDER)).toBe(
      false,
    );
  });

  it('keeps the total bundle under a realistic size cap', () => {
    const wire = buildParamBundle(BASELINE);
    // Target: under 700 bytes so a 93-byte wire overhead + bundle
    // + 16-byte tag fits comfortably under the extended-APDU 64 KB
    // limit and well under any reasonable NFC transceive window.
    // BASELINE is a fully populated bundle so this sets the realistic
    // upper bound with a 128-byte RSA priv + 100-byte ICC PK cert +
    // 112-byte issuer PK cert.
    expect(wire.length).toBeLessThan(700);
  });
});

describe('field validation', () => {
  it('rejects PAN shorter than 12 digits', () => {
    expect(() =>
      buildParamBundle({ ...BASELINE, pan: '12345678901' }),
    ).toThrow(/PAN must be 12-19 digits/);
  });

  it('rejects PAN longer than 19 digits', () => {
    expect(() =>
      buildParamBundle({ ...BASELINE, pan: '12345678901234567890' }),
    ).toThrow(/PAN must be 12-19 digits/);
  });

  it('rejects non-digit PAN', () => {
    expect(() =>
      buildParamBundle({ ...BASELINE, pan: '5413339800000ABC' }),
    ).toThrow(/PAN must be 12-19 digits/);
  });

  it('rejects MK of wrong length', () => {
    expect(() =>
      buildParamBundle({ ...BASELINE, mkAc: Buffer.alloc(8) }),
    ).toThrow(/MK_AC expected 16 bytes/);
  });

  it('rejects fields that exceed MAX_FIELD_LEN', () => {
    const tooLong = Buffer.alloc(MAX_FIELD_LEN + 1);
    expect(() =>
      buildParamBundle({ ...BASELINE, cvmList: tooLong }),
    ).toThrow(/exceeds MAX_FIELD_LEN/);
  });

  it('accepts 128-byte ICC RSA priv (long-form BER length 0x81)', () => {
    // 128 bytes is the normal size for a 1024-bit RSA priv in PKCS#1
    // CRT form — exactly the case that pushed us past short-form.
    const iccRsaPriv128 = Buffer.alloc(128, 0xee);
    const wire = buildParamBundle({ ...BASELINE, iccRsaPriv: iccRsaPriv128 });
    const parsed = parseParamBundle(wire);
    expect(parsed.get(ParamTag.ICC_RSA_PRIV)?.length).toBe(128);
    expect(parsed.get(ParamTag.ICC_RSA_PRIV)?.equals(iccRsaPriv128)).toBe(true);
  });

  it('accepts 255-byte issuer cert at the long-form upper bound', () => {
    const maxCert = Buffer.alloc(255, 0x77);
    const wire = buildParamBundle({ ...BASELINE, issuerPkCert: maxCert });
    const parsed = parseParamBundle(wire);
    expect(parsed.get(ParamTag.ISSUER_PK_CERT)?.length).toBe(255);
  });

  it('rejects URL longer than 255 bytes (past long-form cap)', () => {
    expect(() =>
      buildParamBundle({
        ...BASELINE,
        postProvisionUrl: 'a'.repeat(300),
      }),
    ).toThrow(/exceeds MAX_FIELD_LEN/);
  });
});

describe('parseParamBundle error handling', () => {
  it('rejects truncated TLV header', () => {
    // Just a tag byte, no length byte
    expect(() => parseParamBundle(Buffer.from([0x01]))).toThrow(/truncated/);
  });

  it('rejects a value that overruns the buffer', () => {
    // Tag 0x01, length 0x10 (16), but only 4 bytes follow
    const bad = Buffer.from([0x01, 0x10, 0xaa, 0xbb, 0xcc, 0xdd]);
    expect(() => parseParamBundle(bad)).toThrow(/overruns buffer/);
  });

  it('accepts long-form 0x81 length (128-255 byte values)', () => {
    const value = Buffer.alloc(200, 0x55);
    const wire = Buffer.concat([
      Buffer.from([0x01, 0x81, 200]),
      value,
    ]);
    const parsed = parseParamBundle(wire);
    expect(parsed.get(0x01)?.length).toBe(200);
    expect(parsed.get(0x01)?.equals(value)).toBe(true);
  });

  it('rejects unsupported 0x82 length (>=256 byte values)', () => {
    const bad = Buffer.from([0x01, 0x82, 0x01, 0x00]);
    expect(() => parseParamBundle(bad)).toThrow(/unsupported length byte/);
  });

  it('rejects 0x83+ length prefix', () => {
    const bad = Buffer.from([0x01, 0x83, 0x00, 0x00, 0x00]);
    expect(() => parseParamBundle(bad)).toThrow(/unsupported length byte/);
  });

  it('rejects duplicate tag', () => {
    const dup = Buffer.from([
      0x01, 0x02, 0xaa, 0xbb, // tag=0x01 len=2
      0x01, 0x02, 0xcc, 0xdd, // tag=0x01 again
    ]);
    expect(() => parseParamBundle(dup)).toThrow(/duplicate tag/);
  });
});

describe('referenceBundleForJcDev', () => {
  it('emits a bundle that parses cleanly', () => {
    const wire = referenceBundleForJcDev();
    const parsed = parseParamBundle(wire);
    expect(parsed.size).toBeGreaterThan(20);
  });

  it('is deterministic — same call produces same bytes', () => {
    const a = referenceBundleForJcDev();
    const b = referenceBundleForJcDev();
    expect(a.equals(b)).toBe(true);
  });
});
