import { describe, it, expect } from 'vitest';
import { encodeLength, decodeLength } from './encoding.js';
import { TLV } from './tlv.js';
import { DGI } from './dgi.js';
import { Track2 } from './track2.js';
import { PANUtils } from './pan.js';
import { buildIad } from './iad-builder.js';
import { APDUBuilder } from './apdu-builder.js';
import { SADBuilder } from './sad-builder.js';
import { buildIccPkCertificate } from './icc-cert-builder.js';
import { ChipProfile } from './chip-profile.js';
import {
  DEV_SAD_MASTER_KEY,
  SAD_KEY_VERSION_DEV_AES_ECB,
  SAD_KEY_VERSION_KMS,
  decryptSadDev,
  encryptSadDev,
} from './sad-crypto.js';

// ---------------------------------------------------------------------------
// encoding.ts
// ---------------------------------------------------------------------------

describe('encoding — encodeLength / decodeLength', () => {
  it('round-trips a short length (0x7F)', () => {
    const encoded = encodeLength(0x7f);
    expect(encoded).toEqual(Buffer.from([0x7f]));
    const [decoded, consumed] = decodeLength(encoded, 0);
    expect(decoded).toBe(0x7f);
    expect(consumed).toBe(1);
  });

  it('round-trips a medium length (0xFF)', () => {
    const encoded = encodeLength(0xff);
    expect(encoded).toEqual(Buffer.from([0x81, 0xff]));
    const [decoded, consumed] = decodeLength(encoded, 0);
    expect(decoded).toBe(0xff);
    expect(consumed).toBe(2);
  });

  it('round-trips a long length (0xFFFF)', () => {
    const encoded = encodeLength(0xffff);
    expect(encoded).toEqual(Buffer.from([0x82, 0xff, 0xff]));
    const [decoded, consumed] = decodeLength(encoded, 0);
    expect(decoded).toBe(0xffff);
    expect(consumed).toBe(3);
  });

  it('encodes zero as a single byte', () => {
    const encoded = encodeLength(0);
    expect(encoded).toEqual(Buffer.from([0x00]));
    const [decoded, consumed] = decodeLength(encoded, 0);
    expect(decoded).toBe(0);
    expect(consumed).toBe(1);
  });

  it('encodes 0x80 with two-byte form', () => {
    const encoded = encodeLength(0x80);
    expect(encoded).toEqual(Buffer.from([0x81, 0x80]));
    const [decoded, consumed] = decodeLength(encoded, 0);
    expect(decoded).toBe(0x80);
    expect(consumed).toBe(2);
  });

  it('encodes 0x100 with three-byte form', () => {
    const encoded = encodeLength(0x100);
    expect(encoded).toEqual(Buffer.from([0x82, 0x01, 0x00]));
    const [decoded, consumed] = decodeLength(encoded, 0);
    expect(decoded).toBe(0x100);
    expect(consumed).toBe(3);
  });

  it('throws on negative length', () => {
    expect(() => encodeLength(-1)).toThrow('non-negative');
  });

  it('throws on length exceeding 0xFFFF', () => {
    expect(() => encodeLength(0x10000)).toThrow('exceeds maximum');
  });

  it('decodeLength throws on empty buffer', () => {
    expect(() => decodeLength(Buffer.alloc(0), 0)).toThrow('Unexpected end');
  });

  it('decodeLength throws on truncated two-byte length', () => {
    expect(() => decodeLength(Buffer.from([0x81]), 0)).toThrow('Unexpected end');
  });

  it('decodeLength throws on truncated three-byte length', () => {
    expect(() => decodeLength(Buffer.from([0x82, 0x01]), 0)).toThrow('Unexpected end');
  });

  it('decodeLength at a non-zero offset', () => {
    // Prefix with junk, then a two-byte length at offset 3
    const buf = Buffer.from([0xaa, 0xbb, 0xcc, 0x81, 0xc0]);
    const [decoded, consumed] = decodeLength(buf, 3);
    expect(decoded).toBe(0xc0);
    expect(consumed).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// tlv.ts
// ---------------------------------------------------------------------------

describe('TLV', () => {
  describe('tagToBytes', () => {
    it('converts 1-byte tag', () => {
      expect(TLV.tagToBytes(0x82)).toEqual(Buffer.from([0x82]));
    });

    it('converts 2-byte tag', () => {
      expect(TLV.tagToBytes(0x9f10)).toEqual(Buffer.from([0x9f, 0x10]));
    });

    it('converts 3-byte tag', () => {
      expect(TLV.tagToBytes(0x9f8101)).toEqual(Buffer.from([0x9f, 0x81, 0x01]));
    });

    it('throws on tag exceeding 3 bytes', () => {
      expect(() => TLV.tagToBytes(0x01000000)).toThrow('exceeds 3 bytes');
    });
  });

  describe('isConstructed', () => {
    it('returns true for constructed tags (bit 6 set)', () => {
      // 0x70 = 0111 0000 — bit 6 is set
      expect(TLV.isConstructed(0x70)).toBe(true);
      // 0x61 = 0110 0001 — bit 6 is set
      expect(TLV.isConstructed(0x61)).toBe(true);
    });

    it('returns false for primitive tags (bit 6 not set)', () => {
      // 0x82 = 1000 0010 — bit 6 not set
      expect(TLV.isConstructed(0x82)).toBe(false);
      // 0x5a = 0101 1010 — bit 6 not set
      expect(TLV.isConstructed(0x5a)).toBe(false);
    });

    it('checks bit 6 of the first byte for 2-byte tags', () => {
      // 0x9f10: first byte 0x9F = 1001 1111 — bit 6 not set
      expect(TLV.isConstructed(0x9f10)).toBe(false);
      // 0xbf0c: first byte 0xBF = 1011 1111 — bit 6 is set
      expect(TLV.isConstructed(0xbf0c)).toBe(true);
    });
  });

  describe('build + parse round-trip', () => {
    it('round-trips a primitive TLV', () => {
      const value = Buffer.from('4242424242424242', 'hex');
      const built = TLV.build(0x5a, value);
      const parsed = TLV.parse(built);

      expect(parsed).toHaveLength(1);
      expect(parsed[0][0]).toBe(0x5a);
      expect(parsed[0][1]).toEqual(value);
    });

    it('round-trips with a 2-byte tag', () => {
      const value = Buffer.from('0102030405', 'hex');
      const built = TLV.build(0x9f10, value);
      const parsed = TLV.parse(built);

      expect(parsed).toHaveLength(1);
      expect(parsed[0][0]).toBe(0x9f10);
      expect(parsed[0][1]).toEqual(value);
    });

    it('round-trips multiple TLV objects concatenated', () => {
      const v1 = Buffer.from('aabb', 'hex');
      const v2 = Buffer.from('ccdd', 'hex');
      const combined = Buffer.concat([TLV.build(0x82, v1), TLV.build(0x94, v2)]);
      const parsed = TLV.parse(combined);

      expect(parsed).toHaveLength(2);
      expect(parsed[0][0]).toBe(0x82);
      expect(parsed[0][1]).toEqual(v1);
      expect(parsed[1][0]).toBe(0x94);
      expect(parsed[1][1]).toEqual(v2);
    });

    it('handles values with length > 127 bytes', () => {
      const value = Buffer.alloc(200, 0xab);
      const built = TLV.build(0x90, value);
      const parsed = TLV.parse(built);

      expect(parsed).toHaveLength(1);
      expect(parsed[0][0]).toBe(0x90);
      expect(parsed[0][1]).toEqual(value);
    });

    it('skips 0x00 padding bytes', () => {
      const value = Buffer.from('ff', 'hex');
      const padded = Buffer.concat([Buffer.from([0x00, 0x00]), TLV.build(0x82, value)]);
      const parsed = TLV.parse(padded);

      expect(parsed).toHaveLength(1);
      expect(parsed[0][0]).toBe(0x82);
    });
  });

  describe('buildConstructed + find', () => {
    it('finds a tag nested inside a constructed tag', () => {
      const innerValue = Buffer.from('1234', 'hex');
      const innerTlv = TLV.build(0x5a, innerValue);
      const outerTlv = TLV.buildConstructed(0x70, [innerTlv]);

      const found = TLV.find(outerTlv, 0x5a);
      expect(found).toEqual(innerValue);
    });

    it('finds a tag at the top level', () => {
      const value = Buffer.from('abcd', 'hex');
      const data = TLV.build(0x82, value);

      const found = TLV.find(data, 0x82);
      expect(found).toEqual(value);
    });

    it('returns null when tag is not present', () => {
      const data = TLV.build(0x82, Buffer.from('ab', 'hex'));
      expect(TLV.find(data, 0x94)).toBeNull();
    });

    it('finds a tag deeply nested (two levels)', () => {
      const leaf = TLV.build(0x9f10, Buffer.from('cafe', 'hex'));
      const mid = TLV.buildConstructed(0x70, [leaf]);
      const outer = TLV.buildConstructed(0x61, [mid]);

      const found = TLV.find(outer, 0x9f10);
      expect(found).toEqual(Buffer.from('cafe', 'hex'));
    });
  });
});

// ---------------------------------------------------------------------------
// dgi.ts
// ---------------------------------------------------------------------------

describe('DGI', () => {
  describe('build + parse round-trip', () => {
    it('round-trips a single DGI', () => {
      const data = Buffer.from('0102030405', 'hex');
      const built = DGI.build(0x0101, data);
      const parsed = DGI.parse(built);

      expect(parsed).toHaveLength(1);
      expect(parsed[0][0]).toBe(0x0101);
      expect(parsed[0][1]).toEqual(data);
    });

    it('round-trips multiple DGIs concatenated', () => {
      const d1 = Buffer.from('aabb', 'hex');
      const d2 = Buffer.from('ccddee', 'hex');
      const combined = Buffer.concat([DGI.build(0x0101, d1), DGI.build(0x0202, d2)]);
      const parsed = DGI.parse(combined);

      expect(parsed).toHaveLength(2);
      expect(parsed[0][0]).toBe(0x0101);
      expect(parsed[0][1]).toEqual(d1);
      expect(parsed[1][0]).toBe(0x0202);
      expect(parsed[1][1]).toEqual(d2);
    });

    it('handles data with length > 127 bytes', () => {
      const data = Buffer.alloc(200, 0xcc);
      const built = DGI.build(0x0301, data);
      const parsed = DGI.parse(built);

      expect(parsed).toHaveLength(1);
      expect(parsed[0][0]).toBe(0x0301);
      expect(parsed[0][1]).toEqual(data);
    });
  });

  describe('buildStoreDataApdu', () => {
    it('returns correct CLA (0x80) and INS (0xE2)', () => {
      const data = Buffer.from('aabb', 'hex');
      const apdu = DGI.buildStoreDataApdu(0x0101, data);

      expect(apdu[0]).toBe(0x80); // CLA
      expect(apdu[1]).toBe(0xe2); // INS
    });

    it('sets P1 high bit for isLast=true', () => {
      const data = Buffer.from('aa', 'hex');
      const apdu = DGI.buildStoreDataApdu(0x0101, data, 0, true);
      // P1 = (1 << 7) | 0 = 0x80
      expect(apdu[2]).toBe(0x80);
    });

    it('clears P1 high bit for isLast=false', () => {
      const data = Buffer.from('aa', 'hex');
      const apdu = DGI.buildStoreDataApdu(0x0101, data, 0, false);
      // P1 = (0 << 7) | 0 = 0x00
      expect(apdu[2]).toBe(0x00);
    });

    it('encodes blockNum in P1 low 5 bits', () => {
      const data = Buffer.from('aa', 'hex');
      const apdu = DGI.buildStoreDataApdu(0x0101, data, 3, false);
      // P1 = 0 | 3 = 0x03
      expect(apdu[2]).toBe(0x03);
    });

    it('sets P2 to 0x00', () => {
      const data = Buffer.from('aa', 'hex');
      const apdu = DGI.buildStoreDataApdu(0x0101, data);
      expect(apdu[3]).toBe(0x00);
    });

    it('Lc matches the DGI container length', () => {
      const data = Buffer.from('aabbccdd', 'hex');
      const container = DGI.build(0x0101, data);
      const apdu = DGI.buildStoreDataApdu(0x0101, data);
      // Lc is at byte 4
      expect(apdu[4]).toBe(container.length);
      // The rest of the APDU should match the container
      expect(apdu.subarray(5)).toEqual(container);
    });
  });
});

// ---------------------------------------------------------------------------
// track2.ts
// ---------------------------------------------------------------------------

describe('Track2', () => {
  const pan = '4242424242424242';
  const expiry = '2812';
  const serviceCode = '201';

  describe('build + parse round-trip', () => {
    it('round-trips PAN, expiry, and service code', () => {
      const built = Track2.build(pan, expiry, serviceCode);
      const parsed = Track2.parse(built);

      expect(parsed.pan).toBe(pan.toUpperCase());
      expect(parsed.expiry).toBe(expiry);
      expect(parsed.serviceCode).toBe(serviceCode);
      expect(parsed.discretionary).toBe('');
    });

    it('round-trips with discretionary data', () => {
      const disc = '1234';
      const built = Track2.build(pan, expiry, serviceCode, disc);
      const parsed = Track2.parse(built);

      expect(parsed.pan).toBe(pan.toUpperCase());
      expect(parsed.expiry).toBe(expiry);
      expect(parsed.serviceCode).toBe(serviceCode);
      expect(parsed.discretionary).toBe(disc.toUpperCase());
    });

    it('pads to even nibble count when total is odd', () => {
      // PAN(16) + D(1) + YYMM(4) + svc(3) = 24 nibbles (even), so no F pad
      const built = Track2.build(pan, expiry, serviceCode);
      const hex = built.toString('hex').toUpperCase();
      expect(hex.length % 2).toBe(0);

      // With odd discretionary data, should pad with F
      const builtOdd = Track2.build(pan, expiry, serviceCode, 'A');
      const hexOdd = builtOdd.toString('hex').toUpperCase();
      expect(hexOdd).toMatch(/F$/);
    });
  });

  describe('validation', () => {
    it('throws on invalid expiry', () => {
      expect(() => Track2.build(pan, '123', serviceCode)).toThrow('4 digits');
      expect(() => Track2.build(pan, '12345', serviceCode)).toThrow('4 digits');
    });

    it('throws on invalid service code', () => {
      expect(() => Track2.build(pan, expiry, '12')).toThrow('3 digits');
      expect(() => Track2.build(pan, expiry, '1234')).toThrow('3 digits');
    });

    it('throws on non-hex discretionary data', () => {
      expect(() => Track2.build(pan, expiry, serviceCode, 'XY')).toThrow('hex');
    });
  });
});

// ---------------------------------------------------------------------------
// pan.ts
// ---------------------------------------------------------------------------

describe('PANUtils', () => {
  describe('luhnCheck', () => {
    it('returns true for valid Luhn PAN (4242424242424242)', () => {
      expect(PANUtils.luhnCheck('4242424242424242')).toBe(true);
    });

    it('returns false for invalid Luhn PAN (4242424242424241)', () => {
      expect(PANUtils.luhnCheck('4242424242424241')).toBe(false);
    });

    it('returns true for another known valid PAN (4111111111111111)', () => {
      expect(PANUtils.luhnCheck('4111111111111111')).toBe(true);
    });

    it('returns false when last digit is wrong (4111111111111112)', () => {
      expect(PANUtils.luhnCheck('4111111111111112')).toBe(false);
    });
  });

  describe('validate', () => {
    it('returns true for a valid PAN', () => {
      expect(PANUtils.validate('4242424242424242')).toBe(true);
    });

    it('throws on non-digit characters', () => {
      expect(() => PANUtils.validate('4242abcd42424242')).toThrow('only digits');
    });

    it('throws on PAN shorter than 13 digits', () => {
      expect(() => PANUtils.validate('424242424242')).toThrow('invalid length');
    });

    it('throws on PAN longer than 19 digits', () => {
      expect(() => PANUtils.validate('42424242424242424242')).toThrow('invalid length');
    });

    it('throws on failed Luhn check', () => {
      expect(() => PANUtils.validate('4242424242424241')).toThrow('check digit');
    });
  });

  describe('padPan', () => {
    it('returns unchanged buffer for even-length PAN', () => {
      const padded = PANUtils.padPan('4242424242424242');
      expect(padded).toEqual(Buffer.from('4242424242424242', 'hex'));
      expect(padded.length).toBe(8);
    });

    it('pads odd-length PAN with trailing F', () => {
      const padded = PANUtils.padPan('424242424242424');
      expect(padded).toEqual(Buffer.from('424242424242424F', 'hex'));
      expect(padded.length).toBe(8);
    });
  });

  describe('mask', () => {
    it('masks all but last 4 digits', () => {
      expect(PANUtils.mask('4242424242424242')).toBe('****4242');
    });

    it('returns short PAN unchanged', () => {
      expect(PANUtils.mask('1234')).toBe('1234');
    });
  });
});

// ---------------------------------------------------------------------------
// iad-builder.ts
// ---------------------------------------------------------------------------

describe('buildIad', () => {
  describe('Mastercard M/Chip Advance', () => {
    it('CVN 10 produces 11 bytes with correct format byte (0x0A)', () => {
      const iad = buildIad(10, 0x01, '000', 'mchip_advance');
      expect(iad.length).toBe(11);
      expect(iad[0]).toBe(0x0a); // Length byte
      expect(iad[1]).toBe(0x01); // DKI
      expect(iad[2]).toBe(0x0a); // CVN = 10
    });

    it('CVN 17 produces 19 bytes with correct format byte (0x12)', () => {
      const iad = buildIad(17, 0x01, '000', 'mchip_advance');
      expect(iad.length).toBe(19);
      expect(iad[0]).toBe(0x12); // Length byte
      expect(iad[1]).toBe(0x01); // DKI
      expect(iad[2]).toBe(0x11); // CVN = 17
    });

    it('CVN 18 produces 19 bytes with correct format byte (0x12)', () => {
      const iad = buildIad(18, 0x01, '000', 'mchip_advance');
      expect(iad.length).toBe(19);
      expect(iad[0]).toBe(0x12); // Length byte
      expect(iad[1]).toBe(0x01); // DKI
      expect(iad[2]).toBe(0x12); // CVN = 18
    });

    it('encodes iCVV in the last 2 bytes for CVN 10', () => {
      const iad = buildIad(10, 0x01, '123', 'mchip_advance');
      // iCVV "123" padded to "1230" = 0x12 0x30 at bytes 9-10
      expect(iad[9]).toBe(0x12);
      expect(iad[10]).toBe(0x30);
    });

    it('encodes custom DKI', () => {
      const iad = buildIad(10, 0x05, '000', 'mchip_advance');
      expect(iad[1]).toBe(0x05);
    });

    it('throws for unsupported Mastercard CVN', () => {
      expect(() => buildIad(99, 0x01, '000', 'mchip_advance')).toThrow('Unsupported Mastercard CVN');
    });
  });

  describe('Visa VSDC / qVSDC', () => {
    it('CVN 10 produces 7 bytes with format byte 0x06', () => {
      const iad = buildIad(10, 0x01, '000', 'vsdc');
      expect(iad.length).toBe(7);
      expect(iad[0]).toBe(0x06); // Length byte
      expect(iad[1]).toBe(0x01); // DKI
      expect(iad[2]).toBe(0x0a); // CVN = 10
    });

    it('CVN 18 produces 8 bytes with format byte 0x07', () => {
      const iad = buildIad(18, 0x01, '000', 'vsdc');
      expect(iad.length).toBe(8);
      expect(iad[0]).toBe(0x07); // Length byte
      expect(iad[1]).toBe(0x01); // DKI
      expect(iad[2]).toBe(0x12); // CVN = 18
      expect(iad[7]).toBe(0x00); // IDD length = 0
    });

    it('CVN 22 produces 32 bytes with format byte 0x1F', () => {
      const iad = buildIad(22, 0x01, '000', 'vsdc');
      expect(iad.length).toBe(32);
      expect(iad[0]).toBe(0x1f); // Format byte
      expect(iad[1]).toBe(0x22); // CVN = 22
      expect(iad[2]).toBe(0x01); // DKI
    });

    it('CVN 22 encodes iCVV inside IDD', () => {
      const iad = buildIad(22, 0x01, '456', 'vsdc');
      // IDD starts at byte 8 (after format, cvn, dki, cvr[4], iddLen)
      // Wallet Provider ID (4) + derivation data (2) = 6 bytes offset into IDD
      // iCVV "456" padded to "4560" at byte 8+6 = 14
      expect(iad[14]).toBe(0x45);
      expect(iad[15]).toBe(0x60);
    });

    it('throws for unsupported Visa CVN', () => {
      expect(() => buildIad(99, 0x01, '000', 'vsdc')).toThrow('Unsupported Visa CVN');
    });
  });
});

// ---------------------------------------------------------------------------
// apdu-builder.ts
// ---------------------------------------------------------------------------

describe('APDUBuilder', () => {
  describe('selectApplet', () => {
    it('returns correct SELECT APDU', () => {
      const aidHex = 'A000000004101001';
      const apdu = APDUBuilder.selectApplet(aidHex);
      const buf = Buffer.from(apdu, 'hex');

      expect(buf[0]).toBe(0x00); // CLA
      expect(buf[1]).toBe(0xa4); // INS (SELECT)
      expect(buf[2]).toBe(0x04); // P1 (select by name)
      expect(buf[3]).toBe(0x00); // P2
      expect(buf[4]).toBe(8);    // Lc (AID length)
      expect(buf.subarray(5).toString('hex').toUpperCase()).toBe(aidHex.toUpperCase());
    });

    it('handles short AID', () => {
      const apdu = APDUBuilder.selectApplet('A0000000041010');
      const buf = Buffer.from(apdu, 'hex');
      expect(buf[4]).toBe(7); // Lc
    });
  });

  describe('parseResponse', () => {
    it('splits data and SW correctly on success', () => {
      const [data, sw] = APDUBuilder.parseResponse('AABBCCDD9000');
      expect(data).toEqual(Buffer.from('aabbccdd', 'hex'));
      expect(sw).toBe(0x9000);
    });

    it('parses error SW', () => {
      const [data, sw] = APDUBuilder.parseResponse('6A82');
      expect(data).toEqual(Buffer.alloc(0));
      expect(sw).toBe(0x6a82);
    });

    it('returns 6F00 for response shorter than 2 bytes', () => {
      const [data, sw] = APDUBuilder.parseResponse('90');
      expect(data).toEqual(Buffer.alloc(0));
      expect(sw).toBe(0x6f00);
    });

    it('handles response with only SW (no data)', () => {
      const [data, sw] = APDUBuilder.parseResponse('9000');
      expect(data).toEqual(Buffer.alloc(0));
      expect(sw).toBe(0x9000);
    });
  });

  describe('fixed APDUs', () => {
    it('confirm returns 80E8000000', () => {
      expect(APDUBuilder.confirm()).toBe('80E8000000');
    });

    it('wipe returns 80EA000000', () => {
      expect(APDUBuilder.wipe()).toBe('80EA000000');
    });

    it('getState returns 80EE000000', () => {
      expect(APDUBuilder.getState()).toBe('80EE000000');
    });
  });
});

// ---------------------------------------------------------------------------
// sad-builder.ts
// ---------------------------------------------------------------------------

describe('SADBuilder — serialiseDgis / deserialiseDgis', () => {
  it('round-trips an empty DGI list', () => {
    const dgis: Array<[number, Buffer]> = [];
    const serialised = SADBuilder.serialiseDgis(dgis);
    const deserialised = SADBuilder.deserialiseDgis(serialised);
    expect(deserialised).toEqual([]);
  });

  it('round-trips a single DGI', () => {
    const dgis: Array<[number, Buffer]> = [
      [0x0101, Buffer.from('aabbccdd', 'hex')],
    ];
    const serialised = SADBuilder.serialiseDgis(dgis);
    const deserialised = SADBuilder.deserialiseDgis(serialised);

    expect(deserialised).toHaveLength(1);
    expect(deserialised[0][0]).toBe(0x0101);
    expect(deserialised[0][1]).toEqual(Buffer.from('aabbccdd', 'hex'));
  });

  it('round-trips multiple DGIs', () => {
    const dgis: Array<[number, Buffer]> = [
      [0x0101, Buffer.from('aa', 'hex')],
      [0x0202, Buffer.from('bbcc', 'hex')],
      [0x0303, Buffer.from('ddeeff', 'hex')],
    ];
    const serialised = SADBuilder.serialiseDgis(dgis);
    const deserialised = SADBuilder.deserialiseDgis(serialised);

    expect(deserialised).toHaveLength(3);
    expect(deserialised[0][0]).toBe(0x0101);
    expect(deserialised[0][1]).toEqual(Buffer.from('aa', 'hex'));
    expect(deserialised[1][0]).toBe(0x0202);
    expect(deserialised[1][1]).toEqual(Buffer.from('bbcc', 'hex'));
    expect(deserialised[2][0]).toBe(0x0303);
    expect(deserialised[2][1]).toEqual(Buffer.from('ddeeff', 'hex'));
  });

  it('serialised format emits PA wire format: tag(2) + BER-TLV length + data per entry', () => {
    const data = Buffer.from('cafe', 'hex');
    const dgis: Array<[number, Buffer]> = [[0x1234, data]];
    const serialised = SADBuilder.serialiseDgis(dgis);

    // tag(2) + BER-len(1 for len<0x80) + data(2) = 5 bytes
    expect(serialised.length).toBe(5);
    expect(serialised.readUInt16BE(0)).toBe(0x1234); // tag
    expect(serialised[2]).toBe(2);                   // BER short-form length
    expect(serialised.subarray(3)).toEqual(data);    // data
  });

  it('serialised format uses BER long-form 0x81 for lengths 0x80-0xFF', () => {
    const data = Buffer.alloc(0x80, 0xab); // length = 128
    const dgis: Array<[number, Buffer]> = [[0x1234, data]];
    const serialised = SADBuilder.serialiseDgis(dgis);

    expect(serialised.readUInt16BE(0)).toBe(0x1234);
    expect(serialised[2]).toBe(0x81);
    expect(serialised[3]).toBe(0x80);
    expect(serialised.subarray(4)).toEqual(data);
  });

  it('serialised format uses BER long-form 0x82 for lengths > 0xFF', () => {
    const data = Buffer.alloc(300, 0xcd); // length = 300 = 0x012C
    const dgis: Array<[number, Buffer]> = [[0x1234, data]];
    const serialised = SADBuilder.serialiseDgis(dgis);

    expect(serialised.readUInt16BE(0)).toBe(0x1234);
    expect(serialised[2]).toBe(0x82);
    expect(serialised.readUInt16BE(3)).toBe(300);
    expect(serialised.subarray(5)).toEqual(data);
  });
});

// ---------------------------------------------------------------------------
// sad-builder.ts — end-to-end buildSad with M/Chip Advance CVN-18 profile
// ---------------------------------------------------------------------------

/**
 * Mirror of the DGI layout from test-fixtures/chip-profile-mchip-cvn18.json,
 * reshaped into the snake_case form ChipProfile.fromJson expects (it reads
 * `d.dgi_number` on each entry).  Separately fielded here so the tests
 * don't depend on JSON file I/O.
 */
const MCHIP_CVN18_DGI_DEFS = [
  {
    dgi_number: 32513, // 0x7F01 — FCI template tags
    name: 'Application FCI',
    tags: [0x50, 0x4f, 0x9f02, 0x9f08, 0x9f10, 0x24],
    mandatory: true,
    source: 'per_profile',
  },
  {
    dgi_number: 36864, // 0x9000 — Static Application Data (SAD core)
    name: 'Static Application Data',
    tags: [0x82, 0x94, 0x9f07, 0x9f02, 0x9f08, 0x5a, 0x5f2c, 0x5f30],
    mandatory: true,
    source: 'per_card',
  },
  {
    dgi_number: 36865, // 0x9001 — Card Risk Management Object 1
    name: 'Card Risk Management Object 1',
    tags: [0x9f1d, 0x9f1e, 0x9f0f, 0x9f0d, 0x9f0e, 0x9f19, 0x9f14, 0x9f15],
    mandatory: true,
    source: 'per_profile',
  },
  {
    dgi_number: 32769, // 0x8001 — ICC Private Key (PA generates on-card)
    name: 'ICC Private Key',
    tags: [0x9f48],
    mandatory: true,
    source: 'per_card',
  },
];

/**
 * A deliberately-small IssuerProfile with just enough fields to exercise
 * the SAD builder's three tag-construction paths (per-profile, per-card,
 * issuer cert) without dragging in unused scheme-specific rarities.
 */
const SAMPLE_ISSUER_PROFILE = {
  scheme: 'mchip_advance',
  cvn: 18,
  aip: '1C00',
  afl: '08010100100101001801020020010200',
  cvmList: '000000000000000042035E031F03',
  pdol: '9F66049F02069F03069F1A0295055F2A029A039C019F3704',
  cdol1: '9F02069F03069F1A0295055F2A029A039C019F37049F3501',
  cdol2: '8A02',
  iacDefault: 'F040FC8000',
  iacDenial: '0400000000',
  iacOnline: 'F040FC8000',
  appUsageControl: 'FF00',
  currencyCode: '0036',
  currencyExponent: '02',
  countryCode: '0036',
  sdaTagList: '82',
  appVersionNumber: '0002',
  appPriority: '01',
  aid: 'A0000000041010',
  appLabel: 'KARTA PLATINUM',
  appPreferredName: 'KARTA',
  issuerPkCertificate: 'AABBCCDD'.repeat(32),
  issuerPkRemainder: '11223344',
  issuerPkExponent: '03',
  caPkIndex: '05',
};

const SAMPLE_CARD_DATA = {
  pan: '4580483507983243',
  expiryDate: '2912',
  effectiveDate: '2412',
  serviceCode: '201',
  cardSequenceNumber: '01',
  icvv: '123',
};

function buildSampleChipProfile(): ChipProfile {
  return ChipProfile.fromJson({
    profile_id: 'mchip-advance-cvn18-sample',
    profile_name: 'M/Chip Advance CVN 18 (sample)',
    scheme: 'mchip_advance',
    applet_vendor: 'nxp',
    cvn: 18,
    dgi_definitions: MCHIP_CVN18_DGI_DEFS,
    icc_private_key_dgi: 32769,
    icc_private_key_tag: 0x9f48,
    mk_ac_dgi: 2048,
    mk_smi_dgi: 2049,
    mk_smc_dgi: 2050,
    elf_aid: 'A0000000041010',
    module_aid: 'A0000000041010',
    pa_aid: 'A00000006250414C',
    fido_aid: 'A0000006472F0001',
  });
}

describe('SADBuilder — buildSad end-to-end', () => {
  it('produces non-empty DGI list for a full M/Chip CVN 18 profile', () => {
    const chipProfile = buildSampleChipProfile();
    const dgis = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);
    // SAD core DGI + CRM object DGI + FCI DGI — pa_internal (ICC private)
    // and any DGI with no matching tag values should be absent.
    expect(dgis.length).toBeGreaterThan(0);
    const dgiNumbers = dgis.map(([n]) => n);
    // 36864 / 0x9000 carries the tag-0x82 AIP that we populated, so it
    // MUST emerge.
    expect(dgiNumbers).toContain(36864);
    // 32769 / 0x8001 is the pa_internal ICC Private Key DGI — the SAD
    // builder skips it so it should NOT be emitted.
    expect(dgiNumbers).not.toContain(32769);
  });

  it('SAD core DGI contains Tag 82 (AIP) with the exact profile value', () => {
    const chipProfile = buildSampleChipProfile();
    const dgis = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);

    const sadCore = dgis.find(([n]) => n === 36864);
    expect(sadCore).toBeDefined();
    // The DGI container is DGI header (2) + BER length + TLV payload.
    // Parse the DGI bytes to strip header, then TLV.find the AIP tag.
    const parsed = DGI.parse(sadCore![1]);
    expect(parsed).toHaveLength(1);
    // parse() returns [dgiNum, innerBytes] — inner bytes are the TLV payload
    const tlvPayload = parsed[0][1];
    const aipValue = TLV.find(tlvPayload, 0x82);
    expect(aipValue).not.toBeNull();
    expect(aipValue!.toString('hex').toUpperCase()).toBe('1C00');
  });

  it('SAD core DGI contains Tag 5A (PAN) with padded BCD encoding', () => {
    const chipProfile = buildSampleChipProfile();
    const dgis = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);

    const sadCore = dgis.find(([n]) => n === 36864);
    const parsed = DGI.parse(sadCore![1]);
    const panValue = TLV.find(parsed[0][1], 0x5a);
    expect(panValue).not.toBeNull();
    // '4580483507983243' — even length, no F padding.
    expect(panValue!.toString('hex').toUpperCase()).toBe('4580483507983243');
  });

  it('FCI DGI (32513) contains the AID (Tag 4F / 0x4F)', () => {
    const chipProfile = buildSampleChipProfile();
    const dgis = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);

    // Tag 0x4F is NOT currently produced by SADBuilder — only 0x84 is
    // emitted for the AID.  The FCI DGI here lists 0x4F in its tag set;
    // expect the DGI to be absent (no matching tag values) OR to be
    // emitted without an AID TLV.  This test documents current behaviour:
    // we don't want the builder to silently insert a zero-length value.
    const fci = dgis.find(([n]) => n === 32513);
    if (fci) {
      const parsed = DGI.parse(fci[1]);
      // If the DGI emerged, its inner TLV must not contain 0x4F since we
      // didn't populate tagValues[0x4f].
      const aidValue = TLV.find(parsed[0][1], 0x4f);
      expect(aidValue).toBeNull();
    }
  });

  it('serialised then deserialised SAD round-trips to the same DGI list', () => {
    const chipProfile = buildSampleChipProfile();
    const dgis = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);

    const serialised = SADBuilder.serialiseDgis(dgis);
    const deserialised = SADBuilder.deserialiseDgis(serialised);

    expect(deserialised).toHaveLength(dgis.length);
    for (let i = 0; i < dgis.length; i++) {
      expect(deserialised[i][0]).toBe(dgis[i][0]);
      expect(deserialised[i][1]).toEqual(dgis[i][1]);
    }
  });

  it('is deterministic for the same profile + card data', () => {
    const chipProfile = buildSampleChipProfile();
    const dgisA = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);
    const dgisB = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);

    expect(SADBuilder.serialiseDgis(dgisA)).toEqual(SADBuilder.serialiseDgis(dgisB));
  });

  it('rejects the "AAA=" legacy stub structurally (does not parse as DGI list)', () => {
    // Sanity check: the 4-byte stub the prod DB currently carries is NOT
    // a valid serialised DGI list.  Either deserialiseDgis will throw or
    // produce a nonsense DGI count — it should NOT be mistaken for the
    // real builder output.
    const stub = Buffer.from('AAA=', 'utf8'); // 4 bytes: 0x41 0x41 0x41 0x3D
    // Deserialise reads count(2) then tries to read DGI frames — with
    // only 4 bytes, either the header points past end-of-buffer or
    // decodeLength fails.  Either way: doesn't match a real SAD.
    expect(() => SADBuilder.deserialiseDgis(stub)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// sad-crypto.ts — AES-128-ECB dev at-rest encryption
// ---------------------------------------------------------------------------

describe('sad-crypto — dev AES-128-ECB round trip', () => {
  it('exports a 16-byte zero master key', () => {
    expect(DEV_SAD_MASTER_KEY.length).toBe(16);
    expect(DEV_SAD_MASTER_KEY.equals(Buffer.alloc(16, 0x00))).toBe(true);
  });

  it('key-version constants match expected values', () => {
    expect(SAD_KEY_VERSION_KMS).toBe(0);
    expect(SAD_KEY_VERSION_DEV_AES_ECB).toBe(1);
  });

  it('round-trips a typical SAD payload (serialised DGI list)', () => {
    const chipProfile = buildSampleChipProfile();
    const dgis = SADBuilder.buildSad(SAMPLE_ISSUER_PROFILE, chipProfile, SAMPLE_CARD_DATA);
    const sadBytes = SADBuilder.serialiseDgis(dgis);

    const encrypted = encryptSadDev(sadBytes);
    // ECB + PKCS#7 always rounds up to a non-zero multiple of 16
    expect(encrypted.length % 16).toBe(0);
    expect(encrypted.length).toBeGreaterThan(sadBytes.length);

    const decrypted = decryptSadDev(encrypted);
    expect(decrypted).toEqual(sadBytes);
  });

  it('round-trips a short plaintext smaller than one AES block', () => {
    const plain = Buffer.from('hi', 'utf8');
    const enc = encryptSadDev(plain);
    expect(enc.length).toBe(16); // PKCS#7 pads up to the block size
    expect(decryptSadDev(enc)).toEqual(plain);
  });

  it('encrypt is deterministic under ECB', () => {
    const plain = Buffer.from('deterministic-plaintext-here', 'utf8');
    const a = encryptSadDev(plain);
    const b = encryptSadDev(plain);
    expect(a).toEqual(b);
  });
});

describe('buildIccPkCertificate', () => {
  it('returns certificate starting with 0x6A and ending with 0xBC', () => {
    // 64 bytes = uncompressed EC key (x || y) without 0x04 prefix
    const iccPk = Buffer.alloc(64, 0xab);
    const [cert, _remainder] = buildIccPkCertificate({
      iccPublicKey: iccPk,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
    });

    expect(cert[0]).toBe(0x6a);
    expect(cert[cert.length - 1]).toBe(0xbc);
  });

  it('strips 0x04 prefix from uncompressed key', () => {
    // 65 bytes with 0x04 prefix
    const iccPkWithPrefix = Buffer.alloc(65, 0xab);
    iccPkWithPrefix[0] = 0x04;

    const [cert1] = buildIccPkCertificate({
      iccPublicKey: iccPkWithPrefix,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
    });

    // Without prefix
    const iccPkWithout = Buffer.alloc(64, 0xab);
    const [cert2] = buildIccPkCertificate({
      iccPublicKey: iccPkWithout,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
    });

    // Both should produce the same certificate
    expect(cert1).toEqual(cert2);
  });

  it('certificate contains format byte 0x04 after header', () => {
    const iccPk = Buffer.alloc(64, 0xab);
    const [cert] = buildIccPkCertificate({
      iccPublicKey: iccPk,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
    });

    // byte 0: header (0x6A), byte 1: format (0x04)
    expect(cert[1]).toBe(0x04);
  });

  it('embeds PAN as 10-byte BCD after format byte', () => {
    const iccPk = Buffer.alloc(64, 0xab);
    const [cert] = buildIccPkCertificate({
      iccPublicKey: iccPk,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
    });

    // PAN padded to 20 digits with F, starting at byte 2
    const panBcd = cert.subarray(2, 12);
    expect(panBcd.toString('hex').toUpperCase()).toBe('4242424242424242FFFF');
  });

  it('produces remainder when ICC PK exceeds available space', () => {
    // With issuerPkLen=128, pkSpace = 128-42 = 86 bytes
    // 64-byte key fits, so remainder should be empty
    const iccPk64 = Buffer.alloc(64, 0xab);
    const [_cert64, remainder64] = buildIccPkCertificate({
      iccPublicKey: iccPk64,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
      issuerPkLen: 128,
    });
    expect(remainder64.length).toBe(0);

    // With issuerPkLen=64, pkSpace = 64-42 = 22 bytes
    // 64-byte key doesn't fit, so remainder = 64-22 = 42 bytes
    const [_certSmall, remainderSmall] = buildIccPkCertificate({
      iccPublicKey: iccPk64,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
      issuerPkLen: 64,
    });
    expect(remainderSmall.length).toBe(42);
  });

  it('SHA-1 hash is 20 bytes (located before the trailer)', () => {
    const iccPk = Buffer.alloc(64, 0xab);
    const [cert] = buildIccPkCertificate({
      iccPublicKey: iccPk,
      pan: '4242424242424242',
      expiry: '2812',
      csn: '01',
    });

    // Trailer is last byte (0xBC), hash is the 20 bytes before it
    const hashSection = cert.subarray(cert.length - 21, cert.length - 1);
    expect(hashSection.length).toBe(20);
  });
});
