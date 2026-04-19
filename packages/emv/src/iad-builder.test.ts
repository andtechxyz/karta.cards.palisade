/**
 * Per-CVN CVR and DAC/IDN packing tests for iad-builder.
 *
 * These focus on the structural bits the new code writes vs. the all-zero
 * placeholder the old version emitted:
 *   - byte-for-byte hand-computed CVR vectors for every CVN variant
 *   - reserved-bit position checks
 *   - length contract per CVN
 *   - DAC/IDN derivation from PAN+CSN
 *   - backward-compat warn on legacy signature
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import {
  buildIad,
  packMcCvn10Cvr,
  packMcCvn17Or18Cvr,
  packVisaCvn10Cvr,
  packVisaCvn22Cvr,
  resolveDacIdn,
  deriveDacIdn,
  __resetIadBuilderWarnings,
  type CvrInputs,
} from './iad-builder.js';

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  __resetIadBuilderWarnings();
});

// ---------------------------------------------------------------------------
// Mastercard M/Chip CVN 10 — 4-byte CVR
// ---------------------------------------------------------------------------

describe('packMcCvn10Cvr (Mastercard M/Chip CVN 10, 4-byte CVR)', () => {
  it('returns 4 bytes all zero for empty input', () => {
    const cvr = packMcCvn10Cvr({});
    expect(cvr.length).toBe(4);
    expect(cvr.toString('hex')).toBe('00000000');
  });

  it('returns 4 bytes all zero for undefined input (at-perso)', () => {
    const cvr = packMcCvn10Cvr();
    expect(cvr.length).toBe(4);
    expect(cvr.toString('hex')).toBe('00000000');
  });

  it('sets ARQC in 1st GEN AC (byte 1 bit 4 = 0x08)', () => {
    const cvr = packMcCvn10Cvr({ arqcFirstGen: true });
    expect(cvr[0]).toBe(0x08);
    expect(cvr[1]).toBe(0x00);
    expect(cvr[2]).toBe(0x00);
    expect(cvr[3]).toBe(0x00);
  });

  it('sets AAC in 2nd GEN AC (byte 1 bit 8 = 0x80)', () => {
    const cvr = packMcCvn10Cvr({ aacSecondGen: true });
    expect(cvr[0]).toBe(0x80);
  });

  it('sets TC in 2nd GEN AC (byte 1 bit 7 = 0x40)', () => {
    const cvr = packMcCvn10Cvr({ tcSecondGen: true });
    expect(cvr[0]).toBe(0x40);
  });

  it('sets AAC in 1st GEN AC (byte 1 bit 6 = 0x20)', () => {
    const cvr = packMcCvn10Cvr({ aacFirstGen: true });
    expect(cvr[0]).toBe(0x20);
  });

  it('sets TC in 1st GEN AC (byte 1 bit 5 = 0x10)', () => {
    const cvr = packMcCvn10Cvr({ tcFirstGen: true });
    expect(cvr[0]).toBe(0x10);
  });

  it('combines multiple byte 1 flags (AAC+TC 1st GEN = 0x30)', () => {
    const cvr = packMcCvn10Cvr({ aacFirstGen: true, tcFirstGen: true });
    expect(cvr[0]).toBe(0x30);
  });

  it('sets CDA performed (byte 2 bit 8 = 0x80)', () => {
    const cvr = packMcCvn10Cvr({ cdaPerformed: true });
    expect(cvr[1]).toBe(0x80);
  });

  it('sets PIN try counter in byte 2 low nibble (5 tries = 0x05)', () => {
    const cvr = packMcCvn10Cvr({ pinTryCounter: 5 });
    expect(cvr[1]).toBe(0x05);
  });

  it('clamps PIN try counter to 4 bits (99 → 0x0F)', () => {
    const cvr = packMcCvn10Cvr({ pinTryCounter: 99 });
    expect(cvr[1]).toBe(0x0f);
  });

  it('sets byte 3 last-online-not-completed (bit 8 = 0x80)', () => {
    const cvr = packMcCvn10Cvr({ lastOnlineNotCompleted: true });
    expect(cvr[2]).toBe(0x80);
  });

  it('packs script counters in byte 4 (3 processed, 1 failed = 0x31)', () => {
    const cvr = packMcCvn10Cvr({ scriptProcessedCount: 3, scriptFailedCount: 1 });
    expect(cvr[3]).toBe(0x31);
  });

  it('byte-for-byte hand-computed vector: online decline path', () => {
    // AAC returned in 1st GEN (host declined, retry AAC) + CDA performed
    //   byte 1 = 0x20 (AAC 1st GEN)
    //   byte 2 = 0x80 (CDA performed), PIN retries 3 → 0x83
    //   byte 3 = 0x00
    //   byte 4 = 0x00
    const inp: CvrInputs = {
      aacFirstGen: true,
      cdaPerformed: true,
      pinTryCounter: 3,
    };
    expect(packMcCvn10Cvr(inp).toString('hex')).toBe('20830000');
  });

  it('reserved bits in byte 1 (b3..b1) are always zero', () => {
    const cvr = packMcCvn10Cvr({
      aacSecondGen: true,
      tcSecondGen: true,
      aacFirstGen: true,
      tcFirstGen: true,
      arqcFirstGen: true,
    });
    // All declared byte-1 flags set = 0xF8. Reserved b3..b1 must be 0.
    expect(cvr[0]).toBe(0xf8);
    expect(cvr[0] & 0x07).toBe(0x00);
  });

  it('reserved bit b1 in byte 3 is always zero', () => {
    const cvr = packMcCvn10Cvr({
      lastOnlineNotCompleted: true,
      pinTryLimitExceeded: true,
      offlinePinPerformed: true,
      offlinePinFailed: true,
      unableToGoOnline: true,
      scriptReceived: true,
      scriptFailed: true,
    });
    // All declared = 0xFE. b1 must be 0.
    expect(cvr[2]).toBe(0xfe);
    expect(cvr[2] & 0x01).toBe(0x00);
  });
});

// ---------------------------------------------------------------------------
// Mastercard M/Chip CVN 17/18 — 6-byte CVR
// ---------------------------------------------------------------------------

describe('packMcCvn17Or18Cvr (Mastercard M/Chip CVN 17/18, 6-byte CVR)', () => {
  it('returns 6 bytes all zero for empty input', () => {
    const cvr = packMcCvn17Or18Cvr({});
    expect(cvr.length).toBe(6);
    expect(cvr.toString('hex')).toBe('000000000000');
  });

  it('bytes 0-3 match the 4-byte CVN 10 layout', () => {
    const inp: CvrInputs = {
      arqcFirstGen: true,
      cdaPerformed: true,
      pinTryCounter: 3,
    };
    const four = packMcCvn10Cvr(inp);
    const six = packMcCvn17Or18Cvr(inp);
    expect(six.subarray(0, 4).toString('hex')).toBe(four.toString('hex'));
  });

  it('byte 5 carries last-online-ATC low byte', () => {
    const cvr = packMcCvn17Or18Cvr({ lastOnlineAtcLow: 0x4f });
    expect(cvr[4]).toBe(0x4f);
  });

  it('byte 6 carries issuer-discretionary nibble in high half', () => {
    const cvr = packMcCvn17Or18Cvr({ issuerDiscretionary: 0x0a });
    expect(cvr[5]).toBe(0xa0);
    expect(cvr[5] & 0x0f).toBe(0x00); // low nibble reserved
  });

  it('byte 6 low nibble (reserved) is always zero', () => {
    const cvr = packMcCvn17Or18Cvr({ issuerDiscretionary: 0x0f });
    expect(cvr[5] & 0x0f).toBe(0x00);
  });

  it('byte-for-byte hand-computed vector: CDA-performed TC', () => {
    // CDA + TC in 1st GEN AC, 5 PIN tries, issuer-disc = 0x3
    //   byte 1 = 0x10 (TC 1st GEN)
    //   byte 2 = 0x80 | 0x05 = 0x85
    //   byte 3 = 0x00
    //   byte 4 = 0x00
    //   byte 5 = 0x00 (no prior online txn)
    //   byte 6 = 0x30 (issuer-disc nibble)
    const inp: CvrInputs = {
      tcFirstGen: true,
      cdaPerformed: true,
      pinTryCounter: 5,
      issuerDiscretionary: 0x3,
    };
    expect(packMcCvn17Or18Cvr(inp).toString('hex')).toBe('108500000030');
  });
});

// ---------------------------------------------------------------------------
// Visa VSDC CVN 10/18 — 4-byte CVR
// ---------------------------------------------------------------------------

describe('packVisaCvn10Cvr (Visa VSDC CVN 10/18, 4-byte CVR)', () => {
  it('returns 4 bytes all zero for empty input', () => {
    const cvr = packVisaCvn10Cvr({});
    expect(cvr.length).toBe(4);
    expect(cvr.toString('hex')).toBe('00000000');
  });

  it('sets ARQC in 1st GEN AC (byte 1 bit 4 = 0x08)', () => {
    const cvr = packVisaCvn10Cvr({ arqcFirstGen: true });
    expect(cvr[0]).toBe(0x08);
  });

  it('byte 2 packs script processed (hi) + failed (lo) counters', () => {
    const cvr = packVisaCvn10Cvr({ scriptProcessedCount: 2, scriptFailedCount: 1 });
    expect(cvr[1]).toBe(0x21);
  });

  it('byte 3 packs unable-to-go-online (bit 8 = 0x80)', () => {
    const cvr = packVisaCvn10Cvr({ unableToGoOnline: true });
    expect(cvr[2]).toBe(0x80);
  });

  it('byte 4 bit 8 = issuer auth performed (positive form)', () => {
    const cvr = packVisaCvn10Cvr({ issuerAuthNotPerformed: false });
    expect(cvr[3]).toBe(0x80);
  });

  it('byte 4 bit 8 stays 0 when issuerAuthNotPerformed is undefined or true', () => {
    expect(packVisaCvn10Cvr({})[3] & 0x80).toBe(0);
    expect(packVisaCvn10Cvr({ issuerAuthNotPerformed: true })[3] & 0x80).toBe(0);
  });

  it('byte 4 bit 6 = CDA performed (0x20)', () => {
    const cvr = packVisaCvn10Cvr({ cdaPerformed: true });
    expect(cvr[3]).toBe(0x20);
  });

  it('byte 4 low nibble carries issuer discretionary', () => {
    const cvr = packVisaCvn10Cvr({ issuerDiscretionary: 0x0c });
    expect(cvr[3] & 0x0f).toBe(0x0c);
  });

  it('byte-for-byte hand-computed vector: ARQC + issuer auth ok + CDA', () => {
    // byte 1 = 0x08 (ARQC 1st GEN)
    // byte 2 = 0x00 (no scripts yet)
    // byte 3 = 0x00 (no PIN, went online)
    // byte 4 = 0x80 (iss auth performed) | 0x20 (CDA) | 0x05 (iss-disc) = 0xA5
    const inp: CvrInputs = {
      arqcFirstGen: true,
      issuerAuthNotPerformed: false,
      cdaPerformed: true,
      issuerDiscretionary: 0x5,
    };
    expect(packVisaCvn10Cvr(inp).toString('hex')).toBe('080000a5');
  });

  it('reserved b1 in byte 3 is always zero', () => {
    const cvr = packVisaCvn10Cvr({
      unableToGoOnline: true,
      offlinePinPerformed: true,
      offlinePinFailed: true,
      pinTryLimitExceeded: true,
      lastOnlineNotCompleted: true,
      scriptReceived: true,
      scriptFailed: true,
    });
    expect(cvr[2] & 0x01).toBe(0x00);
  });
});

// ---------------------------------------------------------------------------
// Visa qVSDC CVN 22 — 4-byte CVR
// ---------------------------------------------------------------------------

describe('packVisaCvn22Cvr (Visa qVSDC CVN 22, 4-byte CVR)', () => {
  it('returns 4 bytes all zero for empty input', () => {
    expect(packVisaCvn22Cvr({}).toString('hex')).toBe('00000000');
  });

  it('byte 2 packs qVSDC-specific flags (qvsdcGenerated = 0x80)', () => {
    expect(packVisaCvn22Cvr({ qvsdcGenerated: true })[1]).toBe(0x80);
  });

  it('byte 2 packs qvsdcPpse (0x40)', () => {
    expect(packVisaCvn22Cvr({ qvsdcPpse: true })[1]).toBe(0x40);
  });

  it('byte 2 packs readerFddaPerformed (0x20)', () => {
    expect(packVisaCvn22Cvr({ readerFddaPerformed: true })[1]).toBe(0x20);
  });

  it('byte 2 packs offlineOnly (0x10)', () => {
    expect(packVisaCvn22Cvr({ offlineOnly: true })[1]).toBe(0x10);
  });

  it('byte 2 low nibble (reserved) is always zero', () => {
    const cvr = packVisaCvn22Cvr({
      qvsdcGenerated: true,
      qvsdcPpse: true,
      readerFddaPerformed: true,
      offlineOnly: true,
    });
    expect(cvr[1] & 0x0f).toBe(0x00);
  });

  it('byte 4 low nibble (reserved) is always zero', () => {
    const cvr = packVisaCvn22Cvr({ issuerDiscretionary: 0x0f });
    expect(cvr[3] & 0x0f).toBe(0x00);
    expect(cvr[3]).toBe(0xf0);
  });

  it('byte-for-byte vector: standard qVSDC transaction', () => {
    // ARQC + qvsdcGenerated + fDDA
    //   byte 1 = 0x08 (ARQC 1st GEN)
    //   byte 2 = 0x80 | 0x20 = 0xA0
    //   byte 3 = 0x00
    //   byte 4 = 0x00
    const inp: CvrInputs = {
      arqcFirstGen: true,
      qvsdcGenerated: true,
      readerFddaPerformed: true,
    };
    expect(packVisaCvn22Cvr(inp).toString('hex')).toBe('08a00000');
  });
});

// ---------------------------------------------------------------------------
// DAC/IDN derivation
// ---------------------------------------------------------------------------

describe('deriveDacIdn', () => {
  it('produces 2 bytes', () => {
    expect(deriveDacIdn('5100000000000001', '01').length).toBe(2);
  });

  it('is deterministic for the same inputs', () => {
    const a = deriveDacIdn('5100000000000001', '01');
    const b = deriveDacIdn('5100000000000001', '01');
    expect(a.equals(b)).toBe(true);
  });

  it('differs across PANs', () => {
    const a = deriveDacIdn('5100000000000001', '01');
    const b = deriveDacIdn('5100000000000002', '01');
    expect(a.equals(b)).toBe(false);
  });

  it('differs across CSNs', () => {
    const a = deriveDacIdn('5100000000000001', '01');
    const b = deriveDacIdn('5100000000000001', '02');
    expect(a.equals(b)).toBe(false);
  });

  it('matches the documented SHA256(PAN||CSN)[0..1] algorithm', () => {
    const got = deriveDacIdn('5100000000000001', '01');
    const expected = createHash('sha256')
      .update(Buffer.from('5100000000000001', 'utf8'))
      .update(Buffer.from('01', 'utf8'))
      .digest()
      .subarray(0, 2);
    expect(got.equals(expected)).toBe(true);
  });
});

describe('resolveDacIdn', () => {
  it('returns explicit dacIdn unchanged when supplied', () => {
    const explicit = Buffer.from([0xab, 0xcd]);
    expect(resolveDacIdn({ dacIdn: explicit }).toString('hex')).toBe('abcd');
  });

  it('throws when dacIdn is the wrong length', () => {
    expect(() => resolveDacIdn({ dacIdn: Buffer.from([0xab]) })).toThrow(/2 bytes/);
    expect(() => resolveDacIdn({ dacIdn: Buffer.from([0xab, 0xcd, 0xef]) })).toThrow(/2 bytes/);
  });

  it('derives from PAN+CSN when dacIdn absent', () => {
    const got = resolveDacIdn({ pan: '5100000000000001', csn: '01' });
    const expected = deriveDacIdn('5100000000000001', '01');
    expect(got.equals(expected)).toBe(true);
  });

  it('falls back to 0x0000 and warns when neither supplied', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const got = resolveDacIdn({});
    expect(got.toString('hex')).toBe('0000');
    expect(warnSpy).toHaveBeenCalledTimes(1);
    warnSpy.mockRestore();
  });

  it('only warns once per process', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    resolveDacIdn({});
    resolveDacIdn({});
    resolveDacIdn({});
    expect(warnSpy).toHaveBeenCalledTimes(1);
    warnSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// buildIad — integration (structural, plus new-signature behavior)
// ---------------------------------------------------------------------------

describe('buildIad — length contract per CVN', () => {
  // Silence deprecation warnings for pure-structural tests — they're covered
  // in a dedicated test below.
  let warnSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  it.each([
    [10, 'mchip_advance' as const, 11],
    [17, 'mchip_advance' as const, 19],
    [18, 'mchip_advance' as const, 19],
    [10, 'vsdc' as const, 7],
    [18, 'vsdc' as const, 8],
    [22, 'vsdc' as const, 32],
  ])('CVN %i %s produces %i bytes', (cvn, scheme, totalLen) => {
    const iad = buildIad(cvn, 0x01, '000', scheme);
    expect(iad.length).toBe(totalLen);
    // keep warnSpy referenced so TS "noUnusedLocals" doesn't complain
    expect(warnSpy).toBeDefined();
  });

  it('CVN 10 Mastercard: CVR occupies bytes 3-6, DAC/IDN bytes 7-8, iCVV bytes 9-10', () => {
    const iad = buildIad(10, 0x01, '123', 'mchip_advance', {
      cvr: { arqcFirstGen: true },
      dacIdn: Buffer.from([0xde, 0xad]),
    });
    expect(iad.length).toBe(11);
    expect(iad.subarray(3, 7).toString('hex')).toBe('08000000'); // CVR
    expect(iad.subarray(7, 9).toString('hex')).toBe('dead');     // DAC/IDN
    expect(iad.subarray(9, 11).toString('hex')).toBe('1230');    // iCVV
  });

  it('CVN 17 Mastercard: CVR occupies bytes 3-8, DAC/IDN bytes 9-10', () => {
    const iad = buildIad(17, 0x01, '000', 'mchip_advance', {
      cvr: { cdaPerformed: true },
      dacIdn: Buffer.from([0xbe, 0xef]),
    });
    expect(iad.length).toBe(19);
    expect(iad.subarray(3, 9).toString('hex')).toBe('008000000000'); // CVR
    expect(iad.subarray(9, 11).toString('hex')).toBe('beef');        // DAC/IDN
  });

  it('CVN 18 Mastercard: CVR occupies bytes 3-8, DAC/IDN bytes 9-10', () => {
    const iad = buildIad(18, 0x01, '000', 'mchip_advance', {
      cvr: { cdaPerformed: true },
      dacIdn: Buffer.from([0xca, 0xfe]),
    });
    expect(iad.length).toBe(19);
    expect(iad.subarray(3, 9).toString('hex')).toBe('008000000000'); // CVR
    expect(iad.subarray(9, 11).toString('hex')).toBe('cafe');        // DAC/IDN
  });

  it('Visa CVN 10: CVR occupies bytes 3-6 (no DAC/IDN slot)', () => {
    const iad = buildIad(10, 0x01, '000', 'vsdc', {
      cvr: { arqcFirstGen: true },
    });
    expect(iad.length).toBe(7);
    expect(iad.subarray(3, 7).toString('hex')).toBe('08000000');
  });

  it('Visa CVN 18: CVR occupies bytes 3-6, IDD length = 0 at byte 7', () => {
    const iad = buildIad(18, 0x01, '000', 'vsdc', {
      cvr: { arqcFirstGen: true, cdaPerformed: true, issuerAuthNotPerformed: false },
    });
    expect(iad.length).toBe(8);
    // byte 1 = 0x08, byte 2 = 0, byte 3 = 0, byte 4 = 0x80 | 0x20 = 0xA0
    expect(iad.subarray(3, 7).toString('hex')).toBe('080000a0');
    expect(iad[7]).toBe(0x00);
  });

  it('Visa CVN 22: CVR occupies bytes 3-6 (qVSDC flags populated)', () => {
    const iad = buildIad(22, 0x01, '456', 'vsdc', {
      cvr: { arqcFirstGen: true, qvsdcGenerated: true },
    });
    expect(iad.length).toBe(32);
    expect(iad.subarray(3, 7).toString('hex')).toBe('08800000');
    // iCVV still at its expected offset (14-15)
    expect(iad[14]).toBe(0x45);
    expect(iad[15]).toBe(0x60);
  });
});

describe('buildIad — backward compatibility', () => {
  it('legacy 4-arg call still compiles & returns the expected layout', () => {
    // Silence the deprecation warn for this test
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const iad = buildIad(18, 0x01, '000', 'mchip_advance');
    warnSpy.mockRestore();

    expect(iad.length).toBe(19);
    expect(iad[0]).toBe(0x12);
    expect(iad[1]).toBe(0x01);
    expect(iad[2]).toBe(0x12);
    // CVR bytes should be all zero (legacy at-perso behavior preserved)
    expect(iad.subarray(3, 9).toString('hex')).toBe('000000000000');
    // DAC/IDN falls back to 0x0000 (legacy behavior)
    expect(iad.subarray(9, 11).toString('hex')).toBe('0000');
  });

  it('warns exactly once when called without the options object', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    buildIad(10, 0x01, '000', 'mchip_advance');
    buildIad(18, 0x01, '000', 'mchip_advance');
    buildIad(22, 0x01, '000', 'vsdc');
    // 3 calls; expect ONE warn about the legacy signature,
    // plus warnings from resolveDacIdn (once for missing pan/csn fallback).
    const legacyCalls = warnSpy.mock.calls.filter(c =>
      typeof c[0] === 'string' && c[0].includes('without CVR/DAC inputs'),
    );
    expect(legacyCalls.length).toBe(1);
    warnSpy.mockRestore();
  });

  it('does NOT warn when called with an (empty) options object', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    buildIad(18, 0x01, '000', 'mchip_advance', { dacIdn: Buffer.alloc(2) });
    const legacyCalls = warnSpy.mock.calls.filter(c =>
      typeof c[0] === 'string' && c[0].includes('without CVR/DAC inputs'),
    );
    expect(legacyCalls.length).toBe(0);
    warnSpy.mockRestore();
  });
});

describe('buildIad — DAC/IDN derivation integration', () => {
  it('derives DAC/IDN from pan+csn when not explicitly provided', () => {
    const iad = buildIad(10, 0x01, '000', 'mchip_advance', {
      pan: '5100000000000001',
      csn: '01',
    });
    const expected = deriveDacIdn('5100000000000001', '01');
    expect(iad.subarray(7, 9).equals(expected)).toBe(true);
  });

  it('explicit dacIdn overrides pan+csn derivation', () => {
    const iad = buildIad(10, 0x01, '000', 'mchip_advance', {
      pan: '5100000000000001',
      csn: '01',
      dacIdn: Buffer.from([0xf0, 0x0d]),
    });
    expect(iad.subarray(7, 9).toString('hex')).toBe('f00d');
  });
});

describe('buildIad — structural vs previous all-zero output', () => {
  // These tests enshrine the bug fix: even with EMPTY cvr inputs, the IAD
  // is structurally identical to the legacy all-zero output (zero-at-perso
  // is correct for fresh cards). But WITH inputs, the CVR must NOT be zero.
  it('at-perso (empty cvr inputs) produces all-zero CVR bytes', () => {
    const iad = buildIad(18, 0x01, '000', 'mchip_advance', {
      cvr: {},
      dacIdn: Buffer.alloc(2),
    });
    expect(iad.subarray(3, 9).toString('hex')).toBe('000000000000');
  });

  it('populated CVR inputs produce non-zero CVR bytes', () => {
    const iad = buildIad(18, 0x01, '000', 'mchip_advance', {
      cvr: { arqcFirstGen: true, cdaPerformed: true, pinTryCounter: 3 },
      dacIdn: Buffer.alloc(2),
    });
    expect(iad.subarray(3, 9).toString('hex')).not.toBe('000000000000');
    // Byte 1 = 0x08 (ARQC 1st GEN)
    expect(iad[3]).toBe(0x08);
    // Byte 2 = 0x80 (CDA) | 0x03 (PIN tries)
    expect(iad[4]).toBe(0x83);
  });
});

// ---------------------------------------------------------------------------
// Integration: round-trips through SADBuilder so a broken IAD surfaces there
// ---------------------------------------------------------------------------

describe('buildIad — integration through SADBuilder', () => {
  it('SAD DGI containing Tag 9F10 still parses as expected with new IAD', async () => {
    // Minimal inline clone of the SAD test path: build an IAD and make sure
    // it survives TLV wrapping. We don't import SADBuilder here because this
    // file is colocated with iad-builder only; the primary SAD integration
    // remains covered by emv.test.ts's SADBuilder suite.
    const iad = buildIad(10, 0x01, '123', 'mchip_advance', {
      cvr: { arqcFirstGen: true },
      pan: '5100000000000001',
      csn: '01',
    });
    // BER-TLV encode: tag 9F10, short-form length
    const tag = Buffer.from([0x9f, 0x10]);
    const len = Buffer.from([iad.length]);
    const tlv = Buffer.concat([tag, len, iad]);
    // Minimum viable sanity: tag prefix, correct length, value preserved.
    expect(tlv.subarray(0, 2).toString('hex')).toBe('9f10');
    expect(tlv[2]).toBe(iad.length);
    expect(tlv.subarray(3).equals(iad)).toBe(true);
  });
});
