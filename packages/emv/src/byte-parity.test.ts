/**
 * Byte-parity test: `simulateMChipChipBuild(paramBundle)` vs the legacy
 * `SADBuilder.buildSad(...)` for the same inputs.
 *
 * This is the correctness gate for the prototype.  If the simulated
 * chip output doesn't match what the legacy server-side builder
 * produces for the same profile, the PA v3 applet (once it ports
 * `simulateMChipChipBuild`'s logic to Java) will commit DIFFERENT
 * bytes to chip NVM than a legacy-provisioned card would have.
 * That means a prototype card wouldn't transact at the same POS
 * readers as a legacy card, even though they hold "the same"
 * profile.  Byte parity proves functional equivalence.
 *
 * What we compare:
 *   - Our `simulateMChipChipBuild` produces Map<dgi, bytes>.
 *   - Legacy `SADBuilder.buildSad` produces Array<[dgi, bytes]>.
 *   - For DGIs the prototype handles (0101/0102/8201/9201), the bytes
 *     must match exactly.
 *
 * What we don't compare (deliberately out of scope for prototype):
 *   - DGIs the legacy builder emits that the prototype doesn't
 *     (e.g. DGI 0202 for issuer-specific extension tags).  The
 *     prototype scope is MChip CVN 18 with the four canonical DGIs;
 *     adding more DGIs is a scheme-mchip extension task.
 *   - Tag ordering within a DGI: legacy may order by tag number,
 *     prototype emits in a fixed order.  If the ordering within a
 *     DGI matters to the applet, we normalise here.
 */

import { describe, it, expect } from 'vitest';
import { SADBuilder, type IssuerProfileForSad, type CardData } from './sad-builder.js';
import { ChipProfile } from './chip-profile.js';
import { DGI } from './dgi.js';
import {
  buildMChipParamBundle,
  simulateMChipChipBuild,
  type McipMapperInput,
} from './scheme-mchip.js';

// ---------------------------------------------------------------------------
// Fixture: a realistic MChip CVN 18 profile matching what the current
// issuer-profile seed script stores.  Hex values lifted from
// scripts/seed-karta-platinum-issuer-profile.ts.
// ---------------------------------------------------------------------------

const FIXTURE_PROFILE: IssuerProfileForSad = {
  scheme: 'mchip_advance',
  cvn: 18,
  aip: '3900',
  afl: '08010100',
  cvmList: '000000000000000042031E031F03000000',
  pdol: '',
  cdol1: '',
  cdol2: '',
  iacDefault: '0000000000',
  iacDenial: '0000000000',
  iacOnline: 'F470C4A800',
  appUsageControl: 'FF00',
  currencyCode: '0840',
  currencyExponent: '02',
  countryCode: '0840',
  appVersionNumber: '0002',
  aid: 'A0000000041010',
  appLabel: 'MASTERCARD',
  issuerPkCertificate: '33'.repeat(112),
  issuerPkExponent: '03',
  caPkIndex: 'F5',
};

const FIXTURE_CARD: CardData = {
  pan: '5413339800000003',
  expiryDate: '3012',
  effectiveDate: '2505',
  serviceCode: '201',
  cardSequenceNumber: '01',
  icvv: '000123',
};

const MAPPER_INPUT: McipMapperInput = {
  profile: FIXTURE_PROFILE,
  card: FIXTURE_CARD,
  mkAc: Buffer.alloc(16, 0xaa),
  mkSmi: Buffer.alloc(16, 0xbb),
  mkSmc: Buffer.alloc(16, 0xcc),
  iccRsaPriv: Buffer.alloc(128, 0x11),
  iccPkCert: Buffer.alloc(100, 0x22),
  bankId: 0x00545490,
  progId: 0x00000001,
  postProvisionUrl: 'tap.karta.cards',
};

/**
 * Minimal MChip CVN 18 ChipProfile for the legacy SADBuilder.  Matches
 * the DGI layout the prototype's `simulateMChipChipBuild` produces so
 * we're comparing apples to apples.
 */
const LEGACY_CHIP_PROFILE = new ChipProfile({
  profileId: 'test-mchip-cvn18',
  profileName: 'Test MChip CVN 18 for byte parity',
  scheme: 'mchip_advance',
  appletVendor: 'nxp',
  cvn: 18,
  dgiDefinitions: [
    {
      dgiNumber: 0x0101,
      name: 'App Data',
      tags: [
        0x82, 0x94, 0x9f07, 0x5a, 0x5f24, 0x5f25, 0x57, 0x5f34, 0x84,
        0x9f08, 0x9f42, 0x9f44, 0x5f28, 0x50,
      ],
      mandatory: true,
      source: 'per_card',
    },
    {
      dgiNumber: 0x0102,
      name: 'AFL duplicate',
      tags: [0x94],
      mandatory: true,
      source: 'per_profile',
    },
    // DGI 8201 and 9201 are deliberately NOT in the legacy profile —
    // they contain per-card key material (MK-AC etc) and scheme-
    // specific data that legacy SADBuilder doesn't assemble.  Those
    // DGIs are generated from ParamBundle contents on the prototype
    // side; there's no legacy parity target.
  ],
  iccPrivateKeyDgi: 0x8201,
  iccPrivateKeyTag: 0xdf73,
  mkAcDgi: 0x8201,
  mkSmiDgi: 0x8201,
  mkSmcDgi: 0x8201,
  elfAid: 'A0000000625041',
  moduleAid: 'A00000006250414C',
  paAid: 'A00000006250414C',
  fidoAid: 'A0000006472F0001',
});

// Helper: pull a DGI by number from SADBuilder's output and strip the
// DGI-wrapper header, returning the raw TLV content that the applet
// actually stores in NVM.
//
// Legacy SADBuilder output format per DGI:
//   [DGI tag (2 BE)] [BER length (1-3 bytes)] [TLV payload]
//
// The prototype's `simulateMChipChipBuild` returns just the TLV
// payload — that's what the applet writes to its NVM EMV tag table.
// For byte parity we compare payload-to-payload.
function legacyDgi(
  legacyOutput: Array<[number, Buffer]>,
  dgiNum: number,
): Buffer | undefined {
  const hit = legacyOutput.find(([n]) => n === dgiNum);
  if (!hit) return undefined;
  // Parse the wrapped bytes to extract the raw TLV payload.
  const [[, payload]] = DGI.parse(hit[1]);
  return payload;
}

describe('byte parity — prototype simulateMChipChipBuild vs legacy SADBuilder', () => {
  it('DGI 0101 — App Data — byte-identical', () => {
    const legacy = SADBuilder.buildSad(FIXTURE_PROFILE, LEGACY_CHIP_PROFILE, FIXTURE_CARD);
    const bundle = buildMChipParamBundle(MAPPER_INPUT);
    const chip = simulateMChipChipBuild(bundle);

    const legacyBytes = legacyDgi(legacy, 0x0101);
    expect(legacyBytes).toBeDefined();
    if (!legacyBytes) return;

    // If the bytes diverge, the test output will show the hex diff so
    // a human can see which tag is mis-ordered / mis-encoded.
    if (!chip.dgi0101.equals(legacyBytes)) {
      // eslint-disable-next-line no-console
      console.error(
        '\nByte-parity MISMATCH on DGI 0101:' +
          `\n  prototype: ${chip.dgi0101.toString('hex').toUpperCase()}` +
          `\n  legacy:    ${legacyBytes.toString('hex').toUpperCase()}`,
      );
    }
    expect(chip.dgi0101.equals(legacyBytes)).toBe(true);
  });

  it('DGI 0102 — AFL duplicate — byte-identical', () => {
    const legacy = SADBuilder.buildSad(FIXTURE_PROFILE, LEGACY_CHIP_PROFILE, FIXTURE_CARD);
    const bundle = buildMChipParamBundle(MAPPER_INPUT);
    const chip = simulateMChipChipBuild(bundle);

    const legacyBytes = legacyDgi(legacy, 0x0102);
    expect(legacyBytes).toBeDefined();
    if (!legacyBytes) return;

    if (!chip.dgi0102.equals(legacyBytes)) {
      // eslint-disable-next-line no-console
      console.error(
        '\nByte-parity MISMATCH on DGI 0102:' +
          `\n  prototype: ${chip.dgi0102.toString('hex').toUpperCase()}` +
          `\n  legacy:    ${legacyBytes.toString('hex').toUpperCase()}`,
      );
    }
    expect(chip.dgi0102.equals(legacyBytes)).toBe(true);
  });

  // DGI 8201 + 9201 deliberately not tested for byte parity — legacy
  // SADBuilder doesn't produce them (key material lives in separate
  // pa_internal DGIs).  Prototype builds them from ParamBundle tags;
  // applet-side byte parity is enforced by the JC dev's unit tests.

  it('Tag 57 Track 2 Equivalent survives the ParamBundle round-trip', () => {
    // Regression guard for the BCD serviceCode encoding (the bug that
    // nearly cost us byte parity — serviceCode stored as 2 bytes with
    // leading zero, then decoded + last-3-digits for Track2).  If this
    // ever regresses, the Track 2 bytes will diverge and DGI 0101
    // parity fails.
    const legacy = SADBuilder.buildSad(FIXTURE_PROFILE, LEGACY_CHIP_PROFILE, FIXTURE_CARD);
    const bundle = buildMChipParamBundle(MAPPER_INPUT);
    const chip = simulateMChipChipBuild(bundle);

    // Extract tag 57 from each side by grep-hex.  Both DGIs contain it.
    // Format: 57 LL <pan_compressed><D><expiry><service_code>...
    const legacyHex = legacyDgi(legacy, 0x0101)!.toString('hex').toUpperCase();
    const chipHex = chip.dgi0101.toString('hex').toUpperCase();

    // Extract the bytes between "57" and the next tag (a hack but works
    // for this fixture).
    const legacyTrack2 = /57([0-9A-F]{2})([0-9A-F]+?)(?=5F34|5A|84|9F08|50|94|$)/.exec(legacyHex);
    const chipTrack2 = /57([0-9A-F]{2})([0-9A-F]+?)(?=5F34|5A|84|9F08|50|94|$)/.exec(chipHex);

    expect(legacyTrack2).not.toBeNull();
    expect(chipTrack2).not.toBeNull();
    expect(chipTrack2![0]).toBe(legacyTrack2![0]);
  });

  it('changing the PAN changes both legacy and prototype DGI 0101 identically', () => {
    const altCard: CardData = { ...FIXTURE_CARD, pan: '4929000012345678' };
    const altInput: McipMapperInput = { ...MAPPER_INPUT, card: altCard };

    const legacyA = SADBuilder.buildSad(FIXTURE_PROFILE, LEGACY_CHIP_PROFILE, FIXTURE_CARD);
    const legacyB = SADBuilder.buildSad(FIXTURE_PROFILE, LEGACY_CHIP_PROFILE, altCard);
    const chipA = simulateMChipChipBuild(buildMChipParamBundle(MAPPER_INPUT));
    const chipB = simulateMChipChipBuild(buildMChipParamBundle(altInput));

    // Both legacy and chip sides should diverge between A and B.
    expect(legacyDgi(legacyA, 0x0101)!.equals(legacyDgi(legacyB, 0x0101)!)).toBe(false);
    expect(chipA.dgi0101.equals(chipB.dgi0101)).toBe(false);

    // And the "after" bytes should still be byte-parity-matched.
    expect(chipB.dgi0101.equals(legacyDgi(legacyB, 0x0101)!)).toBe(true);
  });
});
