/**
 * Tests for the ParamBundle path: prepare() router + prepareParamBundle().
 *
 * Focus: verify routing behaviour + ParamRecord write, NOT the full
 * end-to-end ParamBundle byte content (that's proved by the byte-parity
 * test in packages/emv/src/byte-parity.test.ts).
 */

import { vi, describe, it, expect, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    issuerProfile: { findUnique: vi.fn() },
    sadRecord: { create: vi.fn() },
    paramRecord: { create: vi.fn() },
    card: { update: vi.fn() },
    $transaction: vi.fn(),
  },
}));

vi.mock('@aws-sdk/client-kms', () => ({
  KMSClient: vi.fn().mockImplementation(() => ({
    send: vi.fn().mockResolvedValue({
      CiphertextBlob: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    }),
  })),
  EncryptCommand: vi.fn(),
  DecryptCommand: vi.fn(),
}));

vi.mock('@aws-sdk/client-payment-cryptography-data', () => ({
  // GenerateCardValidationData returns a 3-byte iCVV (6 hex chars) so
  // scheme-mchip's Buffer.from(icvv, 'hex') produces exactly 3 bytes.
  // EncryptDataCommand returns 16 hex chars = 8 bytes (dummy MK-AC/etc
  // derived-key payload — mock APC).
  PaymentCryptographyDataClient: vi.fn().mockImplementation(() => ({
    send: vi.fn().mockResolvedValue({ ValidationData: '012345', CipherText: 'AABBCCDDEEFF0011' }),
  })),
  GenerateCardValidationDataCommand: vi.fn(),
  EncryptDataCommand: vi.fn(),
}));

vi.mock('@aws-sdk/client-payment-cryptography', () => ({
  PaymentCryptographyClient: vi.fn().mockImplementation(() => ({
    send: vi.fn().mockResolvedValue({
      Key: { KeyArn: 'arn:aws:payment-cryptography:ap-southeast-2:000:key/derived-mk' },
    }),
  })),
  ImportKeyCommand: vi.fn(),
}));

// Don't mock @palisade/emv here — we want the real buildMChipParamBundle
// to run against the derived inputs.  It's pure (no I/O) so it works fine.

import { prisma } from '@palisade/db';
import { DataPrepService, type PrepareInput } from './data-prep.service.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FULL_MCHIP_PROFILE = {
  // All required MChip CVN 18 fields populated.  Values match the
  // byte-parity test fixture in packages/emv/src/byte-parity.test.ts so
  // the end-to-end bundle round-trips cleanly.
  id:                  'issuer_mchip_cvn18',
  programId:           'prog_test',
  scheme:              'mchip_advance',
  cvn:                 18,
  imkAlgorithm:        'TDES_2KEY',
  derivationMethod:    'METHOD_A',
  tmkKeyArn:           'arn:aws:payment-cryptography:ap-southeast-2:000:key/tmk',
  imkAcKeyArn:         'arn:aws:payment-cryptography:ap-southeast-2:000:key/ac',
  imkSmiKeyArn:        'arn:aws:payment-cryptography:ap-southeast-2:000:key/smi',
  imkSmcKeyArn:        'arn:aws:payment-cryptography:ap-southeast-2:000:key/smc',
  aip:                 '3900',
  afl:                 '08010100',
  cvmList:             '000000000000000042031E031F03000000',
  pdol:                '',
  cdol1:               '',
  cdol2:               '',
  iacDefault:          '0000000000',
  iacDenial:           '0000000000',
  iacOnline:           'F470C4A800',
  appUsageControl:     'FF00',
  currencyCode:        '0840',
  currencyExponent:    '02',
  countryCode:         '0840',
  sdaTagList:          '',
  appVersionNumber:    '0002',
  appPriority:         '',
  aid:                 'A0000000041010',
  appLabel:            'MASTERCARD',
  appPreferredName:    '',
  issuerPkCertificate: '33'.repeat(112),
  issuerPkExponent:    '03',
  issuerPkRemainder:   '',
  caPkIndex:           'F5',
  bankId:              0x00545490,
  progId:              0x00000001,
  postProvisionUrl:    'tap.karta.cards',
};

const FAKE_PREPARE_INPUT: PrepareInput = {
  cardId:    'card_test_01',
  pan:       '5413339800000003',
  expiryYymm:'3012',
  serviceCode:  '201',
  cardSequenceNumber: '01',
  programId: 'prog_test',
};

describe('DataPrepService — ParamBundle path', () => {
  let service: DataPrepService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new DataPrepService();
  });

  it('prepare() routes PARAM_BUNDLE ChipProfiles to prepareParamBundle', async () => {
    (prisma.issuerProfile.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...FULL_MCHIP_PROFILE,
      chipProfile: {
        id: 'chip_mchip_v3',
        name: 'MChip CVN 18 v3',
        scheme: 'mchip_advance',
        vendor: 'nxp',
        cvn: 18,
        dgiDefinitions: [],
        elfAid: '',
        moduleAid: '',
        paAid: 'A0000000625041034C',
        fidoAid: '',
        iccPrivateKeyDgi: 0x8001,
        iccPrivateKeyTag: 0x9F48,
        mkAcDgi: 0x0800,
        mkSmiDgi: 0x0801,
        mkSmcDgi: 0x0802,
        provisioningMode: 'PARAM_BUNDLE',
      },
    });

    // $transaction runs its callback against the mocked prisma tx object.
    (prisma.$transaction as ReturnType<typeof vi.fn>).mockImplementation(
      async (cb: (tx: unknown) => unknown) => cb(prisma),
    );
    (prisma.paramRecord.create as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'pr_test_01',
      proxyCardId: 'pxy_test',
      cardId: 'card_test_01',
      status: 'READY',
    });
    (prisma.card.update as ReturnType<typeof vi.fn>).mockResolvedValue({});

    const result = await service.prepare(FAKE_PREPARE_INPUT);

    expect(result.status).toBe('READY');
    // prepareCard path would have written sadRecord.create; confirm it
    // did NOT.
    expect(prisma.sadRecord.create).not.toHaveBeenCalled();
    // ParamRecord path wrote paramRecord.create.
    expect(prisma.paramRecord.create).toHaveBeenCalledTimes(1);
    // Card.paramRecordId was linked (not proxyCardId).
    expect(prisma.card.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'card_test_01' },
        data: expect.objectContaining({ paramRecordId: expect.any(String) }),
      }),
    );
  });

  it('prepare() routes SAD_LEGACY ChipProfiles to prepareCard (unchanged)', async () => {
    (prisma.issuerProfile.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...FULL_MCHIP_PROFILE,
      chipProfile: {
        id: 'chip_legacy',
        name: 'Legacy MChip',
        scheme: 'mchip_advance',
        vendor: 'nxp',
        cvn: 18,
        dgiDefinitions: [
          // Minimal DGI def so SADBuilder doesn't blow up; tests
          // don't check SAD content, just routing.
          {
            dgi_number: 0x0101,
            name: 'App Data',
            tags: [0x82],
            mandatory: true,
            source: 'per_profile',
          },
        ],
        elfAid: '',
        moduleAid: '',
        paAid: 'A00000006250414C',
        fidoAid: '',
        iccPrivateKeyDgi: 0x8001,
        iccPrivateKeyTag: 0x9F48,
        mkAcDgi: 0x0800,
        mkSmiDgi: 0x0801,
        mkSmcDgi: 0x0802,
        provisioningMode: 'SAD_LEGACY',
      },
    });

    (prisma.sadRecord.create as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'sad_test_01',
      proxyCardId: 'pxy_test_legacy',
      status: 'READY',
    });
    (prisma.card.update as ReturnType<typeof vi.fn>).mockResolvedValue({});

    const result = await service.prepare(FAKE_PREPARE_INPUT);

    expect(result.status).toBe('READY');
    // Legacy path wrote sadRecord.create; confirm ParamRecord.create
    // was NOT touched.
    expect(prisma.sadRecord.create).toHaveBeenCalledTimes(1);
    expect(prisma.paramRecord.create).not.toHaveBeenCalled();
    // Card.proxyCardId was linked (not paramRecordId).
    expect(prisma.card.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ proxyCardId: expect.any(String) }),
      }),
    );
  });

  it('prepareParamBundle rejects a SAD_LEGACY ChipProfile (direct-call guard)', async () => {
    (prisma.issuerProfile.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...FULL_MCHIP_PROFILE,
      chipProfile: {
        id: 'chip_legacy_2',
        name: 'Legacy',
        scheme: 'mchip_advance',
        vendor: 'nxp',
        cvn: 18,
        dgiDefinitions: [],
        elfAid: '', moduleAid: '', paAid: 'A00000006250414C', fidoAid: '',
        iccPrivateKeyDgi: 0, iccPrivateKeyTag: 0, mkAcDgi: 0, mkSmiDgi: 0, mkSmcDgi: 0,
        provisioningMode: 'SAD_LEGACY',
      },
    });

    // badRequest throws an ApiError whose `.message` is the 2nd arg and
    // `.code` is the 1st.  Default toString surfaces the message, so
    // we assert against the message (and separately check the code on
    // a direct catch if we wanted stricter).
    await expect(service.prepareParamBundle(FAKE_PREPARE_INPUT)).rejects.toThrow(
      /provisioningMode=SAD_LEGACY/,
    );
  });
});
