import { vi, describe, it, expect, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks — must be declared before any import that reaches them.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    issuerProfile: { findUnique: vi.fn() },
    sadRecord: { create: vi.fn() },
    card: { update: vi.fn() },
  },
}));

vi.mock('@aws-sdk/client-kms', () => ({
  KMSClient: vi.fn().mockImplementation(() => ({
    send: vi.fn(),
  })),
  EncryptCommand: vi.fn(),
  DecryptCommand: vi.fn(),
}));

vi.mock('@aws-sdk/client-payment-cryptography-data', () => ({
  PaymentCryptographyDataClient: vi.fn().mockImplementation(() => ({
    send: vi.fn().mockResolvedValue({ ValidationData: '123', CipherText: 'AABBCCDD' }),
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

// Partial-mock @palisade/emv: override SADBuilder + ChipProfile but preserve
// the real encryptSadDev / decryptSadDev / key-version constants so the
// encrypt/decrypt test cases exercise the actual crypto path.
vi.mock('@palisade/emv', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    SADBuilder: {
      buildSad: vi.fn().mockReturnValue([]),
      serialiseDgis: vi.fn().mockReturnValue(Buffer.from('DEADBEEF', 'hex')),
    },
    ChipProfile: { fromJson: vi.fn().mockReturnValue({}) },
  };
});

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import { KMSClient } from '@aws-sdk/client-kms';
import { DataPrepService, type PrepareInput } from './data-prep.service.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_CHIP_PROFILE = {
  id: 'chip_01',
  name: 'Test Chip',
  scheme: 'VISA',
  vendor: 'test',
  cvn: 18,
  dgiDefinitions: {},
  elfAid: 'A000000003101001',
  moduleAid: 'A000000003101002',
  paAid: 'D276000085504100',
  fidoAid: 'A0000006472F0001',
  iccPrivateKeyDgi: 0x8001,
  iccPrivateKeyTag: 0x9F48,
  mkAcDgi: 0x8000,
  mkSmiDgi: 0x8010,
  mkSmcDgi: 0x8012,
};

const FAKE_ISSUER_PROFILE = {
  id: 'ip_01',
  programId: 'prog_01',
  scheme: 'VISA',
  cvn: 18,
  tmkKeyArn: 'arn:tmk',
  imkAcKeyArn: 'arn:imk-ac',
  imkSmiKeyArn: 'arn:imk-smi',
  imkSmcKeyArn: 'arn:imk-smc',
  aip: '3800',
  afl: '08010100',
  cvmList: '',
  pdol: '',
  cdol1: '',
  cdol2: '',
  iacDefault: '',
  iacDenial: '',
  iacOnline: '',
  appUsageControl: '',
  currencyCode: '0840',
  currencyExponent: '02',
  countryCode: '0840',
  sdaTagList: '',
  appVersionNumber: '0002',
  appPriority: '01',
  aid: 'A0000000031010',
  appLabel: 'VISA DEBIT',
  appPreferredName: 'VISA',
  issuerPkCertificate: '',
  issuerPkRemainder: '',
  issuerPkExponent: '',
  caPkIndex: '09',
  chipProfile: FAKE_CHIP_PROFILE,
};

const VALID_INPUT: PrepareInput = {
  cardId: 'card_01',
  pan: '4242424242424242',
  expiryYymm: '2812',
  programId: 'prog_01',
};

// ---------------------------------------------------------------------------
// Tests: DataPrepService
// ---------------------------------------------------------------------------

describe('DataPrepService', () => {
  let service: DataPrepService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new DataPrepService();
  });

  describe('prepareCard', () => {
    it('creates SAD record and returns proxyCardId on valid input', async () => {
      (prisma.issuerProfile.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        FAKE_ISSUER_PROFILE,
      );
      (prisma.sadRecord.create as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: 'sad_01',
        proxyCardId: 'pxy_abc123',
        status: 'READY',
      });
      (prisma.card.update as ReturnType<typeof vi.fn>).mockResolvedValue({});

      const result = await service.prepareCard(VALID_INPUT);

      expect(result.proxyCardId).toBe('pxy_abc123');
      expect(result.sadRecordId).toBe('sad_01');
      expect(result.status).toBe('READY');
      expect(prisma.sadRecord.create).toHaveBeenCalledOnce();
      expect(prisma.card.update).toHaveBeenCalledOnce();
    });

    it('throws notFound when programId does not match any profile', async () => {
      (prisma.issuerProfile.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(
        service.prepareCard({ ...VALID_INPUT, programId: 'nonexistent' }),
      ).rejects.toMatchObject({
        status: 404,
        code: 'profile_not_found',
      });
    });
  });

  describe('encryptSad — dev mode (no KMS ARN)', () => {
    it('returns AES-128-ECB ciphertext with keyVersion=1', async () => {
      const plaintext = Buffer.from('hello SAD');
      const result = await (service as any).encryptSad(plaintext, '');

      // keyVersion=1 means AES-128-ECB under DEV_SAD_MASTER_KEY.
      expect(result.keyVersion).toBe(1);
      // ECB + PKCS#7 always rounds to a non-zero multiple of 16.
      expect(result.encrypted.length % 16).toBe(0);
      expect(result.encrypted.length).toBeGreaterThan(0);
      // Round-trip via the matching decrypt path proves the ciphertext
      // really is AES output (not the old base64 buffer).
      const roundTripped = await (
        await import('./data-prep.service.js')
      ).DataPrepService.decryptSad(result.encrypted, '', 1);
      expect(roundTripped.toString()).toBe('hello SAD');
    });
  });

  describe('encryptSad — KMS mode', () => {
    it('calls KMSClient.send with EncryptCommand and returns CiphertextBlob', async () => {
      const fakeCiphertext = new Uint8Array([0xaa, 0xbb, 0xcc]);

      // The service now uses a module-level KMSClient singleton (latency
      // audit opt #5) — reset + re-mock the constructor so the first
      // send() in this test goes through our mock.
      const { _resetKmsSingleton } = await import('./data-prep.service.js');
      _resetKmsSingleton();
      const MockKMS = KMSClient as unknown as ReturnType<typeof vi.fn>;
      const mockSend = vi.fn().mockResolvedValue({ CiphertextBlob: fakeCiphertext });
      MockKMS.mockImplementation(() => ({ send: mockSend }));

      const plaintext = Buffer.from('encrypted SAD');
      const result = await (service as any).encryptSad(plaintext, 'arn:aws:kms:us-east-1:000:key/test');

      expect(mockSend).toHaveBeenCalledOnce();
      expect(result.keyVersion).toBe(0);
      expect(Buffer.from(result.encrypted)).toEqual(Buffer.from(fakeCiphertext));
    });
  });

  describe('decryptSad — dev mode', () => {
    it('AES-128-ECB decrypts what encryptSad produced in dev mode', async () => {
      const original = Buffer.from('my SAD payload');
      const { encrypted } = await (service as any).encryptSad(original, '');

      const result = await DataPrepService.decryptSad(encrypted, '', 1);
      expect(result.toString()).toBe('my SAD payload');
    });

    it('throws on unsupported sadKeyVersion', async () => {
      await expect(
        DataPrepService.decryptSad(Buffer.from('xyz'), '', 99),
      ).rejects.toThrow(/unsupported sadKeyVersion/);
    });
  });

  describe('decryptSad — KMS mode', () => {
    it('calls KMSClient.decrypt and returns Plaintext', async () => {
      const fakePlaintext = new Uint8Array([0x01, 0x02, 0x03]);

      // decryptSad uses the module-level KMSClient singleton — reset so
      // the constructor mock we install here is what actually runs on
      // first use.
      const { _resetKmsSingleton } = await import('./data-prep.service.js');
      _resetKmsSingleton();
      const MockKMS = KMSClient as unknown as ReturnType<typeof vi.fn>;
      MockKMS.mockImplementation(() => ({
        send: vi.fn().mockResolvedValue({ Plaintext: fakePlaintext }),
      }));

      const encrypted = Buffer.from('ciphertext-blob');
      const result = await DataPrepService.decryptSad(encrypted, 'arn:aws:kms:us-east-1:000:key/test', 0);

      expect(Buffer.from(result)).toEqual(Buffer.from(fakePlaintext));
    });
  });

  describe('computeEffectiveDate', () => {
    it('subtracts 5 years from expiry "2812" → "2312"', () => {
      const result = (service as any).computeEffectiveDate('2812');
      expect(result).toBe('2312');
    });

    it('handles single-digit year result "0612" → "0112"', () => {
      const result = (service as any).computeEffectiveDate('0612');
      expect(result).toBe('0112');
    });

    it('clamps to zero: "0312" → "0012" (not negative)', () => {
      const result = (service as any).computeEffectiveDate('0312');
      expect(result).toBe('0012');
    });

    it('preserves the month component', () => {
      const result = (service as any).computeEffectiveDate('3006');
      expect(result).toBe('2506');
    });
  });
});

// EmvDerivationService unit tests live in emv-derivation.test.ts; per-backend
// UdkDeriver tests (including AWS PC request shapes) live in
// udk-deriver.test.ts.  DataPrepService is covered here.
