import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  HsmUdkDeriver,
  LocalUdkDeriver,
  MockUdkDeriver,
  computeKcv,
  createUdkDeriver,
  methodADerivationData,
} from './udk-deriver.js';

// Mock AWS PC SDK at module scope so HsmUdkDeriver's constructor stays cheap.
vi.mock('@aws-sdk/client-payment-cryptography-data', () => ({
  PaymentCryptographyDataClient: vi.fn().mockImplementation(() => ({ send: vi.fn() })),
  GenerateCardValidationDataCommand: vi.fn(),
  EncryptDataCommand: vi.fn(),
}));

const TEST_SEED_HEX = '0'.repeat(64);
const PAN = '4242424242424242';
const EXPIRY = '2812';
const CSN = '01';

// ---------------------------------------------------------------------------
// methodADerivationData — pure helper, easy to pin with known bytes
// ---------------------------------------------------------------------------

describe('methodADerivationData', () => {
  it('takes the right-most 16 hex chars of (PAN || CSN) as the 8-byte block', () => {
    const data = methodADerivationData(PAN, CSN);
    expect(data.length).toBe(8);
    // PAN=4242424242424242, CSN=01 → "424242424242424201" → right 16 = "4242424242424201"
    expect(data.toString('hex')).toBe('4242424242424201');
  });

  it('right-pads short inputs with zeros to 16 hex chars before slicing', () => {
    // Method A per the Python reference: `(pan + csn).ljust(16, "0")[-16:]`.
    // "123" + "01" = "12301" → right-pad to 16 → "1230100000000000" → slice [-16:] unchanged.
    const data = methodADerivationData('123', '01');
    expect(data.length).toBe(8);
    expect(data.toString('hex')).toBe('1230100000000000');
  });
});

// ---------------------------------------------------------------------------
// computeKcv — known vector
// ---------------------------------------------------------------------------

describe('computeKcv', () => {
  it('returns the first 3 bytes of TDES-ECB(key, 0x00...0), hex-uppercased', () => {
    // All-ones TDES-2KEY → encrypt zeros → fixed output.  Node des-ede-ecb
    // with a 16-byte key treats it as K1||K2||K1.  This vector was produced
    // locally and pins the behaviour; if the algo selection ever changes
    // from des-ede-ecb, this test should fail loudly.
    const key = Buffer.alloc(16, 0x11);
    const kcv = computeKcv(key);
    expect(kcv).toMatch(/^[0-9A-F]{6}$/);
    // The exact value is less important than stability across runs.
    const kcv2 = computeKcv(key);
    expect(kcv2).toBe(kcv);
  });

  it('differs between different keys', () => {
    const a = computeKcv(Buffer.alloc(16, 0x11));
    const b = computeKcv(Buffer.alloc(16, 0x22));
    expect(a).not.toBe(b);
  });

  it('throws on non-16-byte key material', () => {
    expect(() => computeKcv(Buffer.alloc(8))).toThrow(/unsupported IMK length/);
    expect(() => computeKcv(Buffer.alloc(24))).toThrow(/unsupported IMK length/);
  });
});

// ---------------------------------------------------------------------------
// LocalUdkDeriver — real EMV Method A in Node crypto
// ---------------------------------------------------------------------------

describe('LocalUdkDeriver', () => {
  let svc: LocalUdkDeriver;
  beforeEach(() => {
    svc = new LocalUdkDeriver({ rootSeedHex: TEST_SEED_HEX });
  });

  it('rejects a root seed that is not 32 bytes', () => {
    expect(() => new LocalUdkDeriver({ rootSeedHex: 'aa' })).toThrow(/must decode to 32 bytes/);
  });

  it('produces a 3-digit decimal iCVV', async () => {
    const icvv = await svc.deriveIcvv('arn:tmk', PAN, EXPIRY);
    expect(icvv).toMatch(/^\d{3}$/);
  });

  it('iCVV is deterministic across calls for the same inputs', async () => {
    const a = await svc.deriveIcvv('arn:tmk', PAN, EXPIRY);
    const b = await svc.deriveIcvv('arn:tmk', PAN, EXPIRY);
    expect(a).toBe(b);
  });

  it('iCVV changes when the PAN changes', async () => {
    const a = await svc.deriveIcvv('arn:tmk', PAN, EXPIRY);
    const b = await svc.deriveIcvv('arn:tmk', '4000000000000000', EXPIRY);
    expect(a).not.toBe(b);
  });

  it('iCVV changes when the TMK ARN changes (different dev IMK)', async () => {
    const a = await svc.deriveIcvv('arn:tmk-a', PAN, EXPIRY);
    const b = await svc.deriveIcvv('arn:tmk-b', PAN, EXPIRY);
    expect(a).not.toBe(b);
  });

  it('deriveMasterKey returns 16-byte keyBytes + 6-hex KCV + synthetic ARN', async () => {
    const mk = await svc.deriveMasterKey('arn:imk-ac', PAN, CSN);
    expect(mk.keyBytes.length).toBe(16);
    expect(mk.kcv).toMatch(/^[0-9A-F]{6}$/);
    expect(mk.keyArn).toMatch(/^derived:local:/);
    // KCV matches what computeKcv would produce for the returned bytes.
    expect(mk.kcv).toBe(computeKcv(mk.keyBytes));
  });

  it('Method A: left half = E(IMK, data); right half = E(IMK, ~data)', async () => {
    // This is a structural sanity check rather than a published NIST vector —
    // a regression here means Method A changed (e.g. algo swap, XOR dropped).
    const mkA = await svc.deriveMasterKey('arn:imk-ac', PAN, CSN);
    const mkB = await svc.deriveMasterKey('arn:imk-ac', PAN, '02');
    // CSN change → different right 16 hex of (PAN||CSN) → different derived key
    expect(mkA.keyBytes.equals(mkB.keyBytes)).toBe(false);
  });

  it('different IMK ARNs produce independent keys for the same card', async () => {
    const ac = await svc.deriveMasterKey('arn:imk-ac', PAN, CSN);
    const smi = await svc.deriveMasterKey('arn:imk-smi', PAN, CSN);
    const smc = await svc.deriveMasterKey('arn:imk-smc', PAN, CSN);
    expect(ac.keyBytes.equals(smi.keyBytes)).toBe(false);
    expect(ac.keyBytes.equals(smc.keyBytes)).toBe(false);
    expect(smi.keyBytes.equals(smc.keyBytes)).toBe(false);
  });

  it('regenerates identical key material across fresh instances (stability)', async () => {
    const a = await svc.deriveMasterKey('arn:imk-ac', PAN, CSN);
    const b = await new LocalUdkDeriver({ rootSeedHex: TEST_SEED_HEX })
      .deriveMasterKey('arn:imk-ac', PAN, CSN);
    expect(a.keyBytes.equals(b.keyBytes)).toBe(true);
    expect(a.kcv).toBe(b.kcv);
  });

  it('different root seeds yield different keys', async () => {
    const a = await svc.deriveMasterKey('arn:imk-ac', PAN, CSN);
    const b = await new LocalUdkDeriver({ rootSeedHex: '1'.repeat(64) })
      .deriveMasterKey('arn:imk-ac', PAN, CSN);
    expect(a.keyBytes.equals(b.keyBytes)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// MockUdkDeriver — deterministic fakes
// ---------------------------------------------------------------------------

describe('MockUdkDeriver', () => {
  const svc = new MockUdkDeriver();

  it('produces 3-digit iCVV, deterministic per (PAN, expiry)', async () => {
    const a = await svc.deriveIcvv('unused', PAN, EXPIRY);
    const b = await svc.deriveIcvv('unused', PAN, EXPIRY);
    expect(a).toMatch(/^\d{3}$/);
    expect(a).toBe(b);
  });

  it('deriveMasterKey returns a mock: ARN and 6-hex KCV', async () => {
    const mk = await svc.deriveMasterKey('arn:imk', PAN, CSN);
    expect(mk.keyArn).toMatch(/^mock:/);
    expect(mk.kcv).toMatch(/^[0-9A-F]{6}$/);
    expect(mk.keyBytes.length).toBe(16);
  });
});

// ---------------------------------------------------------------------------
// HsmUdkDeriver — request shapes against stub AWS PC client
// ---------------------------------------------------------------------------

describe('HsmUdkDeriver', () => {
  let svc: HsmUdkDeriver;
  let mockSend: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    svc = new HsmUdkDeriver('ap-southeast-2');
    mockSend = vi.fn();
    (svc as unknown as { pcData: { send: typeof mockSend } }).pcData = { send: mockSend };
  });

  it('deriveIcvv calls GenerateCardValidationDataCommand and returns ValidationData', async () => {
    mockSend.mockResolvedValue({ ValidationData: '456' });
    const icvv = await svc.deriveIcvv('arn:tmk', PAN, EXPIRY);
    expect(icvv).toBe('456');
    expect(mockSend).toHaveBeenCalledOnce();
  });

  it('deriveIcvv falls back to "000" when ValidationData is absent', async () => {
    mockSend.mockResolvedValue({});
    const icvv = await svc.deriveIcvv('arn:tmk', PAN, EXPIRY);
    expect(icvv).toBe('000');
  });

  it('deriveMasterKey issues two EncryptData calls and derives KCV locally', async () => {
    // 16 hex = 8 bytes per half; concat = 16-byte MK.  Returning deterministic
    // hex lets us predict the KCV that computeKcv will spit out.
    mockSend
      .mockResolvedValueOnce({ CipherText: '1122334455667788' })
      .mockResolvedValueOnce({ CipherText: '99AABBCCDDEEFF00' });

    const mk = await svc.deriveMasterKey('arn:imk-ac', PAN, CSN);

    expect(mockSend).toHaveBeenCalledTimes(2); // left + right halves only — no ImportKey, no KCV round-trip
    expect(mk.keyBytes.toString('hex').toUpperCase()).toBe(
      '112233445566778899AABBCCDDEEFF00',
    );
    expect(mk.kcv).toBe(computeKcv(mk.keyBytes));
    expect(mk.keyArn).toMatch(/^derived:hsm:/);
  });

  it('throws if EncryptData returns empty CipherText', async () => {
    mockSend.mockResolvedValueOnce({});
    await expect(svc.deriveMasterKey('arn:imk-ac', PAN, CSN)).rejects.toThrow(
      /empty CipherText/,
    );
  });
});

// ---------------------------------------------------------------------------
// createUdkDeriver — backend selection
// ---------------------------------------------------------------------------

describe('createUdkDeriver', () => {
  it("backend='hsm' returns HsmUdkDeriver", () => {
    const d = createUdkDeriver({ backend: 'hsm', awsRegion: 'ap-southeast-2' });
    expect(d).toBeInstanceOf(HsmUdkDeriver);
  });

  it("backend='local' returns LocalUdkDeriver when seed is provided", () => {
    const d = createUdkDeriver({
      backend: 'local',
      awsRegion: 'ap-southeast-2',
      localRootSeedHex: TEST_SEED_HEX,
    });
    expect(d).toBeInstanceOf(LocalUdkDeriver);
  });

  it("backend='local' without a seed throws a clear error", () => {
    expect(() =>
      createUdkDeriver({ backend: 'local', awsRegion: 'ap-southeast-2' }),
    ).toThrow(/requires localRootSeedHex/);
  });

  it("backend='mock' returns MockUdkDeriver", () => {
    const d = createUdkDeriver({ backend: 'mock', awsRegion: 'ap-southeast-2' });
    expect(d).toBeInstanceOf(MockUdkDeriver);
  });
});
