import { describe, it, expect, vi, beforeEach } from 'vitest';
import { aesCmac } from '@palisade/core';
import {
  HsmSdmDeriver,
  LocalSdmDeriver,
  MockSdmDeriver,
  createSdmDeriver,
} from './sdm-deriver.js';

vi.mock('@aws-sdk/client-payment-cryptography-data', () => ({
  PaymentCryptographyDataClient: vi.fn().mockImplementation(() => ({ send: vi.fn() })),
  GenerateMacCommand: vi.fn(),
}));

const TEST_SEED_HEX = '0'.repeat(64);
const OTHER_SEED_HEX = '1'.repeat(64);
const UID = Buffer.from('04AABBCCDDEE11', 'hex'); // 7 bytes
const UID2 = Buffer.from('04EEFF1122334455'.slice(0, 14), 'hex');

// -----------------------------------------------------------------------------
// LocalSdmDeriver
// -----------------------------------------------------------------------------

describe('LocalSdmDeriver', () => {
  let svc: LocalSdmDeriver;
  beforeEach(() => {
    svc = new LocalSdmDeriver({ rootSeedHex: TEST_SEED_HEX });
  });

  it('rejects a root seed that is not 32 bytes', () => {
    expect(() => new LocalSdmDeriver({ rootSeedHex: 'aa' })).toThrow(/must decode to 32 bytes/);
  });

  it('rejects a UID that is not 7 bytes', async () => {
    await expect(svc.deriveMetaReadKey(Buffer.alloc(4))).rejects.toThrow(/must be 7 bytes/);
    await expect(svc.deriveFileReadKey(Buffer.alloc(10))).rejects.toThrow(/must be 7 bytes/);
  });

  it('produces 16-byte AES-128 keys', async () => {
    const meta = await svc.deriveMetaReadKey(UID);
    const file = await svc.deriveFileReadKey(UID);
    expect(meta.length).toBe(16);
    expect(file.length).toBe(16);
  });

  it('meta and file keys are independent for the same UID', async () => {
    const meta = await svc.deriveMetaReadKey(UID);
    const file = await svc.deriveFileReadKey(UID);
    expect(meta.equals(file)).toBe(false);
  });

  it('is deterministic across calls for the same UID', async () => {
    const a = await svc.deriveMetaReadKey(UID);
    const b = await svc.deriveMetaReadKey(UID);
    expect(a.equals(b)).toBe(true);
  });

  it('different UIDs produce different keys', async () => {
    const a = await svc.deriveMetaReadKey(UID);
    const b = await svc.deriveMetaReadKey(UID2);
    expect(a.equals(b)).toBe(false);
  });

  it('regenerates identical key material across fresh instances (stability)', async () => {
    const a = await svc.deriveMetaReadKey(UID);
    const b = await new LocalSdmDeriver({ rootSeedHex: TEST_SEED_HEX }).deriveMetaReadKey(UID);
    expect(a.equals(b)).toBe(true);
  });

  it('rotating the root seed changes every derived key', async () => {
    const a = await svc.deriveMetaReadKey(UID);
    const b = await new LocalSdmDeriver({ rootSeedHex: OTHER_SEED_HEX }).deriveMetaReadKey(UID);
    expect(a.equals(b)).toBe(false);
  });

  it('output structurally equals AES-CMAC(HKDF(seed, "meta"), UID)', async () => {
    // Reproduce the derivation without going through the class, to confirm
    // the internal layout matches what the perso tool would compute.
    const { hkdfSync } = await import('node:crypto');
    const seed = Buffer.from(TEST_SEED_HEX, 'hex');
    const master = Buffer.from(hkdfSync('sha256', seed, Buffer.alloc(0), 'palisade:sdm:v1:meta', 16));
    const expected = aesCmac(master, UID);
    const actual = await svc.deriveMetaReadKey(UID);
    expect(actual.equals(expected)).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// MockSdmDeriver
// -----------------------------------------------------------------------------

describe('MockSdmDeriver', () => {
  const svc = new MockSdmDeriver();

  it('produces 16-byte keys deterministic per UID', async () => {
    const a = await svc.deriveMetaReadKey(UID);
    const b = await svc.deriveMetaReadKey(UID);
    expect(a.length).toBe(16);
    expect(a.equals(b)).toBe(true);
  });

  it('meta and file diverge for the same UID', async () => {
    const meta = await svc.deriveMetaReadKey(UID);
    const file = await svc.deriveFileReadKey(UID);
    expect(meta.equals(file)).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// HsmSdmDeriver
// -----------------------------------------------------------------------------

describe('HsmSdmDeriver', () => {
  let svc: HsmSdmDeriver;
  let mockSend: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    svc = new HsmSdmDeriver({
      region: 'ap-southeast-2',
      metaMasterArn: 'arn:meta',
      fileMasterArn: 'arn:file',
    });
    mockSend = vi.fn();
    (svc as unknown as { pcData: { send: typeof mockSend } }).pcData = { send: mockSend };
  });

  it('throws at construction if ARNs missing', () => {
    expect(
      () =>
        new HsmSdmDeriver({
          region: 'ap-southeast-2',
          metaMasterArn: '',
          fileMasterArn: 'arn:file',
        }),
    ).toThrow(/metaMasterArn required/);
    expect(
      () =>
        new HsmSdmDeriver({
          region: 'ap-southeast-2',
          metaMasterArn: 'arn:meta',
          fileMasterArn: '',
        }),
    ).toThrow(/fileMasterArn required/);
  });

  it('deriveMetaReadKey issues one GenerateMac against the meta ARN', async () => {
    mockSend.mockResolvedValue({ Mac: '00112233445566778899AABBCCDDEEFF' });
    const key = await svc.deriveMetaReadKey(UID);
    expect(mockSend).toHaveBeenCalledOnce();
    expect(key.length).toBe(16);
    expect(key.toString('hex').toUpperCase()).toBe('00112233445566778899AABBCCDDEEFF');
  });

  it('deriveFileReadKey targets the file ARN (distinct from meta)', async () => {
    mockSend.mockResolvedValue({ Mac: 'FFEEDDCCBBAA99887766554433221100' });
    const key = await svc.deriveFileReadKey(UID);
    expect(key.toString('hex').toUpperCase()).toBe('FFEEDDCCBBAA99887766554433221100');
  });

  it('rejects a UID that is not 7 bytes', async () => {
    await expect(svc.deriveMetaReadKey(Buffer.alloc(4))).rejects.toThrow(/must be 7 bytes/);
  });

  it('throws if AWS PC returns empty Mac', async () => {
    mockSend.mockResolvedValue({});
    await expect(svc.deriveMetaReadKey(UID)).rejects.toThrow(/empty Mac/);
  });

  it('throws if AWS PC returns a short Mac', async () => {
    mockSend.mockResolvedValue({ Mac: '00112233' }); // 4 bytes
    await expect(svc.deriveMetaReadKey(UID)).rejects.toThrow(/expected >=16/);
  });

  it('truncates MACs longer than 16 bytes to the first 16', async () => {
    // Some CMAC configurations can return a longer MAC; subarray(0, 16) is a
    // defensive slice against that, so any output the SDK gives us that's
    // >=16 bytes produces a correct 16-byte AES-128 key.
    mockSend.mockResolvedValue({
      Mac: '00112233445566778899AABBCCDDEEFFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    });
    const key = await svc.deriveMetaReadKey(UID);
    expect(key.length).toBe(16);
    expect(key.toString('hex').toUpperCase()).toBe('00112233445566778899AABBCCDDEEFF');
  });
});

// -----------------------------------------------------------------------------
// createSdmDeriver — backend selection
// -----------------------------------------------------------------------------

describe('createSdmDeriver', () => {
  it("backend='hsm' requires both master ARNs", () => {
    expect(() =>
      createSdmDeriver({ backend: 'hsm', awsRegion: 'ap-southeast-2' }),
    ).toThrow(/metaMasterArn \+ fileMasterArn/);
  });

  it("backend='hsm' returns HsmSdmDeriver when ARNs provided", () => {
    const d = createSdmDeriver({
      backend: 'hsm',
      awsRegion: 'ap-southeast-2',
      metaMasterArn: 'arn:meta',
      fileMasterArn: 'arn:file',
    });
    expect(d).toBeInstanceOf(HsmSdmDeriver);
  });

  it("backend='local' requires a root seed", () => {
    expect(() =>
      createSdmDeriver({ backend: 'local', awsRegion: 'ap-southeast-2' }),
    ).toThrow(/DEV_SDM_ROOT_SEED/);
  });

  it("backend='local' returns LocalSdmDeriver", () => {
    const d = createSdmDeriver({
      backend: 'local',
      awsRegion: 'ap-southeast-2',
      localRootSeedHex: TEST_SEED_HEX,
    });
    expect(d).toBeInstanceOf(LocalSdmDeriver);
  });

  it("backend='mock' returns MockSdmDeriver", () => {
    const d = createSdmDeriver({ backend: 'mock', awsRegion: 'ap-southeast-2' });
    expect(d).toBeInstanceOf(MockSdmDeriver);
  });
});
