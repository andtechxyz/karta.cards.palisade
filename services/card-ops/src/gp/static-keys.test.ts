/**
 * Unit tests for getGpStaticKeys — verifies:
 *   - CARD_OPS_USE_TEST_KEYS short-circuits to env-wide triplet
 *   - Missing cardId falls back to test keys + warns
 *   - Card with no IssuerProfile falls back to test keys + warns
 *   - Card with missing ARNs falls back to test keys + warns
 *   - Happy path: two cards with different IssuerProfiles get
 *     different key triplets
 *   - KMS-fetch failure falls back gracefully with warning
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks (must be declared before the SUT import)
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    card: { findUnique: vi.fn() },
  },
}));

// Env mock — each test overrides CARD_OPS_USE_TEST_KEYS as needed.
const envMock = vi.fn().mockReturnValue({
  GP_MASTER_KEY: JSON.stringify({
    enc: '404142434445464748494A4B4C4D4E4F',
    mac: '404142434445464748494A4B4C4D4E4F',
    dek: '404142434445464748494A4B4C4D4E4F',
  }),
  CARD_OPS_USE_TEST_KEYS: '',
});
vi.mock('../env.js', () => ({
  getCardOpsConfig: (...a: unknown[]) => envMock(...a),
}));

// Key fetcher mock — returns deterministic per-ARN key material.
const fetchGpKeyMock = vi.fn();
vi.mock('./kms-key-fetcher.js', () => ({
  fetchGpKey: (arn: string) => fetchGpKeyMock(arn),
  _resetGpKeyCache: vi.fn(),
  _setSecretsManagerClientFactory: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import { getGpStaticKeys, _resetGpStaticKeysCache } from './static-keys.js';

const findUnique = () =>
  prisma.card.findUnique as unknown as ReturnType<typeof vi.fn>;

const TEST_KEY = Buffer.from('404142434445464748494A4B4C4D4E4F', 'hex');

beforeEach(() => {
  vi.clearAllMocks();
  _resetGpStaticKeysCache();
  envMock.mockReturnValue({
    GP_MASTER_KEY: JSON.stringify({
      enc: '404142434445464748494A4B4C4D4E4F',
      mac: '404142434445464748494A4B4C4D4E4F',
      dek: '404142434445464748494A4B4C4D4E4F',
    }),
    CARD_OPS_USE_TEST_KEYS: '',
  });
  // Silence warnings by default; individual tests re-spy when they assert.
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});

describe('getGpStaticKeys', () => {
  it('returns test keys when CARD_OPS_USE_TEST_KEYS is set (no DB hop)', async () => {
    envMock.mockReturnValue({
      GP_MASTER_KEY: JSON.stringify({
        enc: '404142434445464748494A4B4C4D4E4F',
        mac: '404142434445464748494A4B4C4D4E4F',
        dek: '404142434445464748494A4B4C4D4E4F',
      }),
      CARD_OPS_USE_TEST_KEYS: '1',
    });

    const keys = await getGpStaticKeys('card_1');
    expect(keys.enc.equals(TEST_KEY)).toBe(true);
    expect(keys.mac.equals(TEST_KEY)).toBe(true);
    expect(keys.dek.equals(TEST_KEY)).toBe(true);
    // Prove we short-circuited — no DB call.
    expect(findUnique()).not.toHaveBeenCalled();
    expect(fetchGpKeyMock).not.toHaveBeenCalled();
  });

  it('warns and falls back when cardId is undefined', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const keys = await getGpStaticKeys(undefined);
    expect(keys.enc.equals(TEST_KEY)).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('no cardId'),
    );
  });

  it('warns and falls back when card has no IssuerProfile', async () => {
    findUnique().mockResolvedValueOnce({ program: null });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const keys = await getGpStaticKeys('card_no_program');
    expect(keys.enc.equals(TEST_KEY)).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('no GP key ARNs configured'),
    );
    expect(fetchGpKeyMock).not.toHaveBeenCalled();
  });

  it('warns and falls back when ARNs are null on IssuerProfile', async () => {
    findUnique().mockResolvedValueOnce({
      program: {
        issuerProfile: {
          gpEncKeyArn: null,
          gpMacKeyArn: null,
          gpDekKeyArn: null,
        },
      },
    });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const keys = await getGpStaticKeys('card_null_arns');
    expect(keys.enc.equals(TEST_KEY)).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('no GP key ARNs configured'),
    );
    expect(fetchGpKeyMock).not.toHaveBeenCalled();
  });

  it('happy path: two cards with different IssuerProfiles get different key material', async () => {
    const KEY_A_ENC = Buffer.alloc(16, 0xA1);
    const KEY_A_MAC = Buffer.alloc(16, 0xA2);
    const KEY_A_DEK = Buffer.alloc(16, 0xA3);
    const KEY_B_ENC = Buffer.alloc(16, 0xB1);
    const KEY_B_MAC = Buffer.alloc(16, 0xB2);
    const KEY_B_DEK = Buffer.alloc(16, 0xB3);

    findUnique()
      .mockResolvedValueOnce({
        program: {
          issuerProfile: {
            gpEncKeyArn: 'arn::A:enc',
            gpMacKeyArn: 'arn::A:mac',
            gpDekKeyArn: 'arn::A:dek',
          },
        },
      })
      .mockResolvedValueOnce({
        program: {
          issuerProfile: {
            gpEncKeyArn: 'arn::B:enc',
            gpMacKeyArn: 'arn::B:mac',
            gpDekKeyArn: 'arn::B:dek',
          },
        },
      });

    fetchGpKeyMock.mockImplementation(async (arn: string) => {
      const map: Record<string, Buffer> = {
        'arn::A:enc': KEY_A_ENC,
        'arn::A:mac': KEY_A_MAC,
        'arn::A:dek': KEY_A_DEK,
        'arn::B:enc': KEY_B_ENC,
        'arn::B:mac': KEY_B_MAC,
        'arn::B:dek': KEY_B_DEK,
      };
      return map[arn];
    });

    const cardA = await getGpStaticKeys('card_A');
    const cardB = await getGpStaticKeys('card_B');

    // Per-card key triplets must be distinct.
    expect(cardA.enc.equals(KEY_A_ENC)).toBe(true);
    expect(cardA.mac.equals(KEY_A_MAC)).toBe(true);
    expect(cardA.dek.equals(KEY_A_DEK)).toBe(true);
    expect(cardB.enc.equals(KEY_B_ENC)).toBe(true);
    expect(cardB.mac.equals(KEY_B_MAC)).toBe(true);
    expect(cardB.dek.equals(KEY_B_DEK)).toBe(true);

    // And the two cards definitely got DIFFERENT keys — the whole
    // point of this refactor.
    expect(cardA.enc.equals(cardB.enc)).toBe(false);
    expect(cardA.mac.equals(cardB.mac)).toBe(false);
    expect(cardA.dek.equals(cardB.dek)).toBe(false);
  });

  it('warns and falls back when KMS fetch rejects', async () => {
    findUnique().mockResolvedValueOnce({
      program: {
        issuerProfile: {
          gpEncKeyArn: 'arn::enc',
          gpMacKeyArn: 'arn::mac',
          gpDekKeyArn: 'arn::dek',
        },
      },
    });
    fetchGpKeyMock.mockRejectedValueOnce(new Error('kms_denied'));
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const keys = await getGpStaticKeys('card_fetch_fail');
    expect(keys.enc.equals(TEST_KEY)).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('kms_denied'),
    );
  });
});
