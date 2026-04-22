/**
 * Unit tests for the install_pa CAP resolver.
 *
 * We don't script the full SCP03/DELETE/LOAD sequence here — that's
 * covered by the scripted-IO test in install-payment-applet.test.ts,
 * and install_pa's GP sequence is basically identical.  What's new and
 * worth pinning down in isolation is the CAP selection rule: which
 * applet bytecode ends up on the card for a given Card row.
 *
 * Priority order the resolver must satisfy, highest first:
 *
 *   1. ChipProfile.provisioningMode = 'PARAM_BUNDLE' → 'pa-v3'
 *   2. ChipProfile.provisioningMode = 'SAD_LEGACY'   → 'pa'
 *   3. No ChipProfile on the chain + CARD_OPS_DEFAULT_PA_CAP='pa-v3' → 'pa-v3'
 *   4. No ChipProfile on the chain + env default unset/pa → 'pa'
 *
 * The whole point of this ordering is that an admin flipping a
 * program's ChipProfile to PARAM_BUNDLE automatically gets pa-v3
 * installed on the next provisioning cycle — server flow and applet
 * bytecode can't drift out of sync.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const mocks = vi.hoisted(() => ({
  cardFindUnique: vi.fn(),
  getCardOpsConfig: vi.fn(),
}));

vi.mock('@palisade/db', () => ({
  prisma: {
    card: { findUnique: mocks.cardFindUnique },
  },
}));

vi.mock('../env.js', () => ({
  getCardOpsConfig: mocks.getCardOpsConfig,
}));

import { resolvePaCapKey } from './install-pa.js';

describe('resolvePaCapKey', () => {
  beforeEach(() => {
    mocks.cardFindUnique.mockReset();
    mocks.getCardOpsConfig.mockReset();
    // Default env — used by rules 3/4.  Individual tests override.
    mocks.getCardOpsConfig.mockReturnValue({ CARD_OPS_DEFAULT_PA_CAP: 'pa' });
  });

  it('returns pa-v3 when ChipProfile.provisioningMode is PARAM_BUNDLE', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          chipProfile: { provisioningMode: 'PARAM_BUNDLE' },
        },
      },
    });
    await expect(resolvePaCapKey('card_abc')).resolves.toBe('pa-v3');
  });

  it('returns pa when ChipProfile.provisioningMode is SAD_LEGACY', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          chipProfile: { provisioningMode: 'SAD_LEGACY' },
        },
      },
    });
    await expect(resolvePaCapKey('card_abc')).resolves.toBe('pa');
  });

  it('prefers ChipProfile over env default (PARAM_BUNDLE wins even if env says pa)', async () => {
    mocks.getCardOpsConfig.mockReturnValue({ CARD_OPS_DEFAULT_PA_CAP: 'pa' });
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          chipProfile: { provisioningMode: 'PARAM_BUNDLE' },
        },
      },
    });
    await expect(resolvePaCapKey('card_abc')).resolves.toBe('pa-v3');
  });

  it('prefers ChipProfile over env default (SAD_LEGACY wins even if env says pa-v3)', async () => {
    mocks.getCardOpsConfig.mockReturnValue({ CARD_OPS_DEFAULT_PA_CAP: 'pa-v3' });
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          chipProfile: { provisioningMode: 'SAD_LEGACY' },
        },
      },
    });
    await expect(resolvePaCapKey('card_abc')).resolves.toBe('pa');
  });

  it('falls back to env default=pa-v3 when ChipProfile is missing', async () => {
    mocks.getCardOpsConfig.mockReturnValue({ CARD_OPS_DEFAULT_PA_CAP: 'pa-v3' });
    // Card row found but no chipProfile down the chain — legacy program
    // that predates the field.
    mocks.cardFindUnique.mockResolvedValue({
      program: { issuerProfile: null },
    });
    await expect(resolvePaCapKey('card_abc')).resolves.toBe('pa-v3');
  });

  it('falls back to pa (legacy) when ChipProfile is missing and env is default', async () => {
    mocks.getCardOpsConfig.mockReturnValue({ CARD_OPS_DEFAULT_PA_CAP: 'pa' });
    mocks.cardFindUnique.mockResolvedValue({
      program: { issuerProfile: null },
    });
    await expect(resolvePaCapKey('card_abc')).resolves.toBe('pa');
  });

  it('falls back to env default when the Card row itself is missing', async () => {
    // cardId that doesn't resolve shouldn't throw here — the SCP03 step
    // below will fail harder and more informatively.  For CAP choice
    // we just use the env default.
    mocks.getCardOpsConfig.mockReturnValue({ CARD_OPS_DEFAULT_PA_CAP: 'pa' });
    mocks.cardFindUnique.mockResolvedValue(null);
    await expect(resolvePaCapKey('card_missing')).resolves.toBe('pa');
  });
});
