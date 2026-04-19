import { describe, it, expect } from 'vitest';
import { EmvDerivationService } from './emv-derivation.js';

// Only exercises the mock-mode path.  The real AWS Payment Cryptography path
// has no usable test stub — it'd be an SDK mock that asserts request shapes,
// which is low-value and already covered by data-prep.service.test.ts.

describe('EmvDerivationService mock mode', () => {
  const svc = new EmvDerivationService('ap-southeast-2', true);

  it('produces a 3-digit iCVV', async () => {
    const icvv = await svc.deriveIcvv('unused-arn', '4242424242424242', '2812');
    expect(icvv).toMatch(/^\d{3}$/);
  });

  it('iCVV is deterministic for the same PAN + expiry', async () => {
    const a = await svc.deriveIcvv('unused-arn', '4242424242424242', '2812');
    const b = await svc.deriveIcvv('unused-arn', '4242424242424242', '2812');
    expect(a).toBe(b);
  });

  it('iCVV changes when PAN changes', async () => {
    const a = await svc.deriveIcvv('unused-arn', '4242424242424242', '2812');
    const b = await svc.deriveIcvv('unused-arn', '4000000000000000', '2812');
    expect(a).not.toBe(b);
  });

  it('deriveMasterKey returns a mock: ARN and 6-hex KCV', async () => {
    const k = await svc.deriveMasterKey('unused-imk', '4242424242424242', '01');
    expect(k.keyArn).toMatch(/^mock:/);
    expect(k.kcv).toMatch(/^[0-9A-F]{6}$/);
  });

  it('deriveAllKeys exercises the full mock path', async () => {
    const keys = await svc.deriveAllKeys(
      'tmk', 'imk-ac', 'imk-smi', 'imk-smc',
      '4242424242424242', '2812', '01',
    );
    expect(keys.icvv).toMatch(/^\d{3}$/);
    expect(keys.mkAcArn).toMatch(/^mock:/);
    expect(keys.mkSmiArn).toMatch(/^mock:/);
    expect(keys.mkSmcArn).toMatch(/^mock:/);
  });
});
