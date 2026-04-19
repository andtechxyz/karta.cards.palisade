import { describe, it, expect, vi } from 'vitest';
import { EmvDerivationService } from './emv-derivation.js';
import type { DerivedMasterKey, UdkDeriver } from './udk-deriver.js';

// EmvDerivationService is now a thin fan-out over UdkDeriver.  The real
// crypto — ECB rounds, KCV, iCVV — is exercised in udk-deriver.test.ts.
// Here we only verify orchestration: that the service forwards each call
// to the injected deriver with the right arguments and reshapes the
// parallel results into DerivedKeys.

function makeStubDeriver(): UdkDeriver & {
  deriveIcvv: ReturnType<typeof vi.fn>;
  deriveMasterKey: ReturnType<typeof vi.fn>;
} {
  const mk = (suffix: string): DerivedMasterKey => ({
    keyArn: `stub:${suffix}`,
    kcv: `KCV${suffix}`,
    keyBytes: Buffer.from(`keybytes-${suffix}`),
  });
  return {
    deriveIcvv: vi.fn().mockResolvedValue('123'),
    deriveMasterKey: vi
      .fn()
      .mockImplementation(async (arn: string) => mk(arn.slice(-3))),
  };
}

describe('EmvDerivationService (orchestrator)', () => {
  it('deriveIcvv forwards to the backend unchanged', async () => {
    const deriver = makeStubDeriver();
    const svc = new EmvDerivationService(deriver);

    const icvv = await svc.deriveIcvv('arn:tmk', '4242424242424242', '2812');

    expect(icvv).toBe('123');
    expect(deriver.deriveIcvv).toHaveBeenCalledWith(
      'arn:tmk',
      '4242424242424242',
      '2812',
    );
  });

  it('deriveAllKeys fans out to four backend calls in parallel', async () => {
    const deriver = makeStubDeriver();
    const svc = new EmvDerivationService(deriver);

    await svc.deriveAllKeys(
      'arn:tmk',
      'arn:imk-ac',
      'arn:imk-smi',
      'arn:imk-smc',
      '4242424242424242',
      '2812',
      '01',
    );

    expect(deriver.deriveIcvv).toHaveBeenCalledWith(
      'arn:tmk',
      '4242424242424242',
      '2812',
    );
    expect(deriver.deriveMasterKey).toHaveBeenCalledTimes(3);
    expect(deriver.deriveMasterKey).toHaveBeenCalledWith(
      'arn:imk-ac',
      '4242424242424242',
      '01',
    );
    expect(deriver.deriveMasterKey).toHaveBeenCalledWith(
      'arn:imk-smi',
      '4242424242424242',
      '01',
    );
    expect(deriver.deriveMasterKey).toHaveBeenCalledWith(
      'arn:imk-smc',
      '4242424242424242',
      '01',
    );
  });

  it('deriveAllKeys reshapes backend outputs into DerivedKeys', async () => {
    const deriver = makeStubDeriver();
    const svc = new EmvDerivationService(deriver);

    const keys = await svc.deriveAllKeys(
      'arn:tmk',
      'arn:imk-ac',
      'arn:imk-smi',
      'arn:imk-smc',
      '4242424242424242',
      '2812',
      '01',
    );

    expect(keys.icvv).toBe('123');
    expect(keys.mkAcArn).toBe('stub:-ac');
    expect(keys.mkAcKcv).toBe('KCV-ac');
    expect(keys.mkAcKeyBytes).toEqual(Buffer.from('keybytes--ac'));
    expect(keys.mkSmiArn).toBe('stub:smi');
    expect(keys.mkSmcArn).toBe('stub:smc');
  });

  it('fromBackend("mock") wires up MockUdkDeriver end-to-end', async () => {
    const svc = EmvDerivationService.fromBackend('mock');

    const icvv = await svc.deriveIcvv('arn:tmk', '4242424242424242', '2812');
    expect(icvv).toMatch(/^\d{3}$/);

    const keys = await svc.deriveAllKeys(
      'arn:tmk',
      'arn:imk-ac',
      'arn:imk-smi',
      'arn:imk-smc',
      '4242424242424242',
      '2812',
      '01',
    );
    expect(keys.icvv).toMatch(/^\d{3}$/);
    expect(keys.mkAcArn).toMatch(/^mock:/);
    expect(keys.mkSmiArn).toMatch(/^mock:/);
    expect(keys.mkSmcArn).toMatch(/^mock:/);
    expect(keys.mkAcKeyBytes).toHaveLength(16);
  });
});
