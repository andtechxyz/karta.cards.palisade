/**
 * EMV key-derivation orchestrator.
 *
 * Fans iCVV + the three per-card master keys (MK-AC, MK-SMI, MK-SMC) out of a
 * single {@link UdkDeriver} call-site.  All actual crypto — ECB rounds, KCV,
 * iCVV generation — happens in the injected backend: see udk-deriver.ts.
 *
 * Ported from palisade-data-prep/app/services/emv_derivation.py, then split:
 * the Python original coupled orchestration to AWS Payment Cryptography calls
 * and hash-based mocks in a single class.  Here the orchestrator stays small
 * and the backend choice (hsm | local | mock) is a constructor argument.
 */

import { createUdkDeriver, type UdkBackend, type UdkDeriver } from './udk-deriver.js';
import { resolveUdkBackend, getDataPrepConfig } from '../env.js';

export interface DerivedKeys {
  icvv: string;
  mkAcArn: string;
  mkAcKcv: string;
  mkAcKeyBytes: Buffer;
  mkSmiArn: string;
  mkSmiKcv: string;
  mkSmiKeyBytes: Buffer;
  mkSmcArn: string;
  mkSmcKcv: string;
  mkSmcKeyBytes: Buffer;
}

export class EmvDerivationService {
  constructor(private readonly deriver: UdkDeriver) {}

  /**
   * Build from the resolved service env.  Used by the running service at
   * startup; tests use the constructor directly with a bespoke UdkDeriver.
   */
  static fromEnv(): EmvDerivationService {
    const cfg = getDataPrepConfig();
    const backend = resolveUdkBackend(cfg);
    return new EmvDerivationService(
      createUdkDeriver({
        backend,
        awsRegion: cfg.AWS_REGION,
        localRootSeedHex: cfg.DEV_UDK_ROOT_SEED,
      }),
    );
  }

  /** Convenience for scripts/tests that want a specific backend explicitly. */
  static fromBackend(
    backend: UdkBackend,
    opts: { awsRegion?: string; localRootSeedHex?: string } = {},
  ): EmvDerivationService {
    return new EmvDerivationService(
      createUdkDeriver({
        backend,
        awsRegion: opts.awsRegion ?? 'ap-southeast-2',
        localRootSeedHex: opts.localRootSeedHex,
      }),
    );
  }

  deriveIcvv(tmkKeyArn: string, pan: string, expiry: string): Promise<string> {
    return this.deriver.deriveIcvv(tmkKeyArn, pan, expiry);
  }

  async deriveAllKeys(
    tmkArn: string,
    imkAcArn: string,
    imkSmiArn: string,
    imkSmcArn: string,
    pan: string,
    expiry: string,
    csn: string,
  ): Promise<DerivedKeys> {
    const [icvv, mkAc, mkSmi, mkSmc] = await Promise.all([
      this.deriver.deriveIcvv(tmkArn, pan, expiry),
      this.deriver.deriveMasterKey(imkAcArn, pan, csn),
      this.deriver.deriveMasterKey(imkSmiArn, pan, csn),
      this.deriver.deriveMasterKey(imkSmcArn, pan, csn),
    ]);

    return {
      icvv,
      mkAcArn: mkAc.keyArn,
      mkAcKcv: mkAc.kcv,
      mkAcKeyBytes: mkAc.keyBytes,
      mkSmiArn: mkSmi.keyArn,
      mkSmiKcv: mkSmi.kcv,
      mkSmiKeyBytes: mkSmi.keyBytes,
      mkSmcArn: mkSmc.keyArn,
      mkSmcKcv: mkSmc.kcv,
      mkSmcKeyBytes: mkSmc.keyBytes,
    };
  }
}
