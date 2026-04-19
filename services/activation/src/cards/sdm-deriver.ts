import { createSdmDeriver, type SdmDeriver } from '@palisade/sdm-keys';
import { assertSdmEnv } from '@palisade/core';
import { getActivationConfig } from '../env.js';

// Process-local SdmDeriver for activation.  Used by the begin-activation
// flow to CMAC the post-activation URL the chip should bake in (the
// karta-url extension payload).  The key used is the same fileRead key
// tap-service derives on every SUN verify — both come from the same
// AWS PC master, so activation and tap see identical per-card keys.

let _deriver: SdmDeriver | null = null;

export function getSdmDeriver(): SdmDeriver {
  if (!_deriver) {
    const cfg = getActivationConfig();
    assertSdmEnv(cfg);
    _deriver = createSdmDeriver({
      backend: cfg.SDM_KEY_BACKEND,
      awsRegion: cfg.AWS_REGION,
      metaMasterArn: cfg.SDM_META_MASTER_KEY_ARN || undefined,
      fileMasterArn: cfg.SDM_FILE_MASTER_KEY_ARN || undefined,
      localRootSeedHex: cfg.DEV_SDM_ROOT_SEED || undefined,
    });
  }
  return _deriver;
}

export function _resetSdmDeriver(): void {
  _deriver = null;
}
