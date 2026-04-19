import { createSdmDeriver, type SdmDeriver } from '@palisade/sdm-keys';
import { assertSdmEnv, getTapConfig } from './env.js';

// -----------------------------------------------------------------------------
// Process-local SdmDeriver.  Built once per process from env; keyed by the
// SDM_KEY_BACKEND setting.  Construction is cheap in 'local'/'mock' and
// allocates an AWS PC client in 'hsm'.
// -----------------------------------------------------------------------------

let _deriver: SdmDeriver | null = null;

export function getSdmDeriver(): SdmDeriver {
  if (!_deriver) {
    const cfg = getTapConfig();
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

/** Test hook — reset the cached deriver after env changes. */
export function _resetSdmDeriver(): void {
  _deriver = null;
}
