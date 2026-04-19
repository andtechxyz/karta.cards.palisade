// Palisade SUN module — NXP AN14683 / AN12196 SDM verifier.
//
// This is a 1:1 port of palisade-sun's sun_validator.py
// (~/Documents/Claude Code/Palisade/palisade-sun/app/services/sun_validator.py).
// Cross-checked against AN14683 Rev 0.1 (17 June 2025) Section 2.5.2.
//
// Public surface — callers should never reach into the individual files.

export {
  SC_SDMENC,
  SC_SDMMAC,
  SCT_1,
  SCT_2,
  SKL_128,
  SKL_256,
  PICC_DATA_TAG,
} from './constants.js';

export { aesCmac } from './cmac.js';
export { decryptPiccData, type PiccData } from './picc.js';
export { deriveSessionKeys, type SessionKeys } from './sessionKeys.js';
export {
  computeSdmmac,
  verifySdmmac,
  extractSdmmacInput,
  verifySunUrl,
  type VerifySunUrlInput,
  type SunVerificationResult,
  type SunVerificationOk,
  type SunVerificationFail,
} from './verify.js';
