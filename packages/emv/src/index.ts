/**
 * @palisade/emv — EMV encoding library for payment card personalisation.
 *
 * Provides BER-TLV, DGI, Track 2, PAN utilities, chip profiles,
 * SAD/IAD building, APDU construction, and ICC certificate building.
 *
 * Ported from palisade-tlv + palisade-data-prep + palisade-rca.
 */

export { encodeLength, decodeLength } from './encoding.js';
export { TLV } from './tlv.js';
export { DGI } from './dgi.js';
export { Track2 } from './track2.js';
export { PANUtils } from './pan.js';
export { EMV_TAGS } from './emv-tags.js';
export type { TagSource, TagInfo } from './emv-tags.js';
export { ChipProfile } from './chip-profile.js';
export type { DGIDefinition, DGISource, ChipProfileData } from './chip-profile.js';
export {
  buildIad,
  packMcCvn10Cvr,
  packMcCvn17Or18Cvr,
  packVisaCvn10Cvr,
  packVisaCvn22Cvr,
  resolveDacIdn,
  deriveDacIdn,
} from './iad-builder.js';
export type { Scheme, CvrInputs, BuildIadOptions } from './iad-builder.js';
export { SADBuilder } from './sad-builder.js';
export type { CardData, IssuerProfileForSad } from './sad-builder.js';
export {
  encryptSadDev,
  decryptSadDev,
  DEV_SAD_MASTER_KEY,
  SAD_KEY_VERSION_DEV_AES_ECB,
  SAD_KEY_VERSION_KMS,
} from './sad-crypto.js';
export { APDUBuilder } from './apdu-builder.js';
export { buildIccPkCertificate } from './icc-cert-builder.js';
export type { IccCertInput } from './icc-cert-builder.js';

// ParamBundle path — MChip CVN 18 chip-computed-DGI prototype.
// See PROTOTYPE_PLAN.md at worktree root for architecture context.
export {
  ParamTag,
  MAX_FIELD_LEN,
  buildParamBundle,
  parseParamBundle,
  referenceBundleForJcDev,
  loadGoldenBundle,
} from './param-bundle-builder.js';
export type { ParamBundleInput, ParamTagValue } from './param-bundle-builder.js';
export {
  MCHIP_CVN_18,
  mapMChipToParamBundle,
  buildMChipParamBundle,
  simulateMChipChipBuild,
} from './scheme-mchip.js';
export type { McipMapperInput, SimulatedChipDgis } from './scheme-mchip.js';

// Embossing file parsing
export type { EmbossingParser, EmbossingRecord, ParseResult, ParseError } from './embossing-parser.js';
export { getParser, parsers, csvParser, fixedWidthParser } from './parsers/index.js';
