// Admin barrel — re-exports the @palisade/card-programs surface plus admin-only bits
// (Prisma-backed CRUD + NDEF template rendering).  Routes and other admin
// modules import from here for a single-stop surface.

export {
  DEFAULT_TIER_RULES,
  matchRule,
  parseTierRuleSet,
  tierRuleSchema,
  tierRuleSetSchema,
  currencySchema,
  normaliseCurrency,
  resolveRulesFromProgram,
} from '@palisade/card-programs';
export type { TierRule, TierRuleSet } from '@palisade/card-programs';

export {
  createProgram,
  getProgram,
  listPrograms,
  resolveNdefUrlsByCardRef,
  resolveNdefUrlsForCard,
  updateProgram,
} from './program.service.js';
export type { UpsertProgramInput, ListProgramsOptions } from './program.service.js';

export { renderNdefUrls, validateNdefUrlTemplate } from './ndef.js';
export type { NdefUrlPair } from './ndef.js';
