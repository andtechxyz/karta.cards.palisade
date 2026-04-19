import type { Program } from '@prisma/client';
import { DEFAULT_TIER_RULES, parseTierRuleSet, type TierRuleSet } from './tier-rules.js';

// -----------------------------------------------------------------------------
// Pure helpers against the Program row — no Prisma reads of their own.  Admin
// owns Program CRUD; every other service that has a Program handy (or null,
// for cards not linked to one) can collapse it to a { rules, currency,
// programId } triple with this helper.
// -----------------------------------------------------------------------------

export interface ResolvedProgramRules {
  rules: TierRuleSet;
  currency: string | null;
  programId: string | null;
}

export function resolveRulesFromProgram(program: Program | null): ResolvedProgramRules {
  if (!program) {
    return { rules: DEFAULT_TIER_RULES, currency: null, programId: null };
  }
  return {
    rules: parseTierRuleSet(program.tierRules),
    currency: program.currency,
    programId: program.id,
  };
}
