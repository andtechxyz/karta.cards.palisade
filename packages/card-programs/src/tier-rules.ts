import { CredentialKind } from '@prisma/client';
import { z } from 'zod';

// -----------------------------------------------------------------------------
// Program-level tier rules.
//
// Each Program owns an ordered list of TierRules that map amount ranges (in
// minor units of the program's currency) to the set of CredentialKinds
// acceptable for authentication at that amount.  Example (Bank A, AUD):
//
//   [
//     { amountMinMinor: 0,      amountMaxMinor: 20000, allowedKinds: ['PLATFORM']       },
//     { amountMinMinor: 20000,  amountMaxMinor: null,  allowedKinds: ['CROSS_PLATFORM'] },
//   ]
//
// → under AUD 200: Face ID / Touch ID / Windows Hello only.
// → AUD 200 and over: NFC card tap only.  (Bio+tap step-up is out of scope
//   for the initial rule model; callers who want it can list both kinds on a
//   rule and layer a second factor server-side later.)
//
// Invariants enforced by `tierRuleSetSchema`:
//   - non-empty
//   - sorted by amountMinMinor ascending
//   - first rule starts at 0
//   - last rule has amountMaxMinor = null (unbounded upper edge)
//   - every rule's amountMaxMinor (when set) equals the next rule's min
//     (contiguous, no gaps, no overlaps)
//   - every rule has at least one allowed kind
// -----------------------------------------------------------------------------

export const tierRuleSchema = z
  .object({
    amountMinMinor: z.number().int().min(0),
    amountMaxMinor: z.number().int().positive().nullable(),
    allowedKinds: z.array(z.nativeEnum(CredentialKind)).min(1),
    label: z.string().min(1).max(128).optional(),
  })
  .refine(
    (r) => r.amountMaxMinor === null || r.amountMaxMinor > r.amountMinMinor,
    { message: 'amountMaxMinor must be greater than amountMinMinor (or null for unbounded)' },
  );

export type TierRule = z.infer<typeof tierRuleSchema>;

export const tierRuleSetSchema = z
  .array(tierRuleSchema)
  .min(1, 'tierRules must contain at least one rule')
  .superRefine((rules, ctx) => {
    if (rules[0].amountMinMinor !== 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'first rule must start at amountMinMinor = 0',
        path: [0, 'amountMinMinor'],
      });
    }
    const last = rules[rules.length - 1];
    if (last.amountMaxMinor !== null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'last rule must have amountMaxMinor = null (unbounded)',
        path: [rules.length - 1, 'amountMaxMinor'],
      });
    }
    for (let i = 0; i < rules.length - 1; i++) {
      const cur = rules[i];
      const next = rules[i + 1];
      if (cur.amountMaxMinor === null) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'only the last rule may be unbounded',
          path: [i, 'amountMaxMinor'],
        });
        return;
      }
      if (cur.amountMaxMinor !== next.amountMinMinor) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `rule ${i} ends at ${cur.amountMaxMinor} but rule ${i + 1} starts at ${next.amountMinMinor} — rules must be contiguous`,
          path: [i + 1, 'amountMinMinor'],
        });
      }
    }
  });

export type TierRuleSet = z.infer<typeof tierRuleSetSchema>;

/**
 * Palisade-wide default ruleset, applied to any card without a linked Program.
 * AUD minor units — AUD 100 = 10 000 cents.  Deliberately simple: biometric
 * under AUD 100, card tap at or above.
 */
export const DEFAULT_TIER_RULES: TierRuleSet = Object.freeze([
  {
    amountMinMinor: 0,
    amountMaxMinor: 10_000,
    allowedKinds: [CredentialKind.PLATFORM],
    label: 'Biometric (under AUD 100)',
  },
  {
    amountMinMinor: 10_000,
    amountMaxMinor: null,
    allowedKinds: [CredentialKind.CROSS_PLATFORM],
    label: 'Card tap (AUD 100 and over)',
  },
]) as TierRuleSet;

/**
 * Parse + validate an unknown value (e.g. Program.tierRules JSON from the DB)
 * against the ruleset schema.  Throws ZodError if invalid.
 */
export function parseTierRuleSet(raw: unknown): TierRuleSet {
  return tierRuleSetSchema.parse(raw);
}

/**
 * Find the rule that covers `amountMinor`.  Since `parseTierRuleSet` enforces
 * contiguous coverage starting at 0 and ending at null, exactly one rule
 * always matches for any non-negative amount.
 */
export function matchRule(rules: TierRuleSet, amountMinor: number): TierRule {
  if (amountMinor < 0) {
    throw new Error(`amountMinor must be non-negative (got ${amountMinor})`);
  }
  const hit = rules.find(
    (r) =>
      amountMinor >= r.amountMinMinor &&
      (r.amountMaxMinor === null || amountMinor < r.amountMaxMinor),
  );
  if (!hit) {
    // Unreachable if the ruleset passed tierRuleSetSchema.  Defensive for
    // callers who construct rules by hand and skip validation.
    throw new Error(`no tier rule matches amount ${amountMinor}`);
  }
  return hit;
}
