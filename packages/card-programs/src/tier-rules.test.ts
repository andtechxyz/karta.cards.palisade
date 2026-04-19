import { describe, it, expect } from 'vitest';
import { CredentialKind } from '@prisma/client';
import {
  DEFAULT_TIER_RULES,
  matchRule,
  parseTierRuleSet,
  tierRuleSetSchema,
  type TierRule,
  type TierRuleSet,
} from './tier-rules.js';

const biomRule: TierRule = {
  amountMinMinor: 0,
  amountMaxMinor: 10_000,
  allowedKinds: [CredentialKind.PLATFORM],
  label: 'bio',
};
const tapRule: TierRule = {
  amountMinMinor: 10_000,
  amountMaxMinor: null,
  allowedKinds: [CredentialKind.CROSS_PLATFORM],
  label: 'tap',
};

describe('tierRuleSetSchema', () => {
  it('accepts a well-formed two-rule set', () => {
    expect(() => parseTierRuleSet([biomRule, tapRule])).not.toThrow();
  });

  it('accepts a single unbounded rule covering all amounts', () => {
    const all: TierRule = {
      amountMinMinor: 0,
      amountMaxMinor: null,
      allowedKinds: [CredentialKind.PLATFORM, CredentialKind.CROSS_PLATFORM],
    };
    expect(() => parseTierRuleSet([all])).not.toThrow();
  });

  it('rejects an empty ruleset', () => {
    expect(() => parseTierRuleSet([])).toThrow();
  });

  it('rejects a first rule that does not start at 0', () => {
    const shifted: TierRule = { ...biomRule, amountMinMinor: 100, amountMaxMinor: 10_000 };
    expect(() => parseTierRuleSet([shifted, tapRule])).toThrow(/start at amountMinMinor = 0/);
  });

  it('rejects a last rule with a bounded upper edge', () => {
    const cappedTap: TierRule = { ...tapRule, amountMaxMinor: 50_000 };
    expect(() => parseTierRuleSet([biomRule, cappedTap])).toThrow(/unbounded/);
  });

  it('rejects a gap between rules', () => {
    const gappedTap: TierRule = { ...tapRule, amountMinMinor: 15_000 };
    expect(() => parseTierRuleSet([biomRule, gappedTap])).toThrow(/contiguous/);
  });

  it('rejects overlapping rules', () => {
    const overlapTap: TierRule = { ...tapRule, amountMinMinor: 5_000 };
    expect(() => parseTierRuleSet([biomRule, overlapTap])).toThrow(/contiguous/);
  });

  it('rejects an unbounded rule that is not the last', () => {
    const unboundedBiom: TierRule = { ...biomRule, amountMaxMinor: null };
    expect(() => parseTierRuleSet([unboundedBiom, tapRule])).toThrow(/only the last rule/);
  });

  it('rejects a rule with amountMaxMinor <= amountMinMinor', () => {
    const inverted: TierRule = { ...biomRule, amountMaxMinor: 0 };
    expect(() => tierRuleSetSchema.parse([inverted, tapRule])).toThrow();
  });

  it('rejects a rule with no allowed kinds', () => {
    const empty: TierRule = { ...biomRule, allowedKinds: [] };
    expect(() => parseTierRuleSet([empty, tapRule])).toThrow();
  });

  it('rejects unknown credential kinds', () => {
    expect(() =>
      // Force an invalid enum through the schema.
      tierRuleSetSchema.parse([
        { ...biomRule, allowedKinds: ['NOT_A_KIND'] },
        tapRule,
      ]),
    ).toThrow();
  });
});

describe('matchRule', () => {
  const rules: TierRuleSet = [biomRule, tapRule];

  it('returns the first rule for amounts in its range', () => {
    expect(matchRule(rules, 0)).toEqual(biomRule);
    expect(matchRule(rules, 9_999)).toEqual(biomRule);
  });

  it('returns the second rule at the boundary (inclusive lower)', () => {
    expect(matchRule(rules, 10_000)).toEqual(tapRule);
  });

  it('returns the unbounded rule for very large amounts', () => {
    expect(matchRule(rules, 1_000_000)).toEqual(tapRule);
  });

  it('throws on negative amounts', () => {
    expect(() => matchRule(rules, -1)).toThrow(/non-negative/);
  });
});

describe('DEFAULT_TIER_RULES', () => {
  it('is a valid ruleset', () => {
    expect(() => parseTierRuleSet(DEFAULT_TIER_RULES)).not.toThrow();
  });

  it('routes AUD 99.99 to PLATFORM (biometric)', () => {
    const rule = matchRule(DEFAULT_TIER_RULES, 9_999);
    expect(rule.allowedKinds).toEqual([CredentialKind.PLATFORM]);
  });

  it('routes AUD 100.00 to CROSS_PLATFORM (tap)', () => {
    const rule = matchRule(DEFAULT_TIER_RULES, 10_000);
    expect(rule.allowedKinds).toEqual([CredentialKind.CROSS_PLATFORM]);
  });
});
