import { z } from 'zod';
import { badRequest } from '@palisade/core';

// -----------------------------------------------------------------------------
// ISO 4217 currency codes.  Shared between program CRUD and transaction
// creation so both surfaces reject malformed codes identically and upper-case
// the input on the way in.  Non-negotiable: currency is persisted upper-case.
// -----------------------------------------------------------------------------

export const currencySchema = z
  .string()
  .length(3, 'Currency must be a 3-letter ISO 4217 code')
  .regex(/^[A-Za-z]{3}$/, 'Currency must be a 3-letter ISO 4217 code')
  .transform((v) => v.toUpperCase());

/**
 * Narrow, imperative form for service callers that don't funnel through a
 * Zod schema (direct imports, seed scripts).  Throws a 400 on malformed input
 * so the boundary behaviour matches the route.
 */
export function normaliseCurrency(raw: string): string {
  const parsed = currencySchema.safeParse(raw);
  if (!parsed.success) {
    throw badRequest('invalid_currency', `Currency must be ISO 4217 3-letter (got ${raw})`);
  }
  return parsed.data;
}
