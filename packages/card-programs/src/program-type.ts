import { z } from 'zod';

/**
 * Program product classification.  Drives UI labels, reporting, and the
 * retail SHIPPED → SOLD activation gate.
 *
 * The underlying DB column is a free String so we can add new types
 * without a schema migration; anything that writes to Program.programType
 * must go through this schema first.
 */
export const PROGRAM_TYPES = [
  'RETAIL',
  'PREPAID_NON_RELOADABLE',
  'PREPAID_RELOADABLE',
  'DEBIT',
  'CREDIT',
] as const;

export type ProgramType = (typeof PROGRAM_TYPES)[number];

export const programTypeSchema = z.enum(PROGRAM_TYPES);

/** Display labels for admin UI.  Keeps copy in one place. */
export const PROGRAM_TYPE_LABELS: Record<ProgramType, string> = {
  RETAIL: 'Retail',
  PREPAID_NON_RELOADABLE: 'Prepaid (Non-Reloadable)',
  PREPAID_RELOADABLE: 'Prepaid (Reloadable)',
  DEBIT: 'Debit',
  CREDIT: 'Credit',
};

/** True when this program sells its cards through retail shelves. */
export function isRetailProgram(programType: string | null | undefined): boolean {
  return programType === 'RETAIL';
}

// -----------------------------------------------------------------------------
// Retail sale status — lives on Card, not Program, but the constants belong
// here because they're tightly coupled to programType='RETAIL'.
// -----------------------------------------------------------------------------

export const RETAIL_SALE_STATUSES = ['SHIPPED', 'SOLD'] as const;
export type RetailSaleStatus = (typeof RETAIL_SALE_STATUSES)[number];
export const retailSaleStatusSchema = z.enum(RETAIL_SALE_STATUSES);
