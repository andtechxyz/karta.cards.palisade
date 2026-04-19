-- Program.programType — product classification.  RETAIL gates activation
-- on a SHIPPED → SOLD transition; the other four (PREPAID_NON_RELOADABLE,
-- PREPAID_RELOADABLE, DEBIT, CREDIT) activate on first tap as before.
-- Default PREPAID_RELOADABLE matches what the prototype has been treating
-- every existing program as, so backfill is a no-op.
ALTER TABLE "Program"
  ADD COLUMN "programType" TEXT NOT NULL DEFAULT 'PREPAID_RELOADABLE';

-- Card.retailSaleStatus — per-card sale state for RETAIL programs only.
-- Left NULL for cards whose program is not RETAIL.  retailSoldAt records
-- the SOLD transition for auditing.
ALTER TABLE "Card"
  ADD COLUMN "retailSaleStatus" TEXT,
  ADD COLUMN "retailSoldAt" TIMESTAMP(3);

-- Index so the admin cards tab can filter "all SHIPPED retail cards" fast.
CREATE INDEX "Card_retailSaleStatus_idx" ON "Card"("retailSaleStatus");
