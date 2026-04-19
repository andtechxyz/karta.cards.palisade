-- Phase 2 of the Vera/Palisade split: cut the Card.vaultEntryId FK and
-- mirror display-safe PAN metadata onto the Card row.
--
-- After this migration Palisade no longer joins Card → VaultEntry for
-- card-list rendering.  Vera's POST /api/vault/register returns an opaque
-- vaultToken; we persist that string here alongside the PAN metadata the
-- caller already supplied.  VaultEntry the model stays for now — Phase 3
-- will remove it from Palisade's schema entirely.

-- 1. Add new columns (nullable so backfill can populate before the FK drops).
ALTER TABLE "Card"
  ADD COLUMN IF NOT EXISTS "vaultToken"     TEXT,
  ADD COLUMN IF NOT EXISTS "panLast4"       TEXT,
  ADD COLUMN IF NOT EXISTS "panBin"         TEXT,
  ADD COLUMN IF NOT EXISTS "cardholderName" TEXT,
  ADD COLUMN IF NOT EXISTS "panExpiryMonth" TEXT,
  ADD COLUMN IF NOT EXISTS "panExpiryYear"  TEXT;

-- 2. Backfill from the existing FK + join.  Done before the FK drops so the
--    join still resolves.  NULL vaultEntryId rows stay NULL here.
UPDATE "Card" c
SET
  "vaultToken"     = v."id",
  "panLast4"       = v."panLast4",
  "panBin"         = v."panBin",
  "cardholderName" = v."cardholderName",
  "panExpiryMonth" = v."panExpiryMonth",
  "panExpiryYear"  = v."panExpiryYear"
FROM "VaultEntry" v
WHERE c."vaultEntryId" = v."id"
  AND c."vaultToken" IS NULL;

-- 3. Drop the FK + unique constraint + the column itself.
ALTER TABLE "Card"
  DROP CONSTRAINT IF EXISTS "Card_vaultEntryId_fkey",
  DROP CONSTRAINT IF EXISTS "Card_vaultEntryId_key";

ALTER TABLE "Card" DROP COLUMN IF EXISTS "vaultEntryId";

-- 4. VaultEntry.idempotencyKey — mirrors the Vera-side field.  Nullable +
--    unique.  Phase 3 removes this table from Palisade's schema entirely.
ALTER TABLE "VaultEntry" ADD COLUMN IF NOT EXISTS "idempotencyKey" TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS "VaultEntry_idempotencyKey_key"
  ON "VaultEntry" ("idempotencyKey");
