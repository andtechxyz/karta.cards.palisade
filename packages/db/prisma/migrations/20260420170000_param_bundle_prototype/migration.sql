-- Phase 3 of the chip-computed-DGI prototype (C17/C22 patent alignment).
--
-- Additive-only migration.  No existing rows, indexes, or constraints
-- change.  Legacy cards / ChipProfiles / provisioning flow continue to
-- work unchanged.
--
-- What this migration does:
--   1. CreateEnum: ProvisioningMode { SAD_LEGACY, PARAM_BUNDLE }
--   2. CreateTable: ParamRecord  (sibling of SadRecord for prototype flow)
--   3. AlterTable: ChipProfile gets a `provisioningMode` column,
--                   default SAD_LEGACY (no behavior change for existing
--                   rows)
--   4. AlterTable: Card gets nullable `paramRecordId` foreign key
--                   (null for every existing card)
--
-- Rollback:
--   Drop Card."paramRecordId" column; drop the ParamRecord table; drop
--   ChipProfile."provisioningMode" column; drop the enum.  Safe to run
--   at any time as long as no ParamRecord rows exist (they won't until
--   we flip a ChipProfile to PARAM_BUNDLE and provision a card).

-- 1. Enum
CREATE TYPE "ProvisioningMode" AS ENUM ('SAD_LEGACY', 'PARAM_BUNDLE');

-- 2. ParamRecord table
CREATE TABLE "ParamRecord" (
    "id"               TEXT    NOT NULL,
    "proxyCardId"      TEXT    NOT NULL,
    "cardId"           TEXT    NOT NULL,
    "bundleEncrypted"  BYTEA   NOT NULL,
    "bundleKeyVersion" INTEGER NOT NULL,
    "schemeByte"       INTEGER NOT NULL,
    "cvnByte"          INTEGER NOT NULL,
    "chipSerial"       TEXT,
    "status"           TEXT    NOT NULL DEFAULT 'READY',
    "expiresAt"        TIMESTAMP(3) NOT NULL,
    "createdAt"        TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ParamRecord_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ParamRecord_proxyCardId_key" ON "ParamRecord"("proxyCardId");
CREATE UNIQUE INDEX "ParamRecord_cardId_key" ON "ParamRecord"("cardId");
CREATE INDEX "ParamRecord_status_idx" ON "ParamRecord"("status");
CREATE INDEX "ParamRecord_expiresAt_idx" ON "ParamRecord"("expiresAt");

-- 3. ChipProfile.provisioningMode
ALTER TABLE "ChipProfile"
  ADD COLUMN "provisioningMode" "ProvisioningMode" NOT NULL DEFAULT 'SAD_LEGACY';

-- 4. Card.paramRecordId — nullable FK to ParamRecord
ALTER TABLE "Card"
  ADD COLUMN "paramRecordId" TEXT;

CREATE UNIQUE INDEX "Card_paramRecordId_key" ON "Card"("paramRecordId");

ALTER TABLE "Card"
  ADD CONSTRAINT "Card_paramRecordId_fkey"
  FOREIGN KEY ("paramRecordId") REFERENCES "ParamRecord"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
