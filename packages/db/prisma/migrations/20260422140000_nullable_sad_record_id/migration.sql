-- ProvisioningSession.sadRecordId: required → optional.
--
-- Prototype (PARAM_BUNDLE) cards use ParamRecord exclusively for
-- personalisation state and don't need a linked SadRecord.  Before
-- this migration the column defaulted to '' (placeholder) which
-- confused retention sweeps and audit joins — they saw rows with
-- sadRecordId='' and tried to dereference them.  Making the column
-- nullable is the correct modelling; dangling '' rows get nulled at
-- migrate time so existing sweepers stop false-positive-joining.
--
-- Legacy SAD_LEGACY cards still populate a real sadRecordId; nothing
-- changes for them.
ALTER TABLE "ProvisioningSession" ALTER COLUMN "sadRecordId" DROP NOT NULL;
ALTER TABLE "ProvisioningSession" ALTER COLUMN "sadRecordId" DROP DEFAULT;
UPDATE "ProvisioningSession" SET "sadRecordId" = NULL WHERE "sadRecordId" = '';
