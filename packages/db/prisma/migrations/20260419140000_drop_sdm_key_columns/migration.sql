-- Per-card SDM keys are no longer stored.  They are derived on every tap
-- via AES-CMAC(MASTER_<role>, UID), with the MASTER keys living in the HSM
-- (AWS Payment Cryptography) in prod and HKDF'd from DEV_SDM_ROOT_SEED in
-- dev/local.  The chip is personalised with the same derivation so the
-- server can reproduce the keys given only its UID.
--
-- This migration is a hard cutover: any existing Card rows that relied on
-- the stored keys must be re-personalised under the new master-keyed
-- derivation.
ALTER TABLE "Card" DROP COLUMN "sdmMetaReadKeyEncrypted";
ALTER TABLE "Card" DROP COLUMN "sdmFileReadKeyEncrypted";
