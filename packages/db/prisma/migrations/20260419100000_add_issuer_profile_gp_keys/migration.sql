-- Per-card GlobalPlatform SCP03 static keys.
--
-- Each IssuerProfile points at three KMS key ARNs (or Secrets Manager
-- secret ARNs) that hold the AES-128 ENC / MAC / DEK triplet used to
-- authenticate admin GP operations against cards issued by this FI.
--
-- Nullable because:
--   - Not every program has its own key set yet (migration window).
--   - Local dev uses the GP test key (0x40..0x4F) via
--     CARD_OPS_USE_TEST_KEYS=1 which bypasses the ARN lookup.
--
-- These REPLACE the single env-wide GP_MASTER_KEY used by Phase 2 of
-- card-ops.  Compromising one issuer's keys no longer compromises every
-- card in the environment.

ALTER TABLE "IssuerProfile" ADD COLUMN "gpEncKeyArn" TEXT;
ALTER TABLE "IssuerProfile" ADD COLUMN "gpMacKeyArn" TEXT;
ALTER TABLE "IssuerProfile" ADD COLUMN "gpDekKeyArn" TEXT;
