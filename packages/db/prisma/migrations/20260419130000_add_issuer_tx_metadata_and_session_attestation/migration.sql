-- IssuerProfile: carry the real metadata the PA applet stashes in NVM during
-- TRANSFER_SAD.  Previously RCA sent placeholder bytes (0x00000001 bankId /
-- progId, 0x01 scheme, mobile.karta.cards URL) regardless of issuer — which
-- worked for the PA's SW=9000 loop but wrote junk to the chip's persistent
-- state.  These columns feed RCA's plan-builder so the exact on-card bytes
-- reflect the per-FI identity.
--
-- Nullable because legacy IssuerProfile rows predate these columns.  RCA's
-- buildPlanForSession rejects empty values with issuer_profile_incomplete
-- unless RCA_ALLOW_MINIMAL_SAD=1 (dev-only fallback for the e2e_fi_2590
-- skeleton profile that still exists in the dev DB).
ALTER TABLE "IssuerProfile"
    ADD COLUMN "bankId" INTEGER,
    ADD COLUMN "progId" INTEGER,
    ADD COLUMN "postProvisionUrl" TEXT;

-- ProvisioningSession: persist the raw chip attestation bytes we capture in
-- GENERATE_KEYS response.  Response layout is W(65) || ATT_SIG(~70-72) ||
-- CPLC(42); RCA previously stored only the 65-byte pubkey and dropped the
-- attestation on the floor.  Persisting the bytes lets us analyse the NXP /
-- Infineon vendor signature offline even while AttestationVerifier.verify()
-- is still in stub mode (warn, don't reject).  Reject-on-fail is blocked on
-- a protocol checkpoint that only lands after mobile rolls client support.
ALTER TABLE "ProvisioningSession"
    ADD COLUMN "attestation" BYTEA;
