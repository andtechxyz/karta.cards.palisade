-- Extend CardStatus with SHIPPED — the true initial state after the
-- provisioning agent has loaded applets + SDM keys at perso bureaus.
-- PERSONALISED is reclassified as the POST-activation step when the
-- provisioning agent writes EMV data (SAD, iCVV, MKAC/SMI/SMC) onto
-- the chip via APDU from the mobile app.
ALTER TYPE "CardStatus" ADD VALUE IF NOT EXISTS 'SHIPPED';

-- Flip the column default to SHIPPED.  Needs a committed enum add first,
-- so it lives in a second statement in this migration.  Postgres allows
-- ADD VALUE + DEFAULT change in the same transaction since v12.
ALTER TABLE "Card" ALTER COLUMN "status" SET DEFAULT 'SHIPPED';

-- Backfill: any existing card that's currently PERSONALISED but has not
-- been activated yet should be SHIPPED under the new naming.  We use the
-- absence of any WebAuthn credential as the proxy for "not activated".
-- Activated/Provisioned/Suspended/Revoked cards stay as-is.
UPDATE "Card"
SET status = 'SHIPPED'
WHERE status = 'PERSONALISED'
  AND NOT EXISTS (
    SELECT 1 FROM "WebAuthnCredential" w WHERE w."cardId" = "Card".id
  );
