-- WebAuthnCredential.preregistered — true when the credential was injected
-- by the perso path before any user-side ceremony.  Backfill defaults to
-- false (existing rows came from the runtime activation flow).
ALTER TABLE "WebAuthnCredential"
  ADD COLUMN "preregistered" BOOLEAN NOT NULL DEFAULT false;

-- Partial unique index: at most one preregistered credential per card.
-- Lets perso re-POST the same credentialId without bloating the row set,
-- and prevents the activation /begin short-circuit from being ambiguous
-- when there are multiple pre-registered creds.
CREATE UNIQUE INDEX "WebAuthnCredential_cardId_preregistered_idx"
  ON "WebAuthnCredential" ("cardId")
  WHERE "preregistered" = true;
