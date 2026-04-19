-- Phase 3 (Palisade side) — drop vault/transaction domain from Palisade's DB.
-- These rows live in Vera's Postgres only.  Palisade keeps the card lifecycle
-- tables (Card, ActivationSession, WebAuthnCredential, ChipProfile,
-- IssuerProfile, SadRecord, ProvisioningSession, EmbossingBatch,
-- EmbossingTemplate, Program, FinancialInstitution, PartnerCredential,
-- MicrositeVersion).  The cross-repo boundary is the opaque Card.vaultToken
-- persisted in Phase 2; no FKs cross the line.
--
-- Drop order follows the FK dependency graph:
--   VaultAccessLog -> VaultEntry, RetrievalToken, Transaction
--   RetrievalToken -> VaultEntry
--   Transaction    -> Card (SET NULL side is Transaction.cardId; we drop
--                     Transaction wholesale, so only Transaction vanishes)
--   VaultEntry     (no remaining incoming FKs after the two above are gone)
--   VaultEncryptionKey, RegistrationChallenge (standalone)

DROP TABLE IF EXISTS "VaultAccessLog";
DROP TABLE IF EXISTS "RetrievalToken";
DROP TABLE IF EXISTS "Transaction";
DROP TABLE IF EXISTS "VaultEntry";
DROP TABLE IF EXISTS "VaultEncryptionKey";
DROP TABLE IF EXISTS "RegistrationChallenge";

-- Enums used only by the tables above.  CredentialKind stays — Card /
-- WebAuthnCredential still reference it.  CardStatus stays too.
DROP TYPE IF EXISTS "VaultEventType";
DROP TYPE IF EXISTS "VaultEventResult";
DROP TYPE IF EXISTS "TransactionStatus";
DROP TYPE IF EXISTS "Tier";
