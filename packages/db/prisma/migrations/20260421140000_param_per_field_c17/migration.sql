-- Phase 8 (patent claim C17/C22 full build-out).
--
-- The prototype's existing ParamRecord.bundleEncrypted column holds the
-- ENTIRE TLV ParamBundle as one KMS-wrapped blob (MKs + ICC RSA priv +
-- AIP + AFL + AUC + PAN + ...).  At rca provisioning time we decrypt
-- the whole blob into rca RAM, ECDH-wrap it for the chip, emit
-- TRANSFER_PARAMS, then scrub.  Plaintext window: ~50 ms.
--
-- Full C17/C22 (as described in PROTOTYPE_PLAN.md §3 "Enhancement
-- path") shrinks that window by splitting the SENSITIVE fields out
-- into individually envelope-encrypted columns.  At wrap time each
-- field is decrypted just-in-time, streamed into the TLV assembler,
-- and scrubbed per-field.  Even if a heap snapshot were taken
-- mid-flight, only one field's plaintext is live at a time.
--
-- Sensitive fields split out (each gets its own envelope cipher +
-- key version column):
--   MK-AC          (16 B AES key, PCI 3.5 / 3.6)
--   MK-SMI         (16 B AES key)
--   MK-SMC         (16 B AES key)
--   ICC RSA priv   (128-256 B EMV ICC signing key)
--
-- Non-sensitive fields stay inside `bundleEncrypted` for compat:
--   AIP, AFL, AUC, expiry, effective, service code, AID, app version,
--   currency, country, app label, iCVV, ICC PK Cert (cert is public),
--   PAN*, PSN, bankId, progId, postProvisionUrl, CVM list, IACs.
--
--   * PAN is sensitive but already protected by the existing vault
--     pattern on the Card row; not duplicated here.
--
-- Rollout protocol:
--   1. This migration applies additively.  All new columns nullable
--      so existing rows keep working without backfill.
--   2. data-prep.prepareParamBundle stays on the legacy bundleEncrypted
--      path until PARAMS_PER_COLUMN=1 is set in its task def.  When
--      the flag is on, new rows get the sensitive fields in the new
--      columns AND a bundleEncrypted that omits them (assembled by
--      rca at wrap time).
--   3. rca autodetects which path a given row uses at wrap time:
--      legacy rows (mkAcEncrypted IS NULL) use bundleEncrypted as-is;
--      new rows (mkAcEncrypted IS NOT NULL) merge per-column decrypts
--      into the TLV bundle before wrap.
--   4. Once the live fleet has rotated to per-column rows, set
--      PARAMS_PER_COLUMN=1 everywhere and keep the legacy path only
--      as a read-only fallback for rows created before the cutover.
--
-- Rollback:
--   Drop the 8 new columns.  Safe as long as no ParamRecord row has
--   mkAcEncrypted / mkSmiEncrypted / mkSmcEncrypted / iccRsaPrivEncrypted
--   NOT NULL.  In that case the operator needs to re-issue those cards
--   first (data-prep.prepareParamBundle against the same cardId with
--   the flag flipped off).

ALTER TABLE "ParamRecord"
    ADD COLUMN "mkAcEncrypted"           BYTEA,
    ADD COLUMN "mkAcKeyVersion"          INTEGER,
    ADD COLUMN "mkSmiEncrypted"          BYTEA,
    ADD COLUMN "mkSmiKeyVersion"         INTEGER,
    ADD COLUMN "mkSmcEncrypted"          BYTEA,
    ADD COLUMN "mkSmcKeyVersion"         INTEGER,
    ADD COLUMN "iccRsaPrivEncrypted"     BYTEA,
    ADD COLUMN "iccRsaPrivKeyVersion"    INTEGER;
