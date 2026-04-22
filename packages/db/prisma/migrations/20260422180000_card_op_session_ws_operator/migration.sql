-- Stage C.2 — operator identity binding on the card-ops WS audit trail.
--
-- Adds two nullable columns to CardOpSession:
--   wsConnectedBy   Cognito sub of the operator whose JWT successfully
--                   authenticated the WS upgrade.  Stamped by the
--                   card-ops upgrade handler after verifying the
--                   `?id_token=` query param against Cognito's JWKS
--                   AND asserting that JWT.sub == initiatedBy.
--   wsConnectedAt   When the WS upgrade authenticated.
--
-- Both nullable because:
--   - Existing rows pre-date the column
--   - Sessions that never reach the WS (e.g. operator clicked Start
--     then aborted) never get stamped; null is the truthful state
--
-- PCI DSS 10.2.5 attribution: separates "who started it" (initiatedBy,
-- existing) from "who drove the APDUs" (wsConnectedBy, new) so audit
-- reads stay unambiguous when a future relay-by-proxy flow splits
-- the two.

ALTER TABLE "CardOpSession"
  ADD COLUMN "wsConnectedBy" TEXT,
  ADD COLUMN "wsConnectedAt" TIMESTAMP(3);

CREATE INDEX "CardOpSession_wsConnectedBy_idx" ON "CardOpSession"("wsConnectedBy");
