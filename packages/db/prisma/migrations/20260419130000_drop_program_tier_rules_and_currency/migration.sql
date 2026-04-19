-- Phase 4c: tierRules + currency move to Vera's TokenisationProgram (token-control
-- concern).  Palisade's Program keeps only card-domain fields (NDEF, FI,
-- embossing, program type).

ALTER TABLE "Program" DROP COLUMN "tierRules";
ALTER TABLE "Program" DROP COLUMN "currency";
