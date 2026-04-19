-- Add cognitoSub to Card (links card to mobile user)
ALTER TABLE "Card" ADD COLUMN "cognitoSub" TEXT;
CREATE INDEX "Card_cognitoSub_idx" ON "Card"("cognitoSub");

-- Add rcaSessionId and proxyCardId to ProvisioningSession
ALTER TABLE "ProvisioningSession" ADD COLUMN "proxyCardId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "ProvisioningSession" ADD COLUMN "rcaSessionId" TEXT;
CREATE UNIQUE INDEX "ProvisioningSession_rcaSessionId_key" ON "ProvisioningSession"("rcaSessionId");

-- Make sadRecordId optional (mobile-initiated sessions may not have one immediately)
ALTER TABLE "ProvisioningSession" ALTER COLUMN "sadRecordId" SET DEFAULT '';
