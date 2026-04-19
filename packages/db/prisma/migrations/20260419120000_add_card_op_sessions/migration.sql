-- Admin-operated card management session.  Mirrors ProvisioningSession
-- but targets GlobalPlatform operations (applet install/uninstall/wipe,
-- state reset, audit listing) driven by an authenticated admin via the
-- card-ops service.  `scpState` carries the live SCP03 session keys
-- during the WS lifetime only (cleared on COMPLETE / FAILED).

-- CreateTable
CREATE TABLE "CardOpSession" (
    "id" TEXT NOT NULL,
    "cardId" TEXT NOT NULL,
    "operation" TEXT NOT NULL,
    "initiatedBy" TEXT NOT NULL,
    "phase" TEXT NOT NULL DEFAULT 'READY',
    "apduLog" JSONB,
    "scpState" JSONB,
    "completedAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "failureReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CardOpSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CardOpSession_cardId_idx" ON "CardOpSession"("cardId");

-- CreateIndex
CREATE INDEX "CardOpSession_phase_idx" ON "CardOpSession"("phase");

-- CreateIndex
CREATE INDEX "CardOpSession_initiatedBy_idx" ON "CardOpSession"("initiatedBy");

-- AddForeignKey
ALTER TABLE "CardOpSession" ADD CONSTRAINT "CardOpSession_cardId_fkey" FOREIGN KEY ("cardId") REFERENCES "Card"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
