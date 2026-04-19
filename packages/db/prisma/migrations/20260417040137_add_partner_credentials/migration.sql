-- CreateTable: PartnerCredential
CREATE TABLE "PartnerCredential" (
    "id" TEXT NOT NULL,
    "financialInstitutionId" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "secretHash" TEXT NOT NULL,
    "salt" TEXT NOT NULL,
    "description" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "revokedAt" TIMESTAMP(3),
    "revokedReason" TEXT,
    "lastUsedAt" TIMESTAMP(3),
    "lastUsedIp" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "PartnerCredential_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "PartnerCredential_keyId_key" ON "PartnerCredential"("keyId");
CREATE INDEX "PartnerCredential_financialInstitutionId_idx" ON "PartnerCredential"("financialInstitutionId");
CREATE INDEX "PartnerCredential_keyId_idx" ON "PartnerCredential"("keyId");
CREATE INDEX "PartnerCredential_status_idx" ON "PartnerCredential"("status");
ALTER TABLE "PartnerCredential" ADD CONSTRAINT "PartnerCredential_financialInstitutionId_fkey"
  FOREIGN KEY ("financialInstitutionId") REFERENCES "FinancialInstitution"("id") ON DELETE CASCADE ON UPDATE CASCADE;
