-- AlterEnum
ALTER TYPE "CardStatus" ADD VALUE 'PROVISIONED';

-- AlterTable: add provisioning fields to Card
ALTER TABLE "Card" ADD COLUMN "proxyCardId" TEXT,
                    ADD COLUMN "provisionedAt" TIMESTAMP(3);

-- CreateIndex
CREATE UNIQUE INDEX "Card_proxyCardId_key" ON "Card"("proxyCardId");

-- CreateTable: ChipProfile
CREATE TABLE "ChipProfile" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "scheme" TEXT NOT NULL,
    "vendor" TEXT NOT NULL,
    "cvn" INTEGER NOT NULL,
    "dgiDefinitions" JSONB NOT NULL,
    "elfAid" TEXT,
    "moduleAid" TEXT,
    "paAid" TEXT NOT NULL DEFAULT 'D276000085504100',
    "fidoAid" TEXT NOT NULL DEFAULT 'A0000006472F0001',
    "iccPrivateKeyDgi" INTEGER NOT NULL DEFAULT 32769,
    "iccPrivateKeyTag" INTEGER NOT NULL DEFAULT 40776,
    "mkAcDgi" INTEGER NOT NULL DEFAULT 2048,
    "mkSmiDgi" INTEGER NOT NULL DEFAULT 2049,
    "mkSmcDgi" INTEGER NOT NULL DEFAULT 2050,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ChipProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable: IssuerProfile
CREATE TABLE "IssuerProfile" (
    "id" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "chipProfileId" TEXT NOT NULL,
    "scheme" TEXT NOT NULL,
    "cvn" INTEGER NOT NULL,
    "imkAlgorithm" TEXT NOT NULL DEFAULT 'TDES_2KEY',
    "derivationMethod" TEXT NOT NULL DEFAULT 'METHOD_A',
    "tmkKeyArn" TEXT NOT NULL DEFAULT '',
    "imkAcKeyArn" TEXT NOT NULL DEFAULT '',
    "imkSmiKeyArn" TEXT NOT NULL DEFAULT '',
    "imkSmcKeyArn" TEXT NOT NULL DEFAULT '',
    "imkIdnKeyArn" TEXT NOT NULL DEFAULT '',
    "issuerPkKeyArn" TEXT NOT NULL DEFAULT '',
    "caPkIndex" TEXT NOT NULL DEFAULT '',
    "issuerPkCertificate" TEXT NOT NULL DEFAULT '',
    "issuerPkRemainder" TEXT NOT NULL DEFAULT '',
    "issuerPkExponent" TEXT NOT NULL DEFAULT '',
    "aid" TEXT NOT NULL DEFAULT '',
    "appLabel" TEXT NOT NULL DEFAULT '',
    "appPreferredName" TEXT NOT NULL DEFAULT '',
    "appPriority" TEXT NOT NULL DEFAULT '',
    "appVersionNumber" TEXT NOT NULL DEFAULT '',
    "aip" TEXT NOT NULL DEFAULT '',
    "afl" TEXT NOT NULL DEFAULT '',
    "cvmList" TEXT NOT NULL DEFAULT '',
    "pdol" TEXT NOT NULL DEFAULT '',
    "cdol1" TEXT NOT NULL DEFAULT '',
    "cdol2" TEXT NOT NULL DEFAULT '',
    "iacDefault" TEXT NOT NULL DEFAULT '',
    "iacDenial" TEXT NOT NULL DEFAULT '',
    "iacOnline" TEXT NOT NULL DEFAULT '',
    "appUsageControl" TEXT NOT NULL DEFAULT '',
    "currencyCode" TEXT NOT NULL DEFAULT '',
    "currencyExponent" TEXT NOT NULL DEFAULT '',
    "countryCode" TEXT NOT NULL DEFAULT '',
    "sdaTagList" TEXT NOT NULL DEFAULT '',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IssuerProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable: SadRecord
CREATE TABLE "SadRecord" (
    "id" TEXT NOT NULL,
    "proxyCardId" TEXT NOT NULL,
    "cardId" TEXT NOT NULL,
    "sadEncrypted" BYTEA NOT NULL,
    "sadKeyVersion" INTEGER NOT NULL,
    "chipSerial" TEXT,
    "status" TEXT NOT NULL DEFAULT 'READY',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SadRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable: ProvisioningSession
CREATE TABLE "ProvisioningSession" (
    "id" TEXT NOT NULL,
    "cardId" TEXT NOT NULL,
    "sadRecordId" TEXT NOT NULL,
    "phase" TEXT NOT NULL DEFAULT 'INIT',
    "iccPublicKey" BYTEA,
    "provenance" TEXT,
    "fidoCredData" TEXT,
    "completedAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "failureReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProvisioningSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "IssuerProfile_programId_key" ON "IssuerProfile"("programId");

-- CreateIndex
CREATE UNIQUE INDEX "SadRecord_proxyCardId_key" ON "SadRecord"("proxyCardId");

-- CreateIndex
CREATE INDEX "SadRecord_status_idx" ON "SadRecord"("status");

-- CreateIndex
CREATE INDEX "SadRecord_expiresAt_idx" ON "SadRecord"("expiresAt");

-- CreateIndex
CREATE INDEX "ProvisioningSession_cardId_idx" ON "ProvisioningSession"("cardId");

-- CreateIndex
CREATE INDEX "ProvisioningSession_phase_idx" ON "ProvisioningSession"("phase");

-- AddForeignKey
ALTER TABLE "IssuerProfile" ADD CONSTRAINT "IssuerProfile_programId_fkey" FOREIGN KEY ("programId") REFERENCES "Program"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IssuerProfile" ADD CONSTRAINT "IssuerProfile_chipProfileId_fkey" FOREIGN KEY ("chipProfileId") REFERENCES "ChipProfile"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SadRecord" ADD CONSTRAINT "SadRecord_cardId_fkey" FOREIGN KEY ("cardId") REFERENCES "Card"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProvisioningSession" ADD CONSTRAINT "ProvisioningSession_cardId_fkey" FOREIGN KEY ("cardId") REFERENCES "Card"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProvisioningSession" ADD CONSTRAINT "ProvisioningSession_sadRecordId_fkey" FOREIGN KEY ("sadRecordId") REFERENCES "SadRecord"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
