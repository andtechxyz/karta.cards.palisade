-- CreateTable: EmbossingTemplate
CREATE TABLE "EmbossingTemplate" (
    "id" TEXT NOT NULL,
    "financialInstitutionId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "supportsVisa" BOOLEAN NOT NULL DEFAULT false,
    "supportsMastercard" BOOLEAN NOT NULL DEFAULT false,
    "supportsAmex" BOOLEAN NOT NULL DEFAULT false,
    "formatType" TEXT NOT NULL,
    "templateEncrypted" BYTEA NOT NULL,
    "templateKeyVersion" INTEGER NOT NULL,
    "templateSha256" TEXT NOT NULL,
    "templateFileName" TEXT NOT NULL,
    "recordLength" INTEGER,
    "fieldCount" INTEGER,
    "parserMeta" JSONB,
    "uploadedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "EmbossingTemplate_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "EmbossingTemplate_financialInstitutionId_idx" ON "EmbossingTemplate"("financialInstitutionId");

-- CreateTable: EmbossingBatch
CREATE TABLE "EmbossingBatch" (
    "id" TEXT NOT NULL,
    "templateId" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "fileName" TEXT NOT NULL,
    "fileSize" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "s3Bucket" TEXT NOT NULL,
    "s3Key" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'RECEIVED',
    "recordCount" INTEGER,
    "recordsSuccess" INTEGER NOT NULL DEFAULT 0,
    "recordsFailed" INTEGER NOT NULL DEFAULT 0,
    "processingError" TEXT,
    "uploadedVia" TEXT NOT NULL,
    "uploadedBy" TEXT,
    "uploadedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processedAt" TIMESTAMP(3),
    CONSTRAINT "EmbossingBatch_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "EmbossingBatch_programId_idx" ON "EmbossingBatch"("programId");
CREATE INDEX "EmbossingBatch_templateId_idx" ON "EmbossingBatch"("templateId");
CREATE INDEX "EmbossingBatch_status_idx" ON "EmbossingBatch"("status");
CREATE INDEX "EmbossingBatch_uploadedAt_idx" ON "EmbossingBatch"("uploadedAt");

-- AlterTable: Program
ALTER TABLE "Program" ADD COLUMN "embossingTemplateId" TEXT;

-- Foreign keys
ALTER TABLE "EmbossingTemplate" ADD CONSTRAINT "EmbossingTemplate_financialInstitutionId_fkey"
  FOREIGN KEY ("financialInstitutionId") REFERENCES "FinancialInstitution"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "EmbossingBatch" ADD CONSTRAINT "EmbossingBatch_templateId_fkey"
  FOREIGN KEY ("templateId") REFERENCES "EmbossingTemplate"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "EmbossingBatch" ADD CONSTRAINT "EmbossingBatch_programId_fkey"
  FOREIGN KEY ("programId") REFERENCES "Program"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "Program" ADD CONSTRAINT "Program_embossingTemplateId_fkey"
  FOREIGN KEY ("embossingTemplateId") REFERENCES "EmbossingTemplate"("id") ON DELETE SET NULL ON UPDATE CASCADE;
