-- CreateTable
CREATE TABLE "FinancialInstitution" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "bin" TEXT,
    "contactEmail" TEXT,
    "contactName" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FinancialInstitution_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "FinancialInstitution_slug_key" ON "FinancialInstitution"("slug");
CREATE INDEX "FinancialInstitution_slug_idx" ON "FinancialInstitution"("slug");

-- AlterTable — add nullable FK to Program
ALTER TABLE "Program" ADD COLUMN "financialInstitutionId" TEXT;

-- AddForeignKey
ALTER TABLE "Program" ADD CONSTRAINT "Program_financialInstitutionId_fkey"
  FOREIGN KEY ("financialInstitutionId") REFERENCES "FinancialInstitution"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

-- Backfill: create a default FI and link any existing programs to it
INSERT INTO "FinancialInstitution" (id, name, slug, status, "createdAt", "updatedAt")
VALUES ('fi_default', 'Default (legacy)', 'default-legacy', 'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

UPDATE "Program" SET "financialInstitutionId" = 'fi_default'
WHERE "financialInstitutionId" IS NULL;
