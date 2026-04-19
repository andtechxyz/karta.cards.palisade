-- AlterTable: add microsite fields to Program
ALTER TABLE "Program" ADD COLUMN "micrositeEnabled" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Program" ADD COLUMN "micrositeActiveVersion" TEXT;

-- CreateTable: MicrositeVersion
CREATE TABLE "MicrositeVersion" (
    "id" TEXT NOT NULL,
    "programId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "s3Prefix" TEXT NOT NULL,
    "uploadedBy" TEXT NOT NULL,
    "fileCount" INTEGER NOT NULL,
    "totalBytes" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "MicrositeVersion_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "MicrositeVersion_programId_version_key" ON "MicrositeVersion"("programId", "version");
CREATE INDEX "MicrositeVersion_programId_idx" ON "MicrositeVersion"("programId");

-- AddForeignKey
ALTER TABLE "MicrositeVersion" ADD CONSTRAINT "MicrositeVersion_programId_fkey" FOREIGN KEY ("programId") REFERENCES "Program"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
