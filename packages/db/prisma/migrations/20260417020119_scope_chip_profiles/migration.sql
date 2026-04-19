ALTER TABLE "ChipProfile" ADD COLUMN "programId" TEXT;
CREATE INDEX "ChipProfile_programId_idx" ON "ChipProfile"("programId");
ALTER TABLE "ChipProfile" ADD CONSTRAINT "ChipProfile_programId_fkey"
  FOREIGN KEY ("programId") REFERENCES "Program"("id") ON DELETE SET NULL ON UPDATE CASCADE;
