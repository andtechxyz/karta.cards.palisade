-- AlterTable
-- ActivationSession.challenge column + unique index were added ad-hoc to
-- this dev DB earlier; guard so migration is idempotent and still correct
-- on a fresh instance.
ALTER TABLE "ActivationSession" ADD COLUMN IF NOT EXISTS "challenge" TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS "ActivationSession_challenge_key" ON "ActivationSession"("challenge");

-- AlterTable
ALTER TABLE "Transaction" ADD COLUMN "allowedCredentialKinds" "CredentialKind"[];

-- CreateTable
CREATE TABLE "Program" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "currency" VARCHAR(3) NOT NULL,
    "tierRules" JSONB NOT NULL,
    "preActivationNdefUrlTemplate" TEXT,
    "postActivationNdefUrlTemplate" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Program_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Card" ADD CONSTRAINT "Card_programId_fkey" FOREIGN KEY ("programId") REFERENCES "Program"("id") ON DELETE SET NULL ON UPDATE CASCADE;
