-- CreateEnum
CREATE TYPE "CardStatus" AS ENUM ('BLANK', 'PERSONALISED', 'ACTIVATED', 'SUSPENDED', 'REVOKED');

-- CreateEnum
CREATE TYPE "VaultEventType" AS ENUM ('CREATE', 'DUPLICATE_REJECTED', 'TOKEN_MINTED', 'TOKEN_CONSUMED', 'PROXY_FORWARDED', 'PROVIDER_TOKENISED');

-- CreateEnum
CREATE TYPE "VaultEventResult" AS ENUM ('SUCCESS', 'FAILURE');

-- CreateEnum
CREATE TYPE "CredentialKind" AS ENUM ('PLATFORM', 'CROSS_PLATFORM');

-- CreateEnum
CREATE TYPE "TransactionStatus" AS ENUM ('PENDING', 'AUTHN_STARTED', 'AUTHN_COMPLETE', 'ARQC_VALID', 'VAULT_RETRIEVED', 'STRIPE_CHARGED', 'COMPLETED', 'FAILED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "Tier" AS ENUM ('TIER_1', 'TIER_2', 'TIER_3');

-- CreateTable
CREATE TABLE "Card" (
    "id" TEXT NOT NULL,
    "cardRef" TEXT NOT NULL,
    "status" "CardStatus" NOT NULL DEFAULT 'PERSONALISED',
    "uidEncrypted" TEXT NOT NULL,
    "uidFingerprint" TEXT NOT NULL,
    "chipSerial" TEXT,
    "sdmMetaReadKeyEncrypted" TEXT NOT NULL,
    "sdmFileReadKeyEncrypted" TEXT NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "lastReadCounter" INTEGER NOT NULL DEFAULT 0,
    "programId" TEXT,
    "batchId" TEXT,
    "vaultEntryId" TEXT,
    "atc" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Card_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ActivationSession" (
    "id" TEXT NOT NULL,
    "cardId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "consumedDeviceLabel" TEXT,
    "readCounter" INTEGER NOT NULL,
    "createdIp" TEXT,
    "createdUa" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ActivationSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VaultEncryptionKey" (
    "id" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "encryptedDekBlob" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retiredAt" TIMESTAMP(3),

    CONSTRAINT "VaultEncryptionKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VaultEntry" (
    "id" TEXT NOT NULL,
    "panLast4" TEXT NOT NULL,
    "panBin" TEXT NOT NULL,
    "cardholderName" TEXT NOT NULL,
    "panExpiryMonth" TEXT NOT NULL,
    "panExpiryYear" TEXT NOT NULL,
    "encryptedPan" TEXT NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    "panFingerprint" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VaultEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RetrievalToken" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "amount" INTEGER NOT NULL,
    "currency" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "purpose" TEXT NOT NULL,
    "createdByIp" TEXT,
    "vaultEntryId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "usedAt" TIMESTAMP(3),

    CONSTRAINT "RetrievalToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VaultAccessLog" (
    "id" TEXT NOT NULL,
    "eventType" "VaultEventType" NOT NULL,
    "result" "VaultEventResult" NOT NULL,
    "actor" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "errorMessage" TEXT,
    "vaultEntryId" TEXT,
    "retrievalTokenId" TEXT,
    "transactionId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VaultAccessLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WebAuthnCredential" (
    "id" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "kind" "CredentialKind" NOT NULL,
    "transports" TEXT[],
    "deviceName" TEXT,
    "cardId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "WebAuthnCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RegistrationChallenge" (
    "id" TEXT NOT NULL,
    "challenge" TEXT NOT NULL,
    "cardId" TEXT NOT NULL,
    "kind" "CredentialKind" NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RegistrationChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Transaction" (
    "id" TEXT NOT NULL,
    "rlid" TEXT NOT NULL,
    "cardId" TEXT NOT NULL,
    "amount" INTEGER NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "merchantRef" TEXT NOT NULL,
    "merchantName" TEXT NOT NULL DEFAULT 'Demo Merchant',
    "status" "TransactionStatus" NOT NULL DEFAULT 'PENDING',
    "tier" "Tier" NOT NULL,
    "actualTier" "Tier",
    "challengeNonce" TEXT NOT NULL,
    "usedCredentialId" TEXT,
    "providerName" TEXT,
    "providerPaymentMethodId" TEXT,
    "providerTxnId" TEXT,
    "arqc" TEXT,
    "atcUsed" INTEGER,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "failureReason" TEXT,

    CONSTRAINT "Transaction_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Card_cardRef_key" ON "Card"("cardRef");

-- CreateIndex
CREATE UNIQUE INDEX "Card_uidFingerprint_key" ON "Card"("uidFingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "Card_vaultEntryId_key" ON "Card"("vaultEntryId");

-- CreateIndex
CREATE INDEX "ActivationSession_cardId_idx" ON "ActivationSession"("cardId");

-- CreateIndex
CREATE INDEX "ActivationSession_expiresAt_idx" ON "ActivationSession"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "VaultEncryptionKey_version_key" ON "VaultEncryptionKey"("version");

-- CreateIndex
CREATE UNIQUE INDEX "VaultEntry_panFingerprint_key" ON "VaultEntry"("panFingerprint");

-- CreateIndex
CREATE INDEX "VaultEntry_panBin_idx" ON "VaultEntry"("panBin");

-- CreateIndex
CREATE INDEX "VaultEntry_panLast4_idx" ON "VaultEntry"("panLast4");

-- CreateIndex
CREATE UNIQUE INDEX "RetrievalToken_token_key" ON "RetrievalToken"("token");

-- CreateIndex
CREATE INDEX "RetrievalToken_vaultEntryId_idx" ON "RetrievalToken"("vaultEntryId");

-- CreateIndex
CREATE INDEX "RetrievalToken_expiresAt_idx" ON "RetrievalToken"("expiresAt");

-- CreateIndex
CREATE INDEX "VaultAccessLog_createdAt_idx" ON "VaultAccessLog"("createdAt");

-- CreateIndex
CREATE INDEX "VaultAccessLog_eventType_idx" ON "VaultAccessLog"("eventType");

-- CreateIndex
CREATE INDEX "VaultAccessLog_vaultEntryId_idx" ON "VaultAccessLog"("vaultEntryId");

-- CreateIndex
CREATE UNIQUE INDEX "WebAuthnCredential_credentialId_key" ON "WebAuthnCredential"("credentialId");

-- CreateIndex
CREATE INDEX "WebAuthnCredential_cardId_idx" ON "WebAuthnCredential"("cardId");

-- CreateIndex
CREATE UNIQUE INDEX "RegistrationChallenge_challenge_key" ON "RegistrationChallenge"("challenge");

-- CreateIndex
CREATE INDEX "RegistrationChallenge_expiresAt_idx" ON "RegistrationChallenge"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "Transaction_rlid_key" ON "Transaction"("rlid");

-- CreateIndex
CREATE UNIQUE INDEX "Transaction_challengeNonce_key" ON "Transaction"("challengeNonce");

-- CreateIndex
CREATE INDEX "Transaction_rlid_idx" ON "Transaction"("rlid");

-- CreateIndex
CREATE INDEX "Transaction_status_idx" ON "Transaction"("status");

-- CreateIndex
CREATE INDEX "Transaction_cardId_idx" ON "Transaction"("cardId");

-- AddForeignKey
ALTER TABLE "Card" ADD CONSTRAINT "Card_vaultEntryId_fkey" FOREIGN KEY ("vaultEntryId") REFERENCES "VaultEntry"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActivationSession" ADD CONSTRAINT "ActivationSession_cardId_fkey" FOREIGN KEY ("cardId") REFERENCES "Card"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RetrievalToken" ADD CONSTRAINT "RetrievalToken_vaultEntryId_fkey" FOREIGN KEY ("vaultEntryId") REFERENCES "VaultEntry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VaultAccessLog" ADD CONSTRAINT "VaultAccessLog_vaultEntryId_fkey" FOREIGN KEY ("vaultEntryId") REFERENCES "VaultEntry"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VaultAccessLog" ADD CONSTRAINT "VaultAccessLog_retrievalTokenId_fkey" FOREIGN KEY ("retrievalTokenId") REFERENCES "RetrievalToken"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VaultAccessLog" ADD CONSTRAINT "VaultAccessLog_transactionId_fkey" FOREIGN KEY ("transactionId") REFERENCES "Transaction"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WebAuthnCredential" ADD CONSTRAINT "WebAuthnCredential_cardId_fkey" FOREIGN KEY ("cardId") REFERENCES "Card"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Transaction" ADD CONSTRAINT "Transaction_cardId_fkey" FOREIGN KEY ("cardId") REFERENCES "Card"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

