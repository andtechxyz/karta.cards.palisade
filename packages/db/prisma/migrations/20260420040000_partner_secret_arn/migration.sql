-- H-6 remediation: PartnerCredential.secretHash is no longer used as the
-- HMAC signing key.  The plaintext HMAC key now lives in Secrets
-- Manager; the ARN is stored here.  Existing rows have secretArn NULL
-- and must be rotated before their next sign attempt.
ALTER TABLE "PartnerCredential" ADD COLUMN "secretArn" TEXT;
