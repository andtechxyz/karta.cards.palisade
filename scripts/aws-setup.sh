#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Palisade AWS infrastructure setup (post-split, Phase 1-5 complete)
#
# Repo scope: card lifecycle + chip provisioning.  Palisade owns tap, the
# activation surface, the admin service (card / program / issuer / chip-
# profile / embossing), data-prep, rca, batch-processor, sftp, and the new
# card-ops (admin-operated GlobalPlatform APDU relay).  Vault + pay +
# transactions live on the Vera repo and are provisioned by Vera's
# aws-setup.sh against the same AWS account.
#
# Services managed here:
#   - palisade-tap              (3001)  public  — SUN / post-activation tap
#   - palisade-activation       (3002)  public  — NFC activation + mobile
#                                                 API, inbound from pay for
#                                                 cross-repo card lookup
#   - palisade-data-prep        (3006)  internal (HMAC) — SAD generation
#   - palisade-rca              (3007)  public  — mobile provisioning WS
#   - palisade-batch-processor  (3008)  worker  — polls DB + S3
#   - palisade-admin            (3009)  public  — admin SPA backend
#   - palisade-card-ops         (3010)  public  — admin-operated GP relay
#                                                 (WebSocket + HMAC-gated
#                                                 /register)
#   - palisade-sftp             (22)    public (NLB) — partner file drop
#
# Cross-repo wiring (managed here):
#   - activation hosts PAY_AUTH_KEYS keyed 'pay' — secret MUST match Vera
#     pay's SERVICE_AUTH_PALISADE_SECRET.  Palisade owns the inbound map;
#     Vera owns the outbound secret.
#   - admin/activation call Vera's vault for PAN ops under SERVICE_AUTH_
#     KEYS keyed 'palisade' (see palisade/PALISADE_VERA_VAULT_SECRET).
#
# Shared AWS substrate:
#   - AWS account: 600743178530 (same as Vera).
#   - VPC, ECS cluster ('vera'), execution role, and public/internal ALBs
#     are created by Vera's aws-setup.sh.  This script appends to them.
#   - Every resource here is prefixed `palisade-*` to coexist with the
#     `vera-*` side.
#   - RDS: Palisade uses a SEPARATE Postgres instance from Vera's — the
#     split doubled up on schemas that couldn't be merged safely.  Local
#     docker-compose exposes host port 5433 to avoid colliding with
#     Vera's host 5432.  The managed RDS instance is provisioned in §9.
#
# ALB rule strategy on manage.karta.cards:
#   - Vera's script sets a priority-4 host-header rule → vera-admin
#   - This script adds a HIGHER-priority (2) rule: host=manage.karta.cards
#     + path=/palisade-api/* → palisade-admin.  /api/* still falls through
#     to vera-admin, keeping the SPA's dual-backend proxy intact.
#   - card-ops (port 3010) gets a separate host-header rule for
#     card-ops.karta.cards; the mobile / web admin connects the relay
#     WebSocket directly to that hostname so WS upgrades don't collide
#     with the admin path-prefix rule above.
#
# Prerequisites:
#   - AWS CLI v2 configured with credentials that can manage ECS, ELB,
#     Secrets Manager, CloudWatch Logs, ECR, IAM, KMS, S3, RDS, and
#     Cognito in ap-southeast-2.
#   - Vera's scripts/aws-setup.sh has already run at least once (creates
#     the public ALB, internal ALB, ECS cluster, and shared execution
#     role that this script references).
#   - jq installed.
# ---------------------------------------------------------------------------
set -euo pipefail

# ===========================================================================
# Constants
# ===========================================================================
REGION="ap-southeast-2"
ACCOUNT="600743178530"
VPC="vpc-09484084ef246d4a0"
CLUSTER="vera"
EXEC_ROLE="arn:aws:iam::${ACCOUNT}:role/vera-ecs-execution"
PUBLIC_ALB_ARN="arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:loadbalancer/app/vera-public/f71842c99b11992c"
INTERNAL_ALB_ARN="arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:loadbalancer/app/vera-internal/f607108ee78ebe20"
PRIVATE_SUBNETS="subnet-0d475c49f65f05e86,subnet-0397a18095049f972"
ECS_SG="sg-086e7b16e5351f155"
ECR_BASE="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
INTERNAL_ALB_DNS="internal-vera-internal-886106335.${REGION}.elb.amazonaws.com"

# Palisade-owned task roles — per-service so each gets the minimum grant.
DATA_PREP_TASK_ROLE="arn:aws:iam::${ACCOUNT}:role/palisade-data-prep-task"
CARD_OPS_TASK_ROLE="arn:aws:iam::${ACCOUNT}:role/palisade-card-ops-task"
ADMIN_TASK_ROLE="arn:aws:iam::${ACCOUNT}:role/palisade-admin-task"
BATCH_PROCESSOR_TASK_ROLE="arn:aws:iam::${ACCOUNT}:role/palisade-batch-processor-task"
SFTP_TASK_ROLE="arn:aws:iam::${ACCOUNT}:role/palisade-sftp-task"

# Vera admin's target group — we route everything on manage.karta.cards
# except /palisade-api/* to it.  The ARN is looked up at runtime rather
# than hard-coded so this script can't drift from Vera's.
VERA_ADMIN_TG_NAME="vera-admin"

# RDS — separate instance from Vera's.  Host port 5433 is docker-compose
# only; the managed instance uses 5432 internally.
RDS_INSTANCE_ID="palisade-prod"
RDS_SUBNET_GROUP="palisade-rds-subnets"
RDS_SG_NAME="palisade-rds"
RDS_DB_NAME="palisade"

# S3 bucket names.
CHIP_PROFILES_BUCKET="palisade-chip-profiles-${ACCOUNT}"
EMBOSSING_BUCKET_NAME="palisade-embossing-${ACCOUNT}"
MICROSITE_BUCKET_NAME="karta-microsites-${ACCOUNT}"

# KMS alias names (aliases are human-readable pointers at rotating key IDs).
KMS_SAD_ALIAS="alias/palisade-sad"

# Cognito — single user pool for mobile + admin.
COGNITO_POOL_NAME="palisade-users"

# Tracking arrays for the final summary
CREATED_SECRETS=()
MIGRATED_SECRETS=()
PLACEHOLDER_SECRETS=()
CREATED_LOG_GROUPS=()
REGISTERED_TASK_DEFS=()
CREATED_TGS=()
CREATED_RULES=()
CREATED_SERVICES=()
SKIPPED_SERVICES=()
CREATED_BUCKETS=()
CREATED_KMS_KEYS=()
CREATED_RDS=()
CREATED_COGNITO=()
CREATED_ROLES=()

# ===========================================================================
# Helper functions
# ===========================================================================
secret_arn() {
  local name="$1"
  aws secretsmanager describe-secret \
    --secret-id "$name" \
    --region "$REGION" \
    --query 'ARN' --output text 2>/dev/null || true
}

secret_value() {
  local name="$1"
  aws secretsmanager get-secret-value \
    --secret-id "$name" \
    --region "$REGION" \
    --query 'SecretString' --output text 2>/dev/null || true
}

ensure_secret() {
  local name="$1"
  local value="$2"
  local arn
  arn=$(secret_arn "$name")
  if [ -n "$arn" ] && [ "$arn" != "None" ]; then
    echo "  [exists] $name"
  else
    aws secretsmanager create-secret \
      --name "$name" \
      --secret-string "$value" \
      --region "$REGION" \
      --output text --query 'ARN' > /dev/null
    CREATED_SECRETS+=("$name")
    if [ "$value" = "CHANGEME" ]; then
      PLACEHOLDER_SECRETS+=("$name")
    fi
    echo "  [created] $name"
  fi
}

migrate_secret() {
  # Copy value from an old Vera-namespaced secret to a new Palisade one
  # (only if the Palisade secret doesn't exist yet).  Used to carry the
  # same random values across the namespace rename without operator
  # action.  Falls back to a placeholder if the source is missing too.
  local old_name="$1"
  local new_name="$2"
  local new_arn
  new_arn=$(secret_arn "$new_name")
  if [ -n "$new_arn" ] && [ "$new_arn" != "None" ]; then
    echo "  [exists] $new_name (skipping migration)"
    return
  fi

  local old_val
  old_val=$(secret_value "$old_name")
  if [ -n "$old_val" ] && [ "$old_val" != "None" ]; then
    aws secretsmanager create-secret \
      --name "$new_name" \
      --secret-string "$old_val" \
      --region "$REGION" \
      --output text --query 'ARN' > /dev/null
    MIGRATED_SECRETS+=("$old_name -> $new_name")
    echo "  [migrated] $old_name -> $new_name"
  else
    ensure_secret "$new_name" "CHANGEME"
    echo "  [warning] Old secret $old_name not found; created $new_name with placeholder"
  fi
}

ensure_log_group() {
  local name="$1"
  if aws logs describe-log-groups \
       --log-group-name-prefix "$name" \
       --region "$REGION" \
       --query "logGroups[?logGroupName=='$name'].logGroupName" \
       --output text 2>/dev/null | grep -q "$name"; then
    echo "  [exists] Log group $name"
  else
    aws logs create-log-group --log-group-name "$name" --region "$REGION"
    aws logs put-retention-policy --log-group-name "$name" --retention-in-days 30 --region "$REGION"
    CREATED_LOG_GROUPS+=("$name")
    echo "  [created] Log group $name (30-day retention)"
  fi
}

get_secret_arn() {
  local name="$1"
  local arn
  arn=$(aws secretsmanager describe-secret \
    --secret-id "$name" \
    --region "$REGION" \
    --query 'ARN' --output text 2>/dev/null)
  if [ -z "$arn" ] || [ "$arn" = "None" ]; then
    echo "FATAL: secret $name not found" >&2
    exit 1
  fi
  echo "$arn"
}

ensure_ecr_repo() {
  local name="$1"
  if aws ecr describe-repositories \
       --repository-names "$name" \
       --region "$REGION" \
       --query 'repositories[0].repositoryName' --output text >/dev/null 2>&1; then
    echo "  [exists] ECR repository $name"
  else
    aws ecr create-repository \
      --repository-name "$name" \
      --region "$REGION" \
      --image-scanning-configuration scanOnPush=true \
      --query 'repository.repositoryName' --output text >/dev/null
    echo "  [created] ECR repository $name"
  fi
}

ensure_iam_role() {
  # ensure_iam_role <role-name> <assume-role-policy-json>
  local name="$1"
  local assume_doc="$2"
  if aws iam get-role --role-name "$name" --query 'Role.RoleName' --output text >/dev/null 2>&1; then
    echo "  [exists] IAM role $name"
  else
    aws iam create-role \
      --role-name "$name" \
      --assume-role-policy-document "$assume_doc" \
      --query 'Role.RoleName' --output text >/dev/null
    CREATED_ROLES+=("$name")
    echo "  [created] IAM role $name"
  fi
}

put_inline_policy() {
  # put_inline_policy <role-name> <policy-name> <policy-json>
  aws iam put-role-policy \
    --role-name "$1" \
    --policy-name "$2" \
    --policy-document "$3" >/dev/null
  echo "  [updated] Inline policy $2 on $1"
}

ASSUME_ECS_TASK='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ecs-tasks.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}'

# ===========================================================================
echo ""
echo "============================================================"
echo " 0. ECR REPOSITORIES"
echo "============================================================"
# ===========================================================================
#
# Every Palisade service gets its own ECR repo.  Created here so a fresh
# account bootstrap can succeed before the ECS task-def registrations
# reference the :latest images.  Image-scan-on-push is enabled to catch
# known CVEs before rollout.

for repo in \
    palisade-tap \
    palisade-activation \
    palisade-data-prep \
    palisade-rca \
    palisade-batch-processor \
    palisade-sftp \
    palisade-admin \
    palisade-card-ops; do
  ensure_ecr_repo "$repo"
done

# ===========================================================================
echo ""
echo "============================================================"
echo " 1. SECRETS MANAGER — migrate and create secrets"
echo "============================================================"
# ===========================================================================

echo ""
echo "--- Migrating Vera-namespaced secrets to palisade/* ---"
# Card-domain secrets moved with the services.  Keep the random material
# stable across the rename so existing EmbossingTemplate rows, HMAC
# verifications, and per-card key derivations continue to work.
migrate_secret "vera/CARD_FIELD_DEK_V1"            "palisade/CARD_FIELD_DEK_V1"
migrate_secret "vera/CARD_FIELD_DEK_ACTIVE_VERSION" "palisade/CARD_FIELD_DEK_ACTIVE_VERSION"
migrate_secret "vera/CARD_UID_FINGERPRINT_KEY"     "palisade/CARD_UID_FINGERPRINT_KEY"
migrate_secret "vera/TAP_HANDOFF_SECRET"           "palisade/TAP_HANDOFF_SECRET"
migrate_secret "vera/PROVISION_AUTH_KEYS"          "palisade/PROVISION_AUTH_KEYS"
migrate_secret "vera/SERVICE_AUTH_ACTIVATION_SECRET" "palisade/SERVICE_AUTH_ACTIVATION_SECRET"
migrate_secret "vera/KMS_SAD_KEY_ARN"              "palisade/KMS_SAD_KEY_ARN"
migrate_secret "vera/DATA_PREP_MOCK_EMV"           "palisade/DATA_PREP_MOCK_EMV"
migrate_secret "vera/CALLBACK_HMAC_SECRET"         "palisade/CALLBACK_HMAC_SECRET"
migrate_secret "vera/SERVICE_AUTH_PROVISIONING_SECRET" "palisade/SERVICE_AUTH_PROVISIONING_SECRET"
migrate_secret "vera/EMBOSSING_KEY_V1"             "palisade/EMBOSSING_KEY_V1"
migrate_secret "vera/EMBOSSING_KEY_ACTIVE_VERSION" "palisade/EMBOSSING_KEY_ACTIVE_VERSION"
migrate_secret "vera/EMBOSSING_BUCKET"             "palisade/EMBOSSING_BUCKET"
migrate_secret "vera/SERVICE_AUTH_BATCH_PROCESSOR_SECRET" "palisade/SERVICE_AUTH_BATCH_PROCESSOR_SECRET"
migrate_secret "vera/POLL_INTERVAL_MS"             "palisade/POLL_INTERVAL_MS"
migrate_secret "vera/SFTP_USERS"                   "palisade/SFTP_USERS"
migrate_secret "vera/SFTP_POLL_INTERVAL_MS"        "palisade/SFTP_POLL_INTERVAL_MS"
migrate_secret "vera/SFTP_STABILITY_MS"            "palisade/SFTP_STABILITY_MS"
# WebAuthn + mobile-app config shared across both sides (pay on Vera and
# activation on Palisade both issue assertions against the same RP).
migrate_secret "vera/WEBAUTHN_RP_ID"               "palisade/WEBAUTHN_RP_ID"
migrate_secret "vera/WEBAUTHN_ORIGINS"             "palisade/WEBAUTHN_ORIGINS"
migrate_secret "vera/WEBAUTHN_RP_NAME"             "palisade/WEBAUTHN_RP_NAME"

echo ""
echo "--- Ensuring all required secrets exist ---"

# -------- Shared --------
# The Palisade RDS instance's connection string.  Created/rotated in §9
# (post-RDS-provision); the placeholder here lets the script boot on a
# fresh account before the DB exists.
ensure_secret "palisade/DATABASE_URL"              "CHANGEME"
ensure_secret "palisade/CORS_ORIGINS"              "CHANGEME"

# -------- Cross-repo HMAC --------
# Palisade ↔ Vera — Palisade calls Vera's vault to register PANs and gets
# back an opaque vaultToken.  Shares Vera's SERVICE_AUTH_KEYS entry keyed
# "palisade".  This secret MUST match that entry.
ensure_secret "palisade/PALISADE_VERA_VAULT_SECRET" "CHANGEME"

# activation's inbound HMAC key map — Vera pay HMAC-signs GET /api/cards/
# lookup/:cardId with keyId='pay'.  Value shape: {"pay":"<32-byte hex>",...}.
# The 'pay' entry MUST match Vera's vera/SERVICE_AUTH_PALISADE_SECRET.
ensure_secret "palisade/PAY_AUTH_KEYS"             "CHANGEME"

# card-ops inbound HMAC key map — activation HMAC-signs POST /api/card-ops
# /register with keyId='activation'.  Shape: {"activation":"<32-byte hex>"}.
# The 'activation' entry MUST match palisade/SERVICE_AUTH_CARD_OPS_SECRET.
ensure_secret "palisade/CARD_OPS_AUTH_KEYS"        "CHANGEME"

# activation → card-ops outbound secret.  Mirrors the CARD_OPS_AUTH_KEYS
# entry keyed 'activation' — rotate together.
ensure_secret "palisade/SERVICE_AUTH_CARD_OPS_SECRET" "CHANGEME"

# HMAC-SHA256 key for the short-lived WebSocket upgrade token rca hands
# to mobile clients (PCI 8.3.6 / patent C3).  Must be 32 bytes = 64 hex
# chars — the zod schema enforces the shape, env.ts rejects anything
# shorter or non-hex.  Generate with `openssl rand -hex 32` and rotate
# by updating this secret + restarting palisade-rca.
ensure_secret "palisade/WS_TOKEN_SECRET"           "CHANGEME"

# HMAC-SHA256 key rca uses to sign provisioning-complete callbacks to
# activation.  activation verifies with the same key — rotate both
# atomically.  Format: 64 hex chars.
ensure_secret "palisade/CALLBACK_HMAC_SECRET"      "CHANGEME"

# -------- Attestation PKI (Option A: compact binary certs, no X.509) --------
# Root CA → Issuer CA → Card cert.  Keys live in KMS, not in app state:
#   alias/palisade-attestation-root     — Root CA (signs the issuer cert
#                                          blob; rotate quarterly).
#   alias/palisade-attestation-issuer   — Issuer CA (signs per-card card
#                                          cert blobs during perso; rotate
#                                          monthly; used via kms:Sign).
#
# The Root public key is pinned in rca's verifier (env-loaded; see
# services/rca/src/services/attestation-verifier.ts::assertAttestation
# ConfigForMode).  The Issuer cert blob is re-verified against the Root
# on every tap — no boot-time caching to avoid "what if env changed"
# bug classes.
#
# Rotation: when the Root CA key rotates, re-sign the Issuer cert blob
# with the new Root key and update KARTA_ATTESTATION_ISSUER_CERT +
# KARTA_ATTESTATION_ROOT_PUBKEY atomically (same ECS deploy).  When the
# Issuer CA key rotates, update just the Issuer cert blob — Root CA
# stays pinned.  Existing card certs issued under an old Issuer key
# keep verifying against the cert blob that was signed at their
# issuance time.
ensure_secret "palisade/KARTA_ATTESTATION_ROOT_PUBKEY" "CHANGEME"
ensure_secret "palisade/KARTA_ATTESTATION_ISSUER_CERT" "CHANGEME"

# -------- Activation service URLs --------
ensure_secret "palisade/ACTIVATION_SERVICE_URL"    "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3002"
# Alias under the rca-facing name.  Same URL, different secret name — kept
# as a distinct secret so the rca task def can be wired through Secrets
# Manager today (task def uses an inline env var, but this makes the
# transition to Secrets-sourced URLs a one-line change later).
ensure_secret "palisade/ACTIVATION_CALLBACK_URL"   "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3002"
ensure_secret "palisade/DATA_PREP_SERVICE_URL"     "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3006"
ensure_secret "palisade/RCA_SERVICE_URL"           "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3007"
ensure_secret "palisade/CARD_OPS_URL"              "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3010"
# Public WS base that the admin SPA connects its APDU-relay WebSocket to.
# Must resolve to the palisade-card-ops target group via the public ALB.
ensure_secret "palisade/CARD_OPS_PUBLIC_WS_BASE"   "wss://card-ops.karta.cards"
# Public WS base the mobile app connects to for provisioning (pa-v3
# applet APDU relay).  Must resolve to palisade-rca via mobile.karta.cards
# → CloudFront → public ALB.  Stored as a secret for parity with
# CARD_OPS_PUBLIC_WS_BASE even though the rca task def currently bakes
# it inline — makes future rotation a Secrets Manager change only.
ensure_secret "palisade/RCA_PUBLIC_WS_BASE"        "wss://mobile.karta.cards"

# Vera vault endpoint — activation uses this on card registration.
ensure_secret "palisade/VERA_VAULT_URL"            "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3004"

# -------- Admin --------
ensure_secret "palisade/SERVICE_AUTH_ADMIN_SECRET" "CHANGEME"
# Microsite CDN + S3 bucket — admin uploads zips, CloudFront serves them.
ensure_secret "palisade/MICROSITE_BUCKET"          "${MICROSITE_BUCKET_NAME}"
ensure_secret "palisade/MICROSITE_CDN_URL"         "https://microsite.karta.cards"
ensure_secret "palisade/EMBOSSING_KMS_KEY_ARN"     "CHANGEME"
# S3 bucket for uploaded chip-profile JSONs (signed CAP file manifests,
# AID catalogs, per-FI key metadata).  Admin writes, card-ops reads.
ensure_secret "palisade/CHIP_PROFILES_BUCKET"      "${CHIP_PROFILES_BUCKET}"

# -------- Mobile app --------
ensure_secret "palisade/MOBILE_APP_URL"            "https://app.karta.cards"

# -------- data-prep — AWS Payment Cryptography + KMS --------
# APC key ARNs referenced per-IssuerProfile in the DB; these env-level
# ARNs are the *fallback* / "root" IMKs used when an IssuerProfile row
# leaves the UDK / MK KDK fields null.  Rotate by publishing a new
# IssuerProfile pointing at a new ARN, never by mutating these in place.
ensure_secret "palisade/APC_UDK_IMK_ARN"           "CHANGEME"
ensure_secret "palisade/APC_MK_KDK_ARN"            "CHANGEME"
ensure_secret "palisade/APC_SDM_META_MASTER_KEY_ARN" "CHANGEME"
ensure_secret "palisade/APC_SDM_FILE_MASTER_KEY_ARN" "CHANGEME"
# KMS key for at-rest SAD blob encryption (palisade-sad alias).  Created
# in §10.  Secret value is set there once the alias is resolved.
ensure_secret "palisade/KMS_SAD_KEY_ARN"           "CHANGEME"
# UDK derivation backend: "hsm" (APC), "local" (HKDF dev), or "mock".
ensure_secret "palisade/DATA_PREP_UDK_BACKEND"     "hsm"
ensure_secret "palisade/DEV_UDK_ROOT_SEED"         ""
ensure_secret "palisade/SAD_TTL_DAYS"              "30"

# -------- SDM (tap) per-card key derivation --------
# Backend: "hsm" (AWS Payment Cryptography), "local" (HKDF+CMAC), "mock".
ensure_secret "palisade/SDM_KEY_BACKEND"           "local"
ensure_secret "palisade/SDM_META_MASTER_KEY_ARN"   "CHANGEME"
ensure_secret "palisade/SDM_FILE_MASTER_KEY_ARN"   "CHANGEME"
ensure_secret "palisade/DEV_SDM_ROOT_SEED"         "CHANGEME"

# -------- card-ops — GlobalPlatform SCP03 master keys --------
# The per-FI GP master keys are stored as Secrets Manager entries keyed
# by IssuerProfile.gp{Enc,Mac,Dek}KeyArn; card-ops' per-session fetcher
# reads the ARN from the DB row and resolves the live value at WS-connect
# time.  This env-level secret is the TEST-KEY fallback (GP 40..4F), used
# when CARD_OPS_USE_TEST_KEYS=1 or the IssuerProfile has null ARN fields.
# Shape: {"enc":"<32hex>","mac":"<32hex>","dek":"<32hex>"}.
ensure_secret "palisade/GP_MASTER_KEY" '{"enc":"404142434445464748494A4B4C4D4E4F","mac":"404142434445464748494A4B4C4D4E4F","dek":"404142434445464748494A4B4C4D4E4F"}'
# Toggle: set to '1' in dev so every card short-circuits to the test keys
# above without requiring a per-IssuerProfile row.  Empty / unset in
# staging + prod so missing ARN fields are a loud warning, not silent
# key reuse.
ensure_secret "palisade/CARD_OPS_USE_TEST_KEYS"    ""
ensure_secret "palisade/WS_TIMEOUT_SECONDS"        "60"

# -------- Cognito --------
# Created in §11.  Secret values set there once the pool + client exist.
ensure_secret "palisade/COGNITO_USER_POOL_ID"      "CHANGEME"
ensure_secret "palisade/COGNITO_CLIENT_ID"         "CHANGEME"

# ===========================================================================
echo ""
echo "============================================================"
echo " 2. CLOUDWATCH LOG GROUPS"
echo "============================================================"
# ===========================================================================

for svc in tap activation admin data-prep rca batch-processor sftp card-ops; do
  ensure_log_group "/ecs/palisade-${svc}"
done

# ===========================================================================
echo ""
echo "============================================================"
echo " 3. ECS TASK DEFINITIONS"
echo "============================================================"
# ===========================================================================

echo ""
echo "--- Resolving secret ARNs ---"
ARN_DATABASE_URL=$(get_secret_arn "palisade/DATABASE_URL")
ARN_CORS_ORIGINS=$(get_secret_arn "palisade/CORS_ORIGINS")
ARN_CARD_FIELD_DEK_V1=$(get_secret_arn "palisade/CARD_FIELD_DEK_V1")
ARN_CARD_FIELD_DEK_ACTIVE_VERSION=$(get_secret_arn "palisade/CARD_FIELD_DEK_ACTIVE_VERSION")
ARN_CARD_UID_FINGERPRINT_KEY=$(get_secret_arn "palisade/CARD_UID_FINGERPRINT_KEY")
ARN_TAP_HANDOFF_SECRET=$(get_secret_arn "palisade/TAP_HANDOFF_SECRET")
ARN_PROVISION_AUTH_KEYS=$(get_secret_arn "palisade/PROVISION_AUTH_KEYS")
ARN_PAY_AUTH_KEYS=$(get_secret_arn "palisade/PAY_AUTH_KEYS")
ARN_CARD_OPS_AUTH_KEYS=$(get_secret_arn "palisade/CARD_OPS_AUTH_KEYS")
ARN_SERVICE_AUTH_ACTIVATION_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_ACTIVATION_SECRET")
ARN_SERVICE_AUTH_ADMIN_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_ADMIN_SECRET")
ARN_SERVICE_AUTH_PROVISIONING_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_PROVISIONING_SECRET")
ARN_SERVICE_AUTH_CARD_OPS_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_CARD_OPS_SECRET")
ARN_CALLBACK_HMAC_SECRET=$(get_secret_arn "palisade/CALLBACK_HMAC_SECRET")
ARN_KMS_SAD_KEY_ARN=$(get_secret_arn "palisade/KMS_SAD_KEY_ARN")
ARN_DATA_PREP_MOCK_EMV=$(get_secret_arn "palisade/DATA_PREP_MOCK_EMV")
ARN_DATA_PREP_UDK_BACKEND=$(get_secret_arn "palisade/DATA_PREP_UDK_BACKEND")
ARN_DEV_UDK_ROOT_SEED=$(get_secret_arn "palisade/DEV_UDK_ROOT_SEED")
ARN_APC_UDK_IMK_ARN=$(get_secret_arn "palisade/APC_UDK_IMK_ARN")
ARN_APC_MK_KDK_ARN=$(get_secret_arn "palisade/APC_MK_KDK_ARN")
ARN_APC_SDM_META_MASTER_KEY_ARN=$(get_secret_arn "palisade/APC_SDM_META_MASTER_KEY_ARN")
ARN_APC_SDM_FILE_MASTER_KEY_ARN=$(get_secret_arn "palisade/APC_SDM_FILE_MASTER_KEY_ARN")
ARN_EMBOSSING_KEY_V1=$(get_secret_arn "palisade/EMBOSSING_KEY_V1")
ARN_EMBOSSING_KEY_ACTIVE_VERSION=$(get_secret_arn "palisade/EMBOSSING_KEY_ACTIVE_VERSION")
ARN_EMBOSSING_BUCKET=$(get_secret_arn "palisade/EMBOSSING_BUCKET")
ARN_EMBOSSING_KMS_KEY_ARN=$(get_secret_arn "palisade/EMBOSSING_KMS_KEY_ARN")
ARN_CHIP_PROFILES_BUCKET=$(get_secret_arn "palisade/CHIP_PROFILES_BUCKET")
ARN_SERVICE_AUTH_BATCH_PROCESSOR_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_BATCH_PROCESSOR_SECRET")
ARN_POLL_INTERVAL_MS=$(get_secret_arn "palisade/POLL_INTERVAL_MS")
ARN_ACTIVATION_SERVICE_URL=$(get_secret_arn "palisade/ACTIVATION_SERVICE_URL")
ARN_DATA_PREP_SERVICE_URL=$(get_secret_arn "palisade/DATA_PREP_SERVICE_URL")
ARN_RCA_SERVICE_URL=$(get_secret_arn "palisade/RCA_SERVICE_URL")
ARN_CARD_OPS_URL=$(get_secret_arn "palisade/CARD_OPS_URL")
ARN_CARD_OPS_PUBLIC_WS_BASE=$(get_secret_arn "palisade/CARD_OPS_PUBLIC_WS_BASE")
ARN_RCA_PUBLIC_WS_BASE=$(get_secret_arn "palisade/RCA_PUBLIC_WS_BASE")
ARN_ACTIVATION_CALLBACK_URL=$(get_secret_arn "palisade/ACTIVATION_CALLBACK_URL")
ARN_WS_TOKEN_SECRET=$(get_secret_arn "palisade/WS_TOKEN_SECRET")
ARN_KARTA_ATTESTATION_ROOT_PUBKEY=$(get_secret_arn "palisade/KARTA_ATTESTATION_ROOT_PUBKEY")
ARN_KARTA_ATTESTATION_ISSUER_CERT=$(get_secret_arn "palisade/KARTA_ATTESTATION_ISSUER_CERT")
ARN_SFTP_USERS=$(get_secret_arn "palisade/SFTP_USERS")
ARN_SFTP_POLL_INTERVAL_MS=$(get_secret_arn "palisade/SFTP_POLL_INTERVAL_MS")
ARN_SFTP_STABILITY_MS=$(get_secret_arn "palisade/SFTP_STABILITY_MS")
ARN_WEBAUTHN_RP_ID=$(get_secret_arn "palisade/WEBAUTHN_RP_ID")
ARN_WEBAUTHN_ORIGINS=$(get_secret_arn "palisade/WEBAUTHN_ORIGINS")
ARN_WEBAUTHN_RP_NAME=$(get_secret_arn "palisade/WEBAUTHN_RP_NAME")
ARN_PALISADE_VERA_VAULT_SECRET=$(get_secret_arn "palisade/PALISADE_VERA_VAULT_SECRET")
ARN_VERA_VAULT_URL=$(get_secret_arn "palisade/VERA_VAULT_URL")
ARN_MOBILE_APP_URL=$(get_secret_arn "palisade/MOBILE_APP_URL")
ARN_MICROSITE_BUCKET=$(get_secret_arn "palisade/MICROSITE_BUCKET")
ARN_MICROSITE_CDN_URL=$(get_secret_arn "palisade/MICROSITE_CDN_URL")
ARN_SAD_TTL_DAYS=$(get_secret_arn "palisade/SAD_TTL_DAYS")
ARN_SDM_KEY_BACKEND=$(get_secret_arn "palisade/SDM_KEY_BACKEND")
ARN_SDM_META_MASTER_KEY_ARN=$(get_secret_arn "palisade/SDM_META_MASTER_KEY_ARN")
ARN_SDM_FILE_MASTER_KEY_ARN=$(get_secret_arn "palisade/SDM_FILE_MASTER_KEY_ARN")
ARN_DEV_SDM_ROOT_SEED=$(get_secret_arn "palisade/DEV_SDM_ROOT_SEED")
ARN_GP_MASTER_KEY=$(get_secret_arn "palisade/GP_MASTER_KEY")
ARN_CARD_OPS_USE_TEST_KEYS=$(get_secret_arn "palisade/CARD_OPS_USE_TEST_KEYS")
ARN_WS_TIMEOUT_SECONDS=$(get_secret_arn "palisade/WS_TIMEOUT_SECONDS")
ARN_COGNITO_USER_POOL_ID=$(get_secret_arn "palisade/COGNITO_USER_POOL_ID")
ARN_COGNITO_CLIENT_ID=$(get_secret_arn "palisade/COGNITO_CLIENT_ID")
echo "  All secret ARNs resolved."

# ---- tap (port 3001) ----
echo ""
echo "--- Registering task definition: palisade-tap ---"
aws ecs register-task-definition \
  --region "$REGION" \
  --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-tap",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "${EXEC_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-tap",
      "image": "${ECR_BASE}/palisade-tap:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 3001, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "ACTIVATION_URL", "value": "https://activation.karta.cards" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",                "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "CARD_FIELD_DEK_V1",           "valueFrom": "${ARN_CARD_FIELD_DEK_V1}" },
        { "name": "CARD_FIELD_DEK_ACTIVE_VERSION","valueFrom": "${ARN_CARD_FIELD_DEK_ACTIVE_VERSION}" },
        { "name": "TAP_HANDOFF_SECRET",          "valueFrom": "${ARN_TAP_HANDOFF_SECRET}" },
        { "name": "SDM_KEY_BACKEND",             "valueFrom": "${ARN_SDM_KEY_BACKEND}" },
        { "name": "SDM_META_MASTER_KEY_ARN",     "valueFrom": "${ARN_SDM_META_MASTER_KEY_ARN}" },
        { "name": "SDM_FILE_MASTER_KEY_ARN",     "valueFrom": "${ARN_SDM_FILE_MASTER_KEY_ARN}" },
        { "name": "DEV_SDM_ROOT_SEED",           "valueFrom": "${ARN_DEV_SDM_ROOT_SEED}" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-tap",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-tap")

# ---- activation (port 3002) ----
echo ""
echo "--- Registering task definition: palisade-activation ---"
aws ecs register-task-definition \
  --region "$REGION" \
  --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-activation",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "${EXEC_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-activation",
      "image": "${ECR_BASE}/palisade-activation:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 3002, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "PAY_URL", "value": "https://pay.karta.cards" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",                   "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "CORS_ORIGINS",                   "valueFrom": "${ARN_CORS_ORIGINS}" },
        { "name": "CARD_FIELD_DEK_V1",              "valueFrom": "${ARN_CARD_FIELD_DEK_V1}" },
        { "name": "CARD_FIELD_DEK_ACTIVE_VERSION",  "valueFrom": "${ARN_CARD_FIELD_DEK_ACTIVE_VERSION}" },
        { "name": "CARD_UID_FINGERPRINT_KEY",       "valueFrom": "${ARN_CARD_UID_FINGERPRINT_KEY}" },
        { "name": "PROVISION_AUTH_KEYS",            "valueFrom": "${ARN_PROVISION_AUTH_KEYS}" },
        { "name": "PAY_AUTH_KEYS",                  "valueFrom": "${ARN_PAY_AUTH_KEYS}" },
        { "name": "TAP_HANDOFF_SECRET",             "valueFrom": "${ARN_TAP_HANDOFF_SECRET}" },
        { "name": "SERVICE_AUTH_ACTIVATION_SECRET", "valueFrom": "${ARN_SERVICE_AUTH_ACTIVATION_SECRET}" },
        { "name": "SERVICE_AUTH_CARD_OPS_SECRET",   "valueFrom": "${ARN_SERVICE_AUTH_CARD_OPS_SECRET}" },
        { "name": "CARD_OPS_URL",                   "valueFrom": "${ARN_CARD_OPS_URL}" },
        { "name": "CARD_OPS_PUBLIC_WS_BASE",        "valueFrom": "${ARN_CARD_OPS_PUBLIC_WS_BASE}" },
        { "name": "WEBAUTHN_RP_ID",                 "valueFrom": "${ARN_WEBAUTHN_RP_ID}" },
        { "name": "WEBAUTHN_ORIGINS",               "valueFrom": "${ARN_WEBAUTHN_ORIGINS}" },
        { "name": "WEBAUTHN_RP_NAME",               "valueFrom": "${ARN_WEBAUTHN_RP_NAME}" },
        { "name": "VERA_VAULT_URL",                 "valueFrom": "${ARN_VERA_VAULT_URL}" },
        { "name": "PALISADE_VERA_VAULT_SECRET",     "valueFrom": "${ARN_PALISADE_VERA_VAULT_SECRET}" },
        { "name": "MOBILE_APP_URL",                 "valueFrom": "${ARN_MOBILE_APP_URL}" },
        { "name": "PALISADE_RCA_URL",               "valueFrom": "${ARN_RCA_SERVICE_URL}" },
        { "name": "COGNITO_USER_POOL_ID",           "valueFrom": "${ARN_COGNITO_USER_POOL_ID}" },
        { "name": "COGNITO_CLIENT_ID",              "valueFrom": "${ARN_COGNITO_CLIENT_ID}" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-activation",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-activation")

# ---- admin (port 3009) ----
# taskRoleArn added in §8 for S3 write (chip-profiles, embossing,
# microsites) + KMS encrypt (embossing payloads).
echo ""
echo "--- Registering task definition: palisade-admin ---"
aws ecs register-task-definition \
  --region "$REGION" \
  --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-admin",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "${EXEC_ROLE}",
  "taskRoleArn": "${ADMIN_TASK_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-admin",
      "image": "${ECR_BASE}/palisade-admin:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 3009, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "WEBAUTHN_ORIGIN", "value": "https://manage.karta.cards" },
        { "name": "PORT",            "value": "3009" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",               "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "CORS_ORIGINS",               "valueFrom": "${ARN_CORS_ORIGINS}" },
        { "name": "SERVICE_AUTH_ADMIN_SECRET",  "valueFrom": "${ARN_SERVICE_AUTH_ADMIN_SECRET}" },
        { "name": "ACTIVATION_SERVICE_URL",     "valueFrom": "${ARN_ACTIVATION_SERVICE_URL}" },
        { "name": "EMBOSSING_BUCKET",           "valueFrom": "${ARN_EMBOSSING_BUCKET}" },
        { "name": "EMBOSSING_KMS_KEY_ARN",      "valueFrom": "${ARN_EMBOSSING_KMS_KEY_ARN}" },
        { "name": "EMBOSSING_KEY_V1",           "valueFrom": "${ARN_EMBOSSING_KEY_V1}" },
        { "name": "EMBOSSING_KEY_ACTIVE_VERSION","valueFrom": "${ARN_EMBOSSING_KEY_ACTIVE_VERSION}" },
        { "name": "MICROSITE_BUCKET",           "valueFrom": "${ARN_MICROSITE_BUCKET}" },
        { "name": "MICROSITE_CDN_URL",          "valueFrom": "${ARN_MICROSITE_CDN_URL}" },
        { "name": "CHIP_PROFILES_BUCKET",       "valueFrom": "${ARN_CHIP_PROFILES_BUCKET}" },
        { "name": "COGNITO_USER_POOL_ID",       "valueFrom": "${ARN_COGNITO_USER_POOL_ID}" },
        { "name": "COGNITO_CLIENT_ID",          "valueFrom": "${ARN_COGNITO_CLIENT_ID}" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-admin",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-admin")

# --- data-prep (port 3006, internal, HMAC-gated) ---
# taskRoleArn added in §8 for payment-cryptography:* on APC IMK ARNs and
# KMS encrypt/decrypt on the SAD key.
echo ""
echo "--- Registering task definition: palisade-data-prep ---"
aws ecs register-task-definition --region "$REGION" --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-data-prep",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXEC_ROLE}",
  "taskRoleArn": "${DATA_PREP_TASK_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-data-prep",
      "image": "${ECR_BASE}/palisade-data-prep:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 3006, "protocol": "tcp" }
      ],
      "environment": [],
      "secrets": [
        { "name": "DATABASE_URL",              "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "PROVISION_AUTH_KEYS",       "valueFrom": "${ARN_PROVISION_AUTH_KEYS}" },
        { "name": "KMS_SAD_KEY_ARN",           "valueFrom": "${ARN_KMS_SAD_KEY_ARN}" },
        { "name": "DATA_PREP_MOCK_EMV",        "valueFrom": "${ARN_DATA_PREP_MOCK_EMV}" },
        { "name": "DATA_PREP_UDK_BACKEND",     "valueFrom": "${ARN_DATA_PREP_UDK_BACKEND}" },
        { "name": "DEV_UDK_ROOT_SEED",         "valueFrom": "${ARN_DEV_UDK_ROOT_SEED}" },
        { "name": "APC_UDK_IMK_ARN",           "valueFrom": "${ARN_APC_UDK_IMK_ARN}" },
        { "name": "APC_MK_KDK_ARN",            "valueFrom": "${ARN_APC_MK_KDK_ARN}" },
        { "name": "APC_SDM_META_MASTER_KEY_ARN","valueFrom": "${ARN_APC_SDM_META_MASTER_KEY_ARN}" },
        { "name": "APC_SDM_FILE_MASTER_KEY_ARN","valueFrom": "${ARN_APC_SDM_FILE_MASTER_KEY_ARN}" },
        { "name": "SAD_TTL_DAYS",              "valueFrom": "${ARN_SAD_TTL_DAYS}" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-data-prep",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-data-prep")

# --- rca (port 3007, public, WebSocket + HMAC-gated) ---
#
# Non-obvious env wiring:
#
#   RCA_PUBLIC_WS_BASE — publicly-reachable WS origin handed to the mobile
#     app in /api/provision/start.  Must match the CloudFront → ALB route
#     on mobile.karta.cards; otherwise the phone gets the internal ALB DNS
#     and the WS upgrade fails.  services/rca/src/env.ts's
#     assertProdRequiredEnv gate blocks startup if this is missing in prod.
#
#   RCA_ENABLE_PARAM_BUNDLE — prototype flag.  '1' routes cards whose
#     Card.paramRecordId != null through the pa-v3 TRANSFER_PARAMS path.
#     Legacy cards (paramRecordId = null) keep using TRANSFER_SAD either
#     way.  Flip to '0' to disable the prototype fleet-wide without
#     redeploying the applet.
#
#   WS_TOKEN_SECRET — 32-byte hex HMAC key for the WS upgrade token
#     (PCI 8.3.6).  Required by env.ts's zod schema; missing it fails
#     startup with a clear error even without the prod gate.
echo ""
echo "--- Registering task definition: palisade-rca ---"
aws ecs register-task-definition --region "$REGION" --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-rca",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXEC_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-rca",
      "image": "${ECR_BASE}/palisade-rca:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 3007, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "DATA_PREP_SERVICE_URL",   "value": "http://${INTERNAL_ALB_DNS}:3006" },
        { "name": "ACTIVATION_CALLBACK_URL", "value": "http://${INTERNAL_ALB_DNS}:3002" },
        { "name": "RCA_PUBLIC_WS_BASE",      "value": "wss://mobile.karta.cards" },
        { "name": "RCA_ENABLE_PARAM_BUNDLE", "value": "1" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",                   "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "PROVISION_AUTH_KEYS",            "valueFrom": "${ARN_PROVISION_AUTH_KEYS}" },
        { "name": "CALLBACK_HMAC_SECRET",           "valueFrom": "${ARN_CALLBACK_HMAC_SECRET}" },
        { "name": "KMS_SAD_KEY_ARN",                "valueFrom": "${ARN_KMS_SAD_KEY_ARN}" },
        { "name": "WS_TOKEN_SECRET",                "valueFrom": "${ARN_WS_TOKEN_SECRET}" },
        { "name": "KARTA_ATTESTATION_ROOT_PUBKEY",  "valueFrom": "${ARN_KARTA_ATTESTATION_ROOT_PUBKEY}" },
        { "name": "KARTA_ATTESTATION_ISSUER_CERT",  "valueFrom": "${ARN_KARTA_ATTESTATION_ISSUER_CERT}" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-rca",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-rca")

# --- batch-processor (port 3008, pure worker — polls DB + S3) ---
# No ALB routing — only exposes /api/health for ECS container healthCheck.
# taskRoleArn added in §8 for S3 read (embossing payloads) + KMS decrypt.
echo ""
echo "--- Registering task definition: palisade-batch-processor ---"
aws ecs register-task-definition \
  --region "$REGION" \
  --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-batch-processor",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "${EXEC_ROLE}",
  "taskRoleArn": "${BATCH_PROCESSOR_TASK_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-batch-processor",
      "image": "${ECR_BASE}/palisade-batch-processor:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 3008, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "AWS_REGION", "value": "${REGION}" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",                         "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "EMBOSSING_KEY_V1",                     "valueFrom": "${ARN_EMBOSSING_KEY_V1}" },
        { "name": "EMBOSSING_KEY_ACTIVE_VERSION",         "valueFrom": "${ARN_EMBOSSING_KEY_ACTIVE_VERSION}" },
        { "name": "EMBOSSING_BUCKET",                     "valueFrom": "${ARN_EMBOSSING_BUCKET}" },
        { "name": "EMBOSSING_KMS_KEY_ARN",                "valueFrom": "${ARN_EMBOSSING_KMS_KEY_ARN}" },
        { "name": "SERVICE_AUTH_BATCH_PROCESSOR_SECRET",  "valueFrom": "${ARN_SERVICE_AUTH_BATCH_PROCESSOR_SECRET}" },
        { "name": "ACTIVATION_SERVICE_URL",               "valueFrom": "${ARN_ACTIVATION_SERVICE_URL}" },
        { "name": "POLL_INTERVAL_MS",                     "valueFrom": "${ARN_POLL_INTERVAL_MS}" }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q -O- http://localhost:3008/api/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-batch-processor",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-batch-processor")

# --- card-ops (port 3010, public ALB + WebSocket + HMAC-gated) ---------------
# Port default in code is 3009 — colliding with admin.  We override via env
# to run both services on the same ECS cluster.  taskRoleArn added in §8
# grants SecretsManager:GetSecretValue on the per-IssuerProfile GP master
# keys that card-ops' static-keys fetcher resolves at WS-connect time
# (see services/card-ops/src/gp/static-keys.ts).  The KMS_SAD_KEY_ARN is
# also needed so personalise_payment_applet can decrypt SadRecord blobs
# in the same encryption envelope as data-prep / rca.
echo ""
echo "--- Registering task definition: palisade-card-ops ---"
aws ecs register-task-definition \
  --region "$REGION" \
  --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-card-ops",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXEC_ROLE}",
  "taskRoleArn": "${CARD_OPS_TASK_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-card-ops",
      "image": "${ECR_BASE}/palisade-card-ops:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 3010, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "PORT",       "value": "3010" },
        { "name": "AWS_REGION", "value": "${REGION}" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",              "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "CARD_OPS_AUTH_KEYS",        "valueFrom": "${ARN_CARD_OPS_AUTH_KEYS}" },
        { "name": "CARD_OPS_PUBLIC_WS_BASE",   "valueFrom": "${ARN_CARD_OPS_PUBLIC_WS_BASE}" },
        { "name": "WS_TIMEOUT_SECONDS",        "valueFrom": "${ARN_WS_TIMEOUT_SECONDS}" },
        { "name": "GP_MASTER_KEY",             "valueFrom": "${ARN_GP_MASTER_KEY}" },
        { "name": "CARD_OPS_USE_TEST_KEYS",    "valueFrom": "${ARN_CARD_OPS_USE_TEST_KEYS}" },
        { "name": "KMS_SAD_KEY_ARN",           "valueFrom": "${ARN_KMS_SAD_KEY_ARN}" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-card-ops",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-card-ops")

# --- sftp (port 22, public via NLB) -----------------------------------------
# taskRoleArn added in §8 for S3 read/write on the embossing bucket.
echo ""
echo "--- Registering task definition: palisade-sftp ---"
aws ecs register-task-definition \
  --region "$REGION" \
  --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-sftp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "${EXEC_ROLE}",
  "taskRoleArn": "${SFTP_TASK_ROLE}",
  "containerDefinitions": [
    {
      "name": "palisade-sftp",
      "image": "${ECR_BASE}/palisade-sftp:latest",
      "essential": true,
      "portMappings": [
        { "containerPort": 22, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "AWS_REGION", "value": "${REGION}" },
        { "name": "SFTP_HOME_BASE", "value": "/home" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",          "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "EMBOSSING_BUCKET",      "valueFrom": "${ARN_EMBOSSING_BUCKET}" },
        { "name": "SFTP_USERS",            "valueFrom": "${ARN_SFTP_USERS}" },
        { "name": "SFTP_POLL_INTERVAL_MS", "valueFrom": "${ARN_SFTP_POLL_INTERVAL_MS}" },
        { "name": "SFTP_STABILITY_MS",     "valueFrom": "${ARN_SFTP_STABILITY_MS}" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/palisade-sftp",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
TASKJSON
)" --query 'taskDefinition.taskDefinitionArn' --output text
REGISTERED_TASK_DEFS+=("palisade-sftp")

# ===========================================================================
echo ""
echo "============================================================"
echo " 4. TARGET GROUPS"
echo "============================================================"
# ===========================================================================

svc_port() {
  case "$1" in
    tap) echo 3001 ;; activation) echo 3002 ;; admin) echo 3009 ;;
    data-prep) echo 3006 ;; rca) echo 3007 ;;
    batch-processor) echo 3008 ;; card-ops) echo 3010 ;; sftp) echo 22 ;;
  esac
}

for svc in tap activation admin data-prep rca batch-processor card-ops sftp; do
  # batch-processor is a pure worker — container healthCheck gates
  # deployments, no TG needed.
  if [ "$svc" = "batch-processor" ]; then
    echo "  [skip] Target group for $svc (pure worker — uses container healthCheck)"
    continue
  fi
  # sftp uses a TCP target group on the NLB — handled separately below.
  if [ "$svc" = "sftp" ]; then
    continue
  fi
  TG_NAME="palisade-${svc}"
  PORT=$(svc_port "$svc")

  EXISTING_TG=$(aws elbv2 describe-target-groups \
    --names "$TG_NAME" \
    --region "$REGION" \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text 2>/dev/null || true)

  if [ -n "$EXISTING_TG" ] && [ "$EXISTING_TG" != "None" ]; then
    echo "  [exists] Target group $TG_NAME ($EXISTING_TG)"
  else
    EXISTING_TG=$(aws elbv2 create-target-group \
      --name "$TG_NAME" \
      --protocol HTTP \
      --port "$PORT" \
      --vpc-id "$VPC" \
      --target-type ip \
      --health-check-protocol HTTP \
      --health-check-path "/api/health" \
      --health-check-interval-seconds 30 \
      --healthy-threshold-count 2 \
      --unhealthy-threshold-count 3 \
      --region "$REGION" \
      --query 'TargetGroups[0].TargetGroupArn' \
      --output text)
    CREATED_TGS+=("$TG_NAME")
    echo "  [created] Target group $TG_NAME ($EXISTING_TG)"
  fi

  var_name="${svc//-/_}"
  eval "TG_ARN_${var_name}=\$EXISTING_TG"
done

# ---- SFTP — TCP target group for NLB (TCP health check on port 22) ----
echo ""
echo "--- SFTP target group (TCP / NLB) ---"

SFTP_TG_ARN=$(aws elbv2 describe-target-groups \
  --names "palisade-sftp" \
  --region "$REGION" \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text 2>/dev/null || true)

if [ -n "$SFTP_TG_ARN" ] && [ "$SFTP_TG_ARN" != "None" ]; then
  echo "  [exists] Target group palisade-sftp ($SFTP_TG_ARN)"
else
  SFTP_TG_ARN=$(aws elbv2 create-target-group \
    --name "palisade-sftp" \
    --protocol TCP \
    --port 22 \
    --vpc-id "$VPC" \
    --target-type ip \
    --health-check-protocol TCP \
    --health-check-interval-seconds 30 \
    --healthy-threshold-count 3 \
    --unhealthy-threshold-count 3 \
    --region "$REGION" \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text)
  CREATED_TGS+=("palisade-sftp")
  echo "  [created] Target group palisade-sftp ($SFTP_TG_ARN)"
fi

# ===========================================================================
echo ""
echo "============================================================"
echo " 5. ALB LISTENER RULES"
echo "============================================================"
# ===========================================================================

# ---- Public ALB listener (HTTP:80) ----
echo ""
echo "--- Public ALB (HTTP:80) ---"

PUBLIC_LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn "$PUBLIC_ALB_ARN" \
  --region "$REGION" \
  --query "Listeners[?Port==\`80\`].ListenerArn | [0]" \
  --output text)

if [ -z "$PUBLIC_LISTENER_ARN" ] || [ "$PUBLIC_LISTENER_ARN" = "None" ]; then
  echo "  [error] No HTTP:80 listener on public ALB — run Vera's aws-setup.sh first." >&2
  exit 1
fi
echo "  Public listener: $PUBLIC_LISTENER_ARN"

EXISTING_RULES=$(aws elbv2 describe-rules \
  --listener-arn "$PUBLIC_LISTENER_ARN" \
  --region "$REGION" \
  --output json)

create_host_rule() {
  local listener_arn="$1"
  local host="$2"
  local tg_arn="$3"
  local priority="$4"
  local existing_rules_json="$5"

  local existing
  existing=$(echo "$existing_rules_json" | jq -r \
    --arg host "$host" \
    '.Rules[] | select(.Conditions[]? | select(.Field=="host-header") | .Values[]? == $host and (.Conditions | length == 1)) | .RuleArn' \
    2>/dev/null || true)

  if [ -n "$existing" ]; then
    echo "  [exists] Rule for host $host -> $tg_arn"
  else
    aws elbv2 create-rule \
      --listener-arn "$listener_arn" \
      --priority "$priority" \
      --conditions "Field=host-header,Values=$host" \
      --actions "Type=forward,TargetGroupArn=$tg_arn" \
      --region "$REGION" \
      --output text --query 'Rules[0].RuleArn' > /dev/null
    CREATED_RULES+=("$host -> $(echo "$tg_arn" | grep -o 'palisade-[a-z-]*')")
    echo "  [created] Rule priority=$priority: $host -> target group"
  fi
}

create_host_path_rule() {
  # host-header + path-pattern rule.  Used for the shared manage.karta.cards
  # admin, where Vera owns /api/* and Palisade owns /palisade-api/*.
  local listener_arn="$1"
  local host="$2"
  local path="$3"
  local tg_arn="$4"
  local priority="$5"
  local existing_rules_json="$6"

  local existing
  existing=$(echo "$existing_rules_json" | jq -r \
    --arg host "$host" --arg path "$path" \
    '.Rules[] | select(
       (.Conditions[]? | select(.Field=="host-header") | .Values[]?) == $host
       and (.Conditions[]? | select(.Field=="path-pattern") | .Values[]?) == $path
     ) | .RuleArn' \
    2>/dev/null || true)

  if [ -n "$existing" ]; then
    echo "  [exists] Rule for $host + $path -> $tg_arn"
  else
    aws elbv2 create-rule \
      --listener-arn "$listener_arn" \
      --priority "$priority" \
      --conditions "Field=host-header,Values=$host" "Field=path-pattern,Values=$path" \
      --actions "Type=forward,TargetGroupArn=$tg_arn" \
      --region "$REGION" \
      --output text --query 'Rules[0].RuleArn' > /dev/null
    CREATED_RULES+=("$host $path -> $(echo "$tg_arn" | grep -o 'palisade-[a-z-]*')")
    echo "  [created] Rule priority=$priority: $host $path -> target group"
  fi
}

# Palisade host-header rules.  Priorities chosen to leave room (6-10)
# below Vera's existing 1-4 and above any future catch-alls.  Public-facing
# ALB rules: tap, activation (incl. /ws for WebSocket upgrades), rca (WS),
# card-ops (WS).  Internal ALB rules: data-prep, card-ops internal-only
# /register (§5b), batch-processor (no ALB).
create_host_rule "$PUBLIC_LISTENER_ARN" "tap.karta.cards"        "$TG_ARN_tap"        6  "$EXISTING_RULES"
create_host_rule "$PUBLIC_LISTENER_ARN" "activation.karta.cards" "$TG_ARN_activation" 7  "$EXISTING_RULES"
create_host_rule "$PUBLIC_LISTENER_ARN" "rca.karta.cards"        "$TG_ARN_rca"        8  "$EXISTING_RULES"
create_host_rule "$PUBLIC_LISTENER_ARN" "card-ops.karta.cards"   "$TG_ARN_card_ops"   9  "$EXISTING_RULES"

# Shared manage.karta.cards — higher priority (=2, beats Vera's 4) so the
# path-based rule wins before the host-only rule to vera-admin.
create_host_path_rule "$PUBLIC_LISTENER_ARN" "manage.karta.cards" "/palisade-api/*" "$TG_ARN_admin" 2 "$EXISTING_RULES"

# ---- Internal ALB (HTTP:3006 for data-prep, HTTP:3007 for rca, HTTP:3010 for card-ops) ----
# rca exposes both a public WS (for the mobile provisioning agent) and an
# internal HTTP endpoint (for activation's inbound callbacks).  card-ops
# internal listener backs activation's HMAC-gated POST /register — the
# public listener is WebSocket-only.
echo ""
echo "--- Internal ALB — Palisade service listeners ---"

ensure_internal_listener() {
  # ensure_internal_listener <port> <tg-arn> <label>
  local port="$1" tg_arn="$2" label="$3"
  local listener_arn
  listener_arn=$(aws elbv2 describe-listeners \
    --load-balancer-arn "$INTERNAL_ALB_ARN" \
    --region "$REGION" \
    --query "Listeners[?Port==\`$port\`].ListenerArn | [0]" \
    --output text 2>/dev/null || true)

  if [ -z "$listener_arn" ] || [ "$listener_arn" = "None" ]; then
    aws elbv2 create-listener \
      --load-balancer-arn "$INTERNAL_ALB_ARN" \
      --protocol HTTP \
      --port "$port" \
      --default-actions "Type=forward,TargetGroupArn=$tg_arn" \
      --region "$REGION" \
      --query 'Listeners[0].ListenerArn' --output text >/dev/null
    echo "  [created] Internal HTTP:$port listener -> $label"
  else
    aws elbv2 modify-listener \
      --listener-arn "$listener_arn" \
      --default-actions "Type=forward,TargetGroupArn=$tg_arn" \
      --region "$REGION" \
      --output text >/dev/null
    echo "  [updated] Internal HTTP:$port listener -> $label"
  fi
}

ensure_internal_listener 3006 "$TG_ARN_data_prep"       "palisade-data-prep"
ensure_internal_listener 3007 "$TG_ARN_rca"             "palisade-rca"
ensure_internal_listener 3010 "$TG_ARN_card_ops"        "palisade-card-ops"

# ---- Public ALB HTTPS:443 listener (requires validated ACM cert) ----
echo ""
echo "--- Public ALB (HTTPS:443) ---"

ACM_CERT_ARN=$(aws acm list-certificates \
  --region "$REGION" \
  --query "CertificateSummaryList[?DomainName=='karta.cards' && Status=='ISSUED'].CertificateArn | [0]" \
  --output text 2>/dev/null || true)

if [ -n "$ACM_CERT_ARN" ] && [ "$ACM_CERT_ARN" != "None" ]; then
  PUBLIC_HTTPS_LISTENER_ARN=$(aws elbv2 describe-listeners \
    --load-balancer-arn "$PUBLIC_ALB_ARN" \
    --region "$REGION" \
    --query "Listeners[?Port==\`443\`].ListenerArn | [0]" \
    --output text 2>/dev/null || true)

  if [ -n "$PUBLIC_HTTPS_LISTENER_ARN" ] && [ "$PUBLIC_HTTPS_LISTENER_ARN" != "None" ]; then
    EXISTING_HTTPS_RULES=$(aws elbv2 describe-rules \
      --listener-arn "$PUBLIC_HTTPS_LISTENER_ARN" \
      --region "$REGION" \
      --output json)

    create_host_rule "$PUBLIC_HTTPS_LISTENER_ARN" "tap.karta.cards"        "$TG_ARN_tap"        6 "$EXISTING_HTTPS_RULES"
    create_host_rule "$PUBLIC_HTTPS_LISTENER_ARN" "activation.karta.cards" "$TG_ARN_activation" 7 "$EXISTING_HTTPS_RULES"
    create_host_rule "$PUBLIC_HTTPS_LISTENER_ARN" "rca.karta.cards"        "$TG_ARN_rca"        8 "$EXISTING_HTTPS_RULES"
    create_host_rule "$PUBLIC_HTTPS_LISTENER_ARN" "card-ops.karta.cards"   "$TG_ARN_card_ops"   9 "$EXISTING_HTTPS_RULES"
    create_host_path_rule "$PUBLIC_HTTPS_LISTENER_ARN" "manage.karta.cards" "/palisade-api/*" "$TG_ARN_admin" 2 "$EXISTING_HTTPS_RULES"
  else
    echo "  [skip] HTTPS:443 listener not found — run Vera's aws-setup.sh first."
  fi
else
  echo "  [skip] No validated ACM cert for karta.cards in $REGION"
fi

# ===========================================================================
echo ""
echo "============================================================"
echo " 5b. NLB — SFTP endpoint (public, TCP:22)"
echo "============================================================"
# ===========================================================================

PUBLIC_SUBNETS=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns "$PUBLIC_ALB_ARN" \
  --region "$REGION" \
  --query "LoadBalancers[0].AvailabilityZones[].SubnetId" \
  --output text | tr '[:space:]' ',' | sed 's/,$//')

SFTP_NLB_ARN=$(aws elbv2 describe-load-balancers \
  --names "palisade-sftp" \
  --region "$REGION" \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text 2>/dev/null || true)

if [ -n "$SFTP_NLB_ARN" ] && [ "$SFTP_NLB_ARN" != "None" ]; then
  echo "  [exists] NLB palisade-sftp ($SFTP_NLB_ARN)"
else
  # shellcheck disable=SC2086
  SFTP_NLB_ARN=$(aws elbv2 create-load-balancer \
    --name "palisade-sftp" \
    --type network \
    --scheme internet-facing \
    --ip-address-type ipv4 \
    --subnets ${PUBLIC_SUBNETS//,/ } \
    --region "$REGION" \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text)
  echo "  [created] NLB palisade-sftp ($SFTP_NLB_ARN)"
  echo "  NLB provisioning takes ~3 min before it's routable — first DNS"
  echo "  lookup will NXDOMAIN until AWS finishes setup."
fi

SFTP_LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn "$SFTP_NLB_ARN" \
  --region "$REGION" \
  --query "Listeners[?Port==\`22\`].ListenerArn | [0]" \
  --output text 2>/dev/null || true)

if [ -z "$SFTP_LISTENER_ARN" ] || [ "$SFTP_LISTENER_ARN" = "None" ]; then
  SFTP_LISTENER_ARN=$(aws elbv2 create-listener \
    --load-balancer-arn "$SFTP_NLB_ARN" \
    --protocol TCP \
    --port 22 \
    --default-actions "Type=forward,TargetGroupArn=${SFTP_TG_ARN}" \
    --region "$REGION" \
    --query 'Listeners[0].ListenerArn' \
    --output text)
  echo "  [created] NLB TCP:22 listener -> palisade-sftp TG"
else
  echo "  [exists] NLB TCP:22 listener ($SFTP_LISTENER_ARN)"
fi

SFTP_NLB_DNS=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns "$SFTP_NLB_ARN" \
  --region "$REGION" \
  --query 'LoadBalancers[0].DNSName' \
  --output text)
echo "  NLB DNS: $SFTP_NLB_DNS"
echo "  Add a CNAME: sftp.karta.cards -> $SFTP_NLB_DNS"

# ===========================================================================
echo ""
echo "============================================================"
echo " 6. ECS SERVICES"
echo "============================================================"
# ===========================================================================

for svc in tap activation admin data-prep rca batch-processor card-ops sftp; do
  SVC_NAME="palisade-${svc}"
  PORT=$(svc_port "$svc")
  var_name="${svc//-/_}"

  if [ "$svc" = "sftp" ]; then
    TG_ARN="$SFTP_TG_ARN"
  else
    eval "TG_ARN=\$TG_ARN_${var_name}"
  fi

  EXISTING_SVC=$(aws ecs describe-services \
    --cluster "$CLUSTER" \
    --services "$SVC_NAME" \
    --region "$REGION" \
    --query "services[?status=='ACTIVE'].serviceName | [0]" \
    --output text 2>/dev/null || true)

  if [ -n "$EXISTING_SVC" ] && [ "$EXISTING_SVC" != "None" ]; then
    echo "  [exists] ECS service $SVC_NAME — updating to latest task definition"
    aws ecs update-service \
      --cluster "$CLUSTER" \
      --service "$SVC_NAME" \
      --task-definition "$SVC_NAME" \
      --force-new-deployment \
      --region "$REGION" \
      --output text --query 'service.serviceName' > /dev/null
    SKIPPED_SERVICES+=("$SVC_NAME (updated)")
  else
    echo "  [creating] ECS service $SVC_NAME"
    if [ "$svc" = "batch-processor" ]; then
      aws ecs create-service \
        --cluster "$CLUSTER" \
        --service-name "$SVC_NAME" \
        --task-definition "$SVC_NAME" \
        --desired-count 1 \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNETS}],securityGroups=[${ECS_SG}],assignPublicIp=DISABLED}" \
        --region "$REGION" \
        --output text --query 'service.serviceName' > /dev/null
    else
      aws ecs create-service \
        --cluster "$CLUSTER" \
        --service-name "$SVC_NAME" \
        --task-definition "$SVC_NAME" \
        --desired-count 1 \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNETS}],securityGroups=[${ECS_SG}],assignPublicIp=DISABLED}" \
        --load-balancers "targetGroupArn=${TG_ARN},containerName=${SVC_NAME},containerPort=${PORT}" \
        --health-check-grace-period-seconds 120 \
        --region "$REGION" \
        --output text --query 'service.serviceName' > /dev/null
    fi
    CREATED_SERVICES+=("$SVC_NAME")
    echo "  [created] ECS service $SVC_NAME"
  fi
done

# ===========================================================================
echo ""
echo "============================================================"
echo " 7. ECS SECURITY GROUP — INBOUND RULES"
echo "============================================================"
# ===========================================================================

INTERNAL_ALB_SG=$(aws elbv2 describe-load-balancers \
  --names vera-internal --region "$REGION" \
  --query 'LoadBalancers[0].SecurityGroups[0]' --output text 2>/dev/null || true)

ensure_sg_ingress() {
  local port="$1" src_sg="$2" desc="$3"
  local exists
  exists=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$ECS_SG" \
    --query "SecurityGroups[0].IpPermissions[?FromPort==\`$port\` && contains(UserIdGroupPairs[].GroupId, \`$src_sg\`)].IpProtocol" \
    --output text 2>/dev/null)
  if [ -n "$exists" ]; then
    echo "  [exists] $ECS_SG inbound :$port from $src_sg"
  else
    aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$ECS_SG" \
      --ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,UserIdGroupPairs=[{GroupId=$src_sg,Description=$desc}]" \
      --query 'SecurityGroupRules[0].SecurityGroupRuleId' --output text >/dev/null
    echo "  [added] $ECS_SG :$port from $src_sg ($desc)"
  fi
}

if [ -n "$INTERNAL_ALB_SG" ] && [ "$INTERNAL_ALB_SG" != "None" ]; then
  ensure_sg_ingress 3006 "$INTERNAL_ALB_SG" "internal-alb-palisade-data-prep"
  ensure_sg_ingress 3007 "$INTERNAL_ALB_SG" "internal-alb-palisade-rca"
  ensure_sg_ingress 3010 "$INTERNAL_ALB_SG" "internal-alb-palisade-card-ops"
fi

# SFTP via NLB — preserves source IP, no SG hop.
EXISTING_SFTP=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$ECS_SG" \
  --query "SecurityGroups[0].IpPermissions[?FromPort==\`22\`].IpProtocol" --output text)
if [ -z "$EXISTING_SFTP" ]; then
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$ECS_SG" \
    --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0,Description="SFTP via NLB"}]' \
    --query 'SecurityGroupRules[0].SecurityGroupRuleId' --output text >/dev/null
  echo "  [added] $ECS_SG :22 from 0.0.0.0/0 (SFTP via NLB)"
else
  echo "  [exists] $ECS_SG inbound :22"
fi

# ===========================================================================
echo ""
echo "============================================================"
echo " 8. IAM — per-service task roles"
echo "============================================================"
# ===========================================================================
#
# Each Palisade service gets its own task role (kept separate from the
# shared execution role so we can grant runtime privileges without widening
# image-pull / secrets-injection scope).

# --- data-prep: AWS Payment Cryptography + KMS on the SAD key ---
ensure_iam_role "${DATA_PREP_TASK_ROLE##*/}" "$ASSUME_ECS_TASK"
put_inline_policy "${DATA_PREP_TASK_ROLE##*/}" "palisade-data-prep-apc-kms" "$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "payment-cryptography:*",
        "payment-cryptography-data:*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:${REGION}:${ACCOUNT}:key/*"
    }
  ]
}
POLICY
)"

# --- card-ops: SecretsManager read on GP master keys per IssuerProfile +
#     KMS decrypt on the SAD key (for personalise_payment_applet).
ensure_iam_role "${CARD_OPS_TASK_ROLE##*/}" "$ASSUME_ECS_TASK"
put_inline_policy "${CARD_OPS_TASK_ROLE##*/}" "palisade-card-ops-gp-keys-kms" "$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [ "secretsmanager:GetSecretValue" ],
      "Resource": [
        "arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:palisade/gp/*",
        "${ARN_GP_MASTER_KEY}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [ "kms:Decrypt", "kms:DescribeKey" ],
      "Resource": "arn:aws:kms:${REGION}:${ACCOUNT}:key/*"
    }
  ]
}
POLICY
)"

# --- admin: S3 write on chip-profiles + embossing + microsites, KMS
#     encrypt on embossing payloads.
ensure_iam_role "${ADMIN_TASK_ROLE##*/}" "$ASSUME_ECS_TASK"
put_inline_policy "${ADMIN_TASK_ROLE##*/}" "palisade-admin-s3-kms" "$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${CHIP_PROFILES_BUCKET}",
        "arn:aws:s3:::${CHIP_PROFILES_BUCKET}/*",
        "arn:aws:s3:::${EMBOSSING_BUCKET_NAME}",
        "arn:aws:s3:::${EMBOSSING_BUCKET_NAME}/*",
        "arn:aws:s3:::${MICROSITE_BUCKET_NAME}",
        "arn:aws:s3:::${MICROSITE_BUCKET_NAME}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [ "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey" ],
      "Resource": "arn:aws:kms:${REGION}:${ACCOUNT}:key/*"
    }
  ]
}
POLICY
)"

# --- batch-processor: S3 read + KMS decrypt on embossing payloads.
ensure_iam_role "${BATCH_PROCESSOR_TASK_ROLE##*/}" "$ASSUME_ECS_TASK"
put_inline_policy "${BATCH_PROCESSOR_TASK_ROLE##*/}" "palisade-batch-processor-s3-kms" "$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [ "s3:GetObject", "s3:ListBucket" ],
      "Resource": [
        "arn:aws:s3:::${EMBOSSING_BUCKET_NAME}",
        "arn:aws:s3:::${EMBOSSING_BUCKET_NAME}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [ "kms:Decrypt", "kms:DescribeKey" ],
      "Resource": "arn:aws:kms:${REGION}:${ACCOUNT}:key/*"
    }
  ]
}
POLICY
)"

# --- sftp: S3 read/write on embossing bucket (partners drop + we pick up).
ensure_iam_role "${SFTP_TASK_ROLE##*/}" "$ASSUME_ECS_TASK"
put_inline_policy "${SFTP_TASK_ROLE##*/}" "palisade-sftp-s3" "$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [ "s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket" ],
      "Resource": [
        "arn:aws:s3:::${EMBOSSING_BUCKET_NAME}",
        "arn:aws:s3:::${EMBOSSING_BUCKET_NAME}/*"
      ]
    }
  ]
}
POLICY
)"

# ===========================================================================
echo ""
echo "============================================================"
echo " 9. RDS — Palisade Postgres instance"
echo "============================================================"
# ===========================================================================
#
# Palisade runs a SEPARATE Postgres instance from Vera's — the two DBs
# can't share because the schemas collide (Palisade's Program vs Vera's
# legacy program rows, different IssuerProfile shapes, etc.).  Local
# docker-compose exposes host port 5433 to avoid clobbering Vera's 5432;
# the managed RDS instance below uses the standard 5432 inside its SG.
#
# The secret palisade/DATABASE_URL is left as CHANGEME so this script
# doesn't leak the RDS master password.  After provisioning, set the
# real URL via:
#   aws secretsmanager put-secret-value \
#     --secret-id palisade/DATABASE_URL \
#     --secret-string "postgres://palisade:<pwd>@<endpoint>:5432/palisade"

RDS_EXISTS=$(aws rds describe-db-instances \
  --db-instance-identifier "$RDS_INSTANCE_ID" \
  --region "$REGION" \
  --query 'DBInstances[0].DBInstanceIdentifier' \
  --output text 2>/dev/null || true)

if [ -n "$RDS_EXISTS" ] && [ "$RDS_EXISTS" != "None" ]; then
  echo "  [exists] RDS instance $RDS_INSTANCE_ID"
  RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier "$RDS_INSTANCE_ID" \
    --region "$REGION" \
    --query 'DBInstances[0].Endpoint.Address' \
    --output text)
  echo "  Endpoint: $RDS_ENDPOINT"
else
  # Subnet group — must cover at least two AZs.
  if ! aws rds describe-db-subnet-groups \
         --db-subnet-group-name "$RDS_SUBNET_GROUP" \
         --region "$REGION" >/dev/null 2>&1; then
    aws rds create-db-subnet-group \
      --db-subnet-group-name "$RDS_SUBNET_GROUP" \
      --db-subnet-group-description "Palisade Postgres subnets" \
      --subnet-ids ${PRIVATE_SUBNETS//,/ } \
      --region "$REGION" \
      --query 'DBSubnetGroup.DBSubnetGroupName' --output text >/dev/null
    echo "  [created] RDS subnet group $RDS_SUBNET_GROUP"
  fi

  # Security group — allows inbound 5432 from the ECS SG only.
  RDS_SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$RDS_SG_NAME" "Name=vpc-id,Values=$VPC" \
    --region "$REGION" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
  if [ -z "$RDS_SG_ID" ] || [ "$RDS_SG_ID" = "None" ]; then
    RDS_SG_ID=$(aws ec2 create-security-group \
      --group-name "$RDS_SG_NAME" \
      --description "Palisade RDS inbound 5432 from ECS tasks" \
      --vpc-id "$VPC" \
      --region "$REGION" \
      --query 'GroupId' --output text)
    aws ec2 authorize-security-group-ingress \
      --group-id "$RDS_SG_ID" \
      --protocol tcp --port 5432 \
      --source-group "$ECS_SG" \
      --region "$REGION" >/dev/null
    echo "  [created] RDS SG $RDS_SG_ID (5432 from $ECS_SG)"
  fi

  # CreateDBInstance — db.t4g.micro for cost; bump in prod via a follow-up
  # modify-db-instance.  Master password is auto-generated into Secrets
  # Manager (ManageMasterUserPassword=true) so we never handle it.
  aws rds create-db-instance \
    --db-instance-identifier "$RDS_INSTANCE_ID" \
    --db-instance-class db.t4g.micro \
    --engine postgres \
    --engine-version 16 \
    --allocated-storage 20 \
    --storage-type gp3 \
    --db-name "$RDS_DB_NAME" \
    --master-username palisade \
    --manage-master-user-password \
    --vpc-security-group-ids "$RDS_SG_ID" \
    --db-subnet-group-name "$RDS_SUBNET_GROUP" \
    --backup-retention-period 7 \
    --publicly-accessible false \
    --storage-encrypted \
    --region "$REGION" \
    --query 'DBInstance.DBInstanceIdentifier' --output text >/dev/null
  CREATED_RDS+=("$RDS_INSTANCE_ID")
  echo "  [created] RDS instance $RDS_INSTANCE_ID (takes ~10 min to become available)"
  echo "  After provisioning, set palisade/DATABASE_URL with the endpoint."
fi

# ===========================================================================
echo ""
echo "============================================================"
echo " 10. S3 + KMS — chip profiles, embossing, microsites, SAD key"
echo "============================================================"
# ===========================================================================

ensure_s3_bucket() {
  # ensure_s3_bucket <bucket-name> <description>
  local bucket="$1"
  local desc="$2"
  if aws s3api head-bucket --bucket "$bucket" --region "$REGION" 2>/dev/null; then
    echo "  [exists] S3 bucket $bucket ($desc)"
  else
    # ap-southeast-2 requires a LocationConstraint.
    aws s3api create-bucket \
      --bucket "$bucket" \
      --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=${REGION}" \
      --query 'Location' --output text >/dev/null
    # Turn on default encryption + block public access.
    aws s3api put-bucket-encryption \
      --bucket "$bucket" \
      --server-side-encryption-configuration \
        '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
      --region "$REGION"
    aws s3api put-public-access-block \
      --bucket "$bucket" \
      --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
      --region "$REGION"
    CREATED_BUCKETS+=("$bucket")
    echo "  [created] S3 bucket $bucket ($desc)"
  fi
}

ensure_s3_bucket "$CHIP_PROFILES_BUCKET"    "chip-profile JSON uploads (admin write, card-ops read)"
ensure_s3_bucket "$EMBOSSING_BUCKET_NAME"   "embossing batch payloads (admin write, batch-processor read)"
ensure_s3_bucket "$MICROSITE_BUCKET_NAME"   "per-program activation microsites (admin write, CloudFront read)"

# ---- KMS — SAD encryption key ----
# SAD blobs are encrypted envelope-style: KMS-wrapped data key, then AES
# inside the blob.  Rotation: AWS-managed annual schedule (enabled below).
# Retention: no key deletion path from this script; use the KMS console to
# schedule a deletion with the default 30-day pending window if needed.
echo ""
echo "--- KMS key: $KMS_SAD_ALIAS ---"
SAD_KEY_ARN=$(aws kms describe-key \
  --key-id "$KMS_SAD_ALIAS" \
  --region "$REGION" \
  --query 'KeyMetadata.Arn' --output text 2>/dev/null || true)

if [ -n "$SAD_KEY_ARN" ] && [ "$SAD_KEY_ARN" != "None" ]; then
  echo "  [exists] KMS key $KMS_SAD_ALIAS ($SAD_KEY_ARN)"
else
  SAD_KEY_ID=$(aws kms create-key \
    --description "Palisade SAD blob encryption (data-prep / rca / card-ops)" \
    --key-usage ENCRYPT_DECRYPT \
    --region "$REGION" \
    --query 'KeyMetadata.KeyId' --output text)
  aws kms enable-key-rotation --key-id "$SAD_KEY_ID" --region "$REGION" >/dev/null
  aws kms create-alias \
    --alias-name "$KMS_SAD_ALIAS" \
    --target-key-id "$SAD_KEY_ID" \
    --region "$REGION" >/dev/null
  SAD_KEY_ARN=$(aws kms describe-key \
    --key-id "$KMS_SAD_ALIAS" \
    --region "$REGION" \
    --query 'KeyMetadata.Arn' --output text)
  CREATED_KMS_KEYS+=("$KMS_SAD_ALIAS")
  echo "  [created] KMS key $KMS_SAD_ALIAS ($SAD_KEY_ARN), rotation enabled"
fi

# Update palisade/KMS_SAD_KEY_ARN to point at the real key ARN (only if the
# secret is still the placeholder so we don't clobber an operator override).
CURRENT_SAD_SECRET=$(secret_value "palisade/KMS_SAD_KEY_ARN")
if [ "$CURRENT_SAD_SECRET" = "CHANGEME" ]; then
  aws secretsmanager put-secret-value \
    --secret-id "palisade/KMS_SAD_KEY_ARN" \
    --secret-string "$SAD_KEY_ARN" \
    --region "$REGION" \
    --query 'ARN' --output text >/dev/null
  echo "  [updated] palisade/KMS_SAD_KEY_ARN -> $SAD_KEY_ARN"
fi

# ===========================================================================
echo ""
echo "============================================================"
echo " 11. COGNITO — user pool for mobile + admin"
echo "============================================================"
# ===========================================================================

COGNITO_POOL_ID=$(aws cognito-idp list-user-pools \
  --max-results 60 \
  --region "$REGION" \
  --query "UserPools[?Name=='$COGNITO_POOL_NAME'].Id | [0]" \
  --output text 2>/dev/null || true)

if [ -n "$COGNITO_POOL_ID" ] && [ "$COGNITO_POOL_ID" != "None" ]; then
  echo "  [exists] Cognito user pool $COGNITO_POOL_NAME ($COGNITO_POOL_ID)"
else
  COGNITO_POOL_ID=$(aws cognito-idp create-user-pool \
    --pool-name "$COGNITO_POOL_NAME" \
    --region "$REGION" \
    --policies '{"PasswordPolicy":{"MinimumLength":12,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":false}}' \
    --auto-verified-attributes email \
    --username-attributes email \
    --mfa-configuration OPTIONAL \
    --enabled-mfas SOFTWARE_TOKEN_MFA \
    --query 'UserPool.Id' --output text)
  CREATED_COGNITO+=("user-pool $COGNITO_POOL_NAME")
  echo "  [created] Cognito user pool $COGNITO_POOL_NAME ($COGNITO_POOL_ID)"
fi

COGNITO_CLIENT_ID=$(aws cognito-idp list-user-pool-clients \
  --user-pool-id "$COGNITO_POOL_ID" \
  --region "$REGION" \
  --query "UserPoolClients[?ClientName=='palisade-mobile'].ClientId | [0]" \
  --output text 2>/dev/null || true)

if [ -n "$COGNITO_CLIENT_ID" ] && [ "$COGNITO_CLIENT_ID" != "None" ]; then
  echo "  [exists] Cognito app client palisade-mobile ($COGNITO_CLIENT_ID)"
else
  COGNITO_CLIENT_ID=$(aws cognito-idp create-user-pool-client \
    --user-pool-id "$COGNITO_POOL_ID" \
    --client-name "palisade-mobile" \
    --no-generate-secret \
    --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH ALLOW_USER_SRP_AUTH \
    --region "$REGION" \
    --query 'UserPoolClient.ClientId' --output text)
  CREATED_COGNITO+=("app-client palisade-mobile")
  echo "  [created] Cognito app client palisade-mobile ($COGNITO_CLIENT_ID)"
fi

# Sync back into Secrets Manager — overwrite the CHANGEME placeholder.
CURRENT_POOL_SECRET=$(secret_value "palisade/COGNITO_USER_POOL_ID")
if [ "$CURRENT_POOL_SECRET" = "CHANGEME" ]; then
  aws secretsmanager put-secret-value \
    --secret-id "palisade/COGNITO_USER_POOL_ID" \
    --secret-string "$COGNITO_POOL_ID" \
    --region "$REGION" --query 'ARN' --output text >/dev/null
  echo "  [updated] palisade/COGNITO_USER_POOL_ID -> $COGNITO_POOL_ID"
fi
CURRENT_CLIENT_SECRET=$(secret_value "palisade/COGNITO_CLIENT_ID")
if [ "$CURRENT_CLIENT_SECRET" = "CHANGEME" ]; then
  aws secretsmanager put-secret-value \
    --secret-id "palisade/COGNITO_CLIENT_ID" \
    --secret-string "$COGNITO_CLIENT_ID" \
    --region "$REGION" --query 'ARN' --output text >/dev/null
  echo "  [updated] palisade/COGNITO_CLIENT_ID -> $COGNITO_CLIENT_ID"
fi

# ===========================================================================
echo ""
echo ""
echo "============================================================"
echo " SUMMARY"
echo "============================================================"
echo ""

if [ ${#MIGRATED_SECRETS[@]} -gt 0 ]; then
  echo "Migrated secrets (old -> new):"
  for s in "${MIGRATED_SECRETS[@]}"; do echo "  - $s"; done
  echo ""
fi

if [ ${#CREATED_SECRETS[@]} -gt 0 ]; then
  echo "Created secrets:"
  for s in "${CREATED_SECRETS[@]}"; do echo "  - $s"; done
  echo ""
fi

if [ ${#CREATED_LOG_GROUPS[@]} -gt 0 ]; then
  echo "Created log groups:"
  for g in "${CREATED_LOG_GROUPS[@]}"; do echo "  - $g"; done
  echo ""
fi

if [ ${#REGISTERED_TASK_DEFS[@]} -gt 0 ]; then
  echo "Registered task definitions:"
  for t in "${REGISTERED_TASK_DEFS[@]}"; do echo "  - $t"; done
  echo ""
fi

if [ ${#CREATED_TGS[@]} -gt 0 ]; then
  echo "Created target groups:"
  for t in "${CREATED_TGS[@]}"; do echo "  - $t"; done
  echo ""
fi

if [ ${#CREATED_RULES[@]} -gt 0 ]; then
  echo "Created ALB listener rules:"
  for r in "${CREATED_RULES[@]}"; do echo "  - $r"; done
  echo ""
fi

if [ ${#CREATED_SERVICES[@]} -gt 0 ]; then
  echo "Created ECS services:"
  for s in "${CREATED_SERVICES[@]}"; do echo "  - $s"; done
  echo ""
fi

if [ ${#SKIPPED_SERVICES[@]} -gt 0 ]; then
  echo "Updated existing ECS services:"
  for s in "${SKIPPED_SERVICES[@]}"; do echo "  - $s"; done
  echo ""
fi

if [ ${#CREATED_BUCKETS[@]} -gt 0 ]; then
  echo "Created S3 buckets:"
  for b in "${CREATED_BUCKETS[@]}"; do echo "  - $b"; done
  echo ""
fi

if [ ${#CREATED_KMS_KEYS[@]} -gt 0 ]; then
  echo "Created KMS keys:"
  for k in "${CREATED_KMS_KEYS[@]}"; do echo "  - $k"; done
  echo ""
fi

if [ ${#CREATED_RDS[@]} -gt 0 ]; then
  echo "Created RDS instances:"
  for r in "${CREATED_RDS[@]}"; do echo "  - $r"; done
  echo ""
fi

if [ ${#CREATED_ROLES[@]} -gt 0 ]; then
  echo "Created IAM roles:"
  for r in "${CREATED_ROLES[@]}"; do echo "  - $r"; done
  echo ""
fi

if [ ${#CREATED_COGNITO[@]} -gt 0 ]; then
  echo "Created Cognito resources:"
  for c in "${CREATED_COGNITO[@]}"; do echo "  - $c"; done
  echo ""
fi

if [ ${#PLACEHOLDER_SECRETS[@]} -gt 0 ]; then
  echo "============================================================"
  echo " ACTION REQUIRED: Update these placeholder secrets"
  echo "============================================================"
  echo ""
  for s in "${PLACEHOLDER_SECRETS[@]}"; do
    echo "  aws secretsmanager put-secret-value --secret-id $s --secret-string '<real value>' --region $REGION"
  done
  echo ""
fi

echo ""
echo "============================================================"
echo " OTHER MANUAL STEPS"
echo "============================================================"
echo ""
echo "1. Verify the ECS security group ($ECS_SG) allows:"
echo "   - Inbound from the public ALB SG on ports 3001, 3002, 3007, 3009, 3010"
echo "     (palisade-tap, -activation, -rca, -admin, -card-ops)"
echo "   - Inbound from the internal ALB SG on ports 3006, 3007, 3010"
echo "     (managed by §7 above — idempotent)"
echo "   - Inbound TCP:22 from 0.0.0.0/0 for SFTP (managed above)"
echo ""
echo "2. DNS records (all pointing at the shared public ALB):"
echo "   - tap.karta.cards"
echo "   - activation.karta.cards"
echo "   - rca.karta.cards"
echo "   - card-ops.karta.cards"
echo "   - manage.karta.cards         (shared with vera-admin)"
echo ""
echo "3. CNAME: sftp.karta.cards -> $SFTP_NLB_DNS"
echo ""
echo "4. Per-IssuerProfile GP master keys: populate"
echo "     palisade/gp/<issuer-profile-id>/enc"
echo "     palisade/gp/<issuer-profile-id>/mac"
echo "     palisade/gp/<issuer-profile-id>/dek"
echo "   and set IssuerProfile.gp{Enc,Mac,Dek}KeyArn to those ARNs in the"
echo "   admin UI.  The palisade-card-ops task role grants"
echo "   secretsmanager:GetSecretValue on all palisade/gp/* prefixes."
echo ""
echo "5. APC IMK ARNs: populate palisade/APC_UDK_IMK_ARN,"
echo "   palisade/APC_MK_KDK_ARN, palisade/APC_SDM_{META,FILE}_MASTER_KEY_ARN"
echo "   with real AWS Payment Cryptography key ARNs before enabling the"
echo "   hsm backend.  Per-IssuerProfile overrides go in the DB row."
echo ""
echo "6. Vera's aws-setup.sh is expected to create vera/SERVICE_AUTH_"
echo "   PALISADE_SECRET with the matching value for PAY_AUTH_KEYS['pay']"
echo "   above.  Rotate both together."
echo ""
echo "7. Vera's aws-setup.sh routes manage.karta.cards -> vera-admin at"
echo "   priority 4.  This script adds priority 2 with a /palisade-api/*"
echo "   path condition -> palisade-admin.  Don't lower either priority."
echo ""
echo "8. Seed palisade/SFTP_USERS with the real partner list (JSON)."
echo ""
echo "9. After RDS becomes available, set palisade/DATABASE_URL with the"
echo "   real endpoint + password (RDS manages the password in Secrets"
echo "   Manager — see the rds!db-$RDS_INSTANCE_ID secret)."
echo ""
echo "Done."
