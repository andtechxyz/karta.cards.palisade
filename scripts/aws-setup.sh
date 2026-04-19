#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Palisade AWS infrastructure setup
#
# Scope: tap (3001), activation (3002), admin (3009), data-prep (3006),
# rca (3007), batch-processor (3008), sftp (22).  Shares the karta.cards
# AWS account (600743178530) and the `vera` ECS cluster with Vera's
# pay/vault/admin services.  Every Palisade resource is prefixed
# `palisade-*` so it coexists with Vera's `vera-*`.
#
# Idempotent: safe to re-run.  Creates or updates secrets, task
# definitions, target groups, ALB listener rules, and ECS services.
#
# ALB rule strategy on manage.karta.cards:
#   - Vera's script sets a priority-4 host-header rule → vera-admin
#   - This script adds a HIGHER-priority (2) rule: host=manage.karta.cards
#     + path=/palisade-api/* → palisade-admin.  /api/* still falls through
#     to vera-admin, keeping the SPA's dual-backend proxy intact.
#
# Prerequisites:
#   - AWS CLI v2 configured with credentials that can manage ECS, ELB,
#     Secrets Manager, CloudWatch Logs, and ECR in ap-southeast-2.
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

# Vera admin's target group — we route everything on manage.karta.cards
# except /palisade-api/* to it.  The ARN is looked up at runtime rather
# than hard-coded so this script can't drift from Vera's.
VERA_ADMIN_TG_NAME="vera-admin"

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
# Shared.
ensure_secret "palisade/DATABASE_URL"              "CHANGEME"
ensure_secret "palisade/CORS_ORIGINS"              "CHANGEME"

# Palisade ↔ Vera — Palisade calls Vera's vault to register PANs and gets
# back an opaque vaultToken.  Shares Vera's SERVICE_AUTH_KEYS entry keyed
# "palisade".  This secret MUST match that entry.
ensure_secret "palisade/PALISADE_VERA_VAULT_SECRET" "CHANGEME"

# SDM — per-card key derivation for tap.
# Backend: "hsm" (AWS Payment Cryptography), "local" (HKDF+CMAC), "mock".
ensure_secret "palisade/SDM_KEY_BACKEND"           "local"
ensure_secret "palisade/SDM_META_MASTER_KEY_ARN"   "CHANGEME"
ensure_secret "palisade/SDM_FILE_MASTER_KEY_ARN"   "CHANGEME"
ensure_secret "palisade/DEV_SDM_ROOT_SEED"         "CHANGEME"

# Activation service URLs — referenced by admin (for batch CSV import
# signing) and by batch-processor (for per-row card registration).
ensure_secret "palisade/ACTIVATION_SERVICE_URL"    "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3002"
ensure_secret "palisade/DATA_PREP_SERVICE_URL"     "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3006"
ensure_secret "palisade/RCA_SERVICE_URL"           "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3007"

# Admin.
ensure_secret "palisade/SERVICE_AUTH_ADMIN_SECRET" "CHANGEME"
# Microsite CDN + S3 bucket — admin uploads zips, CloudFront serves them.
ensure_secret "palisade/MICROSITE_BUCKET"          "karta-microsites-${ACCOUNT}"
ensure_secret "palisade/MICROSITE_CDN_URL"         "https://microsite.karta.cards"
ensure_secret "palisade/EMBOSSING_KMS_KEY_ARN"     "CHANGEME"

# Vera vault endpoint — activation uses this on card registration.
ensure_secret "palisade/VERA_VAULT_URL"            "http://internal-vera-internal-886106335.ap-southeast-2.elb.amazonaws.com:3004"

# Mobile-app deep-link used by activation.
ensure_secret "palisade/MOBILE_APP_URL"            "https://app.karta.cards"

# SAD retention policy (days).
ensure_secret "palisade/SAD_TTL_DAYS"              "30"

# ===========================================================================
echo ""
echo "============================================================"
echo " 2. CLOUDWATCH LOG GROUPS"
echo "============================================================"
# ===========================================================================

for svc in tap activation admin data-prep rca batch-processor sftp; do
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
ARN_SERVICE_AUTH_ACTIVATION_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_ACTIVATION_SECRET")
ARN_SERVICE_AUTH_ADMIN_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_ADMIN_SECRET")
ARN_SERVICE_AUTH_PROVISIONING_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_PROVISIONING_SECRET")
ARN_CALLBACK_HMAC_SECRET=$(get_secret_arn "palisade/CALLBACK_HMAC_SECRET")
ARN_KMS_SAD_KEY_ARN=$(get_secret_arn "palisade/KMS_SAD_KEY_ARN")
ARN_DATA_PREP_MOCK_EMV=$(get_secret_arn "palisade/DATA_PREP_MOCK_EMV")
ARN_EMBOSSING_KEY_V1=$(get_secret_arn "palisade/EMBOSSING_KEY_V1")
ARN_EMBOSSING_KEY_ACTIVE_VERSION=$(get_secret_arn "palisade/EMBOSSING_KEY_ACTIVE_VERSION")
ARN_EMBOSSING_BUCKET=$(get_secret_arn "palisade/EMBOSSING_BUCKET")
ARN_EMBOSSING_KMS_KEY_ARN=$(get_secret_arn "palisade/EMBOSSING_KMS_KEY_ARN")
ARN_SERVICE_AUTH_BATCH_PROCESSOR_SECRET=$(get_secret_arn "palisade/SERVICE_AUTH_BATCH_PROCESSOR_SECRET")
ARN_POLL_INTERVAL_MS=$(get_secret_arn "palisade/POLL_INTERVAL_MS")
ARN_ACTIVATION_SERVICE_URL=$(get_secret_arn "palisade/ACTIVATION_SERVICE_URL")
ARN_DATA_PREP_SERVICE_URL=$(get_secret_arn "palisade/DATA_PREP_SERVICE_URL")
ARN_RCA_SERVICE_URL=$(get_secret_arn "palisade/RCA_SERVICE_URL")
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
        { "name": "TAP_HANDOFF_SECRET",             "valueFrom": "${ARN_TAP_HANDOFF_SECRET}" },
        { "name": "SERVICE_AUTH_ACTIVATION_SECRET", "valueFrom": "${ARN_SERVICE_AUTH_ACTIVATION_SECRET}" },
        { "name": "WEBAUTHN_RP_ID",                 "valueFrom": "${ARN_WEBAUTHN_RP_ID}" },
        { "name": "WEBAUTHN_ORIGINS",               "valueFrom": "${ARN_WEBAUTHN_ORIGINS}" },
        { "name": "WEBAUTHN_RP_NAME",               "valueFrom": "${ARN_WEBAUTHN_RP_NAME}" },
        { "name": "VERA_VAULT_URL",                 "valueFrom": "${ARN_VERA_VAULT_URL}" },
        { "name": "PALISADE_VERA_VAULT_SECRET",     "valueFrom": "${ARN_PALISADE_VERA_VAULT_SECRET}" },
        { "name": "MOBILE_APP_URL",                 "valueFrom": "${ARN_MOBILE_APP_URL}" },
        { "name": "PALISADE_RCA_URL",               "valueFrom": "${ARN_RCA_SERVICE_URL}" }
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
# Cognito config is baked into env defaults (see services/admin/src/env.ts);
# only override with secrets if the pool IDs change.
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
        { "name": "MICROSITE_CDN_URL",          "valueFrom": "${ARN_MICROSITE_CDN_URL}" }
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
echo ""
echo "--- Registering task definition: palisade-data-prep ---"
aws ecs register-task-definition --cli-input-json "$(cat <<TASKJSON
{
  "family": "palisade-data-prep",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXEC_ROLE}",
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
        { "name": "DATABASE_URL",         "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "PROVISION_AUTH_KEYS",  "valueFrom": "${ARN_PROVISION_AUTH_KEYS}" },
        { "name": "KMS_SAD_KEY_ARN",      "valueFrom": "${ARN_KMS_SAD_KEY_ARN}" },
        { "name": "DATA_PREP_MOCK_EMV",   "valueFrom": "${ARN_DATA_PREP_MOCK_EMV}" },
        { "name": "SAD_TTL_DAYS",         "valueFrom": "${ARN_SAD_TTL_DAYS}" }
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

# --- rca (port 3007, internal, WebSocket + HMAC-gated) ---
echo ""
echo "--- Registering task definition: palisade-rca ---"
aws ecs register-task-definition --cli-input-json "$(cat <<TASKJSON
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
        { "name": "ACTIVATION_CALLBACK_URL", "value": "http://${INTERNAL_ALB_DNS}:3002" }
      ],
      "secrets": [
        { "name": "DATABASE_URL",         "valueFrom": "${ARN_DATABASE_URL}" },
        { "name": "PROVISION_AUTH_KEYS",  "valueFrom": "${ARN_PROVISION_AUTH_KEYS}" },
        { "name": "CALLBACK_HMAC_SECRET", "valueFrom": "${ARN_CALLBACK_HMAC_SECRET}" }
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

# --- sftp (port 22, public via NLB) -----------------------------------------
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
    batch-processor) echo 3008 ;; sftp) echo 22 ;;
  esac
}

for svc in tap activation admin data-prep rca batch-processor sftp; do
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
    CREATED_RULES+=("$host -> $(echo "$tg_arn" | grep -o 'palisade-[a-z]*')")
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
    CREATED_RULES+=("$host $path -> $(echo "$tg_arn" | grep -o 'palisade-[a-z]*')")
    echo "  [created] Rule priority=$priority: $host $path -> target group"
  fi
}

# Palisade host-header rules.  Priorities chosen to leave room (6-10)
# below Vera's existing 1-4 and above any future catch-alls.
create_host_rule "$PUBLIC_LISTENER_ARN" "tap.karta.cards"        "$TG_ARN_tap"        6  "$EXISTING_RULES"
create_host_rule "$PUBLIC_LISTENER_ARN" "activation.karta.cards" "$TG_ARN_activation" 7  "$EXISTING_RULES"

# Shared manage.karta.cards — higher priority (=2, beats Vera's 4) so the
# path-based rule wins before the host-only rule to vera-admin.
create_host_path_rule "$PUBLIC_LISTENER_ARN" "manage.karta.cards" "/palisade-api/*" "$TG_ARN_admin" 2 "$EXISTING_RULES"

# ---- Internal ALB (HTTP:3006 for data-prep) ----
echo ""
echo "--- Internal ALB (HTTP:3006 for data-prep) ---"

INTERNAL_3006_LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn "$INTERNAL_ALB_ARN" \
  --region "$REGION" \
  --query "Listeners[?Port==\`3006\`].ListenerArn | [0]" \
  --output text 2>/dev/null || true)

if [ -z "$INTERNAL_3006_LISTENER_ARN" ] || [ "$INTERNAL_3006_LISTENER_ARN" = "None" ]; then
  INTERNAL_3006_LISTENER_ARN=$(aws elbv2 create-listener \
    --load-balancer-arn "$INTERNAL_ALB_ARN" \
    --protocol HTTP \
    --port 3006 \
    --default-actions "Type=forward,TargetGroupArn=${TG_ARN_data_prep}" \
    --region "$REGION" \
    --query 'Listeners[0].ListenerArn' \
    --output text)
  echo "  [created] Internal HTTP:3006 listener -> palisade-data-prep"
else
  echo "  [exists] Internal HTTP:3006 listener ($INTERNAL_3006_LISTENER_ARN)"
  aws elbv2 modify-listener \
    --listener-arn "$INTERNAL_3006_LISTENER_ARN" \
    --default-actions "Type=forward,TargetGroupArn=${TG_ARN_data_prep}" \
    --region "$REGION" \
    --output text > /dev/null
  echo "  [updated] HTTP:3006 default action -> palisade-data-prep"
fi

# ---- Internal ALB (HTTP:3007 for rca) ----
echo ""
echo "--- Internal ALB (HTTP:3007 for rca) ---"

INTERNAL_3007_LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn "$INTERNAL_ALB_ARN" \
  --region "$REGION" \
  --query "Listeners[?Port==\`3007\`].ListenerArn | [0]" \
  --output text 2>/dev/null || true)

if [ -z "$INTERNAL_3007_LISTENER_ARN" ] || [ "$INTERNAL_3007_LISTENER_ARN" = "None" ]; then
  INTERNAL_3007_LISTENER_ARN=$(aws elbv2 create-listener \
    --load-balancer-arn "$INTERNAL_ALB_ARN" \
    --protocol HTTP \
    --port 3007 \
    --default-actions "Type=forward,TargetGroupArn=${TG_ARN_rca}" \
    --region "$REGION" \
    --query 'Listeners[0].ListenerArn' \
    --output text)
  echo "  [created] Internal HTTP:3007 listener -> palisade-rca"
else
  echo "  [exists] Internal HTTP:3007 listener ($INTERNAL_3007_LISTENER_ARN)"
  aws elbv2 modify-listener \
    --listener-arn "$INTERNAL_3007_LISTENER_ARN" \
    --default-actions "Type=forward,TargetGroupArn=${TG_ARN_rca}" \
    --region "$REGION" \
    --output text > /dev/null
  echo "  [updated] HTTP:3007 default action -> palisade-rca"
fi

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

for svc in tap activation admin data-prep rca batch-processor sftp; do
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

echo ""
echo "============================================================"
echo " OTHER MANUAL STEPS"
echo "============================================================"
echo ""
echo "1. Verify the ECS security group ($ECS_SG) allows:"
echo "   - Inbound from the public ALB SG on ports 3001, 3002, 3009"
echo "     (palisade-tap, palisade-activation, palisade-admin)"
echo "   - Inbound from the internal ALB SG on ports 3006, 3007"
echo "     (managed above — idempotent)"
echo "   - Inbound TCP:22 from 0.0.0.0/0 for SFTP (managed above)"
echo ""
echo "2. DNS records (all pointing at the shared public ALB):"
echo "   - tap.karta.cards"
echo "   - activation.karta.cards"
echo "   - manage.karta.cards         (shared with vera-admin)"
echo ""
echo "3. CNAME: sftp.karta.cards -> $SFTP_NLB_DNS"
echo ""
echo "4. ECR repositories: palisade-tap, palisade-activation, palisade-admin,"
echo "   palisade-data-prep, palisade-rca, palisade-batch-processor, palisade-sftp"
echo ""
echo "5. Vera's SERVICE_AUTH_KEYS must contain an entry keyed 'palisade'"
echo "   whose value matches palisade/PALISADE_VERA_VAULT_SECRET.  Palisade's"
echo "   activation HMAC-signs calls to Vera's vault with that key."
echo ""
echo "6. Vera's aws-setup.sh routes manage.karta.cards -> vera-admin at"
echo "   priority 4.  This script adds priority 2 with a /palisade-api/*"
echo "   path condition -> palisade-admin.  Don't lower either priority."
echo ""
echo "7. Seed palisade/SFTP_USERS with the real partner list."
echo ""
echo "Done."
