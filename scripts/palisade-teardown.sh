#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Palisade AWS infrastructure teardown
#
# Removes legacy Palisade resources from ap-southeast-2 now that karta.cards
# handles everything. Run AFTER verifying karta.cards is fully operational.
#
# PRESERVES:
#   - KMS keys (can't be immediately deleted; scheduled for deletion)
#   - AWS Payment Cryptography keys (issuer master keys — still referenced)
#   - S3 bucket contents are emptied before bucket deletion
#
# Prerequisites:
#   - AWS CLI v2 configured for account 600743178530, ap-southeast-2
#   - Confirm karta.cards is handling all traffic before running
# ---------------------------------------------------------------------------
set -euo pipefail

REGION="ap-southeast-2"

echo "============================================================"
echo " Palisade AWS Teardown"
echo "============================================================"
echo ""
echo "This will remove all legacy Palisade infrastructure."
echo "Make sure karta.cards is fully operational first!"
echo ""
read -p "Type 'TEARDOWN' to confirm: " CONFIRM
if [ "$CONFIRM" != "TEARDOWN" ]; then
  echo "Aborted."
  exit 1
fi

echo ""
echo "--- 1. App Runner Services ---"
for svc_url in \
  "arn:aws:apprunner:${REGION}:600743178530:service/palisade-admin" \
  "arn:aws:apprunner:${REGION}:600743178530:service/palisade-sun" \
  "arn:aws:apprunner:${REGION}:600743178530:service/palisade-data-prep"; do
  echo "  Deleting App Runner service: ${svc_url}..."
  aws apprunner delete-service --service-arn "$svc_url" --region "$REGION" 2>/dev/null || echo "  (not found or already deleted)"
done

echo ""
echo "--- 2. ECS Services ---"
# Get the Palisade cluster name
PALISADE_CLUSTER=$(aws ecs list-clusters --region "$REGION" --query "clusterArns[?contains(@, 'palisade') || contains(@, 'Palisade')]" --output text 2>/dev/null || true)
if [ -n "$PALISADE_CLUSTER" ] && [ "$PALISADE_CLUSTER" != "None" ]; then
  for svc in palisade-admin palisade-sun palisade-data-prep palisade-rca; do
    echo "  Scaling down and deleting ECS service: ${svc}..."
    aws ecs update-service --cluster "$PALISADE_CLUSTER" --service "$svc" --desired-count 0 --region "$REGION" 2>/dev/null || true
    aws ecs delete-service --cluster "$PALISADE_CLUSTER" --service "$svc" --force --region "$REGION" 2>/dev/null || echo "  (not found)"
  done
  echo "  Deleting ECS cluster..."
  aws ecs delete-cluster --cluster "$PALISADE_CLUSTER" --region "$REGION" 2>/dev/null || echo "  (not empty or not found)"
else
  echo "  No Palisade ECS cluster found."
fi

echo ""
echo "--- 3. ECR Repositories ---"
for repo in palisade-sun palisade-data-prep palisade-rca palisade-admin; do
  echo "  Deleting ECR repo: ${repo}..."
  aws ecr delete-repository --repository-name "$repo" --force --region "$REGION" 2>/dev/null || echo "  (not found)"
done

echo ""
echo "--- 4. DynamoDB Tables ---"
for table in palisade-card-registry palisade-sad-records palisade-issuer-profiles palisade-provisioning-sessions palisade-programs palisade-audit-log; do
  echo "  Deleting DynamoDB table: ${table}..."
  aws dynamodb delete-table --table-name "$table" --region "$REGION" 2>/dev/null || echo "  (not found)"
done

echo ""
echo "--- 5. S3 Buckets ---"
for bucket in palisade-batch-staging-600743178530 palisade-chip-profiles-600743178530; do
  echo "  Emptying and deleting S3 bucket: ${bucket}..."
  aws s3 rm "s3://${bucket}" --recursive --region "$REGION" 2>/dev/null || true
  aws s3api delete-bucket --bucket "$bucket" --region "$REGION" 2>/dev/null || echo "  (not found)"
done

echo ""
echo "--- 6. ElastiCache ---"
REDIS_CLUSTERS=$(aws elasticache describe-cache-clusters --region "$REGION" --query "CacheClusters[?contains(CacheClusterId, 'palisade')].CacheClusterId" --output text 2>/dev/null || true)
if [ -n "$REDIS_CLUSTERS" ] && [ "$REDIS_CLUSTERS" != "None" ]; then
  for cluster in $REDIS_CLUSTERS; do
    echo "  Deleting ElastiCache cluster: ${cluster}..."
    aws elasticache delete-cache-cluster --cache-cluster-id "$cluster" --region "$REGION" 2>/dev/null || echo "  (not found)"
  done
else
  echo "  No Palisade ElastiCache clusters found."
fi

echo ""
echo "--- 7. KMS Keys (scheduling deletion, 30-day wait) ---"
for alias in palisade-pan-encryption palisade-sad-encryption palisade-uid-encryption; do
  KEY_ID=$(aws kms describe-key --key-id "alias/${alias}" --region "$REGION" --query 'KeyMetadata.KeyId' --output text 2>/dev/null || true)
  if [ -n "$KEY_ID" ] && [ "$KEY_ID" != "None" ]; then
    echo "  Scheduling deletion for KMS key ${alias} (${KEY_ID}) — 30 day wait..."
    aws kms schedule-key-deletion --key-id "$KEY_ID" --pending-window-in-days 30 --region "$REGION" 2>/dev/null || echo "  (already scheduled)"
  else
    echo "  KMS key ${alias} not found."
  fi
done

echo ""
echo "--- 8. CloudWatch Log Groups ---"
for group in /ecs/palisade-admin /ecs/palisade-sun /ecs/palisade-data-prep /ecs/palisade-rca; do
  echo "  Deleting log group: ${group}..."
  aws logs delete-log-group --log-group-name "$group" --region "$REGION" 2>/dev/null || echo "  (not found)"
done

echo ""
echo "============================================================"
echo " Teardown complete."
echo ""
echo " PRESERVED (still needed by karta.cards):"
echo "   - AWS Payment Cryptography keys (issuer master keys)"
echo "   - KMS keys (scheduled for deletion in 30 days — cancel"
echo "     with 'aws kms cancel-key-deletion' if still needed)"
echo "============================================================"
