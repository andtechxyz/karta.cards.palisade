# palisade-card-ops ECS bootstrap runbook

**Status:** AWS infrastructure provisioned; service creation pending first image build.
**Context:** Remote-ops requires card-ops to run as a prod service, not only from an operator's local machine. PCI CPL LSR 6 — the perso NFC link must transit through a trusted service boundary, not a laptop USB port.

## What's already done (committed 2026-04-22)

| Resource | Identifier / ARN |
|---|---|
| ECR repo | `600743178530.dkr.ecr.ap-southeast-2.amazonaws.com/palisade-card-ops` |
| IAM task role | `arn:aws:iam::600743178530:role/vera-card-ops-task` |
| IAM policy | `card-ops-kms-access` inline on task role (`kms:Sign` on attestation-issuer, `kms:Decrypt` on SAD + per-FI GP keys) |
| ALB target group | `palisade-card-ops-tg` on port 3010 (health `/api/health`) |
| ALB listener rule | host `card-ops.karta.cards` → target group, priority 30, on HTTPS listener of `vera-public` |
| Secrets | `palisade/CARD_OPS_AUTH_KEYS`, `palisade/SERVICE_AUTH_CARD_OPS_SECRET`, `palisade/CARD_OPS_PUBLIC_WS_BASE` (created with matching pairs for activation ↔ card-ops HMAC) |
| CI matrix entry | `.github/workflows/deploy.yml` — `card-ops` + port 3010 |
| CI bootstrap tolerance | deploy step skips task-def update when service is `None` (first push only) |

## What's pending

1. **First CI build** — next push to main with card-ops code changes triggers the matrix.  Image lands in ECR at `palisade-card-ops:<sha>`.  Deploy step skips ECS update (service not yet created) and logs a `::notice::` line.

2. **Create the ECS service** (one-time):

   ```bash
   REGION=ap-southeast-2
   CLUSTER=vera
   LATEST_SHA=$(aws ecr describe-images --repository-name palisade-card-ops --region $REGION \
     --query 'sort_by(imageDetails, &imagePushedAt)[-1].imageTags | [0]' --output text)

   # Register task def.  File on disk = docs/runbooks/card-ops-td.template.json
   # (stripped of SHA-dependent fields; fill in LATEST_SHA before registering).
   jq --arg img "600743178530.dkr.ecr.ap-southeast-2.amazonaws.com/palisade-card-ops:$LATEST_SHA" \
     '.containerDefinitions[0].image = $img' \
     docs/runbooks/card-ops-td.template.json > /tmp/card-ops-td.json

   aws ecs register-task-definition --region $REGION --cli-input-json file:///tmp/card-ops-td.json

   # Create the service wired to the existing target group.
   aws ecs create-service \
     --cluster $CLUSTER \
     --service-name palisade-card-ops \
     --task-definition palisade-card-ops \
     --desired-count 1 \
     --launch-type FARGATE \
     --network-configuration "awsvpcConfiguration={subnets=[subnet-0397a18095049f972,subnet-0d475c49f65f05e86],securityGroups=[sg-086e7b16e5351f155,sg-060cc505a1052faa3],assignPublicIp=DISABLED}" \
     --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:ap-southeast-2:600743178530:targetgroup/palisade-card-ops-tg/9a3bb43b214c867b,containerName=palisade-card-ops,containerPort=3010" \
     --health-check-grace-period-seconds 60 \
     --region $REGION
   ```

3. **Wire admin → card-ops outbound auth.**  The admin service needs to sign outbound calls to card-ops.  Add `SERVICE_AUTH_CARD_OPS_SECRET` + `CARD_OPS_URL` to `palisade-admin:N+1` task def.

4. **Tap test.**  With card-ops live in prod + admin wired, the Install-PA button in `manage.karta.cards` should drive a real SCP03 session against the operator's NFC reader (via the admin WS relay).

## Dependencies for strict-mode C16/C23 closure (Stage J)

Card-ops-in-prod is one of two prerequisites for strict-mode verification:

1. card-ops service live (this runbook) + install-PA run against trial card.
2. Attestation priv-scalar wrapping (docs/runbooks/attestation-priv-wrapping.md) — CAP rebuild + sealed STORE_ATTESTATION path shipped.

Both converge at `palisade-rca:19` (strict mode task def already registered).  Flip via:

```bash
aws ecs update-service --cluster vera --service palisade-rca \
  --task-definition palisade-rca:19 --force-new-deployment --region ap-southeast-2
```

## Rollback

Delete the service + keep task def + ECR image for audit:

```bash
aws ecs update-service --cluster vera --service palisade-card-ops --desired-count 0 --region ap-southeast-2
# Wait for drain
aws ecs delete-service --cluster vera --service palisade-card-ops --region ap-southeast-2
# ALB listener rule + target group + IAM role + secrets can stay — re-create
# service when ready.
```
