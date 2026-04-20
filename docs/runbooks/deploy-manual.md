# Manual deploy — no-GHA runbook

When GitHub Actions minutes are exhausted or the workflow is otherwise
unavailable, this is the bypass path: build the docker image on the
local workstation, push to ECR, and roll the ECS service.

**Mirrors `.github/workflows/deploy.yml` exactly** so what you deploy
here is bit-identical to what the GHA pipeline produces.  Uses the
same ECR repo names (`vera-<service>`), tag format (short SHA), ECS
cluster (`vera`), and service names (`vera-<service>`).

**Prereqs on the workstation:**
- Docker Desktop running (for buildx multi-arch support)
- AWS CLI v2 with a profile that has:
  - `ecr:GetAuthorizationToken`
  - `ecr:BatchCheckLayerAvailability`
  - `ecr:PutImage`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`
  - `ecs:DescribeServices`, `ecs:DescribeTaskDefinition`, `ecs:RegisterTaskDefinition`, `ecs:UpdateService`
- Working tree clean on `main` and pushed to origin
- Tests + typecheck green locally (see `deploy.md` pre-flight)

---

## One-shot deploy of a single service

Replace `SERVICE` with the target (`tap`, `activation`, `rca`, `card-ops`,
`data-prep`, `admin`, `batch-processor`, `sftp`, `vault`, `pay`).

```bash
set -euo pipefail

REGION=ap-southeast-2
REGISTRY=600743178530.dkr.ecr.ap-southeast-2.amazonaws.com
CLUSTER=vera
SERVICE=rca                     # <-- change this
REPO=vera-${SERVICE}
SVC=vera-${SERVICE}
SHA=$(git rev-parse --short=7 HEAD)

# 1. ECR login
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"

# 2. Build + push.  buildx --platform linux/amd64 is mandatory on Apple
#    Silicon — ECS Fargate runs x86_64.  The SERVICE build-arg selects
#    which service's dist/ is the entrypoint (see Dockerfile).
docker buildx build \
  --platform linux/amd64 \
  --build-arg SERVICE="$SERVICE" \
  --tag "$REGISTRY/$REPO:$SHA" \
  --tag "$REGISTRY/$REPO:latest" \
  --push \
  .

# 3. Fetch current task definition, swap the image, register new revision.
TASK_DEF_ARN=$(aws ecs describe-services \
  --region "$REGION" --cluster "$CLUSTER" --services "$SVC" \
  --query 'services[0].taskDefinition' --output text)

TASK_DEF=$(aws ecs describe-task-definition \
  --region "$REGION" --task-definition "$TASK_DEF_ARN" \
  --query 'taskDefinition')

NEW_DEF=$(echo "$TASK_DEF" \
  | jq --arg IMAGE "$REGISTRY/$REPO:$SHA" \
      '.containerDefinitions[0].image = $IMAGE' \
  | jq 'del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)')

NEW_ARN=$(aws ecs register-task-definition \
  --region "$REGION" --cli-input-json "$NEW_DEF" \
  --query 'taskDefinition.taskDefinitionArn' --output text)

# 4. Roll the service onto the new revision.
aws ecs update-service \
  --region "$REGION" --cluster "$CLUSTER" --service "$SVC" \
  --task-definition "$NEW_ARN" \
  --force-new-deployment \
  --query 'service.serviceName' --output text

echo "deployed $REGISTRY/$REPO:$SHA → $SVC ($NEW_ARN)"
```

---

## Verify the deploy

After `update-service` returns, the rollout takes 60–120s depending on
container boot time.  Check:

```bash
# Service event timeline
aws ecs describe-services --region ap-southeast-2 \
  --cluster vera --services vera-${SERVICE} \
  --query 'services[0].{desired:desiredCount,running:runningCount,pending:pendingCount,events:events[:3].[createdAt,message]}'

# Fresh task logs (listen for the "listening on :PORT" line)
aws logs tail /ecs/vera-${SERVICE} --region ap-southeast-2 --since 3m

# Direct health probe via ALB (internal services)
curl -fsS https://internal.karta.cards/api/${SERVICE}/health
```

Pay attention to "steady state" in the service events — that's the
signal the new task is healthy and the old one has drained.

---

## Deploy multiple services at once

The GHA matrix runs builds in parallel; locally we can do the same by
putting each build into the background.  The push / ECS roll for each
service is independent.

```bash
for SERVICE in tap activation rca card-ops; do
  (
    echo "=== $SERVICE ==="
    SHA=$(git rev-parse --short=7 HEAD)
    docker buildx build --platform linux/amd64 \
      --build-arg SERVICE="$SERVICE" \
      --tag "$REGISTRY/vera-$SERVICE:$SHA" \
      --tag "$REGISTRY/vera-$SERVICE:latest" \
      --push . \
      2>&1 | sed "s/^/[$SERVICE] /"
  ) &
done
wait
# Then run the register-task-definition + update-service loop
# (cheap, do them sequentially).
```

---

## Rollback

The task definition is immutable once registered; rolling back is a
second `update-service` pointing at the previous revision.

```bash
# Find the prior revision
PREV_ARN=$(aws ecs list-task-definitions \
  --region ap-southeast-2 \
  --family-prefix vera-${SERVICE} \
  --sort DESC --max-items 5 \
  --query 'taskDefinitionArns' --output json \
  | jq -r '.[1]')    # [0] is the one we just deployed; [1] is the previous

aws ecs update-service \
  --region ap-southeast-2 --cluster vera --service vera-${SERVICE} \
  --task-definition "$PREV_ARN" \
  --force-new-deployment
```

Image tags are preserved in ECR indefinitely (no lifecycle policy
removing by age), so rollback is always available as long as the task
def row still exists.

---

## Using CodeBuild instead of a local docker

When the local workstation can't run Docker (Windows dev, CI from a
laptop on battery), CodeBuild can do the image build on AWS while we
stay outside GHA:

```bash
# One-time: create a CodeBuild project (omitted — `aws-setup.sh` already
# provisions build-palisade-<service> projects per the log group listing).

# Trigger an ad-hoc build at current HEAD.  CodeBuild pulls from GitHub,
# pushes to ECR, and prints the image tag at the end.
aws codebuild start-build \
  --region ap-southeast-2 \
  --project-name build-palisade-${SERVICE} \
  --source-version "main" \
  --environment-variables-override name=SERVICE,value=${SERVICE}

# Watch progress
aws codebuild batch-get-builds \
  --region ap-southeast-2 \
  --ids <buildId> \
  --query 'builds[0].{phase:currentPhase,status:buildStatus}'
```

After CodeBuild completes, run step 3 + 4 of the one-shot flow above
(the image is already in ECR at the SHA tag).

---

## Turning on CloudWatch metrics (EMF)

`@palisade/metrics` is wired into `rca` (more services to follow).  It
reads `METRICS_BACKEND` at startup — set it to `cloudwatch` on the ECS
task definition and every `metrics.counter()/gauge()/timing()` call
emits an EMF-formatted stdout line that CloudWatch Logs Insights parses
into metrics.

```bash
# Patch the rca task def to add METRICS_BACKEND=cloudwatch.  Fetch,
# mutate, re-register, point the service at the new revision.
TASK_DEF=$(aws ecs describe-task-definition --region ap-southeast-2 \
  --task-definition vera-rca --query 'taskDefinition')
NEW_DEF=$(echo "$TASK_DEF" | jq '
  .containerDefinitions[0].environment += [
    { "name": "METRICS_BACKEND", "value": "cloudwatch" }
  ]
' | jq 'del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)')
NEW_ARN=$(aws ecs register-task-definition --region ap-southeast-2 \
  --cli-input-json "$NEW_DEF" \
  --query 'taskDefinition.taskDefinitionArn' --output text)
aws ecs update-service --region ap-southeast-2 --cluster vera \
  --service vera-rca --task-definition "$NEW_ARN" --force-new-deployment
```

Emitted metrics (CloudWatch namespace `rca`):

| Metric | Dimensions | When |
|---|---|---|
| `rca.session.started` | — | Every `POST /api/provision/start` |
| `rca.provisioning.complete` | `mode` ∈ {plan,classical} | Atomic commit succeeds |
| `rca.attestation.verify` | `mode` ∈ {strict,permissive}, `result` ∈ {ok,fail}, `path` ∈ {plan,classical} | Every attestation check |
| `rca.plan_step.rejected` | `reason` ∈ {plan_step_state_missing, plan_step_state_expired, plan_step_out_of_range, plan_step_replay, plan_step_skip} | Plan-mode step cursor rejects a response |

Useful CloudWatch alarms to wire up:
- `rca.plan_step.rejected` > 5 in 5 min → mobile bug or attack
- `rca.attestation.verify{result=fail}` > 0 in strict mode → real chip rejection
- `rca.provisioning.complete` drops to 0 over a 15 min window when
  `rca.session.started` > 0 → provisioning stuck

## Gotchas encountered

- **Apple Silicon**: `docker buildx build` without `--platform linux/amd64`
  produces an arm64 image.  ECS Fargate refuses arm64 images on x86_64
  task definitions with `CannotPullContainerError: image manifest does
  not match platform`.  Always pass `--platform linux/amd64` on ARM
  Macs.
- **Secrets resolution at boot**: services call `resolveSecretRefs()`
  in `index.ts` which reads `secretsmanager:` refs from env.  If a
  service crash-loops with "required ARN not set" errors (see
  `vera-tap`'s 2026-04-20 01:42Z outage in CloudWatch), the task def
  is probably missing a `secrets:` entry.  Fix by editing the task
  def JSON before `register-task-definition`, or add the secret to
  `scripts/aws-setup.sh` for permanence.
- **WebSocket services (rca + card-ops)**: the ALB target group's
  health check must point at `/api/health`, not the WS path.  A broken
  health check manifests as endless deploy loops where ECS never
  reaches "steady state".
- **Migrations**: Prisma schema changes ship separately via
  `vera-migrate` (one-off task that runs `prisma migrate deploy`).
  Run the migrate task BEFORE deploying services that rely on the new
  schema so the readers don't see a half-migrated DB.
