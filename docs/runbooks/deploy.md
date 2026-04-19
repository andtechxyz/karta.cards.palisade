# Deploy runbook — Vera + Palisade

How to deploy changes across the split repos, in the right order, with a
rollback path for every destructive step.

**Date last verified against main**: 2026-04-19
**Vera main**: `8843505` (post-Phase 3 shrink)
**Palisade main**: `0ee6c8b` (post-Agent A1 merge)

## The split in one paragraph

Palisade owns card + chip domain: `activation`, `tap`, `data-prep`, `rca`,
`batch-processor`, `sftp`, `card-ops`, `admin` (card-side CRUD).  Vera owns
vault + pay + transactions: `pay`, `vault`, `admin` (vault proxy +
tokenisation programs + capabilities).  Pay on Vera calls Palisade's
activation over HTTP for card lookups / ATC increments / webauthn
credentials via a single shared HMAC (keyId `pay`).  Registration
challenges stay Vera-local; everything else card/chip goes through
Palisade.

---

## Pre-flight checklist

Before any deploy, confirm:

```bash
# Both repos on main, working tree clean
cd /Users/danderson/Vera      && git status --short | grep -v scratch
cd /Users/danderson/Palisade  && git status --short

# Both tests green
cd /Users/danderson/Vera      && npx vitest run
cd /Users/danderson/Palisade  && npx vitest run

# Both tsc clean
cd /Users/danderson/Vera      && npx tsc -b
cd /Users/danderson/Palisade  && npx tsc -b

# Both Prisma schemas validate
cd /Users/danderson/Vera      && npx prisma validate --schema packages/db/prisma/schema.prisma
cd /Users/danderson/Palisade  && npx prisma validate --schema packages/db/prisma/schema.prisma

# Migration lists line up with schema
cd /Users/danderson/Vera      && npx prisma migrate status --schema packages/db/prisma/schema.prisma
cd /Users/danderson/Palisade  && npx prisma migrate status --schema packages/db/prisma/schema.prisma
```

If any of the above fails, stop.  Fix before deploy.

---

## Deploy order (this matters)

The cross-repo contract is: **Vera pay calls Palisade activation**.  If
you deploy Vera first with code that expects a Palisade endpoint that
hasn't shipped yet, pay will 404.  Always:

1. **Palisade first** — schema migrations + new endpoints land
2. **Vera second** — callers start using the newly-available endpoints

For deploys that only touch one repo, obviously skip the other.

---

## Step 1 — snapshot both prod DBs

```bash
# Vera RDS snapshot
aws rds create-db-snapshot \
  --db-instance-identifier vera-prod \
  --db-snapshot-identifier vera-prod-pre-$(date +%Y%m%d-%H%M%S)

# Palisade RDS snapshot
aws rds create-db-snapshot \
  --db-instance-identifier palisade-prod \
  --db-snapshot-identifier palisade-prod-pre-$(date +%Y%m%d-%H%M%S)
```

Wait for both `available` status before proceeding.

**CRITICAL for this session's deploy**: The Vera Phase 3 shrink drops
14 tables — if rollback is needed, the only recovery path is restoring
from this snapshot.  Do not skip.

---

## Step 2 — deploy Palisade

### 2a. Apply migrations

```bash
cd /Users/danderson/Palisade

# Point at prod DB, dry-run first
DATABASE_URL="postgresql://palisade:${PROD_PW}@palisade-prod.rds.amazonaws.com:5432/palisade" \
  npx prisma migrate status --schema packages/db/prisma/schema.prisma

# Apply
DATABASE_URL="postgresql://palisade:${PROD_PW}@palisade-prod.rds.amazonaws.com:5432/palisade" \
  npx prisma migrate deploy --schema packages/db/prisma/schema.prisma
```

Expected output: "All migrations have been successfully applied."  Any
errors → stop, investigate, consider restoring snapshot.

### 2b. Push images + update services

```bash
# Log in to ECR
aws ecr get-login-password --region ap-southeast-2 \
  | docker login --username AWS --password-stdin \
    $ACCOUNT.dkr.ecr.ap-southeast-2.amazonaws.com

# Build + push each Palisade service (8 of them)
for SERVICE in tap activation data-prep rca batch-processor sftp admin card-ops; do
  docker build --build-arg SERVICE=$SERVICE -t palisade-$SERVICE .
  docker tag palisade-$SERVICE:latest \
    $ACCOUNT.dkr.ecr.ap-southeast-2.amazonaws.com/palisade-$SERVICE:$GIT_SHA
  docker push \
    $ACCOUNT.dkr.ecr.ap-southeast-2.amazonaws.com/palisade-$SERVICE:$GIT_SHA
done

# Update ECS task defs + services (one per service)
for SERVICE in tap activation data-prep rca batch-processor sftp admin card-ops; do
  aws ecs update-service \
    --cluster palisade-prod \
    --service palisade-$SERVICE \
    --force-new-deployment
done
```

### 2c. Secrets (add/update before services start)

If any of the following are new to this deploy, update them first (use
your Secrets Manager tool of choice, e.g. console + paste).  Match
caller keyIds.

| Secret | Value | Consumer |
|---|---|---|
| `PAY_AUTH_KEYS` | JSON: `{"pay": "<32-byte-hex>"}` | Palisade activation + card-ops |
| `CARD_OPS_AUTH_KEYS` | JSON: `{"activation": "<32-byte-hex>"}` | Palisade card-ops |
| `SERVICE_AUTH_CARD_OPS_SECRET` | 32-byte hex | Palisade activation |
| `GP_MASTER_KEY` (interim) OR `gpEncKeyArn`/`gpMacKeyArn`/`gpDekKeyArn` (prod) | Per-FI SCP03 keys | card-ops |

### 2d. Verify Palisade

```bash
# Each service responds 200 on /api/health
for H in tap activation data-prep rca batch-processor sftp admin card-ops; do
  curl -sSf https://palisade-$H.karta.cards/api/health \
    && echo " — $H OK"
done
```

---

## Step 3 — deploy Vera

### 3a. Apply migrations — **DESTRUCTIVE** for Phase 3 shrink

```bash
cd /Users/danderson/Vera

# Point at prod, status first
DATABASE_URL="postgresql://vera:${PROD_PW}@vera-prod.rds.amazonaws.com:5432/vera" \
  npx prisma migrate status --schema packages/db/prisma/schema.prisma

# Apply
DATABASE_URL="postgresql://vera:${PROD_PW}@vera-prod.rds.amazonaws.com:5432/vera" \
  npx prisma migrate deploy --schema packages/db/prisma/schema.prisma
```

**WHAT IT DOES**: Migration `20260419200000_phase3_vera_shrink` runs
`DROP TABLE IF EXISTS ... CASCADE` on 14 tables.  If any row data there
matters and wasn't copied to Palisade, it's gone.  Our split flow copied
Card/IssuerProfile/ChipProfile/SadRecord/ProvisioningSession/etc. to
Palisade as part of Phase 1-3.  Confirm Palisade has your production
card data *before* running this migration.

Sanity check:
```bash
# Palisade row count for Card
DATABASE_URL="postgresql://palisade:${PROD_PW}@palisade-prod.rds.amazonaws.com:5432/palisade" \
  psql -c 'SELECT count(*) FROM "Card";'

# Vera row count for the same (should match)
DATABASE_URL="postgresql://vera:${PROD_PW}@vera-prod.rds.amazonaws.com:5432/vera" \
  psql -c 'SELECT count(*) FROM "Card";'
```

Numbers don't match → stop, figure out why before dropping.

### 3b. Push Vera images + update services

```bash
for SERVICE in pay vault admin; do
  docker build --build-arg SERVICE=$SERVICE -t vera-$SERVICE .
  docker tag vera-$SERVICE:latest \
    $ACCOUNT.dkr.ecr.ap-southeast-2.amazonaws.com/vera-$SERVICE:$GIT_SHA
  docker push \
    $ACCOUNT.dkr.ecr.ap-southeast-2.amazonaws.com/vera-$SERVICE:$GIT_SHA
done

for SERVICE in pay vault admin; do
  aws ecs update-service \
    --cluster vera-prod \
    --service vera-$SERVICE \
    --force-new-deployment
done
```

### 3c. Vera secrets

| Secret | Value | Consumer |
|---|---|---|
| `PALISADE_BASE_URL` | `https://palisade-activation-internal.karta.cards` | Vera pay |
| `SERVICE_AUTH_PALISADE_SECRET` | 32-byte hex (matches Palisade's `PAY_AUTH_KEYS[pay]`) | Vera pay |

The two `PAY_AUTH_KEYS[pay]` + `SERVICE_AUTH_PALISADE_SECRET` must be
the same value; rotate together.

### 3d. Verify Vera

```bash
for H in pay vault admin; do
  curl -sSf https://vera-$H.karta.cards/api/health \
    && echo " — $H OK"
done
```

### 3e. Delete retired Vera resources

Only after confirming Vera prod is healthy for 24h:

```bash
# ECS services: stop + delete the 7 moved services
for SERVICE in tap activation data-prep rca batch-processor sftp card-ops; do
  aws ecs update-service --cluster vera-prod --service vera-$SERVICE --desired-count 0
  # Wait ~30s for drain
  aws ecs delete-service --cluster vera-prod --service vera-$SERVICE --force
done

# ALB target groups + listener rules for those services
# (specific rule ARNs vary — list before delete)

# ECR repos: keep last image for audit, delete the rest or leave dormant
```

---

## Step 4 — smoke test

```bash
# End-to-end cross-repo flow
bash /Users/danderson/Vera/scripts/dev-stack.sh smoke
# OR if running against prod (override URLs):
VERA_VAULT_URL=https://vera-vault.karta.cards \
PALISADE_ACTIVATION_URL=https://palisade-activation.karta.cards \
  bash /Users/danderson/Vera/scripts/dev-stack.sh smoke

# Real card tap on Palisade post-deploy
# (manual — requires physical card + reader)
```

---

## Rollback

### Palisade rollback

If Palisade deploy fails, before rolling forward on Vera:

```bash
# 1. Revert ECS service to previous task def
for SERVICE in tap activation data-prep rca batch-processor sftp admin card-ops; do
  # Get previous active task def revision
  PREV=$(aws ecs describe-services \
    --cluster palisade-prod --services palisade-$SERVICE \
    --query 'services[0].deployments[?status==`PRIMARY`].taskDefinition' \
    --output text)
  # Redeploy it
  aws ecs update-service \
    --cluster palisade-prod --service palisade-$SERVICE \
    --task-definition $PREV --force-new-deployment
done

# 2. Revert DB migration if applicable
# Prisma doesn't auto-revert.  If the migration was additive (new table
# or column), leave it — harmless. If it was destructive, restore from
# the pre-deploy snapshot (manual AWS console).
```

### Vera rollback after Phase 3 shrink has run

**Tables are gone.**  Only path back is the RDS snapshot from Step 1.

```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier vera-prod-rollback \
  --db-snapshot-identifier vera-prod-pre-<TIMESTAMP>

# Swap the CNAME / Route53 record
# ... (specific to your infra) ...

# Re-point the ECS services at the rolled-back DB
aws ecs update-service --cluster vera-prod --service vera-pay --force-new-deployment
# (assumes DATABASE_URL comes from a Secrets Manager ref; the
# actual DNS change picks up automatically on next container start)
```

Practical cost: 10-30 min downtime.  Avoid by confirming Palisade has all
necessary card data *before* triggering the destructive migration.

---

## Common gotchas

- **HMAC key mismatch**: if the Palisade pay endpoint returns 401, the
  usual cause is `PAY_AUTH_KEYS[pay]` on Palisade ≠
  `SERVICE_AUTH_PALISADE_SECRET` on Vera.  They must be the same 32-byte hex.
- **Stale Prisma client**: after a migration that drops columns, the
  container needs to run `prisma generate` at build time — verify the
  Dockerfile does so before `tsc -b`.
- **ALB WS support**: card-ops + RCA use WebSocket.  Confirm the target
  group's "stickiness" + load-balancer upgrade support are on.
- **Card-ops port conflict** with admin (both default 3009): explicit
  `PORT=` override on one of them in task def env.
- **`docker compose up` locally doesn't match prod**: local uses
  docker-compose Postgres on 5433 (Palisade) / 5432 (Vera).  Prod uses
  RDS.  Don't rely on local behaviour for prod assumptions.

---

## Contact points

- Prisma migration failures: check `packages/db/prisma/migrations/`
  ordering + the migration SQL itself before rolling back
- WS routing: check the ALB listener rules (port 3007 on Palisade for
  rca, port 3009 for card-ops)
- Cross-repo HMAC: double-check both secrets are the same bytes
- Seed script: `/Users/danderson/Palisade/scripts/seed-545490-issuers.ts`
  can re-populate IssuerProfile / ChipProfile / FinancialInstitution /
  Program if production lost them somehow (idempotent upserts)
