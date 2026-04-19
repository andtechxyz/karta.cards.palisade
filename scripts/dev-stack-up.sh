#!/usr/bin/env bash
#
# dev-stack-up.sh — Bring up the local Vera + Palisade postgres pair,
# run prisma migrations on both, seed Palisade issuer fixtures.
#
# Prints the command the user should run next to start the node services
# (we do NOT start them from here — `npm run dev` is a long-lived
# foreground process in each repo and is best invoked in its own shell).
#
# Prereqs:
#   - docker (or docker compose shim) on PATH
#   - node 22, npm 10
#   - Both repos cloned at sibling paths:
#         /Users/danderson/Vera
#         /Users/danderson/Palisade
#
# Usage:
#   bash scripts/dev-stack-up.sh
#
# Idempotent: re-running starts the stopped postgres containers and
# re-applies migrations (`prisma migrate deploy` is a no-op if the DB
# is already at HEAD).
#
# Side effects: creates / starts two postgres containers
#   vera-postgres (port 5432) and palisade-postgres (port 5433).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERA_REPO="${VERA_REPO:-/Users/danderson/Vera}"
PALISADE_REPO="${PALISADE_REPO:-/Users/danderson/Palisade}"

log() { printf '\033[1;34m[dev-stack-up]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[dev-stack-up] %s\033[0m\n' "$*" >&2; exit 1; }

[[ -d "$VERA_REPO" ]] || die "VERA_REPO not found at $VERA_REPO"
[[ -d "$PALISADE_REPO" ]] || die "PALISADE_REPO not found at $PALISADE_REPO"

command -v docker >/dev/null 2>&1 || die "docker not on PATH"

# --- Postgres: Vera (5432) --------------------------------------------------
log "bringing up Vera postgres (port 5432)"
( cd "$VERA_REPO" && docker compose up -d postgres )

# --- Postgres: Palisade (5433) ---------------------------------------------
log "bringing up Palisade postgres (port 5433)"
( cd "$PALISADE_REPO" && docker compose up -d postgres )

# Give postgres a beat to accept connections.  The healthcheck interval
# on Vera's compose is 5s; Palisade's compose has no healthcheck so we
# poll pg_isready via docker exec.
log "waiting for Vera postgres to accept connections"
for i in {1..20}; do
  if docker exec vera-postgres pg_isready -U vera -d vera >/dev/null 2>&1; then
    break
  fi
  sleep 1
  [[ $i -eq 20 ]] && die "Vera postgres never became ready"
done

log "waiting for Palisade postgres to accept connections"
# Palisade compose doesn't set container_name so derive it from the
# project directory.  Prefer `docker compose ps` which handles naming.
PALISADE_PG=$(
  cd "$PALISADE_REPO" && docker compose ps --format '{{.Name}}' postgres | head -n 1
)
[[ -n "$PALISADE_PG" ]] || die "Could not find Palisade postgres container"
for i in {1..20}; do
  if docker exec "$PALISADE_PG" pg_isready -U palisade -d palisade >/dev/null 2>&1; then
    break
  fi
  sleep 1
  [[ $i -eq 20 ]] && die "Palisade postgres never became ready"
done

# --- Migrations ------------------------------------------------------------
log "running Vera prisma migrate deploy"
(
  cd "$VERA_REPO" && \
  DATABASE_URL="postgresql://vera:vera@localhost:5432/vera?schema=public" \
    npx --yes prisma migrate deploy --schema packages/db/prisma/schema.prisma
)

log "running Palisade prisma migrate deploy"
(
  cd "$PALISADE_REPO" && \
  DATABASE_URL="postgresql://palisade:palisade@localhost:5433/palisade?schema=public" \
    npx --yes prisma migrate deploy --schema packages/db/prisma/schema.prisma
)

# --- Seed data -------------------------------------------------------------
log "seeding Palisade 545490 issuers"
(
  cd "$PALISADE_REPO" && \
  DATABASE_URL="postgresql://palisade:palisade@localhost:5433/palisade?schema=public" \
    npx --yes tsx scripts/seed-545490-issuers.ts
) || log "WARN: seed-545490-issuers failed (non-fatal — may already be seeded)"

# --- Next steps ------------------------------------------------------------
cat <<EOF

\033[1;32m[dev-stack-up]\033[0m Both postgreses up, migrated, seeded.

To bring the node services up, open two terminals:

  # Terminal 1 — Vera (pay, vault, admin on :3003/:3004/:3005)
  cd $VERA_REPO && npm run dev

  # Terminal 2 — Palisade (tap, activation, data-prep, rca, card-ops, admin)
  cd $PALISADE_REPO && npm run dev

Then run the smoke tests:

  bash $SCRIPT_DIR/dev-stack-smoke.sh

Or the integration tests (against the live stack):

  cd $VERA_REPO && INTEGRATION=1 \\
    npx vitest run tests/integration/cross-repo.test.ts

To tear down:

  bash $SCRIPT_DIR/dev-stack-down.sh

EOF
