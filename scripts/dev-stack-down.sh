#!/usr/bin/env bash
#
# dev-stack-down.sh — Tear down the local Vera + Palisade dev stack.
# Stops both postgres compose stacks and kills any stray node processes
# left over from `npm run dev` in either repo.
#
# Usage:
#   bash scripts/dev-stack-down.sh           # stop containers, keep volumes
#   bash scripts/dev-stack-down.sh --volumes # also remove pg volumes (WIPES DATA)
#
# Safe to run even if the stack is already down.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERA_REPO="${VERA_REPO:-/Users/danderson/Vera}"
PALISADE_REPO="${PALISADE_REPO:-/Users/danderson/Palisade}"

log() { printf '\033[1;34m[dev-stack-down]\033[0m %s\n' "$*"; }

NUKE_VOLUMES=0
if [[ "${1:-}" == "--volumes" ]]; then
  NUKE_VOLUMES=1
fi

DOWN_ARGS=()
if [[ $NUKE_VOLUMES -eq 1 ]]; then
  log "including --volumes — pg data will be wiped"
  DOWN_ARGS+=("--volumes")
fi

log "stopping Vera compose stack"
( cd "$VERA_REPO" && docker compose down "${DOWN_ARGS[@]}" 2>/dev/null || true )

log "stopping Palisade compose stack"
( cd "$PALISADE_REPO" && docker compose down "${DOWN_ARGS[@]}" 2>/dev/null || true )

# --- Kill stray `npm run dev` children -------------------------------------
# concurrently spawns `tsx watch` processes; users sometimes ctrl-C the
# parent but leave orphans.  We key off the tsx entry-point paths so we
# don't nuke unrelated node processes.
log "killing stray tsx watch processes from Vera + Palisade dev"
for pattern in \
  "services/tap/src/index.ts" \
  "services/activation/src/index.ts" \
  "services/pay/src/index.ts" \
  "services/vault/src/index.ts" \
  "services/admin/src/index.ts" \
  "services/data-prep/src/index.ts" \
  "services/rca/src/index.ts" \
  "services/card-ops/src/index.ts" \
  "services/batch-processor/src/index.ts" \
  "services/sftp/src/index.ts"; do
  pkill -f "$pattern" 2>/dev/null || true
done

# concurrently + vite dev servers
pkill -f "concurrently -n tap,activation" 2>/dev/null || true
pkill -f "concurrently -n pay,vault" 2>/dev/null || true

log "done"
