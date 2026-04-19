#!/usr/bin/env bash
#
# dev-stack.sh — single-entry dispatcher for the local Vera + Palisade
# integration stack.  Forwards `up`, `down`, and `smoke` subcommands to
# the three focused scripts alongside it.
#
# See docs/runbooks/dev-stack.md for the full runbook.
#
# Usage:
#   bash scripts/dev-stack.sh up     # bring up both pg + migrate + seed
#   bash scripts/dev-stack.sh down   # stop containers + kill node procs
#   bash scripts/dev-stack.sh smoke  # health + cross-repo signed requests
#
# Service startup (`npm run dev`) is NOT orchestrated from here — run it
# in its own shell per repo so logs stay readable and ctrl-C works.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: bash scripts/dev-stack.sh <command>

Commands:
  up     Start both postgreses, run migrations, seed Palisade fixtures.
         Then prints the npm run dev commands to run in separate shells.
  down   Stop both compose stacks and kill stray dev-server node processes.
  smoke  Curl every service's /api/health + exercise cross-repo HMAC
         flows (vault/store, vault/register, cards/lookup).  Assumes the
         stack is already up.

See scripts/dev-stack-{up,down,smoke}.sh for the underlying scripts.
See docs/runbooks/dev-stack.md for the full runbook.
EOF
}

cmd="${1:-}"
case "$cmd" in
  up)
    exec bash "$SCRIPT_DIR/dev-stack-up.sh"
    ;;
  down)
    shift
    exec bash "$SCRIPT_DIR/dev-stack-down.sh" "$@"
    ;;
  smoke)
    exec bash "$SCRIPT_DIR/dev-stack-smoke.sh"
    ;;
  ""|-h|--help|help)
    usage
    exit 0
    ;;
  *)
    printf 'unknown command: %s\n\n' "$cmd" >&2
    usage >&2
    exit 2
    ;;
esac
