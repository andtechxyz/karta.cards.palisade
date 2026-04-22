#!/usr/bin/env bash
#
# dev-stack-smoke.sh — Health + cross-repo signed-request smoke test.
#
# Assumes `bash scripts/dev-stack-up.sh` has been run and BOTH repos'
# `npm run dev` are up in separate shells.
#
# What it proves (in order):
#   1. Every service's /api/health returns 200 + {ok: true}.
#   2. A Palisade-signed request (keyId='activation') can POST to Vera's
#      vault/store and receive a vaultEntryId + panLast4.
#   3. If Vera's /api/vault/register exists, the same HMAC reaches it and
#      returns {vaultToken, panLast4}.
#   4. If Palisade's /api/cards/lookup/:cardId exists (parallel-agent work),
#      a pay-signed request reaches it and returns card state.
#
# Everything in step 3+4 is 404-tolerant: if the route isn't there yet,
# we warn and continue rather than fail.  Steps 1 and 2 are hard fails.
#
# Usage:
#   bash scripts/dev-stack-smoke.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERA_REPO="${VERA_REPO:-/Users/danderson/Vera}"
PALISADE_REPO="${PALISADE_REPO:-/Users/danderson/Palisade}"

log()  { printf '\033[1;34m[smoke]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[smoke]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[smoke]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[smoke] FAIL: %s\033[0m\n' "$*" >&2; EXIT_CODE=1; }

EXIT_CODE=0

# --- Secrets --------------------------------------------------------------
# These MUST match the defaults in tests/setup.ts.  Each test secret is a
# distinct repeated hex digit so a cross-keyspace leak fails loudly.
SERVICE_AUTH_ACTIVATION_SECRET="${SERVICE_AUTH_ACTIVATION_SECRET:-$(printf '6%.0s' {1..64})}"
SERVICE_AUTH_PAY_SECRET="${SERVICE_AUTH_PAY_SECRET:-$(printf '5%.0s' {1..64})}"

# --- Health checks --------------------------------------------------------
check_health() {
  local name="$1" url="$2"
  local body status
  body=$(curl -sS -o /tmp/dev-stack-smoke-body -w '%{http_code}' "$url" 2>/dev/null || echo '000')
  status="$body"
  if [[ "$status" != "200" ]]; then
    fail "$name health returned $status (url: $url)"
    return 1
  fi
  if ! grep -q '"ok":true' /tmp/dev-stack-smoke-body; then
    fail "$name health missing {ok:true} — body: $(cat /tmp/dev-stack-smoke-body)"
    return 1
  fi
  ok "$name health OK"
}

log "phase 1: health checks"

# Vera-repo services.  Ports match the PORT defaults in the Vera repo.
check_health "vera-pay"       "http://localhost:3003/api/health"
check_health "vera-vault"     "http://localhost:3004/api/health"
# Vera-repo admin on :3005 (see Vera/services/admin).  Not to be confused
# with palisade-admin (:3009) which is card-side.
check_health "vera-admin"     "http://localhost:3005/api/health"

# Palisade services.  Palisade admin is on 3009 (see its env.ts — 3005
# is Vera's admin, so Palisade picked 3009 to avoid collision).
# card-ops ALSO defaults to 3009; if the admin-colocation comment is
# accurate then one of them runs on a different port in practice.  We
# only probe admin here; add card-ops probe explicitly if/when it
# moves to its own port.
check_health "palisade-tap"        "http://localhost:3001/api/health"
check_health "palisade-activation" "http://localhost:3002/api/health"
check_health "palisade-data-prep"  "http://localhost:3006/api/health"
check_health "palisade-rca"        "http://localhost:3007/api/health"
check_health "palisade-admin"      "http://localhost:3009/api/health"

if [[ $EXIT_CODE -ne 0 ]]; then
  fail "health phase failed — not attempting signed-request phase"
  exit $EXIT_CODE
fi

# --- Signed request helper -------------------------------------------------
# Build a VeraHmac Authorization header in pure node so we don't depend on
# any service being importable from the shell.  Node 22 ships with the
# crypto module; no npm install needed.
sign_request() {
  local method="$1" path="$2" body="$3" key_id="$4" secret="$5"
  node --input-type=module -e '
    import { createHmac, createHash } from "node:crypto";
    const [method, path, body, keyId, secret] = process.argv.slice(1);
    const ts = Math.floor(Date.now() / 1000);
    const bodyHash = createHash("sha256")
      .update(Buffer.from(body, "utf8"))
      .digest("hex");
    const canonical = `${method}\n${path}\n${ts}\n${bodyHash}`;
    const sig = createHmac("sha256", Buffer.from(secret, "hex"))
      .update(canonical)
      .digest("hex");
    process.stdout.write(`VeraHmac keyId=${keyId},ts=${ts},sig=${sig}`);
  ' "$method" "$path" "$body" "$key_id" "$secret"
}

# --- Phase 2: Palisade (keyId=activation) → Vera vault/store --------------
log "phase 2: Palisade-signed request to Vera vault/store"

STORE_BODY='{"pan":"4242424242424242","expiryMonth":"12","expiryYear":"2028","cardholderName":"Smoke Test","purpose":"dev_stack_smoke"}'
STORE_AUTH=$(sign_request POST /api/vault/store "$STORE_BODY" activation "$SERVICE_AUTH_ACTIVATION_SECRET")

STORE_RESP=$(mktemp)
STORE_CODE=$(
  curl -sS -o "$STORE_RESP" -w '%{http_code}' \
    -X POST http://localhost:3004/api/vault/store \
    -H 'content-type: application/json' \
    -H "authorization: $STORE_AUTH" \
    -d "$STORE_BODY"
)

if [[ "$STORE_CODE" == "201" ]] || [[ "$STORE_CODE" == "200" ]]; then
  if grep -q '"panLast4":"4242"' "$STORE_RESP"; then
    ok "vault/store round-trip: $(cat "$STORE_RESP")"
  else
    fail "vault/store 2xx but missing panLast4 — body: $(cat "$STORE_RESP")"
  fi
else
  fail "vault/store returned $STORE_CODE — body: $(cat "$STORE_RESP")"
fi

# --- Phase 3: /api/vault/register (optional, not-yet-landed) --------------
log "phase 3: Palisade-signed request to Vera vault/register (optional)"

REG_BODY='{"cardRef":"smoke_card_1","pan":"4242424242424242","expiryMonth":"12","expiryYear":"2028","cardholderName":"Smoke Test","idempotencyKey":"smoke_1"}'
REG_AUTH=$(sign_request POST /api/vault/register "$REG_BODY" activation "$SERVICE_AUTH_ACTIVATION_SECRET")

REG_RESP=$(mktemp)
REG_CODE=$(
  curl -sS -o "$REG_RESP" -w '%{http_code}' \
    -X POST http://localhost:3004/api/vault/register \
    -H 'content-type: application/json' \
    -H "authorization: $REG_AUTH" \
    -d "$REG_BODY"
)

case "$REG_CODE" in
  200|201)
    if grep -q '"vaultToken"' "$REG_RESP" && grep -q '"panLast4"' "$REG_RESP"; then
      ok "vault/register round-trip: $(cat "$REG_RESP")"
    else
      warn "vault/register 2xx but missing expected fields — body: $(cat "$REG_RESP")"
    fi
    ;;
  404)
    warn "vault/register 404 — endpoint not yet landed on Vera vault; skipping"
    ;;
  *)
    fail "vault/register returned $REG_CODE — body: $(cat "$REG_RESP")"
    ;;
esac

# --- Phase 4: Pay → Palisade /api/cards/lookup/:cardId (optional) ---------
log "phase 4: pay-signed request to Palisade cards/lookup (optional)"

LOOKUP_PATH="/api/cards/lookup/smoke-card-id"
LOOKUP_AUTH=$(sign_request GET "$LOOKUP_PATH" "" pay "$SERVICE_AUTH_PAY_SECRET")

LOOKUP_RESP=$(mktemp)
LOOKUP_CODE=$(
  curl -sS -o "$LOOKUP_RESP" -w '%{http_code}' \
    -X GET "http://localhost:3002$LOOKUP_PATH" \
    -H "authorization: $LOOKUP_AUTH"
)

case "$LOOKUP_CODE" in
  200)
    ok "cards/lookup round-trip: $(cat "$LOOKUP_RESP")"
    ;;
  404)
    # 404 is ambiguous here — could mean the route doesn't exist OR the
    # card id we passed is bogus.  Inspect the body to disambiguate.
    if grep -q 'card_not_found\|not found' "$LOOKUP_RESP"; then
      ok "cards/lookup reachable; returned card_not_found for bogus id as expected"
    else
      warn "cards/lookup 404 with non-card-not-found body — route may not be landed yet: $(cat "$LOOKUP_RESP")"
    fi
    ;;
  401)
    warn "cards/lookup 401 — HMAC not accepted (may need PROVISION_AUTH_KEYS entry for keyId=pay)"
    ;;
  *)
    warn "cards/lookup returned $LOOKUP_CODE — body: $(cat "$LOOKUP_RESP")"
    ;;
esac

# --- Summary --------------------------------------------------------------
if [[ $EXIT_CODE -eq 0 ]]; then
  ok "smoke tests passed"
else
  fail "smoke tests had failures — see above"
fi

exit $EXIT_CODE
