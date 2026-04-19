# Runbook: Local Vera + Palisade Dev Stack

**Document Owner:** Platform Team
**Last Reviewed:** 2026-04-19

## 1. Scope

This runbook covers running Vera and Palisade side-by-side on a developer laptop and exercising the cross-repo HMAC-signed flows end-to-end without deploying.

**Primary use cases:**
1. Reproducing a bug that only surfaces when both repos are live (e.g. Palisade activation failing to register against Vera vault).
2. Smoke-testing a cross-repo change before PR (e.g. a new signed request path).
3. Validating that the wire protocol between `@palisade/service-auth` and `@vera/service-auth` stays byte-compatible after a refactor on either side.

**Not covered here:**
- Full mobile-app provisioning flow (requires the iOS/Android builds).
- AWS-specific flows (KMS / Payment Cryptography / S3) — those stub out in dev, with local AES-128-ECB for SAD blobs.

## 2. Prerequisites

- `docker` or `docker compose` on PATH (Docker Desktop / Colima / similar).
- Node 22, npm 10.
- Both repos cloned at sibling paths:
  - `/Users/danderson/Vera`
  - `/Users/danderson/Palisade`

## 3. Bring the stack up

```bash
# From either repo root — the script is identical on both sides.
bash scripts/dev-stack.sh up
```

What this does:

1. `docker compose up -d postgres` in Vera (container `vera-postgres`, host port 5432).
2. `docker compose up -d postgres` in Palisade (container auto-named, host port 5433).
3. Polls `pg_isready` until both postgreses accept connections.
4. Runs `prisma migrate deploy` against each repo's DB.
5. Runs `scripts/seed-545490-issuers.ts` against Palisade (non-fatal: if already seeded, the script no-ops).
6. Prints instructions for starting the node services.

Then start the services in two shells:

```bash
# Terminal A
cd /Users/danderson/Vera && npm run dev

# Terminal B
cd /Users/danderson/Palisade && npm run dev
```

Both repos use `concurrently` + `tsx watch` so the services live-reload on save.

### Port map

Ports match the `PORT` default in each service's `src/env.ts`.

| Service                  | Repo      | Port | Notes                                          |
| ------------------------ | --------- | ---- | ---------------------------------------------- |
| tap                      | Palisade  | 3001 |                                                |
| activation               | Palisade  | 3002 |                                                |
| pay                      | Vera      | 3003 |                                                |
| vault                    | Vera      | 3004 |                                                |
| admin (Vera)             | Vera      | 3005 |                                                |
| data-prep                | Palisade  | 3006 |                                                |
| rca                      | Palisade  | 3007 |                                                |
| batch-processor          | Palisade  | 3008 |                                                |
| admin (Palisade)         | Palisade  | 3009 | Set to 3009 to avoid clash with Vera admin.    |
| card-ops                 | Palisade  | 3009 | Same default as Palisade admin; override with `PORT=` env var when running both. |
| postgres (Vera)          | Vera      | 5432 |                                                |
| postgres (Palisade)      | Palisade  | 5433 | Mapped to 5432 inside the container.           |

**Known pin:** Palisade's card-ops and admin both default to `PORT=3009` — in practice one of them is set to a different port via the env. If both services are being run, set `PORT=3010 npm run dev -w services/card-ops` (or similar) in a third shell.

## 4. Smoke test

After `npm run dev` is up in both repos:

```bash
bash scripts/dev-stack.sh smoke
```

This runs four phases:

1. **Health** — curl `/api/health` on every service; assert 200 + `{ok:true}`.
2. **Cross-repo HMAC: Palisade → Vera vault/store** — mint a `VeraHmac keyId=activation,...` signature using the test secret (`6` × 64), POST a test PAN to Vera's `/api/vault/store`, assert `{panLast4:"4242"}`. This is the hard assertion — a failure means the HMAC wire protocol has drifted or the test secrets in `tests/setup.ts` don't match the env the services booted with.
3. **Cross-repo HMAC: Palisade → Vera vault/register** (optional) — same signed request pattern against `/api/vault/register`, looking for `{vaultToken, panLast4}`. **Skips on 404** — the route was described in the task brief but isn't landed on the Vera vault at time of writing; this phase will start hard-asserting once the endpoint ships.
4. **Cross-repo HMAC: Vera pay → Palisade cards/lookup** (optional) — reverse direction, pay signs a GET to Palisade `/api/cards/lookup/:cardId`. **Currently skips** — the endpoint is landing via a parallel agent and may not be present.

Phase 1 + 2 are mandatory; the script exits non-zero if either fails. Phases 3 + 4 print warnings but don't gate.

### What a successful run looks like

```
[smoke] phase 1: health checks
[smoke] vera-pay health OK
[smoke] vera-vault health OK
[smoke] vera-admin health OK
[smoke] palisade-tap health OK
[smoke] palisade-activation health OK
[smoke] palisade-data-prep health OK
[smoke] palisade-rca health OK
[smoke] palisade-admin health OK
[smoke] phase 2: Palisade-signed request to Vera vault/store
[smoke] vault/store round-trip: {"vaultEntryId":"...","panLast4":"4242","deduped":false}
[smoke] phase 3: Palisade-signed request to Vera vault/register (optional)
[smoke] vault/register 404 — endpoint not yet landed on Vera vault; skipping
[smoke] phase 4: pay-signed request to Palisade cards/lookup (optional)
[smoke] cards/lookup reachable; returned card_not_found for bogus id as expected
[smoke] smoke tests passed
```

### What a failure looks like

If phase 2 fails with 401 `unknown_key` or `bad_signature`, the most common cause is **the service started with a real `.env` that has different secrets than `tests/setup.ts`**. The smoke script uses the deterministic test secrets (`5` × 64 for pay, `6` × 64 for activation) — for the smoke to pass, either:

- Don't load `.env` when running `npm run dev` (delete the file or rename), so `getConfig()` falls through to the test defaults; OR
- Override the shell env before `npm run dev`:
  ```bash
  SERVICE_AUTH_ACTIVATION_SECRET="$(printf '6%.0s' {1..64})" \
  SERVICE_AUTH_KEYS='{"pay":"'$(printf '5%.0s' {1..64})'","activation":"'$(printf '6%.0s' {1..64})'","admin":"'$(printf '7%.0s' {1..64})'"}' \
    npm run dev
  ```

A future follow-up is a `scripts/dev-stack.env` file both repos source from, to keep this consistent.

## 5. Vitest integration run

The smoke script is curl-only; for a richer assertion surface there's a vitest file that hits the same endpoints:

```bash
cd /Users/danderson/Vera && \
  INTEGRATION=1 npx vitest run tests/integration/cross-repo.test.ts
```

The `INTEGRATION=1` flag unlocks the file — without it the whole suite is skipped so normal `npm test` runs stay hermetic.

## 6. Tear down

```bash
bash scripts/dev-stack.sh down              # stop containers, keep pg data
bash scripts/dev-stack.sh down --volumes    # nuke pg data (full reset)
```

The `down` command also pkills any stray `tsx watch` processes left behind by an orphaned `npm run dev`.

## 7. Follow-ups (out of scope for the harness)

- [ ] Vera `/api/vault/register` endpoint — currently absent; `vault-client.registerCard()` on Palisade POSTs there expecting `{vaultToken, panLast4}`. Add the route on vault and remove the 404-tolerance in phase 3 of the smoke script + the soft-skip in `tests/integration/cross-repo.test.ts`.
- [ ] Admin `/api/capabilities` endpoint — would return `{hasVera:true, hasPalisade:true}` for the admin SPA to branch on. Not landed; `describe.todo` placeholder in the integration test.
- [ ] Shared `scripts/dev-stack.env` — see §4 above; remove the need for callers to construct the test-secret strings by hand.
- [ ] CI stage — no GitHub Actions job runs the smoke today. Candidate: a matrix job that brings up both postgreses via `services:` in the workflow, runs `dev-stack-up.sh`, starts both repos' `npm run dev` in the background, then runs `dev-stack-smoke.sh` + the vitest file. Out of scope for the initial harness because it requires wiring up a Palisade checkout step in the Vera workflow (or vice versa).
