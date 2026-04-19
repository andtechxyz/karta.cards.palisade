# Palisade — card issuance, personalisation, activation

Palisade is the card-side service family. It handles everything from data
prep and personalisation through to SUN-tap decrypt, activation ceremonies,
and runtime APDU relay. PAN tokenisation is **not** in scope here — card
data is vaulted via an HTTP call to Vera at registration time, and Palisade
only stores the opaque token Vera returns.

This repo is one half of a two-repo split:

- **Vera** (`/Users/danderson/Vera`) — vault + OBO ARQC + payment
  orchestration. Sold independently.
- **Palisade** (this repo) — card issuance, personalisation, activation,
  tap decrypt, RCA. Sold independently.

Both can ship to the same AWS org but neither depends on the other at
build/test time. Palisade → Vera traffic is HMAC-signed HTTP only.

## Services

```
services/
├── tap/              SUN-tap landing — NXP AN14683 PICC decrypt + CMAC + session mint
├── activation/       Session begin/finish, card register, WebAuthn (CROSS_PLATFORM)
├── data-prep/        EMV SAD prep; AWS Payment Cryptography for UDK derivation + SAD encrypt
├── rca/              Real-time chip authentication relay; plan-mode WS, attestation verifier stub
├── card-ops/         Admin GlobalPlatform ops — install_pa, install_payment_applet,
│                     personalise_payment_applet, list_applets, reset_pa_state; SCP03 over WS
├── admin/            Card + program + IssuerProfile + ChipProfile CRUD; partner ingestion;
│                     serves `/api/capabilities`; path-rewrites `/palisade-api/*` → `/api/*`
├── batch-processor/  Embossing batch parser; routes to activation's /api/cards/register
└── sftp/             Partner file ingester; writes EmbossingBatch rows
```

Each service has its own ECS task def and ALB priority (see
`scripts/aws-setup.sh`). Ports: tap 3001, activation 3002, admin 3009,
data-prep 3006, rca 3007, batch-processor 3008, sftp 22, card-ops
shares admin's 3009 ALB target via path routing.

## Packages

```
packages/
├── core/               Shared utils: ApiError, validation, key-provider interface, env shapes
├── db/                 Prisma schema (Palisade-owned tables only) + shared client
├── webauthn/           @simplewebauthn wrapper — CTAP1 for NFC activation
├── card-programs/      Program-type classification + NDEF URL template resolution (tier
│                       rules moved to Vera's @vera/programs in Phase 4c)
├── service-auth/       HMAC-SHA256 request signing + verification middleware
├── vault-client/       Typed HMAC client to Vera's vault service
├── retention/          PCI-DSS TTL sweeps (activation sessions only post-split)
├── emv/                TLV, DGI, Track2, chip profiles, SAD/IAD builders, APDUs, CAP parser
├── provisioning-client/ HTTP client for data-prep provisioning calls
├── sdm-keys/           SDM key-derivation backends (hsm / local / mock)
├── cognito-auth/       AWS Cognito middleware for admin + activation routes
├── handoff/            Cross-service NDEF handoff signing
└── metrics/            EMF + noop metrics backends (@palisade/metrics)
```

## Talking to Vera

Palisade never reads or writes Vera's database. All cross-side calls are
HMAC-signed HTTP via `@palisade/vault-client`:

- `POST {VERA_VAULT_URL}/api/vault/register` — idempotent PAN vaulting;
  returns `{ vaultToken, panLast4 }` which Palisade stores as
  `Card.vaultToken` + `Card.panLast4` (plus the rest of the mirrored
  display metadata). The call is keyed by `cardRef` as the
  `idempotencyKey`, so retries are safe.

If Vera is down, card registration is the only Palisade flow that
blocks. SUN tap, activation session minting, card-ops install/perso,
batch processing, and the WebAuthn ceremony continue to work (they
don't touch the vault).

The shared admin SPA is hosted out of Vera's admin service but reaches
Palisade admin via `/palisade-api/*`. An in-app middleware on Palisade
admin rewrites `/palisade-api/*` → `/api/*` so every route declaration
stays on `/api/*` (see commit `b0dd850`). Production's ALB priority-2
rule matches `manage.karta.cards` + `/palisade-api/*` and forwards to
palisade-admin; Vera's priority-4 host-only rule catches everything
else. `CORS_ORIGINS` on Palisade admin must include
`https://manage.karta.cards` so the SPA's preflights pass.

## First run

```bash
docker compose up -d         # Postgres on port 5433 to avoid colliding with Vera's 5432
npm install
cp .env.example .env
npm run prisma:generate
npm run prisma:migrate
npm run dev
```

The activation frontend runs on `5174`; the shared admin SPA (served by
Vera) runs on `5176` and proxies `/palisade-api/*` → `3009` for Palisade
admin calls.

## Operational runbooks

See `docs/runbooks/` for:

- `key-rotation.md` — per-FI GP keys (Secrets Manager), UDK derivations
  (AWS Payment Cryptography), SDM master keys, card-field DEK, inter-
  service HMAC.
- `fi-onboarding.md` — FI onboarding end-to-end; references the
  `seed-545490-issuers.ts` template and the admin SPA's IssuerProfile
  and ChipProfile pages.
- `incident-response.md` — common operational failures including
  cross-repo (Palisade ⇌ Vera) failure modes.
- `attestation-vendor-rekey.md` — NXP / Infineon anchor rotation.

## Relationship to sibling projects

- **Vera** — the other half of this split. See above.
- **`~/Documents/Claude Code/New T4T/`** — original SUN-tap activation
  prototype (Python + Next.js). Palisade's `services/tap/src/sun/` is a
  1:1 port of its `sun_validator.py` / `key_manager.py`.
- **`~/Documents/Claude Code/Palisade/`** — Python-based legacy card
  issuance platform. Named overlap is coincidental — this Node repo is
  the runtime/edge layer; the Python one is the factory side. No code
  sharing.
