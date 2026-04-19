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
├── data-prep/        EMV SAD prep; AWS Payment Cryptography for key derivation
├── rca/              Real-time chip authentication relay (WebSocket APDU proxy)
├── batch-processor/  Embossing batch parser; routes to activation's /api/cards/register
└── sftp/             Partner file ingester; writes EmbossingBatch rows
```

## Packages

```
packages/
├── core/               Shared utils: ApiError, validation, key-provider interface
├── db/                 Prisma schema (Palisade-owned tables only) + shared client
├── webauthn/           @simplewebauthn wrapper — CTAP1 for NFC activation
├── card-programs/      Tier-rule engine + NDEF URL template resolution
├── service-auth/       HMAC-SHA256 request signing + verification middleware
├── vault-client/       Typed HMAC client to Vera's vault service
├── retention/          PCI-DSS TTL sweeps
├── emv/                TLV, DGI, Track2, chip profiles, SAD/IAD builders, APDUs
├── provisioning-client/ HTTP client for data-prep provisioning calls
└── cognito-auth/       AWS Cognito middleware for admin routes
```

## Talking to Vera

Palisade never reads or writes Vera's database. All cross-side calls are
HMAC-signed HTTP via `@palisade/vault-client`:

- `POST {VERA_VAULT_URL}/api/vault/register` — idempotent PAN vaulting;
  returns `{ vaultToken }` which Palisade stores as `Card.vaultToken`.

If Vera is down, card registration is the only Palisade flow that blocks.
SUN tap, activation session minting, and the registration ceremony
continue to work (they don't touch the vault).

## First run

```bash
docker compose up -d
npm install
cp .env.example .env
npm run prisma:generate
npm run prisma:migrate
npm run dev
```

## Relationship to sibling projects

- **Vera** — the other half of this split. See above.
- **`~/Documents/Claude Code/New T4T/`** — original SUN-tap activation
  prototype (Python + Next.js). Palisade's `services/tap/src/sun/` is a
  1:1 port of its `sun_validator.py` / `key_manager.py`.
- **`~/Documents/Claude Code/Palisade/`** — Python-based legacy card
  issuance platform. Named overlap is coincidental — this Node repo is
  the runtime/edge layer; the Python one is the factory side. No code
  sharing.
