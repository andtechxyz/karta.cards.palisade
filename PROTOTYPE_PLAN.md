# MChip Chip-Computed-DGI Prototype Plan

**Worktree branch:** `prototype/mchip-chip-computed-dgi`
**Base commit:** `2f5b9a6` on `main`
**Status:** planning only — no code changes yet
**Estimated effort:** 12–18 weeks with 1 JavaCard dev + 1 backend dev in parallel

---

## Goal

Implement a **functional prototype** that satisfies patent claims C17/C22
("no perso image outside the SE") for a single payment scheme —
**Mastercard M/Chip Advance, CVN 18** — with enough fidelity to:

1. Successfully provision a test card end-to-end where the DGI perso image
   is assembled on-chip from a compact server-supplied parameter bundle.
2. Prove byte-parity with the current server-built perso image so we know
   the chip produces a functionally equivalent EMV profile.
3. Transact at a Mastercard M/Chip test POS (not commercial
   certification — just reference reader parity).
4. Measure the latency added to the OTA perso flow (expected: +400–650ms).

**Explicit non-goals for prototype:**

- Visa VSDC support (add after MChip lands)
- Mastercard commercial certification (months-long cycle, separate track)
- Older MChip CVN variants (10, 17)
- Fleet re-personalisation of deployed cards (prototype uses virgin cards)
- Full chip-owned RSA keygen (hybrid: HSM generates ICC RSA, chip receives
  encrypted; see §3 "Key Management" below)

---

## 1. Architecture — before vs after

### Before (today)

```
┌────────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────┐
│  data-prep     │   │ SadRecord    │   │ rca          │   │ PA     │
│  service       │──▶│  (encrypted  │──▶│ (decrypts +  │──▶│ applet │
│  - HSM derives │   │   in DB)     │   │  ships SAD)  │   │ parses │
│    EMV keys    │   │  KMS wrapped │   │              │   │  DGIs, │
│  - builds DGIs │   │   ~600-800B  │   │              │   │ commits│
│  - assembles   │   │              │   │              │   │   to   │
│    SAD image   │   │              │   │              │   │  NVM   │
└────────────────┘   └──────────────┘   └──────────────┘   └────────┘
      ▲                                        │
      │                                        │
  APC (HSM)                          Plaintext SAD lives ~50ms
                                     in rca RAM, scrubbed after
                                     APDU build (S-2 scrub,
                                     commit d697d4f)
```

**Where plaintext perso image exists:** data-prep RAM at build time;
rca RAM for ~50ms at provisioning time.  C17/C22 literal violation:
the image transits the rca container's memory.

### After (prototype)

```
┌────────────────┐   ┌──────────────────┐   ┌──────────────┐   ┌──────────┐
│  data-prep     │   │ ParamRecord      │   │ rca          │   │ PA v3    │
│  service       │──▶│  (encrypted to   │──▶│ (ships param │──▶│ applet   │
│  - HSM derives │   │   chip pubkey)   │   │  bundle)     │   │  - ECDH  │
│    EMV keys    │   │                  │   │              │   │    unwrap│
│  - assembles   │   │  ~180-250 B      │   │              │   │  - builds│
│    param bundle│   │                  │   │              │   │    DGIs  │
│    (NOT DGIs)  │   │                  │   │              │   │  - self- │
│  - ECDH-wraps  │   │                  │   │              │   │    signs │
│    to chip pub │   │                  │   │              │   │    ICC PK│
└────────────────┘   └──────────────────┘   └──────────────┘   │    cert  │
      ▲                                                         │  - commit│
      │                                                         │    to NVM│
  APC (HSM)                                                     └──────────┘
```

**Where plaintext perso image exists:** only on-chip, inside the SE
boundary.  C17/C22 literally satisfied.

---

## 2. Protocol — parameter bundle format

The ECDH-wrapped ParamRecord contains fields the chip needs to reconstruct
a full M/Chip CVN 18 perso image.  Target size: < 256 bytes so it fits
in a single extended-APDU payload without chaining.

```
ParamBundle (decrypted, TLV-encoded):
┌──────────────────────────────────────────────────────────────────────┐
│ Tag     Len  Value                                                   │
├──────────────────────────────────────────────────────────────────────┤
│ 0x01    0x10 PAN (16 BCD-packed nibbles, right-padded with 0xF)      │
│ 0x02    0x01 PSN (Primary Sequence Number, 1 byte BCD)               │
│ 0x03    0x02 Expiry (YYMM, 2 bytes BCD, big-endian)                  │
│ 0x04    0x03 Effective date (YYMMDD, 3 bytes BCD)                    │
│ 0x05    0x03 Service code (3 bytes BCD)                              │
│ 0x06    0x01 Scheme: 0x01 = MChip (constant for prototype)           │
│ 0x07    0x01 CVN: 0x12 = CVN 18 (constant for prototype)             │
│ 0x08    0x07 AID: A0000000041010 (MC-EMV)                            │
│ 0x09    0x10 MK-AC (16 bytes, AES or 3DES depending on card-scheme)  │
│ 0x0A    0x10 MK-SMI (16 bytes)                                       │
│ 0x0B    0x10 MK-SMC (16 bytes)                                       │
│ 0x0C    0x02 AIP (Application Interchange Profile, 2 bytes)          │
│ 0x0D    var  AFL (Application File Locator, typically 12-20 bytes)   │
│ 0x0E    0x02 Application Usage Control (AUC, 2 bytes)                │
│ 0x0F    0x05 IAC-Default (5 bytes)                                   │
│ 0x10    0x05 IAC-Denial  (5 bytes)                                   │
│ 0x11    0x05 IAC-Online  (5 bytes)                                   │
│ 0x12    var  CVM List (variable, typically 20-40 bytes)              │
│ 0x13    0x04 Bank ID (4 bytes big-endian)                            │
│ 0x14    0x04 Program ID (4 bytes big-endian)                         │
│ 0x15    var  Post-provisioning URL (variable, ≤ 64 bytes for MChip)  │
│ 0x16    0x80 ICC RSA Private Key (1024-bit CRT components, 128B)     │
│              — encrypted-and-signed delivery; see §3                 │
│ 0x17    var  ICC PK Modulus (from APC — chip uses to build cert)     │
└──────────────────────────────────────────────────────────────────────┘
```

Total: ~200–240 bytes typical.

Transported in the APDU payload that replaces today's `TRANSFER_SAD`:

```
CLA = 0x80, INS = 0xE2 (STORE_DATA — reused)
P1  = 0x80 (last block)
P2  = 0x00
Lc  = len
Data = [8-byte ephemeral ECDH pubkey X-coord]
       || [12-byte nonce]
       || [ciphertext(param bundle) — AES-128-GCM]
       || [16-byte GCM tag]
```

### ECDH wrap protocol

The chip's `GENERATE_KEYS` APDU today emits a P-256 ECC pubkey
(uncompressed, 65B = 0x04 ‖ X ‖ Y).  Server uses this pubkey to:

1. Generate an ephemeral P-256 keypair server-side.
2. Compute shared secret = ECDH(server_ephemeral_priv, chip_pub).
3. Derive AES-128 key + 96-bit GCM nonce via HKDF(shared_secret,
   "paramBundleV1 ‖ sessionId").
4. AES-128-GCM encrypt the ParamBundle TLV blob.
5. Ship `[server_ephemeral_pub || nonce || ct || tag]` to chip.

Chip:
1. Receives the APDU.
2. Extracts `server_ephemeral_pub` (32B X-coord).
3. Computes shared secret = ECDH(chip_priv, server_ephemeral_pub).
4. Derives AES-128 key + nonce via same HKDF.
5. AES-128-GCM decrypts — any tampering fails the GCM tag.
6. Parses the TLV bundle.

Security properties:
- Forward secrecy: server's ephemeral keypair is discarded after each
  ParamBundle build
- No perso image ciphertext at rest (ParamRecord stored as bundle-at-rest
  encrypted with a fresh per-card session key — see §4)
- Chip validates authenticity via GCM tag before acting on any byte

---

## 3. Key Management — hybrid model

**Why hybrid:** Full C17/C22 literal would have the chip derive per-card
EMV keys itself from a master.  That violates the "master stays in HSM"
posture.  Hybrid keeps masters in APC and delivers per-card keys to the
chip encrypted; the chip never has access to the master.

### What APC does (server side, unchanged from today)

For each card at prepare-time:
- MK-AC, MK-SMI, MK-SMC derived from the issuer master via
  EMV Option A (MK = CMAC(IMK, PAN ‖ PSN))
- ICC RSA keypair (1024-bit for prototype, 1984-bit for production M/Chip)
  generated inside APC
- All five secrets (3 MKs + ICC RSA priv + ICC RSA pub) bundled into the
  ParamBundle, then the whole bundle ECDH-wrapped to the chip's pubkey

### What the chip does

- On TRANSFER_PARAMS: ECDH-unwrap → extract MK-AC/SMI/SMC, ICC RSA priv/pub
- Store the three AES/3DES MKs in dedicated DGI slots (DGI 8201 in MChip)
- Store ICC RSA priv key in chip's secure storage
- **Self-sign an ICC PK Certificate** per EMV Book 2 §5.4 using the
  issuer-PK cert the chip already has (or receives in the ParamBundle)
- Build all DGIs inline
- Commit to NVM in a single transaction

### ICC PK certificate — important detail

The ICC PK cert (Tag 9F46) is built from:
- ICC Pubkey (modulus + exp)
- Cardholder account number
- Cert expiry
- ICC PK Certificate Serial Number
- Signature by **Issuer Private Key** (which is a HUGE key that the chip
  will NOT have)

Options:
- **(a) Ship the fully-signed ICC PK cert in the ParamBundle.** Issuer key
  signs server-side in APC; chip just stores the cert. Prototype uses this.
  Cert is public information (sent to POS in GenerateAC), so encrypting it
  to the chip via ECDH is paranoia not security.  But we keep it in the
  wrapped bundle for simplicity.
- **(b) Chip self-signs with its own ICC priv key.** Wrong — cert is
  signed by the ISSUER, not the ICC.  The chip cannot be the signer.

Going with **(a)** — the ICC PK cert is a server-computed, server-signed
artifact.  The chip's ONLY role for the cert is to store + serve it at
POS time in the GENERATE_AC response.

### Removing the SAD encryption layer

Today: `sadEncrypted` in DB is the full perso image, AES-GCM-wrapped with
a KMS data-key.  Decrypted in rca RAM, parsed to DGIs, shipped to PA.

In the prototype: **remove this layer entirely.**  ParamBundle at rest is
stored encrypted-to-chip-pubkey but since we don't have the chip pubkey
until `GENERATE_KEYS` runs (chip-generated at provisioning time), we
can't wrap at prepare-time.

Path taken: ParamBundle stored in DB **encrypted with a per-card server-side
AES key** (analogous to today's KMS-wrapped SadRecord).  At provisioning
time, rca decrypts with that key, then ECDH-wraps to the chip pubkey just
before sending.  Plaintext window: still ~50 ms in rca RAM.

**This means the prototype doesn't fully satisfy C17/C22 either** — it
just shifts the boundary.  Full C17/C22 requires "parameters at rest,
never image" — which the prototype delivers.  The 50ms rca-RAM
plaintext window applies to raw parameters, not to a full DGI perso
image.  That's a meaningful improvement (less surface area) but
intellectually honest to call out.

**Enhancement path:** store ParamBundle as plaintext fields per column
(PAN encrypted separately, keys encrypted separately via per-card APC
HSM keys).  Then at provisioning time, assemble the TLV blob + wrap to
chip pubkey.  Plaintext assembly is ~10ms and individual fields are
protected.  Out of scope for prototype.

---

## 4. JavaCard applet — PA v3

Target: extend `applets/pa` (the existing Provisioning Agent applet —
NOT pav2, which is the T4T applet).

### New / changed APDUs

| APDU | CLA | INS | Notes |
|---|---|---|---|
| GENERATE_KEYS | 0x80 | 0xE0 | Unchanged — chip returns ECC pubkey |
| TRANSFER_PARAMS | 0x80 | 0xE2 | Replaces TRANSFER_SAD; ECDH-wrapped ParamBundle |
| FINAL_STATUS | 0x80 | 0xE6 | Unchanged — returns provenance hash |
| CONFIRM | 0x80 | 0xE8 | Unchanged — latches COMMITTED state |
| WIPE | 0x80 | 0xEA | Unchanged — resets to IDLE |

### Applet internal flow on TRANSFER_PARAMS

```
processTransferParams(apdu):
  buf = apdu.getBuffer()
  extractEphemeralPubkey(buf) → server_ephemeral_pub
  shared = ecdh(chip_priv, server_ephemeral_pub)
  (key, nonce) = hkdf(shared, "paramBundleV1 ‖ session_id")
  plaintext = aes128gcm_decrypt(key, nonce, ciphertext, tag)
  params = parse_tlv(plaintext)

  // Build DGIs inline from params
  buildDgi0101(params)           // App Data
  buildDgi0102(params)           // AFL
  buildDgi8201(params)           // Key slots (MK-AC/SMI/SMC) + ICC RSA priv
  buildDgi9201(params)           // MChip scheme data

  // Build provenance hash
  provenance = sha256(dgi0101 ‖ dgi0102 ‖ dgi8201 ‖ dgi9201)
  storeProvenance(provenance)

  // Commit via JCSystem.beginTransaction() / commitTransaction()
  commitAllDgisToNvm()

  // Scrub plaintext param buffer
  zeroize(plaintext, 0, plaintext.length)
  zeroize(shared, 0, shared.length)
  zeroize(key, 0, key.length)

  state = STATE_PARAMS_LOADED  // next expected: FINAL_STATUS
  setResponseSw(0x9000)
```

### DGI builders (scheme-specific)

Each DGI is assembled byte-by-byte inline.  For MChip CVN 18:

**DGI 0101 — Application Data**
```
[0x82, 0x02, AIP(2B)]
[0x94, len, AFL(var)]
[0x9F07, 0x02, AUC(2B)]
[0x5A, len, PAN(var, BCD)]
[0x5F24, 0x03, ExpiryDate(YYMMDD, 3B BCD)]  // MChip re-encodes
[0x5F30, 0x02, ServiceCode(2B BCD)]
[0x9F08, 0x02, AppVersionNumber(2B)]
[0x9F42, 0x02, AppCurrencyCode(2B)]  // static for prototype
[0x9F44, 0x01, AppCurrencyExponent(1B)]
[0x5F34, 0x01, PSN(1B BCD)]
```

**DGI 0102 — AFL + SFI layout**
```
[0x94, len, AFL(var)]  // Already in 0101 but MChip expects dupe here
```

**DGI 8201 — Key slots (encrypted by scheme)**
```
[0x9F52, 0x10, MK_AC(16B)]
[0x9F53, 0x10, MK_SMI(16B)]
[0x9F54, 0x10, MK_SMC(16B)]
[0x9F46, cert_len, ICC_PK_Certificate(~176B, server-signed)]
[0xDF?, priv_len, ICC_Priv_RSA(CRT components, ~128B)]
```

**DGI 9201 — MChip scheme data**
```
[CVR_Length, CVR_Default(5B)]
[0x9F0D, 0x05, IAC_Default(5B)]
[0x9F0E, 0x05, IAC_Denial(5B)]
[0x9F0F, 0x05, IAC_Online(5B)]
[0x8E, len, CVM_List(var)]
[0x9F4F, len, Log_Format(var)]  // optional
```

### JavaCard size budget

Estimated applet size after change:
- Current PA.cap: ~40 KB
- ECDH unwrap + HKDF + AES-GCM: +8 KB
- DGI builder logic (MChip only): +6 KB
- TLV assembly helpers: +2 KB
- **Target: ~56 KB** (leaves headroom under typical 64 KB limit)

If size becomes tight, options:
- Push HKDF constants into a separate `Const` class (dedup)
- Share TLV helpers with pav2 via shareable interface (complex; avoid for prototype)
- Drop some scheme-specific constants that can be shipped in ParamBundle

---

## 5. Server-side — data-prep + rca changes

### @palisade/emv refactor

Current: `sad-builder.ts` assembles full DGI byte stream.  New:
`param-bundle-builder.ts` assembles the TLV bundle with scheme-specific
parameter layout but NO DGI construction.

Files touched:
- `packages/emv/src/param-bundle-builder.ts` **(new)** — TLV assembly
- `packages/emv/src/scheme-mchip.ts` **(new)** — MChip CVN 18 parameter
  mapper (takes ChipProfile + IssuerProfile → ParamBundle fields)
- `packages/emv/src/sad-builder.ts` — **retained** for legacy fallback
  behind a feature flag; eventually removed once prototype graduates
- `packages/emv/src/icc-cert-builder.ts` — **retained** (now
  exclusively server-side for ICC PK cert signing)

### @palisade/emv-ecdh package (new, thin wrapper)

Files touched:
- `packages/emv-ecdh/src/index.ts` **(new)** — wraps Node's
  `crypto.diffieHellman` + HKDF + AES-GCM
- `packages/emv-ecdh/src/hkdf.ts` **(new)** — HKDF-SHA256 (there's an
  HKDF in @palisade/core already; consider deduping)

### data-prep service

File `services/data-prep/src/services/data-prep.service.ts`:
- Add `prepareParamBundle(cardId, pan, expiry, ...)` method in parallel
  to `prepareCard`.  Behind feature flag `DATA_PREP_BACKEND=paramBundle`
  (default `sad` for backward compat).
- `prepareParamBundle`:
  1. HSM-derives per-card EMV keys (same as today via APC)
  2. APC generates ICC RSA keypair
  3. Server signs ICC PK Cert with issuer key
  4. Assembles ParamBundle TLV
  5. Encrypts ParamBundle with a fresh per-card AES-128-GCM data-key,
     wraps the data-key with KMS (envelope encryption — mirror of the
     existing SAD-at-rest pattern)
  6. Stores `ParamRecord` row in DB

New Prisma model:
```prisma
model ParamRecord {
  id               String   @id @default(cuid())
  cardId           String   @unique
  proxyCardId      String   @unique
  bundleEncrypted  Bytes    // AES-GCM(ParamBundle) + data-key wrapped with KMS
  bundleKeyVersion Int
  schemeByte       Int      // 0x01 for MChip
  cvnByte          Int      // 0x12 for CVN 18
  status           SadStatus @default(READY)
  createdAt        DateTime  @default(now())
  expiresAt        DateTime
}
```

Coexists with SadRecord.  During migration, cards can have either or both;
rca's provisioning flow picks based on which the prepare call populated.

### rca service

File `services/rca/src/services/session-manager.ts`:
- Add `buildParamBundleApdu(ctx, chipPubkey)` alongside existing
  `buildTransferSadApdu` in plan-builder.  Selected via the `ChipProfile`
  that points at either a legacy SAD flow or the new ParamBundle flow.
- `handlePlanKeygen` or `handleKeygenResponse` — after extracting
  chipPubkey from GENERATE_KEYS response, use it to wrap the ParamBundle
  for the TRANSFER_PARAMS step.
- Update plan step 2 generation to be chipPubkey-aware.

Currently plan mode pre-computes all APDUs at plan-send time (before the
chip's pubkey is known).  The ParamBundle APDU depends on the chip's
pubkey — which means plan mode needs a checkpoint between step 1
(GENERATE_KEYS response) and step 2 (TRANSFER_PARAMS).  Options:

- **(a) Server emits step 2 on receipt of step 1 response.**  Add a
  `{type: 'plan_step', i: 2, apdu: '...'}` message emitted after
  GENERATE_KEYS lands.  Mobile inserts it into its plan queue.
- **(b) Abandon plan mode for ParamBundle cards; use classical.**
  Simpler.  Mobile loses plan-mode latency benefit on ParamBundle cards
  but those are the prototype slice and latency is already +400-650ms
  for the chip work.
- **(c) Pre-compute ParamBundle APDU at plan-build time using a cached
  chip pubkey from the last GENERATE_KEYS.**  Not viable —
  GENERATE_KEYS is ephemeral per session; re-using is an attack vector.

Prototype: **(b).**  Revisit once ParamBundle is stable.

---

## 6. DB migration

Single Prisma migration file:

```
packages/db/prisma/migrations/NNNNNNNN_param_bundle_prototype/migration.sql

CREATE TABLE "ParamRecord" (...);
CREATE INDEX "ParamRecord_cardId_idx" ON "ParamRecord"(cardId);
CREATE INDEX "ParamRecord_status_idx" ON "ParamRecord"(status);

-- Card table: nullable pointer to ParamRecord for prototype cards
ALTER TABLE "Card" ADD COLUMN "paramRecordId" TEXT;
ALTER TABLE "Card" ADD CONSTRAINT "Card_paramRecordId_fkey"
  FOREIGN KEY ("paramRecordId") REFERENCES "ParamRecord"("id");
```

Coexists with SadRecord.  Cards that use the prototype flow have
`paramRecordId` set; legacy cards have `proxyCardId → SadRecord` as today.
ChipProfile gets a `provisioningMode` field: `SAD_LEGACY` or `PARAM_BUNDLE`.

---

## 7. Test strategy

### Unit

- `packages/emv/src/param-bundle-builder.test.ts`: TLV round-trip for
  every defined tag + bounds checking (PAN len, AFL len, CVM list)
- `packages/emv-ecdh/src/index.test.ts`: round-trip ECDH + HKDF + AES-GCM
  against a known-answer vector (generate vectors from OpenSSL)
- `services/data-prep/src/services/data-prep.service.param.test.ts`:
  prepareParamBundle with mock APC + KMS — asserts bundle length,
  field positions, key material placement

### Integration (on test silicon)

- Test harness that flashes PA v3.cap to a virgin JCOP 5 card
- Issues the full flow: GENERATE_KEYS → TRANSFER_PARAMS → FINAL_STATUS
  → CONFIRM
- Dumps chip NVM via SCP03 + GET_DATA to inspect committed DGIs
- Compares dumped DGIs byte-for-byte with what the legacy `sad-builder.ts`
  would have produced for the same inputs — **byte parity is the correctness
  gate**

### E2E on test POS

- Provision a card end-to-end via the new flow
- Present card to Mastercard M/Chip reference reader
- Verify: SELECT AID succeeds → GET PROCESSING OPTIONS succeeds →
  READ RECORDS returns the DGIs → GENERATE_AC succeeds with valid ARQC

---

## 8. Rollout (when prototype graduates)

**Phase 0 — Prototype (this plan):**
- Feature flag `DATA_PREP_BACKEND=paramBundle` is per-card-request
  (or per-program).  Only virgin test cards use it.

**Phase 1 — Small fleet trial:**
- Issue 50–100 new cards with ParamBundle flow.  Real Mastercard M/Chip.
- Monitor: provisioning success rate, latency p95/p99, any scheme-reader
  compat issues.  Measured over 2–4 weeks.

**Phase 2 — New issuance default:**
- Flip `paramBundle` to default for all new MChip CVN 18 issuance.
- Legacy cards keep using SadRecord path.

**Phase 3 — VSDC prototype:**
- Mirror of this plan for Visa VSDC CVN 10/18/22.  Scheme-specific code
  is isolated in `scheme-visa.ts`.

**Phase 4 — Decommission SAD path:**
- All new issuance uses ParamBundle.  SadRecord stays in DB for legacy
  cards until they age out.  `sad-builder.ts` + `icc-cert-builder.ts`
  retained for legacy replay only.

---

## 9. Rollback

Prototype design preserves rollback at every phase:

- **Bad applet CAP after install:** card-ops `install_pa` (existing op)
  can re-install the previous CAP version.  For fresh test cards this
  is a non-issue — they were virgin.
- **Bad ParamBundle format:** flip feature flag back to SAD; new cards
  use legacy path.  Already-provisioned ParamBundle cards are a separate
  migration problem (their state is on-chip, not recoverable by backend
  flag).
- **DB migration:** reversible — ParamRecord table can be dropped if
  not yet in use by any real card.  Card table's new column is nullable.
- **Cert issue:** Since prototype doesn't go for Mastercard commercial
  cert, "rollback" just means "stop using on those test cards."

---

## 10. Latency expectations

Measured against current ~5.8s end-to-end provisioning:

| Stage | Today | Prototype | Delta |
|---|---|---|---|
| Tap → activation redirect | 300ms | 300ms | 0 |
| Mobile /provisioning/start | 500ms | 500ms | 0 |
| WS open + attestation | 800ms | 800ms | 0 |
| SELECT PA | 150ms | 150ms | 0 |
| GENERATE_KEYS | 400ms | 400ms | 0 |
| TRANSFER_(SAD/PARAMS) | 800ms | **~1200–1450ms** | **+400–650ms** |
| FINAL_STATUS | 200ms | 200ms | 0 |
| CONFIRM | 200ms | 200ms | 0 |
| Server callback + DB commit | 400ms | 400ms | 0 |
| **Total** | **~5.8s** | **~6.2–6.4s** | **+400–650ms** |

Prototype delta breakdown on-chip during TRANSFER_PARAMS:
- ECDH unwrap: ~50–80ms
- Store ICC RSA priv: ~20ms
- Build DGI 0101: ~30–50ms
- Build DGI 0102: ~20–30ms
- Build DGI 8201 (cert store + key placement): ~30–50ms
- Build DGI 9201 (MChip scheme data): ~50–80ms
- ICC PK cert verify + store: ~100–150ms (JCOP RSA-verify is fast)
- NVM commit: ~80–120ms (same as today)

---

## 11. Milestones + time estimates

| Week | Milestone | Owner |
|---|---|---|
| 1 | Applet skeleton: ECDH unwrap + HKDF + AES-GCM on JC, round-trip test vector | JC dev |
| 2 | `@palisade/emv-ecdh` package + unit tests + known-answer vectors | Backend dev |
| 3 | `packages/emv/param-bundle-builder` + `scheme-mchip` module | Backend dev |
| 4 | PA v3 DGI builders: 0101 + 0102 on applet | JC dev |
| 5 | `data-prep` `prepareParamBundle` method + Prisma migration | Backend dev |
| 6 | PA v3 DGI builders: 8201 + 9201 on applet | JC dev |
| 7 | `rca` TRANSFER_PARAMS wiring + classical-mode-only for prototype | Backend dev |
| 8 | First chip-to-chip flash + integration test: flash PA v3, run flow, dump NVM | JC + backend joint |
| 9 | Byte-parity validation: diff dumped DGIs vs legacy server-built | JC + backend joint |
| 10 | POS reader test: present provisioned card to Mastercard M/Chip reader | JC + backend joint |
| 11 | Latency measurement + buffer optimisation if needed | JC dev |
| 12 | Fix 1st-round issues found during POS test | JC + backend joint |
| 13 | (Buffer) 2nd-round scheme quirks, edge cases (expiry rollover, short PANs) | JC dev |
| 14 | (Buffer) Applet size optimisation if tight | JC dev |
| 15 | (Buffer) Re-cert the applet signing chain | JC dev |
| 16 | Documentation + handoff prep | Both |
| 17–18 | (Buffer) Mastercard reference test-network validation | Both |

**If either dev stream slips 1–2 weeks, prototype lands at week 18–20.**

---

## 12. Risks + open questions

| Risk | Mitigation |
|---|---|
| Applet size > 64 KB limit | Strip MChip-specific constants into ParamBundle; share TLV helpers between 0101/0102/8201/9201 |
| JavaCard RSA-1024 sign not fast enough for in-flow cert signing | Ship pre-signed ICC PK cert in ParamBundle; don't sign on-chip |
| ECDH key-agreement timing too slow on JCOP 5 | Measure early (week 1 milestone) — if >200ms add to latency budget |
| DGI byte-parity fails due to scheme quirks | Add diff tool; iterate on app data/TLV tag placement until parity |
| M/Chip reader rejects chip-built perso | Cert review with Mastercard — may require tweaking AIP/AUC bytes |
| Fleet coordination: new prototype cards vs legacy needs routing | ChipProfile.provisioningMode flag handles it — backend picks flow per card |
| APC generates RSA differently than expected | Test APC ICC RSA generation + import into ParamBundle early (week 5) |
| Prisma migration disruption in prod | Migration is additive-only (new table, nullable column on Card) — no downtime |
| JCOP 5 vendor-specific API quirks (NXP vs Infineon) | Test on BOTH silicon types; parameterise applet if needed |
| Re-enrolment if cert chain changes | Out of scope for prototype; accept that prototype cards need re-perso when keys rotate |

### Open questions to resolve before kickoff

1. **Who's the JavaCard dev?** Resource allocation blocks week 1.
2. **Do we have JCOP 5 test silicon + a virgin card pool?** 50–100 virgin
   JCOP 5 cards needed for Phase 1.
3. **Mastercard M/Chip reference reader access?** Needed for POS validation
   in week 10.  Commercial Mastercard test network access takes 2–4 weeks
   lead time.
4. **Certification requirement:** Is this ever going through Mastercard
   commercial cert, or is reference-reader parity sufficient for
   production use?  Cert cycle is 3–6 months separate.
5. **1024 vs 1984-bit ICC RSA:** Prototype uses 1024 for size+speed; but
   production MChip requires ≥1984.  Does prototype need to match production
   bit-length from day 1?
6. **Mobile app changes:** The mobile needs to handle the new
   TRANSFER_PARAMS APDU shape (extended-length, potentially bigger data
   block than TRANSFER_SAD).  Verify mobile NFC layer can send/receive
   ≥256-byte APDUs.

---

## 13. Success criteria

Prototype is considered complete when:

1. ✅ A virgin JCOP 5 card with PA v3.cap flashed can be provisioned
   end-to-end via the new ParamBundle flow.
2. ✅ The committed DGI byte stream on that card is byte-identical to
   what the legacy `@palisade/emv/sad-builder.ts` would have produced
   for the same input parameters.
3. ✅ The provisioned card successfully transacts at a Mastercard M/Chip
   reference POS reader (GENERATE_AC produces a valid ARQC).
4. ✅ Measured latency delta is ≤ 700ms added to end-to-end perso (budget
   was 400–650ms; allow 10% headroom).
5. ✅ The legacy SadRecord provisioning path still works for non-prototype
   cards (feature flag toggle, no regression).
6. ✅ A rollback runbook exists for each phase.

At that point: prototype is frozen; Phase 1 (small-fleet trial) can begin
with a decision gate from engineering + security + compliance.

---

## Appendix A — Files created / modified

### New files

```
packages/emv/src/param-bundle-builder.ts
packages/emv/src/param-bundle-builder.test.ts
packages/emv/src/scheme-mchip.ts
packages/emv/src/scheme-mchip.test.ts
packages/emv-ecdh/package.json
packages/emv-ecdh/tsconfig.json
packages/emv-ecdh/src/index.ts
packages/emv-ecdh/src/hkdf.ts
packages/emv-ecdh/src/index.test.ts
services/data-prep/src/services/data-prep.service.param.ts
services/data-prep/src/services/data-prep.service.param.test.ts
packages/db/prisma/migrations/NNNNNNNN_param_bundle_prototype/migration.sql
applets/pa/src/main/java/com/palisade/pa/ProcessTransferParams.java
applets/pa/src/main/java/com/palisade/pa/DgiBuilderMchip.java
applets/pa/src/main/java/com/palisade/pa/EcdhUnwrap.java
docs/runbooks/param-bundle-rollout.md
```

### Modified files

```
packages/emv/src/index.ts         — export new modules
packages/emv/package.json         — no new deps
services/data-prep/src/services/data-prep.service.ts
                                   — add prepareParamBundle
                                     alongside prepareCard
services/data-prep/src/routes/data-prep.routes.ts
                                   — POST /prepare accepts `backend` param
services/rca/src/services/session-manager.ts
                                   — ParamBundle-aware buildPlanContext
services/rca/src/services/plan-builder.ts
                                   — buildParamBundleApdu builder
services/card-ops/src/operations/install-pa.ts
                                   — points at pa-v3.cap when feature
                                     flag set on the ChipProfile
packages/db/prisma/schema.prisma
                                   — ParamRecord model + Card.paramRecordId
services/activation/src/cards/register.service.ts
                                   — call prepareParamBundle on new cards
                                     whose program points at ParamBundle
                                     ChipProfile
```

---

## Appendix B — Test vectors to generate before week 1

To avoid blocking the JC dev, backend should produce these reference vectors
so the applet can validate its ECDH + HKDF + AES-GCM implementation before
an integration test:

1. **P-256 ECDH test vectors:** RFC 6979 or NIST CAVP sample pairs
2. **HKDF-SHA256 test vectors:** RFC 5869 test cases
3. **AES-128-GCM test vectors:** NIST CAVP GCMVS samples (5–10 pairs)
4. **ParamBundle round-trip:** 3 reference ParamBundles with known input
   parameters, expected TLV bytes, expected post-ECDH ciphertext
5. **DGI byte-parity goldens:** For the same input parameters, produce
   both the legacy SAD byte stream (via current `sad-builder.ts`) and a
   reference "what the chip should produce" byte stream.  Used as the
   byte-parity test.
