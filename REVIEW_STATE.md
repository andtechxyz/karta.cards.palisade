# Prototype branch — state for review

**Branch:** `prototype/mchip-chip-computed-dgi`
**Latest commit:** `7dbbb0d` (Phase 7 rca TRANSFER_PARAMS wiring)
**Test status:** 776 tests pass (717 on `main` + 59 new prototype tests)
**All 7 phases complete.**

## What's built (ready for review)

### Server-side — full implementation + tests

| Commit | Phase | Deliverable |
|---|---|---|
| `6ff2071` | Plan | `PROTOTYPE_PLAN.md` — 719-line architecture spec |
| `0f1404b` | 1 | `@palisade/emv-ecdh` — ECDH + HKDF + AES-GCM wrapper, 13 tests inc. RFC 5869 KATs |
| `48f9583` | 2 | `param-bundle-builder` + `scheme-mchip` — TLV format + MChip mapper + on-chip simulator, 35 tests |
| `02284fd` | 5 | Byte-parity test — proves simulator matches legacy `SADBuilder` for DGIs 0101/0102, 4 tests |
| `bb1135c` | 3 | Prisma migration — `ProvisioningMode` enum + `ParamRecord` model + `Card.paramRecordId` + `ChipProfile.provisioningMode` (all additive, defaults preserve legacy behaviour) |
| `5dfde41` | 4 | `data-prep.prepare()` router + `prepareParamBundle()` method, 3 tests — routes on `ChipProfile.provisioningMode` |
| `7dbbb0d` | 7 | `rca` `handleKeygenResponse` dispatch + `buildTransferParamsApdu` + `RCA_ENABLE_PARAM_BUNDLE` env flag, 4 tests |

### JavaCard applet — source ready (compilation deferred to JC dev)

| Commit | Deliverable | Status |
|---|---|---|
| `f576a68` | `applets/pa-v3/` — full source tree | Design-complete, not compiled |

**Applet files for the JC dev:**

```
applets/pa-v3/
├── README.md                          # 280 lines — APDU ref, build/install, tests
├── build.xml                          # ant-javacard build (mirror of pav2)
└── src/main/java/com/palisade/pa/
    ├── Constants.java                 # Single source of truth (mirrors TS side)
    ├── ParamBundleParser.java         # TLV parser — mirror of parseParamBundle
    ├── EcdhUnwrapper.java             # ECDH + HKDF + AES-GCM — mirror of
    │                                    packages/emv-ecdh
    ├── DgiBuilderMchip.java           # On-chip DGI assembly — mirror of
    │                                    simulateMChipChipBuild
    └── ProvisioningAgentV3.java       # APDU dispatch + state machine
```

## Coexistence — nothing breaks legacy provisioning

**Two guards must both flip before a single byte of prototype code
executes on any provisioning session:**

1. `ChipProfile.provisioningMode = 'PARAM_BUNDLE'` — per-card
   schema property.  Every existing ChipProfile row defaults to
   `SAD_LEGACY` and never touches prototype code.

2. `RCA_ENABLE_PARAM_BUNDLE = '1'` — rca task-def env flag, default
   `'0'`.  Even if a card has `paramRecordId` set, flag-off forces
   legacy `TRANSFER_SAD` dispatch.

Isolation table:

| Layer | Legacy path | Prototype path | Coexist safely? |
|---|---|---|---|
| Schema | `SadRecord` table + `Card.proxyCardId` | `ParamRecord` table + `Card.paramRecordId` | ✅ — disjoint, additive migration |
| data-prep | `prepareCard` → `SadRecord` | `prepareParamBundle` → `ParamRecord` | ✅ — router picks based on `ChipProfile.provisioningMode` default=SAD_LEGACY |
| rca | `buildTransferSadApdu` (unchanged) | `buildTransferParamsApdu` (new) | ✅ — null-check first, then env flag |
| On-chip AID | `A00000006250414C` (PA v1) | `A0000000625041034C` (pa-v3) | ✅ — different LOAD domains, can coexist on one chip or on different cards |
| Mobile WS | Unchanged | Unchanged | ✅ — protocol identical; just a bigger APDU body |

**Existing cards** (`e2e_fi_2590` et al.): zero behaviour change.  They
have `paramRecordId = null`, so rca always falls through to the
legacy branch regardless of env flag state.

## What an isolated tap test needs

| Prerequisite | How it's obtained |
|---|---|
| `pa-v3.cap` compiled | JC dev + JCOP 5 SDK (deferred — source is ready) |
| `pa-v3.cap` installed on a **virgin** card | `gp --install pa-v3.cap --applet A0000000625041034C --create A0000000625041034C` |
| `ChipProfile.provisioningMode = 'PARAM_BUNDLE'` row | Admin UI or one-off SQL (new ChipProfile row; don't touch existing ones) |
| `IssuerProfile` + `Program` pointing at the new ChipProfile | Admin UI |
| Card registered against that Program → triggers `data-prep.prepare()` → routes to `prepareParamBundle` → writes ParamRecord | Existing register flow unchanged; dispatch is data-driven |
| `RCA_ENABLE_PARAM_BUNDLE=1` on the rca task def serving the prototype card | Task-def env var (can be a separate dev task-def alongside prod's at `'0'`) |
| Tap + provisioning flow runs → rca dispatches to prototype path | Automatic via Card.paramRecordId + env flag |

**A production rca task-def keeps `RCA_ENABLE_PARAM_BUNDLE='0'`**.
Prototype testing happens on a dedicated task-def (dev environment,
separate ECS service revision, or feature-flag rollout) where the
flag is `'1'`.

## Deploy sequence for an isolated test

When ready to actually run the prototype:

1. **Wait for pa-v3.cap** from the JC dev.  (Server side doesn't
   need this to deploy — can land pa-v3 on `main` via this branch
   ahead of time.)

2. **Run the migration** — `prisma migrate deploy` against the RDS
   instance.  Additive, safe during live traffic.  Verified on staging
   first.

3. **Deploy data-prep** with Phase 4 code.  Zero behaviour change
   for any existing ChipProfile (all default SAD_LEGACY).

4. **Deploy rca** with Phase 7 code + `RCA_ENABLE_PARAM_BUNDLE='0'`
   (the default).  Zero behaviour change for any existing card.
   Verified on staging with a full legacy tap test before prod.

5. **Create a new ChipProfile + IssuerProfile + Program** with
   `provisioningMode='PARAM_BUNDLE'`, pointing at the pa-v3 AID.
   Bound to ONE test card that's been physically flashed with pa-v3.

6. **Spin up a separate rca task-def revision** with
   `RCA_ENABLE_PARAM_BUNDLE='1'`.  Route the prototype test card's
   traffic to this task-def (via ALB listener rule path, dedicated
   internal DNS, or just mobile-side URL override).

7. **Run the isolated tap test.**  Register → tap → provision → POS.
   Verify: mobile sees `type:'complete'`, chip NVM has 4 DGIs byte-
   matching the byte-parity goldens, POS reader issues GENERATE_AC
   successfully.

8. **Legacy fleet continues unaffected** on the production rca task-
   def with flag `='0'`.

## Summary of all prototype commits on branch

```
7dbbb0d prototype phase 7: rca TRANSFER_PARAMS wiring (env-flag gated)
5dfde41 prototype phase 4: data-prep prepareParamBundle + prepare() router
bb1135c prototype phase 3: Prisma migration — ParamRecord + provisioningMode
484fa5f prototype: REVIEW_STATE.md — snapshot for review
f576a68 prototype phase 6: pa-v3 applet source (for JC-dev review)
02284fd prototype phase 5: byte-parity test — chip-simulator vs legacy SADBuilder
48f9583 prototype phase 2: param-bundle-builder + scheme-mchip + 35 unit tests
0f1404b prototype phase 1: @palisade/emv-ecdh package
6ff2071 plan: MChip chip-computed-DGI prototype (C17/C22 patent alignment)
```

## 6 open questions (from `PROTOTYPE_PLAN.md` §12) — none resolved by this session

1. Who's the JavaCard dev?
2. JCOP 5 test silicon + virgin-card pool?
3. Mastercard M/Chip reference reader access?
4. Commercial cert or reference-reader parity only?
5. ICC RSA 1024 vs 1984 bit?
6. Mobile APDU size support — ≥256-byte APDUs (short-APDU chaining vs extended APDUs)?

Prototype can't run until #1 and #2 are resolved.  Server-side is
ready to deploy behind flags whenever.
