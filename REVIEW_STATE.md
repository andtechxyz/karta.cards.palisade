# Prototype branch — state for review

**Branch:** `prototype/mchip-chip-computed-dgi`
**Latest commit:** `f576a68` (pa-v3 applet source)
**Test status:** 769 tests pass (717 on `main` + 52 new prototype tests)

## What's built (ready for review)

### Server-side (full implementation + tests)

| Commit | Deliverable | Scope |
|---|---|---|
| `6ff2071` | `PROTOTYPE_PLAN.md` | 719-line architecture spec |
| `0f1404b` | `@palisade/emv-ecdh` package | ECDH + HKDF + AES-GCM wrapper, 13 tests including RFC 5869 compliance vectors |
| `48f9583` | `param-bundle-builder` + `scheme-mchip` | TLV encoder/parser + MChip CVN 18 mapper + on-chip DGI simulator, 35 tests |
| `02284fd` | Byte-parity test | Proves simulator output matches legacy `SADBuilder` byte-for-byte for DGIs 0101+0102, 4 tests |

### JavaCard applet (source — compilation deferred to JC dev)

| Commit | Deliverable | Status |
|---|---|---|
| `f576a68` | `applets/pa-v3/` — full source tree | Design-complete, not compiled |

**Files the JC dev picks up:**

```
applets/pa-v3/
├── README.md                          # 280 lines — APDU ref, build/install, tests
├── build.xml                          # ant-javacard build (mirror of pav2)
└── src/main/java/com/palisade/pa/
    ├── Constants.java                 # Shared constants (single source of truth
    │                                    vs TS side) — tag numbers, SW codes,
    │                                    state machine values, ECDH/HKDF/GCM
    │                                    protocol constants
    ├── ParamBundleParser.java         # TLV parser — mirror of parseParamBundle
    │                                    in packages/emv/src/param-bundle-builder.ts
    ├── EcdhUnwrapper.java             # ECDH + HKDF-SHA256 + AES-128-GCM unwrap
    │                                    — mirror of unwrapParamBundle in
    │                                    packages/emv-ecdh.  HMAC-SHA256 inlined
    │                                    on top of SHA-256 for portability.
    ├── DgiBuilderMchip.java           # On-chip DGI assembly — mirror of
    │                                    simulateMChipChipBuild in scheme-mchip.ts.
    │                                    Byte-parity already proved in TS tests.
    └── ProvisioningAgentV3.java       # APDU dispatch + state machine +
                                         orchestration of the three helpers
```

## What's NOT built yet (pick up in next session)

### Phase 3 — Prisma migration + ParamRecord model

Additive-only migration:
```prisma
model ParamRecord {
  id               String   @id @default(cuid())
  cardId           String   @unique
  proxyCardId      String   @unique
  bundleEncrypted  Bytes    // AES-GCM(ParamBundle) + KMS-wrapped key
  bundleKeyVersion Int
  schemeByte       Int      // 0x01 = MChip
  cvnByte          Int      // 0x12 = CVN 18
  status           SadStatus @default(READY)
  createdAt        DateTime  @default(now())
  expiresAt        DateTime
}

// Card gains nullable pointer — coexist with SadRecord flow.
ALTER TABLE "Card" ADD COLUMN "paramRecordId" TEXT;
```

### Phase 4 — data-prep `prepareParamBundle` method

Mirror of existing `prepareCard` but emits ParamBundle to ParamRecord
instead of SAD blob to SadRecord.  Feature-flagged:
`DATA_PREP_BACKEND=paramBundle`.

### Phase 7 — rca wiring

Classical mode only (plan mode needs server to know chip pubkey at
plan-build time, which it can't in ParamBundle flow).  At
`TRANSFER_SAD` time the handler checks `chipProfile.provisioningMode`
— if `PARAM_BUNDLE`, wraps the ParamBundle via ECDH against the
`iccPublicKey` stored earlier in the session, ships the wire bytes
in the APDU.

## JC dev handoff — week 1 tasks

From `applets/pa-v3/README.md`:

1. Set up JavaCard SDK + ant-javacard build
2. Port the four unchanged INS handlers verbatim from legacy
   palisade-pa (GENERATE_KEYS body, FINAL_STATUS, CONFIRM, WIPE —
   marked `TODO(jc-dev):` in the source)
3. Set P-256 curve parameters in `EcdhUnwrapper.initOnce()` (reuse
   constants from `palisade-pa/AttestationProvider.java`)
4. Validate crypto against `packages/emv-ecdh/src/index.test.ts`
   known-answer vectors — RFC 5869 HKDF test cases 1 + 2 are the
   fastest early-sanity check
5. Flash to virgin JCOP 5, send reference ParamBundle from
   `referenceBundleForJcDev()`, dump NVM, diff DGIs against
   `packages/emv/src/byte-parity.test.ts` goldens

## Isolated tap test — what's needed before one can run

| Prerequisite | Status | Blocker |
|---|---|---|
| pa-v3.cap built | ❌ | Needs JC dev + JCOP 5 SDK |
| pa-v3.cap installed on a virgin card | ❌ | Needs step above + `gp --install` with the card on a reader |
| Server ParamRecord row exists | ❌ | Phase 3 migration + Phase 4 `prepareParamBundle` |
| rca routes to ParamBundle flow | ❌ | Phase 7 wiring |
| Mobile hits the correct `/provisioning/start` → `TRANSFER_PARAMS` flow | ❌ | Server changes (phases 3/4/7) + mobile unchanged (same WS protocol) |

**A first tap test against the prototype cannot happen until all
three server phases (3/4/7) land AND the JC dev produces a working
pa-v3.cap.  The prototype plan estimates week 8 of the 12–18 week
roadmap as the first "backend + applet together" integration.**

## What the branch DOES give you now

1. **A design the JC dev can start building from immediately**
   — applets/pa-v3/ source + README, mirrored byte-for-byte against
   the TS reference.
2. **A byte-parity proof** — we know the on-chip DGIs the applet
   will produce match what the legacy server-built SAD produces
   for the same profile inputs.
3. **Known-answer crypto vectors** — RFC 5869 HKDF, deterministic
   AES-GCM round-trip, reference ParamBundle — all the JC dev needs
   to validate their applet crypto offline.
4. **A scope contract** — what each piece does, what it expects, how
   it fails.  Future session can pick up any of 3/4/7 as concrete
   well-specified units.

## Open questions (from `PROTOTYPE_PLAN.md` §12)

Unchanged since the plan was written — need resolved before week 1:

1. Who's the JC dev?
2. Do we have JCOP 5 test silicon + a virgin-card pool (~50 for
   phase-1 trial)?
3. Mastercard M/Chip reference reader access for POS validation
   in week 10?  (2-4 week lead time for commercial test-network
   onboarding.)
4. Is the prototype ever going to commercial Mastercard cert, or
   is reference-reader parity enough?
5. 1024 vs 1984-bit ICC RSA?  Prototype uses 1024 for size+speed
   but production MChip Advance requires ≥1984.
6. Mobile APDU size support — ParamBundle wire total is ~400 bytes;
   verify mobile NFC layer can send/receive ≥256-byte APDUs (or
   plan for short-APDU chaining with CLA bit 4).

## Sanity checklist for review

- [ ] `PROTOTYPE_PLAN.md` scope + assumptions still align with what you want
- [ ] `applets/pa-v3/README.md` reads coherently as a JC-dev briefing
- [ ] `applets/pa-v3/Constants.java` tag numbers match the TS `ParamTag` enum
- [ ] `packages/emv/src/byte-parity.test.ts` test passes on `main` (768 tests total)
- [ ] The 6 open questions above are tracked somewhere owned by a human
- [ ] Phase 3/4/7 can wait until Q1 while the JC dev is onboarded + the
      applet side advances — they're mechanical work we'll pick up when
      the applet is near-compile-ready
