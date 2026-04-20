# pa-v3 — Palisade Provisioning Agent v3 (chip-computed DGIs)

JavaCard applet for the C17/C22 patent-alignment prototype.  Accepts an
ECDH-wrapped parameter bundle via `TRANSFER_PARAMS` (0x80 E2) and
assembles the MChip CVN 18 perso image **on-chip**, replacing the
legacy flow where the server built the full DGI image and shipped it
wholesale.

## Scope

- **MChip Advance CVN 18 only** for this prototype.  VSDC + older MChip
  CVNs added in follow-up work — see `PROTOTYPE_PLAN.md` at the
  worktree root.
- Hybrid key model: APC HSM still derives MK-AC/MK-SMI/MK-SMC and
  generates the ICC RSA keypair.  Chip receives these encrypted via
  ECDH → HKDF → AES-128-GCM.
- No fleet re-personalisation in prototype scope — install on virgin
  JCOP 5 cards only.

## Package / AID layout

| Element | Value | Notes |
|---|---|---|
| Package AID | `A000000062504103` | v1 was `A0000000625041` |
| Module AID | `A0000000625041034C` | v1 was `A00000006250414C` |
| Instance AID | `A0000000625041034C` | Same as module AID |

AIDs bumped so v1 and v3 can coexist during migration — different
package AID = distinct LOAD domain, no conflict during `gp --install`.

## Build

```bash
export JC_HOME=/path/to/Java_Card_Classic_API-3.0.5
ant -f build.xml build
```

Output: `build/pa-v3.cap` (~60 KB estimated, under JCOP 5's typical
64 KB applet-size budget).  Requires ant + OpenJDK 11 + JavaCard
Classic API 3.0.5 SDK.

## Install via gp.jar

```bash
# Delete v1 PA if installed
java -jar gp.jar --key <GP_MASTER> --delete A00000006250414C

# Install v3 package + create PA instance
java -jar gp.jar --key <GP_MASTER> \
  --install build/pa-v3.cap \
  --applet A0000000625041034C \
  --create A0000000625041034C
```

## APDU reference

### GENERATE_KEYS (unchanged from v2)

`0x80 E0 00 00 <Lc> <keyType=0x01><sessionId>`

- `keyType = 0x01` → ECC P-256.
- `sessionId` (up to 63 bytes) → ASCII cuid2 from RCA; mixed into
  HKDF info on the chip during TRANSFER_PARAMS to bind the bundle to
  this specific provisioning session.
- Response: `ICCPubKey(65 uncompressed SEC1) || Attestation(~72 DER) ||
  CPLC(42) || 9000`
- State: IDLE → KEYGEN_COMPLETE

### TRANSFER_PARAMS (new — replaces TRANSFER_SAD)

`0x80 E2 00 00 <Lc> <body>`

Body format:
```
server_ephemeral_pub_uncompressed (65 B — 0x04 || X || Y)
|| derived_nonce (12 B — must match HKDF output on chip)
|| ciphertext (variable)
|| gcm_tag (16 B)
```

Total body size typically 93 + ~300 bytes ParamBundle = ~400 bytes.
Uses extended APDUs or short-APDU chaining (CLA bit 4 set for
non-final chain blocks).

- Response: empty body, SW 9000 on success
- Errors:
  - `6985` — not in KEYGEN_COMPLETE state
  - `6A80` — GCM tag verify failed (tampering, wrong key, wrong session)
  - `6A81` — ParamBundle missing required tag (PAN, MK-AC, etc.)
  - `6A82` — unsupported scheme or CVN (non-MChip, non-CVN18)
- State: KEYGEN_COMPLETE → PARAMS_COMMITTED

### FINAL_STATUS (unchanged from v2)

`0x80 E6 00 00 00`

- Response: `status(1) || provenance_hash(32) || fido_cred_len(1) ||
  fido_cred_id(var) || 9000`
- State: PARAMS_COMMITTED → AWAITING_CONFIRM

### CONFIRM (unchanged from v2)

`0x80 E8 00 00 00`

- Response: empty body, SW 9000
- State: AWAITING_CONFIRM → COMMITTED

### WIPE (unchanged from v2)

`0x80 EA 00 00 00`

- Zeros all DGI NVM + sessionId; state → IDLE
- Valid from ANY state including COMMITTED (irreversible once
  re-provisioned)
- Response: SW 9000

## ParamBundle tags the applet expects

Mirror of `packages/emv/src/param-bundle-builder.ts`'s `ParamTag`.
See `Constants.PB_*` for the single source of truth.  When adding a
tag on the server side, add the matching constant here AND update
`ParamBundleParser.validateMChipCvn18` if the tag is required.

| Tag | Name | Len | Required |
|---:|---|---|:---:|
| 0x01 | PAN | 6-10 | ✅ |
| 0x02 | PSN | 1 | ✅ |
| 0x03 | Expiry YYMM (BCD) | 2 | ✅ |
| 0x04 | Effective YYMM | 2 | ✅ |
| 0x05 | Service code (BCD, leading-zero padded) | 2 | ✅ |
| 0x06 | Scheme byte | 1 | ✅ |
| 0x07 | CVN byte | 1 | ✅ |
| 0x08 | AID | 5-16 | ✅ |
| 0x09-0x0B | MK-AC / MK-SMI / MK-SMC | 16 each | ✅ |
| 0x0C | AIP | 2 | ✅ |
| 0x0D | AFL | 4+ | ✅ |
| 0x0E | AUC | 2 | ✅ |
| 0x0F-0x11 | IAC-Default/Denial/Online | 5 each | ✅ |
| 0x12 | CVM List | 10-252 | ✅ |
| 0x13 | Bank ID (BE uint32) | 4 | |
| 0x14 | Program ID | 4 | |
| 0x15 | Post-provision URL | ≤64 | |
| 0x16 | ICC RSA Priv (PKCS#1) | 128 | ✅ |
| 0x17 | ICC PK Certificate | 1-244 | ✅ |
| 0x18 | App label (ASCII) | ≤16 | |
| 0x19 | App preferred name | ≤16 | |
| 0x1A | App version | 2 | ✅ |
| 0x1B | Currency code | 2 | ✅ |
| 0x1C | Currency exponent | 1 | ✅ |
| 0x1D | Country code | 2 | ✅ |
| 0x1E | iCVV | 3 | ✅ |

Tag numbers use single-byte TLV (0x01..0x7F).  Lengths use BER short-
form (<0x80) plus 0x81 long-form (128-255).  `0x82+` length prefix
rejected — server enforces MAX_FIELD_LEN=255.

## DGIs the applet produces

| DGI | Name | Built from | Approx size |
|---|---|---|---|
| 0x0101 | App Data | Per-card + per-profile tags | ~120 B |
| 0x0102 | AFL duplicate | AFL only | ~6 B |
| 0x8201 | Key slots | MK-AC/SMI/SMC + ICC PK cert + ICC RSA priv | ~200 B |
| 0x9201 | MChip scheme data | CVR defaults + IACs + CVM list + iCVV | ~50 B |

Byte-parity with the legacy server-built SAD proved in
`packages/emv/src/byte-parity.test.ts` for DGIs 0101/0102.  8201 +
9201 have no legacy parity target (legacy SADBuilder doesn't emit
them) — applet-side unit tests + POS transaction tests are the
correctness gate.

## ECDH / HKDF / AES-GCM constants

MUST match `packages/emv-ecdh/src/index.ts`:

| Thing | Value |
|---|---|
| Curve | P-256 (prime256v1) |
| HKDF salt | `"paramBundleV1"` (13 bytes ASCII) |
| HKDF info | `sessionId` bytes (variable) |
| HKDF output | 28 bytes (16 AES key + 12 GCM nonce) |
| AES mode | 128-bit GCM |
| GCM tag length | 16 bytes |
| AAD | empty |

HMAC-SHA256 implemented inline on top of `MessageDigest.ALG_SHA_256`
for portability (not all JC platforms expose `Signature.ALG_HMAC_SHA_256`
natively).  See `EcdhUnwrapper.hmacSha256`.

## Known answer vectors for JC dev

Backend produces reference vectors for standalone applet parser/
crypto validation BEFORE a full integration round-trip with rca:

1. **HKDF-SHA256 RFC 5869 test case 1+2** — already covered by
   `packages/emv-ecdh/src/index.test.ts`; vectors match Node's own
   HKDF output.
2. **ECDH + HKDF + AES-GCM round-trip** — generated via
   `wrapParamBundleDeterministic(serverEphemeralPriv=0xAA*32, ...)`
   for reproducibility.
3. **ParamBundle reference** — `referenceBundleForJcDev()` in
   param-bundle-builder.ts emits a stable test bundle with known
   tag ordering.
4. **DGI byte-parity goldens** — `byte-parity.test.ts` shows the
   expected DGI 0101/0102 bytes.  Tests generated live; the JC dev
   can dump their applet output and `diff` against these in a CI.

## Patent compliance

### C17 / C22 — no perso image outside the SE

**Server never has plaintext DGIs.**  What leaves the server (at rest
and on the wire) is:
- ParamBundle ciphertext (AES-GCM wrapped with a per-session ECDH key
  that only the target chip can derive)
- Raw parameter fields if the legacy SAD path is used instead —
  eventually both paths will share a parameter schema but for now
  coexist.

Plaintext perso image exists ONLY inside the SE, for ~50 ms during
TRANSFER_PARAMS processing, in CLEAR_ON_DESELECT transient RAM, and
is explicitly zeroed via `Util.arrayFillNonAtomic` before return.

### C4 — nonce binding (still applies in v3)

The same C4 "nonce binding" story from v2 applies here:

- **Working enforcement (server-side):** SadRecord/ParamRecord
  `status: READY → CONSUMED` transition inside the provisioning
  `$transaction` — replay prevented by refusing to re-issue a
  consumed bundle.
- **Optional chip-side defence-in-depth:** The `sessionId` mixed into
  HKDF info already binds the bundle to a specific provisioning
  session.  If the same session id is replayed, HKDF produces the
  same AES key + nonce — but GCM's authenticated encryption means
  the chip would accept a validly-encrypted bundle regardless.
  Adding chip-side "don't accept a sessionId I've seen before"
  requires EEPROM-persisting a sessionId-history list and bumping the
  schema when it fills up.  Deferred as before — same cost/benefit
  trade documented in `applets/pa-v3/README.md`.

### C5 — state machine

Strict state transitions enforced in `Constants.STATE_*`.  Any APDU
that violates the state machine returns `6985 SW_WRONG_STATE`.
Match patent C5 requirement for explicit pending → committed
transitions.

## Test harness (deferred to integration phase)

The JC dev needs these tests on actual JCOP 5 silicon:

1. **Flash + FCI round-trip** — install CAP, SELECT AID, verify FCI
2. **GENERATE_KEYS** — returns 65-byte ECC pubkey + 9000
3. **TRANSFER_PARAMS happy path** — decrypt + DGI build + SW 9000
4. **TRANSFER_PARAMS tampered ciphertext** — flip one byte → 6A80
5. **TRANSFER_PARAMS wrong sessionId** — server wraps for session A,
   chip uses session B → 6A80 (HKDF key differs → GCM fails)
6. **TRANSFER_PARAMS missing required tag** → 6A81
7. **TRANSFER_PARAMS wrong scheme/cvn** → 6A82
8. **State machine** — TRANSFER_PARAMS before GENERATE_KEYS → 6985
9. **FINAL_STATUS** — returns provenance hash; SW 9000
10. **CONFIRM** — latches to COMMITTED; SW 9000
11. **Post-CONFIRM GENERATE_KEYS** → 6985 (re-provisioning not allowed)
12. **WIPE** — zeros state; back to IDLE

Integration test fixture lives at `applets/pa-v3/test/` (to be
written alongside the applet compilation milestone in week 8 of the
prototype plan).

## Known limitations / TODOs in source

Search the source for `TODO(jc-dev):` — marks spots where the v2
applet source needs to be ported verbatim (GENERATE_KEYS body,
FINAL_STATUS provenance computation, CONFIRM state latch).  Those
aren't new design work — they're unchanged from palisade-pa v2.

## Next steps for the JC dev

1. Set up JavaCard SDK + ant-javacard build (mirror `applets/pav2/`).
2. Port GENERATE_KEYS / FINAL_STATUS / CONFIRM / WIPE bodies from
   palisade-pa/src/com/palisade/pa/ProvisioningAgent.java.
3. Wire up the EC private key's curve parameters in
   EcdhUnwrapper.initOnce() — P-256 constants standard (reuse
   palisade-pa/AttestationProvider.java's setA/setB/setG values).
4. Test against `packages/emv-ecdh`'s known-answer vectors.
5. Test against `packages/emv/src/byte-parity.test.ts` golden DGIs.
6. Flash to a virgin JCOP 5 card; verify state machine; tag SW codes.
7. Run full e2e via rca (see `PROTOTYPE_PLAN.md` phase 7+).
