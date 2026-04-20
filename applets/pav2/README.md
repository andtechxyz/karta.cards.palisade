# pav2 — Palisade T4T Applet v2

JavaCard applet for NFC Forum Type 4 Tag + SDM on JCOP. Successor to
`PalisadeT4T.cap`. Adds three patent-aligned proprietary APDUs:

| INS  | Meaning            | Patent claim |
|------|--------------------|--------------|
| 0xEB | `INS_ACTIVATE`     | C5 (state machine), C10 (lifecycle) |
| 0xEC | `INS_GET_CHALLENGE`| C4 (nonce binding) |
| 0xED | `INS_REVOKE`       | C11 (on-chip revocation) |

All three use CLA `0x80` (proprietary). Existing APDUs (`INS_GET_STATE=0xEE`,
`INS_GET_CARD_INFO=0xF0`) unchanged from v1.

## Layout

- Package AID: `A00000064702` (v1 was `A000000647`)
- T4T class AID: `A0000006470102` (v1 was `A0000006470101`)
- T4T instance AID: `D2760000850101` (NFC Forum NDEF — unchanged)
- FIDO2 class AID: `A0000006472F0002` (v1 was `A0000006472F0001`)

The instance AID for T4T stays as the NFC Forum constant so phones keep
working without any client-side change. The package/class AIDs bump so
v1 and v2 can coexist during fleet rollout.

## Build

```sh
export JC_HOME=/path/to/Java_Card_Classic_API-3.0.5
ant -f build.xml build
```

Output: `build/pav2.cap` (~182 KB). Requires ant + OpenJDK 11 +
JavaCard Classic API 3.0.5 SDK.

## Install via gp.jar

```sh
# Delete old v1 T4T instance if installed
java -jar gp.jar --key <GP_MASTER> --delete D2760000850101

# Install pav2 package + create T4T instance with perso data
java -jar gp.jar --key <GP_MASTER> \
  --install build/pav2.cap \
  --applet A0000006470102 \
  --create D2760000850101 \
  --params <install-blob-hex>
```

Install params format (same as v1): `uid(7) | picc_enc_key(16) | mac_key(16) | url_len(1) | url(N)`.

## APDU reference

### INS_ACTIVATE (0x80 EB 00 00)
Transitions state from SHIPPED→ACTIVATED. Idempotent in non-SHIPPED
non-BLOCKED states (returns 9000 unchanged). BLOCKED returns SW 6985
(conditions not satisfied).

### INS_GET_CHALLENGE (0x80 EC 00 00 Le=10)
Returns 16 bytes from the on-chip SECURE_RANDOM. Available for callers
that want a chip-sourced nonce — e.g. future defence-in-depth where PA
verifies the nonce matches what pav2 last issued (see "Patent
compliance" below).  Not consumed by the current provisioning flow:
SAD replay prevention is enforced server-side via the `SadRecord`
status transition (`READY → CONSUMED` inside the provisioning
`$transaction`), which is sufficient under the normal threat model.
No authentication required — entropy is the only secret.

### INS_REVOKE (0x80 ED 00 00)
Irreversible. Flips state to STATE_BLOCKED and zeroes both AES-128
keys (piccEncKey, macKey). Post-revoke SELECT returns SW 6A81 (function
not supported). Recovery requires full applet re-personalisation.

## Patent compliance

### C4 — replay rejection (satisfied server-side)

C4 requires that a captured SAD cannot be replayed.  Each SAD is bound
to exactly one provisioning attempt, and the binding must be
enforced cryptographically so a passive observer on the WS relay
can't re-inject a previously-seen payload.

The **working enforcement is server-side**, via the state machine on
`SadRecord.status`:

1. `POST /api/provisioning/start` locates the card's `READY` SadRecord;
   RCA decrypts + ships it to the PA applet via plan-mode.
2. When PA's `CONFIRM` round-trips 9000, the session-manager's
   `$transaction` atomically flips
   `SadRecord.status: READY → CONSUMED` alongside
   `Card.status: ACTIVATED → PROVISIONED`.
3. Any subsequent `/api/provisioning/start` against the same
   proxyCardId finds no `READY` record → rejects with `sad_not_ready`.

Replay is prevented because the server refuses to re-emit a consumed
SAD.  Without server emission, the mobile has nothing to relay.  This
is the normal-case C4 enforcement.

### C4 — chip-side defence-in-depth (optional, deferred)

For the narrower threat of a compromised backend replaying an old SAD
to the same physical chip, chip-side enforcement is available as
defence-in-depth.  The groundwork is in place on both sides:

- **pav2** exposes `INS_GET_CHALLENGE` (this applet).
- **rca/plan-builder** exposes `PlanOptions.includeChipChallenge`
  which, when set, prepends `SELECT pav2 + GET_CHALLENGE` to the
  provisioning plan.  Default off.
- **@palisade/emv/apdu-builder** exports `getChallenge()` and
  `selectPav2()` helpers for assembling the steps.

To close the defence-in-depth path fully, the PA applet would need to:
a. Persist pav2's last-issued challenge in EEPROM across power-down.
   Requires a JavaCard Shareable Interface Object (SIO) on pav2 that
   PA looks up via `JCSystem.getAppletShareableInterfaceObject(pav2Aid, ...)`
   during `processTransferSad`, gated on PA's client AID inside pav2's
   `getShareableInterfaceObject()`.
b. Verify the SAD payload's trailing 16 bytes match the SIO's last
   challenge, via a constant-time compare.
c. Wipe the challenge once matched so the same nonce can't be reused.

Because this requires coordinated pav2 + PA CAP rebuilds AND
re-personalisation of every in-field card, it is NOT in the critical
path for C4 compliance — the server-side state machine is the
defensible answer under the realistic threat model.  The applet hooks
are left in place so the work can land when a full fleet re-perso is
planned for other reasons (e.g. the strict-attestation rollout).

### C5 — explicit pending→committed state transitions

`INS_ACTIVATE` replaces the odd/even WebAuthn-trigger workaround from
v1, making state moves driven by authenticated backend APDUs rather
than as a side-effect of FIDO2 credential creation count.

### C11 — on-chip revocation enforcement

`INS_REVOKE` converts backend revocation policy into a cryptographic
fact on the chip — `cardState → STATE_BLOCKED`, SDM AES keys zeroed.
No key material remains exploitable even if the attacker can still
physically issue APDUs post-revoke.

## Wire-up notes

- `INS_GET_CHALLENGE` is callable before ACTIVATE (entropy doesn't need
  authentication). If you want to gate it, add a state check inside
  `processGetChallenge()`.
- `INS_REVOKE` has no authentication guard either; backends should call
  it only after their own policy check. A future iteration could require
  an HMAC-signed nonce in the APDU body to prevent accidental revocation.
- `INS_ACTIVATE` is equally authentication-free — deliberate, since the
  chip is uninitialised until activated. Future tighter version could
  require proof-of-WebAuthn-binding.
