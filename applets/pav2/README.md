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
Returns 16 bytes from the on-chip SECURE_RANDOM. Caller (RCA) binds the
challenge into a SAD prefix for replay protection. No authentication
required — entropy is the only secret.

### INS_REVOKE (0x80 ED 00 00)
Irreversible. Flips state to STATE_BLOCKED and zeroes both AES-128
keys (piccEncKey, macKey). Post-revoke SELECT returns SW 6A81 (function
not supported). Recovery requires full applet re-personalisation.

## Patent compliance

The pav2 additions close three partial/missing claims from the overnight
audit:

- **C4** (nonce binding + replay rejection): `INS_GET_CHALLENGE` gives the
  RCA a chip-issued random that must appear in the next SAD prefix.
- **C5** (explicit pending→committed state transitions): `INS_ACTIVATE`
  replaces the odd/even WebAuthn-trigger workaround from v1, making state
  moves driven by authenticated backend APDUs.
- **C11** (on-chip revocation enforcement): `INS_REVOKE` converts backend
  revocation policy into a cryptographic fact on the chip — no key
  material remains exploitable.

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
