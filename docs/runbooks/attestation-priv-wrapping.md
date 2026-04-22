# Attestation priv scalar wrapping — remote-ops design

**Status:** design + server scaffold landed; applet CAP rebuild + ship pending.
**Driver:** PCI CPL LSR 6 closure for remote operations. Palisade is cloud-only; there is no CP-PSR-audited perso terminal to contain the raw-priv-scalar-over-NFC transit. Current `STORE_ATTESTATION P1=0x01` wire sends the 32-byte P-256 private scalar as plaintext APDU body (`services/card-ops/src/operations/install-pa.ts:311`), which is blocking under remote ops.

---

## Current wire (pre-fix; vulnerable under remote ops)

```
       ┌──────────────────────────────────────────────┐
       │  card-ops (prod ECS, future)                 │
       │  POST /attestation/issue → data-prep         │
       │  receives: { cardAttestPrivRaw(32), ... }    │
       │  sends over NFC, SCP03 already scrubbed:     │
       │                                              │
       │    80 EC 01 00 20 || <raw 32-byte scalar>    │
       │                                              │
       │  attacker with NFC proximity sniffs scalar   │
       │  → can impersonate the card's attestation    │
       └──────────────────────────────────────────────┘
```

**Threat under remote ops:** attacker sitting between the operator's machine and the card (a compromised NFC reader driver, a MITM on a shared USB hub, a malicious service-mesh sidecar) can observe the `80 EC 01 00 20 …` APDU and extract the scalar. Once extracted, they can issue fake attestation signatures indistinguishable from the real chip's.

---

## Proposed wire (fix)

Use the **same ECDH wrapper format** already live for TRANSFER_PARAMS (`packages/emv-ecdh/src/index.ts` + `applets/pa-v3/.../EcdhUnwrapper.java`). The applet handles unwrap already — the only new bit is a bootstrap ephemeral keypair the applet emits once at install time.

### New wire shape

1. **Bootstrap keypair** — `IssuerAttestation.initOnce()` generates a fresh one-shot P-256 bootstrap keypair alongside the attestation state. Private half persists in EEPROM until STORE_ATTESTATION completes; then scrubbed.
2. **GET_ATTESTATION_BOOTSTRAP_PUBKEY** — new APDU, `CLA=80 INS=E4 P1=00 P2=00 Le=41`, returns the 65-byte SEC1 uncompressed bootstrap pubkey.
3. **Server wrap** — data-prep uses the bootstrap pubkey + a fresh server ephemeral keypair + `wrapParamBundle(...)` from `@palisade/emv-ecdh` to seal a TLV bundle containing:
   - tag 0x01 (1B): priv scalar (32B)
   - tag 0x02 (1B): card cert blob (~179B)
   - tag 0x03 (1B): CPLC (42B)
4. **STORE_ATTESTATION_SEALED** — new P1 value `0x81` takes the wrapped-bundle blob. Applet unwraps via existing `EcdhUnwrapper` logic, parses the inner TLV, stores each field via the same `loadPrivKey/loadCardCert/loadCplc` helpers as today.
5. **Cleanup** — after successful STORE_ATTESTATION_SEALED, applet wipes the bootstrap priv key. Any later STORE_ATTESTATION APDUs fail (state != IDLE or bootstrap-consumed guard).

### Protection properties

- **Confidentiality on the NFC wire**: AES-128-CBC ciphertext keyed by HKDF(ECDH(bootstrap_pub, server_ephemeral_priv) || session_id). Attacker sees ciphertext + bootstrap_pub + server_ephemeral_pub; recovering the scalar requires breaking ECDH.
- **Replay protection**: each install uses a fresh bootstrap keypair. Replaying a recorded APDU against a new install fails because the new bootstrap priv is different.
- **Tamper detection**: HMAC-SHA256 tag on (IV || ciphertext). Mutating any bit invalidates the tag → applet returns `SW_PARAM_BUNDLE_GCM_FAILED` (reused constant).
- **Applet code reuse**: `EcdhUnwrapper` is already battle-tested on the TRANSFER_PARAMS path. Same wire format, same state machine, just a different destination for the unwrapped plaintext.

---

## Server-side implementation

### `packages/emv-ecdh/src/attestation-wrap.ts` (new)

New helper `wrapAttestationBundle(...)` that composes:

```ts
function wrapAttestationBundle(input: {
  bootstrapPubUncompressed: Buffer;  // 65-byte chip-side pubkey from GET_ATTESTATION_BOOTSTRAP_PUBKEY
  sessionId: string;                 // stable install session id (binds HKDF info)
  cardAttestPrivRaw: Buffer;         // 32-byte P-256 scalar from issueCardCert
  cardCert: Buffer;                  // card_pubkey(65) || cplc(42) || sig(DER) from issueCardCert
  cplc: Buffer;                      // 42-byte CPLC
}): Buffer  // wire body: server_pub(65) || iv(12) || ciphertext || hmac_tag(16)
```

Internally builds the inner TLV `[0x01 0x20 <priv>] [0x02 <cardCertLen> <cardCert>] [0x03 0x2A <cplc>]`, then delegates to the existing `wrapParamBundle`.

### `services/card-ops/src/operations/install-pa.ts`

Replace the current three-APDU raw flow with:

```ts
// 1. Fetch bootstrap pubkey (new)
const bootstrapResp = await sendAndRecv(io, Buffer.from('80E4000041', 'hex'));
const bootstrapPub = bootstrapResp.subarray(0, 65);

// 2. Fetch CPLC (unchanged — still via GET DATA 9F7F before SCP03 scrub)
// 3. issueCardCert(cplc, kmsSigner) (unchanged)

// 4. Wrap via ECDH
const wrapped = wrapAttestationBundle({
  bootstrapPubUncompressed: bootstrapPub,
  sessionId: cardOpSessionId,
  cardAttestPrivRaw: bundle.cardAttestPrivRaw,
  cardCert: bundle.cardCert,
  cplc,
});

// 5. SELECT PA + single sealed STORE_ATTESTATION APDU
await sendAndRecv(io, Buffer.concat([
  Buffer.from([0x80, 0xEC, 0x81, 0x00, wrapped.length]),
  wrapped,
]));

// 6. Scrub the plaintext scalar from memory as before.
bundle.cardAttestPrivRaw.fill(0);
```

No data-prep-side changes if card-ops imports `wrapAttestationBundle` directly (same pattern the current install-pa already uses).

---

## Applet-side implementation

### `applets/pa-v3/.../IssuerAttestation.java` additions

```java
private KeyPair bootstrapKp;        // one-shot P-256 keypair, generated at initOnce
private boolean bootstrapConsumed;  // guards against replay

public byte[] getBootstrapPubkey() {
  // Return the 65-byte SEC1 bootstrap pubkey.
  ...
}

public void unwrapAndLoad(byte[] wrappedBlob, short off, short len) {
  if (bootstrapConsumed) ISOException.throwIt(SW_WRONG_STATE);
  // Use EcdhUnwrapper against bootstrapKp.getPrivate() + sessionId
  // Parse inner TLV (tags 0x01/0x02/0x03) into loadPrivKey / loadCardCert / loadCplc
  ...
  bootstrapKp.getPrivate().clearKey();  // scrub bootstrap priv
  bootstrapConsumed = true;
}
```

### `applets/pa-v3/.../ProvisioningAgentV3.java` dispatcher

```java
case Constants.INS_STORE_ATTESTATION:
  byte p1 = buffer[ISO7816.OFFSET_P1];
  if (p1 == Constants.ATTEST_P1_SEALED_BUNDLE /* 0x81 */) {
    attestation.unwrapAndLoad(buffer, dataOff, lc);
  } else {
    // legacy raw paths preserved for now — remove after fleet
    // migration to 0x81 completes.
    attestation.loadPrivKey(...) / loadCardCert(...) / loadCplc(...);
  }
  break;

case Constants.INS_GET_ATTESTATION_BOOTSTRAP_PUBKEY:  // 0xE4
  short pubLen = attestation.getBootstrapPubkey(buffer, (short)0);
  apdu.setOutgoingAndSend((short)0, pubLen);
  break;
```

---

## CAP rebuild checklist (operator task)

1. `cd applets/pa-v3 && ant clean build` — outputs `build/pa-v3.cap`.
2. Smoke test on the trial card:
   - Install fresh: `install-PA` should now include the sealed-bundle STORE_ATTESTATION.
   - Tap with strict mode off (permissive): should still succeed (sealed path optional-but-preferred).
   - Flip strict mode on `palisade-rca:19` → tap should verify the full chain.
3. Commit the rebuilt CAP as a separate PR with the corresponding SHA manifest (once Stage H.1 lands).

---

## Compatibility window

During rollout both the sealed (0x81) and raw (0x01/0x02/0x03) paths stay accepted. Fleet migration plan:
1. Land this PR (server + applet code).
2. Re-perso trial card via sealed path; verify strict-mode tap.
3. Remove raw-path support from `IssuerAttestation.java` in a follow-up CAP rebuild once ops confirms all cards migrated.

Cards personalised under the old raw path continue to work — their attestation material is already loaded; they never need to re-run STORE_ATTESTATION.

---

## What landed in the committed server scaffold

- `packages/emv-ecdh/src/attestation-wrap.ts` — `wrapAttestationBundle()` helper (compiles, typechecks, 2 unit tests: round-trip and tag-mutation-rejection).
- `services/card-ops/src/operations/install-pa.ts` — feature-flagged branch (`ATTESTATION_USE_SEALED_STORE=1`) that uses the sealed path when the env flag is on. Default off (legacy raw path continues to work until operator rebuilds the CAP + flips the flag).
- `applets/pa-v3/src/main/java/com/palisade/pa/IssuerAttestation.java` — comments marking the planned `unwrapAndLoad` hook; no new compiled code until CAP rebuild.

---

## Out of scope (future work)

- HSM-backed bootstrap keypair (today it's javacard-native — fine for CP-LSR because the applet itself is a secure element).
- Forward secrecy beyond per-install (each install generates a fresh bootstrap keypair, which is already an FS win — but it doesn't help if the attacker later compromises the chip).
- Post-quantum — ECDH P-256 on NIST curve is fine under current PCI threat model; revisit in 2030+.
