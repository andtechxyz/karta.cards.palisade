# Runbook: Key Rotation

**Document Owner:** Security Team
**Last Reviewed:** 2026-04-19
**Applies to:** Palisade (card + chip). Vera (vault + pay) rotates its own
vault PAN DEK, vault fingerprint key, and ARQC root seed via the mirrored
procedures in `/Users/danderson/Vera/docs/security/key-management-procedures.md`.

**Related:** [fi-onboarding.md](./fi-onboarding.md), [incident-response.md](./incident-response.md), [attestation-vendor-rekey.md](./attestation-vendor-rekey.md)

---

## 1. Scope

Routine rotation of Palisade's secret material. For emergency rotation following a suspected compromise, follow [incident-response.md](./incident-response.md) first, then return here for the mechanical steps.

**Post-split key ownership:**

| Key / secret | Owner | Storage |
|---|---|---|
| GP SCP03 per-FI keys (ENC/MAC/DEK) | Palisade | AWS Secrets Manager, ARN per `IssuerProfile.gp{Enc,Mac,Dek}KeyArn` |
| GP SCP03 fallback test keys (`GP_MASTER_KEY`) | Palisade | `palisade/GP_MASTER_KEY` secret (dev/sample cards only) |
| UDK derivations (IMK-AC / IMK-SMI / IMK-SMC / TMK / Issuer PK) | Palisade | AWS Payment Cryptography, ARN per `IssuerProfile` |
| SDM per-card read keys | Palisade | Derived at tap time, never stored — masters in AWS Payment Cryptography per `SDM_META_MASTER_KEY_ARN` / `SDM_FILE_MASTER_KEY_ARN` |
| Card-field DEK (Card.uidEncrypted) | Palisade | `palisade/CARD_FIELD_DEK_V1` in Secrets Manager |
| Vault PAN DEK (VaultEntry.encryptedPan) | Vera | `vera/VAULT_PAN_DEK_V1` in Secrets Manager |
| Vault PAN fingerprint key | Vera | `vera/VAULT_PAN_FINGERPRINT_KEY` |
| Vera root ARQC seed | Vera | `vera/VERA_ROOT_ARQC_SEED` |
| Inter-service HMAC (`SERVICE_AUTH_KEYS`) | Both repos maintain their own map | `{vera,palisade}/SERVICE_AUTH_KEYS` |

## 2. SERVICE_AUTH_KEYS (per-caller HMAC)

Two-phase to avoid a traffic-split outage.

1. Generate new secret: `openssl rand -hex 32`
2. **Phase 1 — dual-key window.** Edit the `SERVICE_AUTH_KEYS` Secrets Manager entry to include BOTH the old and new keyId for the caller (e.g. `{"pay": "<old>", "pay_v2": "<new>"}`). Redeploy the *receiving* services so they accept either. Do NOT rotate the caller's env yet.
3. **Phase 2 — caller switch.** Update the caller's `SERVICE_AUTH_*_SECRET` to the new value, redeploy the caller. Watch CloudWatch for any `401` on inter-service calls for ~10 minutes.
4. **Cleanup.** Remove the old keyId from `SERVICE_AUTH_KEYS`, redeploy receivers.

**Verify rotation worked:** every caller's `SERVICE_AUTH_*_SECRET` now hashes to the receiver's lone keyId. `curl` a signed health endpoint from a dev box using the new key — 200 expected, 401 if misaligned.

**Detect stale secrets still in use:** CloudWatch metric filter on receiver logs for `serviceAuth: unknown keyId` — should be zero after the cleanup phase.

**Rollback:** re-add the old keyId to `SERVICE_AUTH_KEYS`, redeploy receivers, point the caller's env back at the old secret. No data-at-rest impact; these are wire-protocol auth keys only.

## 3. GP SCP03 keys — per-FI (production) and test-keys fallback (dev)

Track 1 (`40cc455 card-ops: Track 1 — per-FI GP SCP03 keys + APDU audit
log`) landed a per-FI GP key fetcher (`services/card-ops/src/keys/gp-key-fetcher.ts`)
that resolves ENC/MAC/DEK from Secrets Manager ARNs on the card's
`IssuerProfile`. Production rotation is a per-FI operation against those
three ARNs; dev / sample-card rotation touches the `GP_MASTER_KEY`
fallback only.

### 3a. Per-FI GP keys (production path)

Keys: `IssuerProfile.gpEncKeyArn` / `gpMacKeyArn` / `gpDekKeyArn` — each
points at an AWS Secrets Manager entry under `palisade/card-ops/gp/<fi>/<role>`.
The card-ops service reads them via `GpKeyFetcher`; rotation is
fi-scoped and does not touch other issuers.

1. Coordinate with the perso partner that ships cards for the FI — they
   hold the matching SCP03 key set. Schedule a window during which no
   new cards for that FI are personalised.
2. Generate the new three-key set (`openssl rand -hex 16` × 3); deliver
   to the perso partner via the agreed secure channel (SCP01 key-exchange
   or equivalent). Do NOT update Secrets Manager yet.
3. Once the partner confirms the new keys are live on the perso line:
   create three new Secrets Manager entries (versioned under the same
   `palisade/card-ops/gp/<fi>/<role>` names — Secrets Manager maintains
   the prior version for rollback) and update the `IssuerProfile` rows
   with the new ARNs if namespacing changed.
4. Redeploy card-ops. First install/personalise operation against that
   FI validates the new keys; APDU audit log in the database records the
   SCP03 handshake outcome — failures are visible immediately.

**Verify:** one loopback install against a throwaway card in the new
key set; confirm `CardOpSession.status = 'COMPLETED'` and the APDU audit
log shows no `SCP03_AUTH_FAILED`.

**Detect stale:** CloudWatch metric filter on `SCP03_AUTH_FAILED` count;
should stay at pre-rotation baseline.

**Rollback:** Secrets Manager `restore-secret` to the prior version, or
flip `IssuerProfile.gp*KeyArn` rows back to the previous ARN. No code
change needed — the fetcher reads from the ARN at handshake time.

### 3b. `GP_MASTER_KEY` — dev / sample-card fallback only

The `GP_MASTER_KEY` env var carries a JSON `{enc,mac,dek}` triple used
only when `CARD_OPS_USE_TEST_KEYS='1'` OR the card's `IssuerProfile` has
no GP ARN populated (both typical in local dev against virgin JCOP
sample cards). Production must leave `CARD_OPS_USE_TEST_KEYS` unset and
populate the per-FI ARNs above.

1. Generate new keys: `openssl rand -hex 16` × 3.
2. Update Secrets Manager `palisade/GP_MASTER_KEY` with the new JSON triple.
3. Redeploy card-ops.
4. Verify with a loopback install against a sample card configured for
   the test-keys fallback.

**Rollback:** Secrets Manager `restore-secret`; no data-at-rest impact.

## 4. DEV_UDK_ROOT_SEED / DEV_SDM_ROOT_SEED

Dev-only derivation seeds, used when `SDM_KEY_BACKEND=local` and the
data-prep UDK backend is `local`. Never used against real cards.

1. `openssl rand -hex 32 > /tmp/new_seed`
2. Update `palisade/DEV_SDM_ROOT_SEED` (and, if rotating UDK, the
   equivalent UDK root seed your data-prep local backend uses).
3. Redeploy affected dev services (tap, activation, data-prep, card-ops).
4. Re-run `scripts/regen-sad-e2e.ts` for any e2e test cards so they pick
   up the new derivations.

No rollback needed; the only impact is invalidating existing dev-card
sessions. In prod (`SDM_KEY_BACKEND=hsm`, UDK backend `hsm`), these seeds
are not read.

## 5. AWS Payment Cryptography — UDK derivations (issuer master keys)

All EMV issuer master keys (TMK, IMK-AC, IMK-SMI, IMK-SMC, Issuer RSA
PK) live in AWS Payment Cryptography; Palisade grants IAM and references
them via the ARNs on `IssuerProfile`.

The data-prep service derives per-card UDKs on demand via
`DeriveKey`/`GenerateMac` against these ARNs — nothing per-card is stored.

1. Confirm the target key has `enableKeyRotation=true` on its APC key policy.
2. Auto-rotation runs annually and produces a new version on the SAME
   ARN — callers continue to reference the ARN, no code change required.
3. Verify post-rotation: run `scripts/import-issuer-keys.ts --dry-run` to
   confirm the ARNs in IssuerProfile still resolve. Issue a test
   cryptogram via data-prep and confirm the parent bank's HSM returns
   `APPROVED`.

**Detect stale:** AWS CloudTrail logs every key use; a non-rotating key
shows identical `keyVersion` attribute month over month.

**Rollback:** AWS maintains the previous version for 90 days. Rollback
via AWS console (`aws payment-cryptography restore-key`).

## 6. AWS Payment Cryptography — SDM master keys

Two AES-128 CMAC keys live in APC:

- `SDM_META_MASTER_KEY_ARN` — derives per-card `K_meta` via `AES-CMAC(K_master_meta, UID)` per NXP AN14683.
- `SDM_FILE_MASTER_KEY_ARN` — derives per-card `K_file`.

Tap derives both on every tap; nothing per-card persists.

1. Rotation follows the same dual-ARN pattern as §3a: create a new APC
   key, update one of the two ARNs on the card-ops / tap / activation
   services' env to point at the new one, redeploy.
2. APC auto-rotation generates a new version on the SAME ARN; no code
   change required when using auto-rotation.
3. Verify: tap a known-good test card; confirm the SUN verify succeeds
   and the `SDM.CMAC` check passes.

**Rollback:** APC key-version rollback as in §5, or env revert to the
prior ARN.

## 7. KMS-managed SAD encryption

KMS-managed. Key: the CMK referenced by `KMS_SAD_KEY_ARN` (shared across
data-prep, rca, and card-ops' `personalise_payment_applet` op so the
same SAD ciphertext round-trips).

1. Ensure automatic rotation is on (`aws kms enable-key-rotation --key-id <arn>`).
2. AWS rotates annually; existing SAD ciphertext remains decryptable
   under any historical version for the key's lifetime.
3. New SAD blobs minted after rotation use the new version transparently.
4. Verify: `aws kms describe-key --key-id <arn>` →
   `KeyRotationStatus.KeyRotationEnabled: true`.

**Rollback:** not applicable — AWS retains older versions automatically.

## 8. Card-field DEK (`CARD_FIELD_DEK_V1`)

Encrypts `Card.uidEncrypted`. Used by tap (read) and activation (write).
Dual-version is mandatory because existing cards carry ciphertext keyed
to the active version.

1. Generate new: `openssl rand -hex 32`.
2. Add as `CARD_FIELD_DEK_V2` in Secrets Manager. Do NOT change
   `CARD_FIELD_DEK_ACTIVE_VERSION` yet.
3. Redeploy tap + activation so both can decrypt V1 ciphertext and
   encrypt under V2 when the active version flips.
4. Flip `CARD_FIELD_DEK_ACTIVE_VERSION=2`, redeploy. New writes now
   encrypt under V2; old V1 ciphertext continues to decrypt.
5. Optional: background re-encrypt pass to bring all V1 ciphertext
   forward to V2 so the old key can eventually be removed.

**Rollback:** flip `CARD_FIELD_DEK_ACTIVE_VERSION` back to 1.

## 9. Inter-service HMAC on the Palisade ⇌ Vera seam

The `palisade` keyId in Vera's `SERVICE_AUTH_KEYS` and Palisade's
`PALISADE_VERA_VAULT_SECRET` must be kept in sync. Rotation uses the
same two-phase pattern as §2 — add a second keyId in Vera's map first,
flip Palisade to the new secret, then remove the old keyId.

Both repos ship their own `SERVICE_AUTH_KEYS` entry; do NOT share secret
values across the two maps for any keyId other than `palisade`.
