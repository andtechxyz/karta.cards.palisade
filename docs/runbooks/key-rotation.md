# Runbook: Key Rotation

**Document Owner:** Security Team
**Last Reviewed:** 2026-04-19
**Related:** [fi-onboarding.md](./fi-onboarding.md), [incident-response.md](./incident-response.md), [../security/key-management-procedures.md](../security/key-management-procedures.md)

---

## 1. Scope

Routine rotation of Palisade's secret material. For emergency rotation following a suspected compromise, follow [incident-response.md](./incident-response.md) first, then return here for the mechanical steps.

## 2. SERVICE_AUTH_KEYS (per-caller HMAC)

Two-phase to avoid a traffic-split outage.

1. Generate new secret: `openssl rand -hex 32`
2. **Phase 1 — dual-key window.** Edit the `SERVICE_AUTH_KEYS` Secrets Manager entry to include BOTH the old and new keyId for the caller (e.g. `{"pay": "<old>", "pay_v2": "<new>"}`). Redeploy the *receiving* services so they accept either. Do NOT rotate the caller's env yet.
3. **Phase 2 — caller switch.** Update the caller's `SERVICE_AUTH_*_SECRET` to the new value, redeploy the caller. Watch CloudWatch for any `401` on inter-service calls for ~10 minutes.
4. **Cleanup.** Remove the old keyId from `SERVICE_AUTH_KEYS`, redeploy receivers.

**Verify rotation worked:** every caller's `SERVICE_AUTH_*_SECRET` now hashes to the receiver's lone keyId. `curl` a signed health endpoint from a dev box using the new key — 200 expected, 401 if misaligned.

**Detect stale secrets still in use:** CloudWatch metric filter on receiver logs for `serviceAuth: unknown keyId` — should be zero after the cleanup phase.

**Rollback:** re-add the old keyId to `SERVICE_AUTH_KEYS`, redeploy receivers, point the caller's env back at the old secret. No data-at-rest impact; these are wire-protocol auth keys only.

## 3. GP_MASTER_KEY (SCP03 static)

**NOTE:** The card-ops track is migrating this from static env keys to AWS Payment Cryptography. Update this section once PR [track-1] lands — rotation will become an APC key rekey operation, see §6 below. Until then:

1. Coordinate with partners that ship personalised cards — they hold the matching static key.
2. Schedule a maintenance window: no personalisation during swap.
3. Generate new `GP_MASTER_KEY`, deliver to the perso partner via the agreed SCP01 key-exchange channel.
4. Update Secrets Manager `palisade/GP_MASTER_KEY`, redeploy card-ops.
5. Verify with a loopback personalisation against a throwaway card.

**Rollback:** keep the old key under a versioned Secrets Manager entry for 30 days; rollback is swap env + redeploy.

## 4. DEV_UDK_ROOT_SEED / DEV_SDM_ROOT_SEED

Dev-only; derivation seeds not used against real cards. Rotation is mechanical:

1. `openssl rand -hex 32 > /tmp/new_seed`
2. Update `palisade/DEV_*_ROOT_SEED`.
3. Redeploy affected dev services.
4. Re-run `scripts/regen-sad-e2e.ts` for any e2e test cards so they pick up keys derived from the new seed.

No rollback needed; the only impact is invalidating existing dev-card sessions.

## 5. AWS Payment Cryptography (issuer master keys)

AWS manages key material; Palisade grants IAM.

1. Confirm the target key (IMK-AC, IMK-SMI, IMK-SMC, TMK, Issuer PK) has `enableKeyRotation=true` on the AWS Payment Cryptography key policy.
2. Auto-rotation runs annually and produces a new version on the SAME ARN — callers continue to reference the ARN, no code change required.
3. Verify post-rotation: run `scripts/import-issuer-keys.ts --dry-run` to confirm the ARNs in IssuerProfile still resolve. Issue a test cryptogram via data-prep and confirm the parent bank's HSM returns `APPROVED`.

**Detect stale:** AWS CloudTrail logs every key use; a non-rotating key shows identical `keyVersion` attribute month over month.

**Rollback:** AWS maintains the previous version for 90 days. Rollback via AWS console (`aws payment-cryptography restore-key`).

## 6. KMS-managed SAD encryption

KMS-managed. Key: the CMK referenced by `KMS_SAD_KEY_ARN`.

1. Ensure automatic rotation is on (`aws kms enable-key-rotation --key-id <arn>`).
2. AWS rotates annually; existing SAD ciphertext remains decryptable under any historical version for the key's lifetime.
3. New SAD blobs minted after rotation use the new version transparently.
4. Verify: `aws kms describe-key --key-id <arn>` → `KeyRotationStatus.KeyRotationEnabled: true`.

**Rollback:** not applicable — AWS retains older versions automatically.
