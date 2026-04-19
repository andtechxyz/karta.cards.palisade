# Runbook: Incident Response — Common Failure Modes

**Document Owner:** Security Team
**Last Reviewed:** 2026-04-19
**Related:** [key-rotation.md](./key-rotation.md), [attestation-vendor-rekey.md](./attestation-vendor-rekey.md), [../security/incident-response-plan.md](../security/incident-response-plan.md)

---

## 1. Scope

Tactical recovery steps for the operational failures on-call sees most often. For security incidents (key compromise, data breach), route through [../security/incident-response-plan.md](../security/incident-response-plan.md) FIRST. This runbook is the 3 a.m. "the tap is stuck" kind of issue.

## 2. Tap fails mid-provisioning (chip at intermediate PA state)

**Symptom:** user reports the card went through the NFC tap but the mobile app hangs at "finalising"; `ProvisioningSession.phase` is stuck at `SAD_TRANSFER` or `AWAITING_FINAL`.

**Diagnosis:**
1. Pull the session: `SELECT id, phase, updatedAt FROM "ProvisioningSession" WHERE "cardId" = '<id>' ORDER BY "createdAt" DESC LIMIT 1;`
2. If `phase NOT IN ('COMPLETE','FAILED')` and `updatedAt > now() - interval '1h'`, it's in-flight — wait. If older than an hour the reaper will archive it on the next cron.
3. Check the RCA service's CloudWatch logs for the `rcaSessionId`.

**Recovery:**
1. Ask the cardholder to open the mobile app and retry — the PA applet holds state per card but the session can be re-opened.
2. If the retry fails at the same phase, mark the session as FAILED manually and invoke the `reset_pa_state` card-ops operation (once Track 1 lands — until then, escalate to engineering):
   ```
   POST /api/card-ops/reset-pa-state
   { "cardRef": "<ref>" }
   ```
3. The reset clears the applet's intermediate state so the next TRANSFER_SAD starts fresh.

**Rollback:** none — the card is idle until the next tap.

## 3. SAD record stuck CONSUMED on a failed session

**Symptom:** re-provisioning attempt fails with "no READY SAD record for proxyCardId", but a CONSUMED record exists.

**Recovery:**
1. Confirm the originating ProvisioningSession did actually fail (`phase = FAILED`), not just slow.
2. Regenerate via:
   ```
   DATABASE_URL=... tsx scripts/regen-sad-e2e.ts \
     --card-ref <ref> --pan <pan> --expiry <YYMM>
   ```
3. This upserts the SadRecord, flipping status back to READY and bumping `expiresAt`.
4. Retry the provisioning flow.

**Prevention:** the reaper will hard-delete CONSUMED records after 30 days, so the regen won't conflict long-term. If regen is common, escalate — it suggests a flaky RCA relay.

## 4. Callback (RCA → activation) timing out

**Symptom:** provisioning completes on the card but activation never flips `Card.status` to PROVISIONED; RCA logs show `timeout calling activation /api/provisioning/callback`.

**Diagnosis:**
1. Confirm the internal ALB is healthy: `aws elbv2 describe-target-health --target-group-arn <activation-tg>`.
2. Confirm the RCA security group has egress to the internal ALB's SG (port 443). The most common cause is a newly-tightened SG dropping the rule.
3. Test the path: from an RCA ECS task exec, `curl -v https://<internal-alb-dns>/api/health` — expect 200. 403 means SG is OK but auth failed (check `SERVICE_AUTH_KEYS`); timeout means SG.

**Recovery:**
1. Restore the SG ingress rule (`aws ec2 authorize-security-group-ingress`).
2. Once restored, the RCA has a bounded retry — up to 3 attempts over 30 seconds. If those all expired before the fix, manually re-trigger the callback:
   ```
   POST /api/admin/provisioning/<sessionId>/replay-callback
   ```
3. Card status should flip within seconds.

## 5. APC mock/real flag flip went wrong

**Symptom:** after a deploy toggling `PAYMENT_CRYPTO_MOCK=false`, personalisation fails with opaque errors from AWS Payment Cryptography; CloudWatch shows `AccessDeniedException`.

**Recovery:**
1. Immediate rollback — set `PAYMENT_CRYPTO_MOCK=true` in the affected service's Secrets Manager entry, force a new ECS deploy:
   ```
   aws ecs update-service --service data-prep --force-new-deployment
   ```
2. Within ~2 minutes traffic returns to mock-mode HSM — unblocks ops but the cards personalised during this window have stub cryptograms and MUST be flagged for rework.
3. Investigate the root cause: in ~90% of cases the IAM role attached to the task doesn't have `payment-cryptography-data:*` for the specific key ARNs. Update the role, re-enable real mode.

**Verification after re-enable:** one test card goes through the full flow with `PAYMENT_CRYPTO_MOCK=false`; confirm `SadRecord.sadEncrypted` is a real HSM-wrapped blob (>= 512 bytes) not the mock stub.

## 6. Suspected counterfeit-chip attestation failure

**Symptom:** once the attestation verifier goes from warn-only to reject, a legitimate card is rejected with `ATTESTATION_MISMATCH`.

**Diagnosis:**
1. Pull the attestation payload: `SELECT "attestationRaw" FROM "Card" WHERE "cardRef" = '<ref>';`
2. Run it against the verifier in trace mode (when Track 2 lands; for now the verifier is stubbed — any failure here is a code bug, not a counterfeit). Verify:
   - Chip serial matches the expected NXP/Infineon vendor prefix.
   - Cert chain walks up to the vendor root anchor configured per [attestation-vendor-rekey.md](./attestation-vendor-rekey.md).

**Escalation:**
1. If the chain is valid but the serial is unknown, mark the card for security team review — do NOT auto-pass.
2. If the chain fails cryptographic verification and the card came through a trusted FI, contact the FI to confirm the batch; the root cause is usually a stale trust anchor (vendor did a CA rekey and Palisade hasn't pulled the new anchor).
3. Follow [attestation-vendor-rekey.md](./attestation-vendor-rekey.md) to refresh the anchor before resuming provisioning for that vendor.

**Rollback:** if a large batch is being rejected after a verifier flip, toggle the verifier back to warn-only while root cause is determined. Record the toggle in the incident log — production must not stay warn-only more than 72 hours per §4.5 of the parent IR plan.
