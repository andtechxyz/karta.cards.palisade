# Palisade Incident Response Plan

**Status:** Draft — 2026-04-21.
**Owner:** Platform Security (security@karta.cards).
**Applies to:** any event affecting CHD, key material, or service availability on the Palisade stack.

> Keep this short enough to read in a 3am Slack page. Long narrative belongs in `SECURITY.md`.

---

## 1. Severity tiers

| Sev | Criteria | Response target |
|-----|----------|-----------------|
| **SEV-1** | CHD exposure, key compromise, full platform outage, attestation Root CA compromise | Page on-call immediately; warroom within 15 min; customer + regulator notification within 72 h (GDPR) / 24 h (PCI). |
| **SEV-2** | Partial outage (one service), auth bypass, attestation Issuer CA compromise, KMS key exfil attempt detected | On-call paged; warroom within 1 h; ship a mitigation same day. |
| **SEV-3** | Degraded performance, non-blocking vuln found in prod, misconfigured log retention | Ticket opened; address in the current sprint. |
| **SEV-4** | Lint / audit findings, docs drift, test-only issues | Backlog. |

---

## 2. Detection triggers

**Automated (when the alarm infra lands — CPL LSR 8 in remediation):**
- CloudWatch alarms on error rate > 5 % for 5 min.
- CloudWatch alarms on HTTP 401/403 rate > 10/min (brute force).
- GuardDuty findings (when enabled).
- AWS Config rule violations (KMS disabled, SG wide-open, public S3).
- `npm audit` failing CI (as of 2026-04-21).

**Manual:**
- Operator reports "something's off" in the admin UI.
- Third-party disclosure to security@karta.cards.
- Tap-test failures with unexpected SW codes in the field.

---

## 3. Immediate response (first 30 minutes)

1. **Acknowledge + page on-call.** Slack `#sev-1` with: what, when noticed, blast radius estimate, who's responding.
2. **Preserve evidence.** Do NOT start nuking anything. Snapshot affected log groups with a `StartQuery` / export to S3. Freeze ECS task definitions (`aws ecs list-task-definitions`).
3. **Contain, don't eradicate (yet).**
   - Stop the bleed: scale the affected service to 0 if necessary; disable the offending ALB listener rule.
   - Rotate compromised credentials: new Secrets Manager version, then force-redeploy to pick up the rotation.
   - Revoke compromised sessions: delete `CardOpSession` / `ProvisioningSession` rows or mark them FAILED.
4. **Comms.** Update `#sev-1` every 30 min with: current hypothesis, next steps, ETA. No speculation outside the warroom.

---

## 4. Containment playbooks

### 4.1 Suspected HMAC key leak (service-auth)
1. Rotate the leaked secret in Secrets Manager (new version).
2. Update every service's task def to the new ARN version (`aws ecs update-service --force-new-deployment`).
3. Verify via `curl -H "Authorization: HMAC <old>"` returns 401 within 5 min of rollout.
4. Revoke old secret version after 7 days (grace for in-flight requests).

### 4.2 Suspected KMS key compromise (SAD / ParamBundle encryption)
1. Disable the KMS key (`aws kms disable-key`). All in-flight SAD encrypts/decrypts start failing — expected.
2. Create a new KMS key + alias (`alias/palisade-sad-encryption-v2`).
3. Update `palisade/KMS_SAD_KEY_ARN` secret. `sadKeyVersion` increments — new rows wrap under new key.
4. Existing rows remain decryptable via `sadKeyVersion=1` until the retention reaper expires them. Do NOT re-encrypt in place — that's a separate migration job.
5. Schedule old key for deletion (30-day AWS default waiting period).

### 4.3 Suspected attestation Root CA compromise
Catastrophic — every card in the fleet has to be re-personalised with a new Issuer cert.

1. Disable the compromised Root KMS key.
2. Generate a new Root in KMS.
3. Re-sign the Issuer cert blob against the new Root.
4. Update `palisade/KARTA_ATTESTATION_ROOT_PUBKEY` + `palisade/KARTA_ATTESTATION_ISSUER_CERT` atomically.
5. **Set `PALISADE_ATTESTATION_MODE=permissive` temporarily** — strict mode would reject every live card until re-perso'd.
6. Run `install-pa` against every card in the field to STORE_ATTESTATION with fresh material.
7. Flip back to `strict`.

### 4.4 Suspected attestation Issuer CA compromise (but Root is intact)
Less catastrophic; Root validates new issuer cert.
1. Generate new Issuer CA in KMS.
2. Sign new Issuer cert with Root CA.
3. Update `palisade/KARTA_ATTESTATION_ISSUER_CERT`.
4. re-perso every card. Keep `strict` mode on throughout.

### 4.5 Data breach (PII / CHD exposure)
1. Identify exposed record set via CloudWatch Logs Insights + database audit.
2. Legal + Compliance notification chain: CEO → CTO → Legal → DPO → customers + regulators.
3. Timelines (PCI DSS 12.10):
   - **1 h:** internal escalation complete.
   - **24 h:** regulator notification (PCI card brands if CHD).
   - **72 h:** customer notification (GDPR if EU PII).
4. Forensic preservation: snapshot RDS, copy log streams to S3 with Object Lock.
5. Post-mortem within 5 business days; publish to internal security channel.

### 4.6 Test keys detected in production
(PCI 3.6 — GP test keys `40..4F` are hardwired as dev defaults.)

1. Startup guard in `services/card-ops/src/env.ts` should prevent this. If it fires, the service fails to boot — that IS the alert.
2. If somehow test keys ARE in prod (guard bypassed), treat as SEV-1 key compromise:
   - Every SCP03 session that used those keys is assumed MITM'd.
   - All cards personalised in that window require re-perso.
   - Rotate GP master keys per §4.1-style rotation.

---

## 5. Escalation chain

Slack `#sev-1` → on-call engineer → VP Engineering → CTO → Legal → CEO.

External notification authority:
- **PCI card brands (Visa / Mastercard):** Compliance Officer only.
- **Data-protection regulators:** DPO only.
- **Media:** CEO + Legal only.

Everyone else: no external statements. Period.

---

## 6. Post-incident review

Within 5 business days of SEV-1 or SEV-2:

- Timeline (UTC) of what happened, what was observed, what we did.
- Root cause (5-whys).
- What we'd do differently — detection gap, response gap, playbook gap.
- Preventive controls to land in the next sprint.
- Policy/runbook updates needed.

Publish to `docs/postmortems/YYYY-MM-DD-<slug>.md` (create the directory).

---

## 7. Drills

Run a table-top exercise **quarterly**. Cycle through §4.1–§4.6 so every on-call has touched at least one. Log the drill in the compliance calendar.
