# PCI Card Production (CPP) v4.0 — Logical Security Requirements Audit

**Scope:** Server-side card provisioning platform (Palisade). Physical card plant (CM) is out of scope and separately audited under CP-PSR.
**Branch audited:** `prototype/mchip-chip-computed-dgi` @ commit `22c7825`.
**Date:** 2026-04-21.

> ⚠️  Design-time audit, not a QSA-signed CPP assessment. Use to close gaps before live cardholder provisioning.

---

## Summary

| LSR | Area | Severity | Status |
|-----|------|----------|--------|
| 1 | Policies & governance | Medium | no formal POLICIES.md; operator identity missing from audit trail |
| 2 | Key management | **High** | no docs'd rotation; no attestation escrow; `PARAMS_PER_COLUMN=0` default |
| 3 | Systems security / SDLC | **High** | `npm audit` soft-fail; CAP + Docker images unsigned; no SBOM |
| 4 | Logical access control | **High** | operator Cognito sub not in audit logs; no per-card authz check |
| 5 | Data destruction | Medium | APDU log retention not set; Node GC scrubbing unproven |
| 6 | Personalisation data | **High** | raw P-256 attestation priv scalar over NFC; plaintext ParamBundle window |
| 7 | Network security | Medium | inter-service HTTP on internal ALB; no WAF rate limits |
| 8 | Audit logs | **High** | no 1-year retention; no immutable archive; no correlation IDs |
| 9 | Code integrity | **High** | CAP files + Docker images unsigned; no SBOM; GH Actions long-lived keys |

**Overall posture:** Prototype-stage security; **not production-ready for live cardholder data** until Critical + High remediations land.

---

## Detailed findings

### LSR 1 — Policies & governance (Medium)
**Current:** role separation via ECS task roles + service boundaries; Cognito admin group + MFA; per-pair HMAC secrets.
**Gaps:**
- No written POLICIES.md / RACI for key rotation, attestation Root CA rotation, incident approval chains.
- Operator identity (Cognito sub) not captured on `CardOpSession.apduLog` — audit trail says *what* happened but not *who*.

**Remediation:**
1. Add `POLICIES.md` covering: key-rotation approval chain, attestation cert update process, emergency break-glass, test-key ban in prod.
2. Add `CardOpSession.operatorId` column populated from the authenticated admin JWT at session create; include in every `ApduAuditEntry` and CloudWatch log line.

---

### LSR 2 — Key management (High)
**Current (strong):**
- **IMK / UDK / MK-KDK** in AWS Payment Cryptography (HSM, non-exportable).
- **SCP03 GP keys** — test keys (`40..4F`) are dev default, production guard in `services/card-ops/src/env.ts:108-124` rejects both `CARD_OPS_USE_TEST_KEYS=1` and well-known-test-key bytes when `NODE_ENV=production`.
- **Attestation Root CA** — KMS alias `alias/palisade-attestation-root`, offline-signs only at Issuer cert rotation.
- **Attestation Issuer CA** — KMS alias `alias/palisade-attestation-issuer`, `kms:Sign` only (now granted to `vera-data-prep-task` via inline policy `attestation-issuer-kms-sign`).
- **Per-card attestation priv scalar** — generated in memory, installed via STORE_ATTESTATION, buffer `.fill(0)`'d (`install-pa.ts:330`).
- **SAD/ParamBundle at rest** — KMS envelope (`alias/palisade-sad-encryption`).

**Gaps:**
- **WS_TOKEN_SECRET, CALLBACK_HMAC_SECRET rotation cadence undocumented.** Rotation today is breaking — no dual-key grace window.
- **`PARAMS_PER_COLUMN=0` default** — full plaintext ParamBundle lands in rca RAM at wrap time; per-field envelope (commit `9c25b73`) is scaffolded but the env flag is flipped off.
- **No attestation keypair escrow.** Per-card P-256 priv is destroyed post-STORE; if a card is later suspected of a key-compromise event, there is no key to revoke / re-sign against.
- **No ARN format validation** on `gpEncKeyArn`, `gpMacKeyArn`, `gpDekKeyArn` IssuerProfile columns — a typo silently degrades to test-keys fallback in dev and to a start-up error in prod.
- **Attestation cert rotation** has no runbook: rotating `alias/palisade-attestation-root` requires atomic update of `KARTA_ATTESTATION_ROOT_PUBKEY` + re-sign of `KARTA_ATTESTATION_ISSUER_CERT` + re-issuance (via STORE_ATTESTATION) of every live card's cert. No tooling supports this today.

**Remediation:**
1. Document rotation cadence for `WS_TOKEN_SECRET` + `CALLBACK_HMAC_SECRET` (suggest quarterly). Add dual-key verification (`@palisade/service-auth` accepts an array of keys for a grace window).
2. Flip `PARAMS_PER_COLUMN=1` on `palisade-data-prep` task def after the per-field migration is confirmed deployed.
3. Decide on attestation escrow policy; document in POLICIES.md (prototype: none; production: TBD).
4. Add zod regex validation `/^arn:aws:kms:/` on IssuerProfile ARN fields.
5. Write `docs/runbooks/attestation-cert-rotation.md`.

---

### LSR 3 — Card production systems security / SDLC (High)
**Current:** TypeScript strict; Zod schemas; Prisma (no raw SQL); vitest suite; ECR scan-on-push; ECS Fargate isolation.
**Gaps:**
- **`npm audit --audit-level=high continue-on-error: true`** in `.github/workflows/deploy.yml:80` — high-severity CVEs don't block CI.
- **PA CAP files are unsigned.** `services/card-ops/src/operations/install-pa.ts` sends the CAP LOAD blocks verbatim with no hash-manifest check; an attacker with S3-write could swap the CAP.
- **Docker images are unsigned.** ECR scan catches known CVEs but no cosign/notary provenance proof.
- **No SBOM** published per build.
- **GitHub Actions uses long-lived AWS access keys** (`AWS_ACCESS_KEY_ID` + `SECRET`), not OIDC federation.

**Remediation:**
1. Remove `continue-on-error: true` from the npm audit step.
2. Add SHA-256 manifest to `chip-profile.json` keyed by `capKey` (`pa-v3` → sha256); `loadCap()` verifies before INSTALL [load].
3. Add `cosign sign` step after `docker build-push-action` in deploy.yml.
4. Generate SBOM with `cyclonedx-npm` in the test job; upload as a CI artifact.
5. Move CI AWS auth to GitHub OIDC + `AssumeRoleWithWebIdentity`; delete the long-lived access key.

---

### LSR 4 — Logical access control (High)
**Current:** Cognito + MFA for admin; HMAC for S2S (keyId-scoped); per-service ECS task roles.
**Gaps:**
- **Operator identity not logged** on `CardOpSession` / `ApduAuditEntry` — you can see APDU traffic but not who drove it.
- **No per-card authorization check** in `install-pa` / `personalise-payment-applet` — any operator in the `admin` Cognito group can drive any card.
- **No card-op session inactivity timeout** — abandoned sessions linger with SCP03 keys scrubbed but the session row open.
- **No rate limiting** on card-ops `/register` or the WS APDU relay.

**Remediation:**
1. `CardOpSession.operatorId` + propagate to `ApduAuditLogger.recordCommand/Response`.
2. Add per-card authz middleware: operator's Cognito groups must include the target card's `program.issuerProfile.fiId` admin role.
3. `CardOpSession.lockedUntilAt` with `WS_TIMEOUT_SECONDS + 60` grace window; sweeper expires lingering rows.
4. Per-operator rate limit on `/register` (10/min).

---

### LSR 5 — Data destruction (Medium)
**Current:**
- EMV MKs `.fill(0)` after use (`data-prep.service.ts:278-298`).
- SAD plaintext scrubbed post-encrypt.
- Attestation priv scalar scrubbed post-STORE (`install-pa.ts:330`).
- SCP03 session keys scrubbed in `finally { scrub(); }`.
- SAD at-rest retention = 30 days via `SAD_TTL_DAYS`.

**Gaps:**
- `CardOpSession.apduLog` retention not set — rows grow indefinitely.
- Node GC doesn't guarantee `.fill(0)`'d buffers are wiped from RAM before GC runs — for high-assurance scrubbing, would need libsodium-style native addon.
- `ParamRecord` has no explicit TTL column.
- RDS backup retention not documented — snapshots beyond 30 days may retain SAD rows we thought were expired.

**Remediation:**
1. `CardOpSession.apduLog` TTL = 1 year; archive to S3 Glacier pre-delete (immutable write).
2. `ParamRecord.expiresAt` column; retention reaper (already in todos as "ParamRecord retention reaper").
3. Audit RDS backup retention against SAD/ParamRecord TTL; document in SECURITY.md.

---

### LSR 6 — Personalisation data handling (High — **headline finding**)
**Current:**
- SAD / ParamBundle encrypted at rest and wrapped (ECDH to chip session pubkey) in transit over NFC.
- STORE_ATTESTATION (Drop 4b, this commit) sends the per-card P-256 private scalar `raw` — no wrapping — over NFC in the APDU data field.

**Headline gap (LSR 6 + LSR 2):**
> `services/card-ops/src/operations/install-pa.ts:311-314` transmits the 32-byte attestation priv scalar as the body of `STORE_ATTESTATION P1=0x01`, with SCP03 `scrub()`ed immediately before the SELECT PA. The APDU is raw plaintext on the NFC interface during install-pa.

This is acceptable **only** if the personalisation NFC link is assumed physically air-gapped (dedicated perso terminal, no relay). CP-LSR 6 treats the NFC link between operator terminal and chip as part of the secure card production environment — that's the standard interpretation. If Palisade's install-pa is ever driven from a non-trusted operator environment (e.g., over WebSocket relay from a browser in an internet café), this becomes a blocking finding.

**Remediation options (pick one):**
1. **Keep as-is with explicit policy** — document that install-pa MUST run only from a CP-PSR-audited perso terminal. Add a startup check that the card-ops service runs only in the perso environment (network ACL, mTLS cert pinning).
2. **Wrap the scalar under a per-card KMS envelope** — data-prep returns `{ wrappedPriv, wrapIv, wrapTag }` instead of the raw scalar; applet `IssuerAttestation` extended to unwrap (requires CAP change).
3. **Chip-assisted key agreement** — applet generates a one-time ephemeral pubkey, server derives an ECDH shared secret, wraps the scalar with it; chip unwraps on-device. Heaviest but strongest.

For the prototype + trial card today: option 1 (policy-doc the requirement) is what you have. Document it in POLICIES.md and revisit when moving to a production perso environment.

**Other LSR 6 gaps:**
- ParamBundle has a microsecond plaintext window in rca RAM at wrap time (`handleKeygenResponse`). Flip `PARAMS_PER_COLUMN=1` to narrow it to individual fields.
- CAP files carried over the same link without a hash manifest (see LSR 3).

---

### LSR 7 — Network security (Medium)
**Current:** VPC + private subnets; ECS SG `sg-086e7b16e5351f155`; public ALB HTTPS terminated; internal ALB carries HTTP.
**Gaps:**
- Inter-service HTTP on internal ALB (see PCI DSS CF-2).
- No AWS WAF / Shield rules documented.
- No cache-control headers on WS upgrade endpoint (CloudFront could theoretically cache the token).
- CORS fallback origin list is broad.

**Remediation:** (same as PCI DSS CF-2) ACM cert + TLS on internal ALB; WAF rate-limit rules on public ALB.

---

### LSR 8 — Audit logs (High)
**Current:**
- `ApduAuditLogger` captures command/response with redaction for STORE DATA / PUT KEY / INSTALL.
- CloudWatch log groups exist, 30-day retention.
- Metrics emitted via `@palisade/metrics`.

**Gaps:**
- Operator identity absent (see LSR 4).
- 30-day CloudWatch retention < PCI 10.7 requirement of 1 year online + 3 months archive.
- No immutable archive (logs could be mutated in-place if DB is compromised).
- No cross-service correlation ID.
- No compliance-specific events (`test_key_detected_in_prod`, `attestation_cert_rotated`, `admin_mfa_disabled`).

**Remediation:**
1. Raise all `/ecs/palisade-*` CloudWatch retention to **90 days** (safe to do tonight) and plan for 1 year.
2. Enable CloudTrail for `kms:Sign` / `SecretsManager:*` / `IAM:*` events; route to S3 bucket with Object Lock.
3. Inject `X-Request-ID` header at ALB; pass through every service; log with every APDU audit entry.
4. Add compliance event emitters in `@palisade/metrics` wrapper.

---

### LSR 9 — Code integrity (High)
Same as LSR 3 block: CAP unsigned, Docker unsigned, no SBOM, GH Actions long-lived creds.

**Plus:** no applet version/build-id tracking. `install-pa`'s `{complete}` message returns only the `capKey` name (`pa` vs `pa-v3`) — no build hash, no commit SHA. Hard to correlate "this card has applet version X" against "version X has CVE Y".

**Remediation:** embed build metadata in chip-profile JSON; log it on every install.

---

## Physical security (CP-PSR)

**Out of scope for this audit.** Physical card plant, secure transport, air-gapped perso terminal — all managed by the Card Manufacturer partner, separately CP-PSR-audited.

**Cross-boundary assumptions Palisade makes:**
- NFC perso link between `card-ops` and the chip is physically air-gapped (trusted terminal).
- Blank chip cards arrive in sealed transport from CM with serial-number attestation.
- Admin operators running card-ops are inside a CP-PSR-audited facility.

If these assumptions change — e.g., remote personalisation over the internet — LSR 6 headline finding flips from "policy-controlled" to "blocking."

---

## Critical + High actions, prioritized

### Tonight (safe, additive)
- [x] Created this audit doc.
- [x] IAM grant `kms:Sign` on attestation-issuer to `vera-data-prep-task` (applied as inline policy).
- [x] Created `palisade/KMS_ATTESTATION_ISSUER_ARN` secret.
- [x] Registered `palisade-data-prep:9` with the new secret (not deployed).
- [x] Registered `palisade-rca:19` with `PALISADE_ATTESTATION_MODE=strict` (not deployed).
- [ ] Remove `continue-on-error: true` on npm audit in deploy.yml.
- [ ] Write `SECURITY.md`, `INCIDENT_RESPONSE.md`, `.well-known/security.txt`.
- [ ] Raise CloudWatch Logs retention on all `/ecs/palisade-*` groups to 90 days.

### Operator review (morning)
- [ ] LSR 2: flip `PARAMS_PER_COLUMN=1`.
- [ ] LSR 3: remove `continue-on-error`, add cosign, add SBOM (code change in deploy.yml).
- [ ] LSR 4: operator identity in audit (schema + middleware change).
- [ ] LSR 6: POLICIES.md explicitly calling out the CP-PSR perso-environment requirement.
- [ ] LSR 8: CloudTrail enablement, S3 Object Lock, correlation IDs.

### Production-gating (before first live cardholder)
- [ ] LSR 9: CAP signing + verification on install-pa.
- [ ] LSR 9: Docker image cosign.
- [ ] LSR 4: program-scoped RBAC.
- [ ] LSR 6: decision on attestation priv-scalar wrapping (option 1 / 2 / 3 from above).
- [ ] LSR 7: internal ALB TLS.
- [ ] LSR 8: 1-year log retention + immutable archive.
