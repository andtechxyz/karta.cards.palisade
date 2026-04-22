# Palisade Security Policy

**Status:** Draft — 2026-04-21. Update quarterly.
**Owner:** Platform Security (security@karta.cards).
**Applies to:** the Palisade monorepo + the services it deploys to the shared AWS Vera account.

> This document is the single source of truth for how Palisade handles cardholder data, key material, and system access. It backs the PCI DSS + PCI Card Production Logical Security audits in this directory. Where the runtime code disagrees with this policy, the runtime code is wrong.

---

## 1. Data classification

| Class | Examples | Where it lives | Control |
|-------|----------|----------------|---------|
| **P0 — Sensitive Authentication Data** | CVC / CVV2, full Track 1/2, PIN | Must never persist in Palisade. CVC flows through to Vera vault only. | Zod schemas at intake; scrub pre-persist; audit for plaintext in logs. |
| **P1 — Cardholder Data (CHD)** | Full PAN, expiry | Stored only as `vaultToken` in Palisade; full PAN lives in Vera vault. | KMS envelope in Vera; Palisade stores `panLast4` plaintext only. |
| **P2 — EMV issuer keys** | MK-AC, MK-SMI, MK-SMC, ICC RSA priv, UDK-derivation IMKs | AWS Payment Cryptography HSM; per-IssuerProfile ARNs. | `kms:Sign`/`payment-cryptography:*` scoped per task role; never exported plaintext. |
| **P2 — Attestation keys** | Per-card P-256 priv; Issuer CA; Root CA | KMS (alias/palisade-attestation-{root,issuer}); per-card priv generated in memory, scrubbed post-STORE. | Root CA offline, Issuer CA `kms:Sign` only on data-prep role. |
| **P2 — SAD / ParamBundle** | Pre-encrypted perso payload | RDS Postgres; KMS envelope via `alias/palisade-sad-encryption`. | `PARAMS_PER_COLUMN=1` narrows plaintext window to per-field. |
| **P3 — Service secrets** | HMAC keys, WS token secret, callback secret | AWS Secrets Manager `palisade/*` namespace. | 64-hex-char rotation; quarterly. |
| **P4 — Operational metadata** | Card status, provisioning timestamps, IP, UA | RDS Postgres (at-rest encrypted). | Standard RBAC; row-level encryption planned. |

---

## 2. Encryption standards

- **At rest:** AES-256-GCM via KMS envelope for all P1–P2 data. RDS encryption enabled by default. S3 bucket default encryption `aws:kms`.
- **In transit (external):** TLS 1.2+ enforced at public ALB; prefer TLS 1.3. HSTS via `helmet()`.
- **In transit (internal):** **currently HTTP on internal ALB — in remediation** (PCI DSS CF-2 / CPL LSR 7). Target: TLS 1.2+ via ACM cert on the internal ALB listener.
- **HMAC:** SHA-256 only. ±60 s replay window. Per-caller `keyId`.
- **Card attestation:** ECDSA-P256 + SHA-256; compact binary Option-A certs (no X.509).
- **NFC (card perso link):** assumed to be inside a CP-PSR-audited facility (`card-ops` runs only from a trusted perso terminal). Attestation priv scalar transits this link raw; acceptable only under that assumption.

---

## 3. Key management

### Creation
- **Issuer Master Keys** (IMK/MK-KDK): generated in AWS Payment Cryptography at FI onboarding; one per IssuerProfile.
- **Attestation Root CA**: generated in KMS at cluster bootstrap (`scripts/aws-setup.sh`); pubkey pinned in `palisade/KARTA_ATTESTATION_ROOT_PUBKEY`.
- **Attestation Issuer CA**: generated in KMS; pubkey signed by Root CA and pinned in `palisade/KARTA_ATTESTATION_ISSUER_CERT`.
- **Per-card attestation priv**: ephemeral, generated in `data-prep/services/attestation-issuer.ts`, never persisted.
- **SCP03 GP keys**: test keys `40..4F` in dev; per-FI production keys in KMS (ARN on IssuerProfile).

### Rotation
| Key | Cadence | Process |
|-----|---------|---------|
| WS_TOKEN_SECRET | Quarterly | TBD — needs dual-key verify window in `@palisade/service-auth` before zero-downtime rotation works |
| CALLBACK_HMAC_SECRET | Quarterly | Same |
| Attestation Root CA | Annually | Runbook: `docs/runbooks/attestation-cert-rotation.md` (to write) |
| Attestation Issuer CA | Semi-annually | Re-sign by current Root; update `KARTA_ATTESTATION_ISSUER_CERT` secret; rca picks up on restart |
| IMKs | Per FI contract (typically annually) | Per-IssuerProfile ARN swap |
| SCP03 GP keys | Per FI contract | Per-IssuerProfile ARN swap |
| SAD encryption key | When compromised | `KMS_SAD_KEY_ARN` swap; existing SadRecords remain readable via `sadKeyVersion` |

### Storage
- All long-lived keys in AWS KMS or AWS Payment Cryptography — never on disk, never in env vars, never in git.
- Ephemeral session material (ECDH shared keys, SCP03 session keys, per-card attestation priv) scrubbed with `.fill(0)` after use.

### Escrow
- **IMKs / GP keys**: KMS default behaviour — multi-region key backup optional per FI contract.
- **Attestation Root CA**: no escrow; if lost, requires manual pen-and-paper ceremony to rebuild chain.
- **Per-card attestation priv**: **no escrow by policy.** If a card's attestation key is suspected compromised, the card is revoked and re-personalised with a fresh key.

### Destruction
- Secrets Manager versions pruned after rotation (AWS default policy).
- KMS keys scheduled for deletion with a 30-day waiting period.
- `ParamRecord` / `SadRecord` rows swept by retention reaper at TTL.
- `CardOpSession.apduLog` retention: **currently not enforced — in remediation** (CPL LSR 5).

---

## 4. Access control

### Administrators
- Cognito pool with MFA **required** at the pool level.
- `admin` group membership required for the admin UI (`services/admin/src/index.ts`).
- **Gap:** no program-scoped RBAC yet — every admin sees every FI's data. Remediation planned.

### Cardholders
- Cognito user + WebAuthn credential binding to `Card.cognitoSub`.
- Per-card access enforced at query time (`activation/src/routes/cards-mine.routes.ts`).

### Service-to-service
- HMAC-SHA256 per-caller (`keyId` scopes tap / activation / pay / batch-processor).
- Keys in Secrets Manager; rotated per §3.

### Operators (card-ops)
- Currently no operator identity on audit trail — **in remediation** (CPL LSR 4).
- One `CardOpSession` per install/perso; session-scoped SCP03 keys scrubbed on completion.

---

## 5. Logging & monitoring

- Every ECS service logs to CloudWatch under `/ecs/palisade-<service>`.
- Retention raised to **365 days** on 2026-04-21 (PCI DSS 10.7 baseline).
- APDU audit with redaction (`services/card-ops/src/ws/apdu-audit.ts`): STORE DATA, PUT KEY, INSTALL data redacted; commands + phases + SW preserved.
- Metrics: `@palisade/metrics` — CloudWatch namespace per service.
- **Gaps in remediation:** no SIEM aggregation; no baseline alarms; no X-Request-ID correlation header; no CloudTrail for `kms:Sign` / `SecretsManager:*` / `IAM:*` with Object Lock.

---

## 6. Change management

- All prod code lives on `main`. Feature branches are prototype / fix-specific.
- CI (`.github/workflows/deploy.yml`) runs: `npm ci` → `npm audit --audit-level=high` (**enforced** as of 2026-04-21) → `tsc -b` → `vitest run` → matrix build+push+deploy.
- Deploy on push to `main` (no manual approval gate in CI today). Rollback via `aws ecs update-service --task-definition <prior-rev>`.

---

## 7. Incident response

See `docs/compliance/INCIDENT_RESPONSE.md`.

---

## 8. Compliance calendar

| Quarter | Task |
|---------|------|
| Q1 | Security training for all engineers; pen test kickoff |
| Q2 | Annual external pen test (PCI DSS 11.3); attestation cert rotation |
| Q3 | Dependency major-version updates; review threat model |
| Q4 | Policy review; incident-response drill |

---

## 9. Known outstanding gaps

All tracked in the PCI DSS / CPL audit docs in this directory. Highest priority:

1. **CVC in plaintext on internal ALB** — batch-processor → activation body. Internal only, HMAC-signed, but violates PCI 3/4. *Target: remove CVC from the batch payload entirely.*
2. **Inter-service HTTP** on internal ALB. *Target: ACM cert + HTTPS listener.*
3. **Operator identity missing from APDU audit log.* Target: `CardOpSession.operatorId` from Cognito sub.*
4. **CAP files + Docker images unsigned.** *Target: CAP hash manifest + cosign on Docker push.*
5. **GitHub Actions long-lived AWS keys.** *Target: OIDC federation + `AssumeRoleWithWebIdentity`.*
6. **PARAMS_PER_COLUMN=0 default in prod** — plaintext ParamBundle window wider than C17 design intends. *Target: flip to `1` after migration verified.*
7. **No annual external pen test scheduled.* Target: contract by end of Q2.*
