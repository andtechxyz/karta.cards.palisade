# Morning runbook — 2026-04-22

## Where we left off last night

**Patent adherence:** 99% complete. Drop 4b code shipped; strict flip + trial-card re-perso remaining.

**Live services (all on commit `91ccf67`, permissive attestation mode):**
- `palisade-rca:18` — Drop 4b rca plan-builder + CONFIRM race fix
- `palisade-data-prep:8` — Drop 4b data-prep `/api/data-prep/attestation/issue` route
- `palisade-tap:1`, `palisade-activation:1` — pre-Drop-4b images; still on main `2f5b9a6`

**Pre-staged, NOT deployed:**
- `palisade-rca:19` — same image, `PALISADE_ATTESTATION_MODE=strict` env added
- `palisade-data-prep:9` — same image, `KMS_ATTESTATION_ISSUER_ARN` secret wired

**AWS infra ready:**
- IAM inline policy `attestation-issuer-kms-sign` on `vera-data-prep-task` (`kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on the issuer alias).
- Secret `palisade/KMS_ATTESTATION_ISSUER_ARN` = `alias/palisade-attestation-issuer` ARN.
- Attestation PKI live (root pubkey + issuer cert already pinned in secrets from last night).

---

## Morning deploy sequence — C16/C23 strict verification

### Step 1 — reinstall the PA applet on the trial card (gets attestation material loaded)

On your local operator machine (where `card-ops` runs):

```bash
export KMS_ATTESTATION_ISSUER_ARN="arn:aws:kms:ap-southeast-2:600743178530:alias/palisade-attestation-issuer"
export AWS_REGION=ap-southeast-2
# plus whatever AWS creds + DATABASE_URL + other env your local card-ops
# setup uses (default: ~/.aws/credentials + scripts/dev-stack-up.sh)
```

Then via the admin UI (or directly via the card-ops WS):

1. Put card `e2e_fi_2590` on the reader.
2. Click **Install PA** on the admin UI. This now runs the new Drop 4b flow:
   - `DELETE` existing PA package + instance (idempotent).
   - `INSTALL [load]` + `LOAD` blocks + `INSTALL [install+selectable]` (pa-v3 CAP).
   - **NEW:** `GET DATA 9F7F` → 42-byte CPLC.
   - **NEW:** `issueCardCert(cplc, kmsSigner)` → {priv, cardCert, pubkey}.
   - **NEW:** `SELECT PA` + `STORE_ATTESTATION P1=0x01/0x02/0x03`.
3. Admin UI shows progress phases `ATTESTATION_FETCH_CPLC`, `ATTESTATION_STORE_PRIV/CERT/CPLC`. If any SW != 9000, install fails — re-run.

Success ⇒ chip now carries:
- per-card P-256 attestation private key in DGI A001,
- Issuer-CA-signed card cert in DGI A002,
- CPLC in DGI A003.

Next GENERATE_KEYS from this chip will emit the `attestSig` trailer automatically.

### Step 2 — flip strict mode on palisade-rca

One-line deploy of the pre-registered task def `:19`:

```bash
aws ecs update-service \
  --cluster vera \
  --service palisade-rca \
  --task-definition palisade-rca:19 \
  --region ap-southeast-2 \
  --force-new-deployment \
  --query 'service.{td:taskDefinition,desired:desiredCount}'
```

Wait ~60 s for the new task to come up (watch `aws ecs describe-services --cluster vera --services palisade-rca | jq '.services[0].deployments'`).

Strict mode is now live. Every incoming tap plan will include a `GET_ATTESTATION_CHAIN` step, and the keygen-step verifier will chain-walk Root → Issuer → Card → session.

### Step 3 — re-perso the trial card

Same as before — backend reset (`scripts/reset-card-for-retap.ts` when the tsx-in-prod-image bug is fixed, or use the inline Prisma one-shot we ran last night in `/tmp/reset-overrides.json`), then tap.

### Step 4 — tap to verify

On the phone:
1. Tap card → palisade-tap SUN verify → handoff.
2. Deep link → admin app → **Provision Card**.
3. Card on reader. App connects to rca WS.

Look for in rca logs (`aws logs tail /ecs/palisade-rca --since 2m`):

- `[rca][plan] attestation chain received: session=... cardCertLen=180` (approximate) — GET_ATTESTATION_CHAIN step returned the stashed cardCert.
- `[rca] provisioning complete: session=... card=...` — strict verifier ran and passed.
- CloudWatch metric `rca.attestation.verify` count with `result=ok` + `mode=strict`.

If it fails:
- `cardCert missing` → step 1 didn't land; re-install PA.
- `issuer cert signature does not verify against Root CA` → KMS secret drift; check `palisade/KARTA_ATTESTATION_ROOT_PUBKEY` matches the Root CA's actual pubkey.
- `attestation signature does not verify against card cert pubkey` → Issuer CA signed the cert with a different key than the one pinned.

### Step 5 — merge to main

Once the strict-mode tap succeeds:

```bash
cd /Users/danderson/Palisade/.claude/worktrees/dgi-chip-prototype
git checkout main
git pull
git merge prototype/mchip-chip-computed-dgi --no-ff
git push
# CI auto-deploys on push to main for all 6 services in the matrix.
```

---

## Overnight compliance work (review + decide)

### Audits
- `docs/compliance/PCI_DSS_4_0_1_AUDIT_2026-04-21.md` — posture ≈ 70 / 100. Headline gaps: CVC in plaintext HTTP body (CF-1), inter-service HTTP (CF-2), no centralized logging + alerting (CF-3), no annual pen test (CF-4).
- `docs/compliance/PCI_CARD_PRODUCTION_AUDIT_2026-04-21.md` — prototype-stage for CPL. Headline: raw P-256 attestation priv scalar over NFC link is acceptable only under the assumption the perso terminal is CP-PSR-audited. Document this assumption or wrap the scalar.

### What landed tonight (additive only; nothing in prod changed behaviour)
- IAM inline policy `attestation-issuer-kms-sign` on `vera-data-prep-task`.
- Secret `palisade/KMS_ATTESTATION_ISSUER_ARN`.
- Task defs `palisade-data-prep:9` + `palisade-rca:19` registered, NOT deployed.
- CloudWatch Logs retention on all 7 `/ecs/palisade-*` log groups raised from indefinite-default to **365 days** (PCI 10.7 baseline).
- `deploy.yml` — removed `continue-on-error: true` on `npm audit --audit-level=high`. Local audit is clean (0 vulnerabilities); next CI run enforces.
- Policy docs:
  - `docs/compliance/SECURITY.md`
  - `docs/compliance/INCIDENT_RESPONSE.md`
  - `.well-known/security.txt` (not yet wired into ALB routing — morning item)

### What needs your decision
1. **CVC in batch-processor → activation body** — drop entirely vs separate-endpoint redirect. Coordinate with Vera vault team.
2. **Inter-service ALB TLS** — ACM cert on internal ALB, listener swap HTTP→HTTPS. Cross-repo with Vera infra.
3. **Annual pen test** — contract a QSA; scope includes attestation PKI chain.
4. **Operator identity audit trail** — schema migration + middleware; plan sprint time.
5. **CAP signing + Docker image cosign** — CI/CD change; plan sprint time.
6. **GitHub Actions OIDC federation** — kill the long-lived `AWS_ACCESS_KEY_ID`; one-time setup.

### Morning housekeeping
- [ ] Wire `.well-known/security.txt` into the public ALB / CloudFront (static file → `/.well-known/security.txt`).
- [ ] Verify the next CI run on push-to-main doesn't break on the new npm-audit enforcement.
- [ ] Flip `PARAMS_PER_COLUMN=1` on `palisade-data-prep:9` env (or a :10) once strict-flip is stable.

---

## Rollback

If the strict flip breaks tapping:

```bash
aws ecs update-service \
  --cluster vera \
  --service palisade-rca \
  --task-definition palisade-rca:18 \
  --region ap-southeast-2 \
  --force-new-deployment
```

Back to permissive in ~60 s. Trial card keeps working.

If the attestation material got corrupted during install-pa (rare — would show as CPLC parse fail or STORE_ATTESTATION SW != 9000 during install):
- `INS_WIPE` via admin UI → reinstall PA.
