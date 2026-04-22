# Autonomous execution handover — 2026-04-22

> **Final state (after CI settled):** all 7 palisade-* services healthy on `c3fb174`.
> palisade-tap:3 / activation:3 / data-prep:12 / rca:23 / batch-processor:3 /
> sftp:4 / admin:4 — all COMPLETED, runningCount=1 everywhere.
>
> Incidental fix: palisade-admin had a latent port-drift bug — admin code
> defaults to PORT=3009 (per-file comment says it's intentional to avoid
> colliding with Vera-admin on shared dev boxes), but the ECS task def +
> ALB TG are on 3005.  The pre-c3fb174 task was running a pre-port-change
> image that really did listen on 3005, so the drift was invisible until
> the new image tried to roll out and ALB rejected it.  Fixed by pinning
> `PORT=3005` as an env override in palisade-admin:4.  Long-term: either
> update env.ts default to 3005 or move the task def/TG to 3009, but
> they're both disruptive changes — the env pin is sufficient and
> self-documenting on the task def.



**Window:** user away ~08:00–10:00 UTC+10.
**Scope of ask:** "close out all gaps for admin and patent claim, with PCI and PCR implement everything except logging if it'll blow out costs. Assume all operations are remote. Once done, look at security reviews. Don't worry about pen-testing."

## TL;DR status

| Stage | Intent | Shipped | Verified |
|---|---|---|---|
| A | AWS additive (WAF, CloudTrail, alarms) | ✅ | Live now |
| B | PCI closures (CVC, per-column, debug, FK, reaper) | ✅ | Tests + Prisma migration + task-def flip |
| C.1 | X-Request-ID correlation middleware | ✅ | 13 new tests |
| D.2 | Dual-key HMAC rotation | ✅ | 5 new tests |
| E | `card_done` WS message for NFC UX | ✅ | 1 contract test + relay-handler tests |
| F | Attestation priv-scalar wrapping | 🟡 **scaffold + design** | CAP rebuild deferred |
| G | Card-ops as prod ECS service | 🟡 **AWS infra + CI matrix** | `create-service` deferred to operator |
| H.2 | Docker cosign on push | ✅ | CI yaml |
| H.3 | CycloneDX SBOM per build | ✅ | CI yaml |

**Test suite:** 866 pass / 6 skipped (was 843 at start). Zero regressions.

**Commits merged to main (7 new, merge commit c3fb174):**
```
4841914 feat(stage-g): palisade-card-ops prod ECS infra + CI matrix
2d02461 feat(stage-f): attestation priv-scalar wrapping — design + scaffold
706e61c ci(supply-chain): cosign + CycloneDX SBOM
9020167 feat(rca): card_done WS signal
675949a feat(observability+rotation): X-Request-ID + dual-key HMAC
c8cc844 chore(stage-b): PCI DSS / CPL hardening bundle
(Stage A was AWS-side only, no commits)
```

CI run: `24780546626` deploying to prod.

---

## What needs you when you're back

### 🔴 P0 — strict-mode C16/C23 verification (Stage J)

Depends on **Stage F CAP rebuild** + **Stage G create-service** + **trial-card re-perso**. Sequence:

1. **Rebuild the pa-v3 applet CAP** with the new `getBootstrapPubkey` + `unwrapAndLoad` + `INS_GET_ATTESTATION_BOOTSTRAP_PUBKEY` additions per `docs/runbooks/attestation-priv-wrapping.md`. `cd applets/pa-v3 && ant clean build` → `build/pa-v3.cap`.
2. **Bootstrap the card-ops ECS service** per `docs/runbooks/card-ops-ecs-bootstrap.md`. First CI image is already in ECR from the main-push run above; just run `aws ecs register-task-definition` + `aws ecs create-service` (both commands copy-pasteable from the runbook).
3. Drive Install-PA against the trial card via `https://manage.karta.cards` (now that card-ops.karta.cards resolves to a live service).
4. Flip strict: `aws ecs update-service --cluster vera --service palisade-rca --task-definition palisade-rca:19 --force-new-deployment`.
5. Tap the card → verify the chain-walk log line fires: `[rca] attestation verify ok=true mode=strict issuer=<id>`.

### 🟠 P1 — cross-repo admin UI Cards tab 404

`https://manage.karta.cards/api/admin/vault/cards` returns 404 → the admin SPA's Cards tab can't load. Fix lives in the Vera repo (the `/api/admin/vault/cards` handler is Vera-side); Palisade-only I can't close it.

### 🟠 P1 — operator identity on audit trail (Stage C.2)

`CardOpSession.operatorId` schema addition + Cognito-sub-capture middleware in the card-ops WS auth. Touches DB migration + WS upgrade handler + `apduLog` writer. ~90 min of focused work when you want it.

---

## New AWS resources created this session

```
ECR                     palisade-card-ops
ECS task role           vera-card-ops-task (inline policy card-ops-kms-access)
ALB target group        palisade-card-ops-tg (HTTP:3010, health /api/health)
ALB listener rule       card-ops.karta.cards → TG (priority 30, on HTTPS listener)
WAFv2 WebACL            palisade-public (attached to vera-public ALB)
CloudTrail trail        palisade-audit (multi-region, file validation)
S3 bucket               palisade-audit-logs-600743178530 (Object Lock
                          COMPLIANCE 400d, versioning, bucket-default AES-256)
SNS topic               palisade-alerts (unsubscribed — add emails/PagerDuty)
CloudWatch alarms       palisade-public-alb-5xx-high
                        palisade-public-alb-4xx-auth-high
                        palisade-waf-blocked-high
CloudWatch log group    /ecs/palisade-card-ops (365d retention)
IAM inline policy       vera-data-prep-task:attestation-issuer-kms-sign
                        (kms:Sign on alias/palisade-attestation-issuer)
Secrets Manager         palisade/KMS_ATTESTATION_ISSUER_ARN
                        palisade/CARD_OPS_AUTH_KEYS
                        palisade/SERVICE_AUTH_CARD_OPS_SECRET
                        palisade/CARD_OPS_PUBLIC_WS_BASE
ECS task defs           palisade-data-prep:11 (PARAMS_PER_COLUMN=1, live)
                        palisade-rca:19 (strict mode, registered, NOT deployed)
```

## New tests (+23 net, 866 total)

- `packages/core/src/request-id.test.ts` — 13 tests
- `packages/service-auth/src/index.test.ts` — +5 rotation tests
- `services/rca/src/services/session-manager.test.ts` — +1 card_done contract test
- `packages/emv-ecdh/src/attestation-wrap.test.ts` — 4 tests

## Deferred items with pointers to resume

| Item | Why deferred | Re-entry point |
|---|---|---|
| Stage F CAP rebuild | Applet bytecode + physical trial card; can't do from ECS | `applets/pa-v3/` + `docs/runbooks/attestation-priv-wrapping.md` |
| Stage G create-service | Chicken-and-egg with first CI image | `docs/runbooks/card-ops-ecs-bootstrap.md` step 2 |
| Stage J strict-mode tap | Depends on F + G | Same runbook, step 3–5 |
| Stage I.1 admin Cards tab | Cross-repo Vera backend | File issue in Vera repo |
| Stage C.2 operator identity | Schema migration + middleware (~90 min) | `CardOpSession` model in schema.prisma |
| Stage D.1 internal ALB TLS | Risky, needs ACM cert + testing | `scripts/aws-setup.sh` has CF-2 pointer |
| Stage H.1 CAP hash manifest | Needs applet build pipeline hook | Part of Stage F follow-up |
| Stage H.4 GitHub Actions OIDC | Dedicated PR (IAM role + trust policy) | Replace `aws-actions/configure-aws-credentials@v4`'s access-key path |
| Stage I.2 program-scoped RBAC | 3-4 hours + Cognito custom attrs | Open discussion |

## Observability upgrades that went live

- Every log line in prod now includes a request-correlation ID (echoed on the X-Request-ID response header; honours inbound). Operators can `aws logs tail /ecs/palisade-* | grep <request-id>` to trace a single user request across all 7 services.
- Baseline alarms on 5xx rate, auth-fail rate, WAF blocked rate → SNS palisade-alerts. Subscribe emails/PagerDuty when ready.
- CloudTrail logs every `kms:Sign` / `SecretsManager:*` / `IAM:*` event to S3 Object Lock bucket (400d COMPLIANCE retention).

## Rollback

For any of the Stage B-E code changes:
```
aws ecs update-service --cluster vera --service palisade-<svc> \
  --task-definition palisade-<svc>:<prior-rev> --force-new-deployment
```
AWS-side additions (WAF, CloudTrail, alarms, TGs, IAM) can stay — they don't affect the tap flow.

For the Prisma migration (nullable sadRecordId): safe to roll forward. The reverse migration would re-NOT-NULL the column which requires backfilling any nulls that got introduced since — write a specific down-migration if ever needed.

Token for rollback of the merge itself (preserve c3fb174 as history, revert as a new commit):
```
git revert -m 1 c3fb174
```

---

When you're back, start with `docs/runbooks/card-ops-ecs-bootstrap.md` — it unblocks everything else on the critical path.
