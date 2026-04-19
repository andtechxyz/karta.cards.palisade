# Runbook: Attestation Vendor Re-Keying

**Document Owner:** Security Team
**Last Reviewed:** 2026-04-19
**Applies to:** Palisade (`services/rca` owns `AttestationVerifier`;
attestations are stored on Palisade's `Card.attestationRaw`). Vera has
no involvement in attestation — the verifier is entirely card-side.

**Related:** [incident-response.md](./incident-response.md), [key-rotation.md](./key-rotation.md)

---

## 1. Scope

Chip-vendor attestation trust anchors (NXP, Infineon) rotate periodically — either on a scheduled vendor CA refresh or following a compromise notification. This runbook covers rolling the anchors Palisade uses to verify chip attestations.

**Current status (2026-04-19):** Track 2 (`eb8a9e0`) landed the
verifier scaffolding on `services/rca` — storage shape, metric
counters, WS flow integration, and the call site from the SAD-transfer
protocol are all live. The cryptographic cert-chain check itself is
still stubbed (every attestation passes), so the rekey choreography
described below is not yet exercised in production. Read this as
forward-looking documentation until the stub is replaced; when that
lands, no changes to the choreography below are expected.

## 2. Where trust anchors live

Expected layout when the verifier is de-stubbed:

```
Secrets Manager:
  palisade/ATTESTATION_TRUST_ANCHORS_NXP      — PEM bundle, NXP CA chain roots
  palisade/ATTESTATION_TRUST_ANCHORS_INFINEON — PEM bundle, Infineon CA chain roots
```

The verifier module (`services/rca/src/attestation/`) loads both at
startup into an in-memory cert pool. Anchor rotation follows the same
dual-write pattern as [key-rotation.md §2](./key-rotation.md) — old and
new anchors live side-by-side for a window so cards issued before the
vendor rekey still verify.

Per-vendor config (which anchor file to load for which vendor) sits in
`services/rca/src/attestation/config.ts`. Don't hardcode anchor
contents into code.

## 3. Rotating anchors (normal vendor CA refresh)

1. Obtain the new PEM bundle from the vendor. Verify its SHA-256 against the vendor's published fingerprint before doing anything else.
2. **Phase 1 — dual-anchor.** Concatenate the new bundle onto the existing Secrets Manager entry (old certs first, then new). Redeploy `services/rca` (the verifier runs in-process there). The verifier now accepts chips issued under either anchor.
3. **Phase 2 — migrate.** Coordinate with the vendor on when cards issued under the old anchor stop arriving. Typically 60–90 days of dual-accept.
4. **Phase 3 — cleanup.** Replace the Secrets Manager entry with only the new bundle. Redeploy.

**Verify:** after each phase, tap a test card known to carry the new-anchor attestation; confirm verification passes. Run a dashboard query on `attestation.verifier.failures` — should stay at the pre-rotation baseline throughout.

**Rollback:** revert Secrets Manager to the previous version (`aws secretsmanager restore-secret --secret-id <arn>`) and redeploy. The verifier is stateless so rollback is immediate.

## 4. Emergency rekey (compromise)

If the vendor notifies of an anchor compromise:

1. Treat as P1 per [../security/incident-response-plan.md](../security/incident-response-plan.md) §2.
2. Work with the vendor to confirm the compromise scope — which anchor, which date range of chips.
3. Skip the 60–90 day dual-accept window. Flip the verifier to reject-only-new anchor AS SOON AS the vendor confirms no more compromised chips are in circulation.
4. Cards in the compromised range are quarantined: `UPDATE "Card" SET status = 'SUSPENDED' WHERE "chipSerial" LIKE '<compromised prefix>%'`. Security team approves the exact filter.
5. Post-mortem captures the full list of suspended cards for potential replacement.

## 5. Detection of anchor drift

Alarm on:

- `attestation.verifier.failures` > baseline + 2σ sustained 15 minutes — probable anchor staleness.
- CloudWatch metric filter on `verifier: unknown CA` log lines — should be zero; any hit is a bug OR a surprise vendor rekey.

## 6. Post-flip checklist

- [ ] Vendor's published fingerprint matches what's in Secrets Manager (SHA-256 sanity).
- [ ] Zero new failures on `attestation.verifier.failures` for a rolling hour.
- [ ] Old anchor's expiry dates (NotAfter) recorded in the onboarding log with a calendar reminder at NotAfter - 60 days.
