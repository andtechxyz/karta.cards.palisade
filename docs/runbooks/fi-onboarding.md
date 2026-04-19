# Runbook: Financial Institution Onboarding

**Document Owner:** Platform Team
**Last Reviewed:** 2026-04-19
**Related:** [key-rotation.md](./key-rotation.md), [incident-response.md](./incident-response.md)

---

## 1. Scope

End-to-end steps to bring a new FI live on Palisade. Covers the issuer profile, chip profile, key ARNs, and pre-flight test card. Stop at step 7 if this is a pilot with internal cards only; continue to step 8 for an external-traffic go-live.

**This is currently a manual runbook.** Track 3 (admin UI) will land a web flow that automates steps 2–6. Until then, every row below is applied via `psql` or a seed script; double-check each insert and keep a copy of the values in the FI's onboarding record.

## 2. IssuerProfile creation

One IssuerProfile per Program. Minimum fields the data-prep service reads to build a SAD:

```sql
INSERT INTO "IssuerProfile" (
  id, "programId", "chipProfileId",
  scheme, cvn, "imkAlgorithm", "derivationMethod",
  "tmkKeyArn", "imkAcKeyArn", "imkSmiKeyArn", "imkSmcKeyArn", "issuerPkKeyArn",
  "caPkIndex", "issuerPkCertificate", "issuerPkRemainder", "issuerPkExponent",
  aid, "appLabel", "appPriority", "appVersionNumber",
  aip, afl, "cvmList", pdol, cdol1, cdol2,
  "iacDefault", "iacDenial", "iacOnline",
  "appUsageControl", "currencyCode", "currencyExponent", "countryCode", "sdaTagList"
) VALUES (...);
```

- `scheme`: `"mchip_advance"` or `"vsdc"` — MUST match the chosen `ChipProfile`.
- `cvn`: numeric CVN (10/17/18/22). MUST match the chip profile's CVN.
- The TLV-constant fields (AIP, AFL, CVM List, etc.) come from the scheme's personalisation spec — never invented.

Worked example: `scripts/seed-karta-platinum-issuer-profile.ts` has a complete M/Chip Advance CVN-18 seed. Copy and adapt.

## 3. ChipProfile association

If the FI uses an already-seeded chip family (NXP JCOP5 M/Chip, Infineon SLJ52 VSDC), link the existing ChipProfile by id. Otherwise, create a new one — upload DGI definitions via `scripts/import-chip-profile.ts` (once Track 3 ships) or by direct INSERT matching `test-fixtures/chip-profile-mchip-cvn18.json`'s shape.

## 4. Key ARN population

Every IssuerProfile needs populated AWS Payment Cryptography ARNs before the first real card can be personalised:

- `tmkKeyArn` — TMK (iCVV / CVC3 derivation)
- `imkAcKeyArn` — IMK-AC (ARQC)
- `imkSmiKeyArn` — IMK-SMI (script-message MAC)
- `imkSmcKeyArn` — IMK-SMC (script-message encryption)
- `issuerRsaKeyArn` → stored as `issuerPkKeyArn` (RSA key signing ICC PK certificates)

When the card-ops track lands, add the three GP fields to the same profile:

- `gpEncKeyArn`, `gpMacKeyArn`, `gpDekKeyArn` — SCP03 session-key derivation

Use `scripts/import-issuer-keys.ts --program <id> --from <json>` to bulk-set the ARNs. Each ARN must be a live AWS Payment Cryptography key with the data-prep service IAM role attached as an accessor (see [../security/key-management-procedures.md §5](../security/key-management-procedures.md)).

## 5. Pre-computed certificates

`issuerPkCertificate` (Tag 90), `issuerPkRemainder` (Tag 92), `issuerPkExponent` (Tag 9F32), `caPkIndex` — these are the output of scheme CA enrollment. Copy verbatim from the CA-provided issuer certificate. Never regenerate locally.

## 6. Test card registration

With the profile in place, register a handful of test cards via `scripts/register-test-cards.mjs`:

```bash
DATABASE_URL=... node scripts/register-test-cards.mjs \
  --program <programId> \
  --count 5 \
  --bin <6-digit BIN>
```

Keep the output — the script prints `cardRef` + PAN per row. Store those in the FI onboarding record (encrypted — treat as RESTRICTED per [../security/data-classification.md](../security/data-classification.md)).

## 7. Smoke tap

1. Hand one test card to a tester with access to a contactless-capable Android device.
2. Tap the card; verify the SUN URL hits activation and 200s.
3. Complete the WebAuthn ceremony.
4. Confirm `Card.status` in DB transitions SHIPPED → ACTIVATED → PERSONALISED → PROVISIONED.
5. Attempt one Pay transaction; verify ARQC validates and the transaction reaches COMPLETED.

A failure at any step means do NOT proceed; see [incident-response.md](./incident-response.md) §Tap fails mid-provisioning.

## 8. Go/no-go checklist

Before flipping the FI to accept external traffic:

- [ ] Both IssuerProfile rows (staging + prod) populated with real ARNs (no `arn:stub:pending-phase2`).
- [ ] All five smoke-tap test cards reached `PROVISIONED`.
- [ ] CloudWatch dashboard shows zero `APDUError` counters over the last 60 minutes.
- [ ] Reaper job ([../../scripts/reaper-sad-sessions.ts](../../scripts/reaper-sad-sessions.ts)) is scheduled and its last run's exit code is 0.
- [ ] Rollback plan signed off: `UPDATE "Program" SET "financialInstitutionId" = NULL WHERE id = '<programId>'` removes the new FI's cards from routing within 30 seconds of next service deploy.
