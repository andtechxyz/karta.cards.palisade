# Runbook: Financial Institution Onboarding

**Document Owner:** Platform Team
**Last Reviewed:** 2026-04-19
**Applies to:** Palisade (IssuerProfile + ChipProfile + FinancialInstitution
lives on Palisade's DB). Vera has no FI-onboarding surface — Palisade is
sole owner of the issuer-profile lifecycle post-split.

**Related:** [key-rotation.md](./key-rotation.md), [incident-response.md](./incident-response.md)

---

## 1. Scope

End-to-end steps to bring a new FI live on Palisade. Covers the issuer
profile, chip profile, key ARNs, and pre-flight test card. Stop at step 7
if this is a pilot with internal cards only; continue to step 8 for an
external-traffic go-live.

**Current tooling:**

- **Seed script** — `scripts/seed-545490-issuers.ts` provisions 545490 Pty Ltd
  (M/Chip Advance v1.2.3, CVN 18, MC AU) and Karta USA Inc (VSDC 2.9.2,
  CVN 22, Visa US) in one shot. Use this as the template for the next
  FI — fork, adjust constants, and re-run.
- **Admin UI (shared SPA, hosted by Vera, calls Palisade admin via
  `/palisade-api/*`)** — writes most of the fields listed below live
  via the Issuer Profile and Chip Profile tabs. Agent B (commits
  `42e62aa` Palisade + `4f1e80b` Vera) added form fields for
  `bankId`, `progId`, and `postProvisionUrl`, so the three acquirer-side
  identifiers are now in the UI, not just the seed script.
- **psql fallback** — for anything the UI / seed script doesn't cover
  yet (e.g. backfilling GP ARNs before the APC key ceremony), apply
  directly and keep a copy of every value in the FI's onboarding record.

## 2. IssuerProfile creation

One IssuerProfile per Program. Either:

- Admin SPA → "Issuer Profiles" → "New" (preferred; uses Palisade's
  `POST /api/admin/issuer-profiles` route added in `e5430b3` +
  `42e62aa` — covers bankId, progId, postProvisionUrl, scheme, CVN,
  derivation method, every TLV constant, and the five key ARNs).
- `scripts/seed-545490-issuers.ts` for a scripted double-FI drop; fork
  this for the next FI.
- `psql` for one-off backfills:

```sql
INSERT INTO "IssuerProfile" (
  id, "programId", "chipProfileId",
  "bankId", "progId", "postProvisionUrl",
  scheme, cvn, "imkAlgorithm", "derivationMethod",
  "tmkKeyArn", "imkAcKeyArn", "imkSmiKeyArn", "imkSmcKeyArn", "issuerPkKeyArn",
  "gpEncKeyArn", "gpMacKeyArn", "gpDekKeyArn",
  "caPkIndex", "issuerPkCertificate", "issuerPkRemainder", "issuerPkExponent",
  aid, "appLabel", "appPriority", "appVersionNumber",
  aip, afl, "cvmList", pdol, cdol1, cdol2,
  "iacDefault", "iacDenial", "iacOnline",
  "appUsageControl", "currencyCode", "currencyExponent", "countryCode", "sdaTagList"
) VALUES (...);
```

- `bankId` / `progId` — acquirer-side identifiers used in downstream
  reporting; populated by the admin form fields added in `4f1e80b`.
- `postProvisionUrl` — optional per-program landing URL the activation
  SPA redirects to on PROVISIONED. Leave NULL for default behaviour.
- `scheme`: `"mchip_advance"` or `"vsdc"` — MUST match the chosen `ChipProfile`.
- `cvn`: numeric CVN (10/17/18/22). MUST match the chip profile's CVN.
- The TLV-constant fields (AIP, AFL, CVM List, etc.) come from the
  scheme's personalisation spec — never invented.
- `gpEncKeyArn` / `gpMacKeyArn` / `gpDekKeyArn` — per-FI SCP03 static
  keys for card-ops install / perso; populate once the FI's partner has
  exchanged keys. Leave NULL and set `CARD_OPS_USE_TEST_KEYS=1` if
  running against a virgin JCOP sample card during onboarding.

Worked examples:
- `scripts/seed-karta-platinum-issuer-profile.ts` — complete M/Chip
  Advance CVN-18 seed, single FI.
- `scripts/seed-545490-issuers.ts` — two-FI seed (MC AU + Visa US)
  covering `446ebbe`'s ARN field-name fixes; mirrors the shape required
  by the admin UI.

## 3. ChipProfile association

If the FI uses an already-seeded chip family (NXP JCOP5 M/Chip,
Infineon SLJ52 VSDC), link the existing ChipProfile by id. Otherwise,
create a new one via the admin SPA (Chip Profiles tab — backed by
`POST /api/admin/chip-profiles` on Palisade) or a direct INSERT matching
`test-fixtures/chip-profile-mchip-cvn18.json`'s shape.

Agent A landed `ChipProfile.paymentAppletCapFilename` (`99343dc`) —
set this to the exact filename of the payment-applet CAP shipped in
`services/card-ops/cap-files/` (e.g. `mchip_advance_v1.2.3.cap`). The
`install_payment_applet` and `personalise_payment_applet` card-ops
operations resolve the CAP via this field, so a ChipProfile without it
cannot personalise a payment applet at card-ops time.

## 4. Key ARN population

Every IssuerProfile needs populated ARNs before the first real card can
be personalised:

**AWS Payment Cryptography (UDK derivations) — populated from the APC key ceremony:**

- `tmkKeyArn` — TMK (iCVV / CVC3 derivation)
- `imkAcKeyArn` — IMK-AC (ARQC)
- `imkSmiKeyArn` — IMK-SMI (script-message MAC)
- `imkSmcKeyArn` — IMK-SMC (script-message encryption)
- `issuerPkKeyArn` — RSA key signing ICC PK certificates

**AWS Secrets Manager (SCP03 static keys) — populated from the CPI GP key exchange:**

- `gpEncKeyArn`, `gpMacKeyArn`, `gpDekKeyArn` — SCP03 ENC/MAC/DEK
  resolved by `card-ops` via `GpKeyFetcher` (see [key-rotation.md §3a](./key-rotation.md)).

Use `scripts/import-issuer-keys.ts --program <id> --from <json>` to
bulk-set the ARNs. Each APC ARN must be a live AWS Payment Cryptography
key with the data-prep service IAM role attached as an accessor (see
[../security/key-management-procedures.md §5](../security/key-management-procedures.md));
each GP Secrets Manager ARN must be readable by the card-ops service
IAM role.

**External gates blocking full population (2026-04-19):**

1. APC key ceremony — produces the 5 APC ARNs per IssuerProfile.
2. CPI GP SCP03 master ceremony — produces the 3 Secrets Manager ARNs
   per IssuerProfile.

Until both ceremonies complete for a given FI, leave the card-ops side
in `CARD_OPS_USE_TEST_KEYS=1` mode, set `DATA_PREP_MOCK_EMV=true`, and
issue only test cards.

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
