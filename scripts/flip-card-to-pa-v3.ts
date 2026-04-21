#!/usr/bin/env tsx
/**
 * Flip a single Card's ChipProfile to `PARAM_BUNDLE` for the pa-v3 trial.
 *
 * After this runs, two things change for the target card:
 *
 *   1. `install_pa` on card-ops picks `pa-v3.cap` instead of `pa.cap`
 *      (via the CAP toggle in services/card-ops/src/operations/install-pa.ts).
 *   2. `data-prep.prepare()` routes to `prepareParamBundle()` instead of
 *      `prepareCard()`, so the next registration cycle writes a
 *      `ParamRecord` + `Card.paramRecordId` instead of a `SadRecord`.
 *
 * Every other card bound to the same `ChipProfile` is ALSO affected — the
 * toggle lives on ChipProfile, not Card.  So if you share a ChipProfile
 * across multiple cards, either:
 *   (a) clone the ChipProfile first and bind only the trial card's
 *       IssuerProfile to the clone, or
 *   (b) accept that every card in that program is now on the prototype
 *       path.
 *
 * The script chooses (a) by default — it creates a NEW ChipProfile row
 * scoped to this card's program, copies all fields from the current
 * ChipProfile, flips `provisioningMode` to `PARAM_BUNDLE`, and repoints
 * the IssuerProfile at it.  Pass `--in-place` to skip the clone and flip
 * the existing ChipProfile directly (blast-radius = every program using
 * that profile).
 *
 * Dry-run by default.  Pass `--apply` to actually write.
 *
 * Usage:
 *   tsx scripts/flip-card-to-pa-v3.ts --card-ref e2e_fi_2590
 *   tsx scripts/flip-card-to-pa-v3.ts --card-ref e2e_fi_2590 --apply
 *   tsx scripts/flip-card-to-pa-v3.ts --card-ref e2e_fi_2590 --apply --in-place
 *
 * Revert:
 *   tsx scripts/flip-card-to-pa-v3.ts --card-ref e2e_fi_2590 --apply --revert
 *   (Flips the ChipProfile back to SAD_LEGACY.  Does NOT delete the
 *   cloned profile — manual cleanup via psql if you want it gone.)
 *
 * Env:
 *   DATABASE_URL — Postgres connection string for the target env.
 */

import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';

const { values } = parseArgs({
  options: {
    'card-ref': { type: 'string' },
    apply:      { type: 'boolean', default: false },
    'in-place': { type: 'boolean', default: false },
    revert:     { type: 'boolean', default: false },
    help:       { type: 'boolean', default: false },
  },
});

if (values.help || !values['card-ref']) {
  console.error(`Usage: tsx scripts/flip-card-to-pa-v3.ts --card-ref <ref> [--apply] [--in-place] [--revert]

Dry-run by default.  Add --apply to write.

Options:
  --card-ref <ref>   Card.ref to flip (e.g. e2e_fi_2590)
  --apply            Commit the change (default: dry-run)
  --in-place         Flip the existing ChipProfile instead of cloning
                     (affects every program using that profile)
  --revert           Flip back to SAD_LEGACY (does not delete clones)
  --help             Show this help
`);
  process.exit(values.help ? 0 : 1);
}

const prisma = new PrismaClient();

async function main(): Promise<void> {
  const cardRef = values['card-ref']!;
  const targetMode = values.revert ? 'SAD_LEGACY' : 'PARAM_BUNDLE';

  const card = await prisma.card.findFirst({
    where: { cardRef },
    include: {
      program: {
        include: {
          issuerProfile: {
            include: { chipProfile: true },
          },
        },
      },
    },
  });
  if (!card) {
    console.error(`[flip] card.ref='${cardRef}' not found`);
    process.exit(1);
  }
  const issuer = card.program?.issuerProfile;
  if (!issuer) {
    console.error(`[flip] card '${cardRef}' has no IssuerProfile on its Program`);
    process.exit(1);
  }
  const currentProfile = issuer.chipProfile;
  const currentMode = currentProfile.provisioningMode;

  console.log(`[flip] card=${cardRef} (id=${card.id})`);
  console.log(`[flip] program=${card.program!.id}`);
  console.log(`[flip] currentChipProfile=${currentProfile.id} (${currentProfile.name})`);
  console.log(`[flip] currentMode=${currentMode}  →  targetMode=${targetMode}`);

  if (currentMode === targetMode) {
    console.log(`[flip] already in target mode; no-op`);
    return;
  }

  if (!values.apply) {
    console.log(`[flip] DRY RUN — no changes written.  Re-run with --apply to commit.`);
    if (!values['in-place']) {
      console.log(`[flip] Would clone ChipProfile '${currentProfile.name}' → '${currentProfile.name}_pa_v3'`);
      console.log(`[flip] Would set IssuerProfile.chipProfileId → <new clone id>`);
      console.log(`[flip] Would set new ChipProfile.provisioningMode = ${targetMode}`);
    } else {
      console.log(`[flip] Would set ChipProfile(${currentProfile.id}).provisioningMode = ${targetMode}`);
      console.log(`[flip] WARNING: --in-place touches every program using this profile`);
    }
    return;
  }

  await prisma.$transaction(async (tx) => {
    if (values['in-place']) {
      await tx.chipProfile.update({
        where: { id: currentProfile.id },
        data: { provisioningMode: targetMode },
      });
      console.log(`[flip] in-place: ChipProfile(${currentProfile.id}).provisioningMode = ${targetMode}`);
      return;
    }

    if (values.revert) {
      // For --revert without --in-place: we flip the CURRENT profile
      // back (it might be the clone).  The caller can then manually
      // repoint IssuerProfile if they want to return to the original.
      await tx.chipProfile.update({
        where: { id: currentProfile.id },
        data: { provisioningMode: targetMode },
      });
      console.log(`[flip] revert: ChipProfile(${currentProfile.id}).provisioningMode = ${targetMode}`);
      return;
    }

    // Clone path — create a new ChipProfile scoped to this card's program.
    // Copy every business field; Prisma auto-populates id/createdAt/updatedAt.
    const clone = await tx.chipProfile.create({
      data: {
        name: `${currentProfile.name}_pa_v3`,
        scheme: currentProfile.scheme,
        vendor: currentProfile.vendor,
        cvn: currentProfile.cvn,
        dgiDefinitions: currentProfile.dgiDefinitions as object,
        elfAid: currentProfile.elfAid,
        moduleAid: currentProfile.moduleAid,
        paAid: currentProfile.paAid,
        fidoAid: currentProfile.fidoAid,
        iccPrivateKeyDgi: currentProfile.iccPrivateKeyDgi,
        iccPrivateKeyTag: currentProfile.iccPrivateKeyTag,
        mkAcDgi: currentProfile.mkAcDgi,
        mkSmiDgi: currentProfile.mkSmiDgi,
        mkSmcDgi: currentProfile.mkSmcDgi,
        paymentAppletCapFilename: currentProfile.paymentAppletCapFilename,
        // Scope this clone to just this program — ChipProfile.programId
        // flips the profile from "shared catalog" to "only visible to
        // this program", so flipping it doesn't ripple to unrelated FIs.
        programId: card.program!.id,
        provisioningMode: targetMode,
      },
    });
    console.log(`[flip] created clone ChipProfile(${clone.id}) name=${clone.name} mode=${clone.provisioningMode}`);

    await tx.issuerProfile.update({
      where: { id: issuer.id },
      data: { chipProfileId: clone.id },
    });
    console.log(`[flip] repointed IssuerProfile(${issuer.id}).chipProfileId → ${clone.id}`);
  });

  console.log(`[flip] done.`);
  console.log(`[flip] Next steps:`);
  console.log(`[flip]   1. Confirm card-ops env has CARD_OPS_DEFAULT_PA_CAP unset (we're driven by ChipProfile now)`);
  console.log(`[flip]   2. Confirm rca env has RCA_ENABLE_PARAM_BUNDLE='1'`);
  console.log(`[flip]   3. From admin UI: "Install PA" on card ${cardRef} — watch for capKey='pa-v3' in the complete frame`);
  console.log(`[flip]   4. Register / tap the card — data-prep.prepare() will route to prepareParamBundle`);
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
