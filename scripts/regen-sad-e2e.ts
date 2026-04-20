#!/usr/bin/env tsx
/**
 * Regenerate a SAD record for an e2e card so the PA applet sees a real
 * TLV/DGI blob on TRANSFER_SAD instead of the historic `AAA=` stub.
 *
 * This is a local developer tool — NOT a service endpoint.  It bypasses
 * the running data-prep service and builds the SAD in-process so the
 * script stays useful even when data-prep is down, AWS Payment
 * Cryptography is unreachable, or the provisioning flow is half-deployed.
 *
 * Flow:
 *   1. Load the Card + Program + IssuerProfile + ChipProfile.
 *   2. Use mock-mode EmvDerivationService (no AWS calls) for iCVV + KCVs.
 *   3. SADBuilder.buildSad(profile, chipProfile, cardData) → DGI list.
 *   4. SADBuilder.serialiseDgis(dgis) → flat plaintext bytes.
 *   5. encryptSadDev(bytes) → AES-128-ECB ciphertext under the static
 *      dev master key.  Raw bytes go into SadRecord.sadEncrypted;
 *      sadKeyVersion = 1 so the RCA's decrypt path knows to use
 *      decryptSadDev().
 *   6. Upsert SadRecord.  Update Card.proxyCardId if it hasn't been
 *      linked yet.
 *
 * Secrets:
 *   --pan is passed on the command line rather than read from the vault.
 *   That's deliberate — this script is dev-only and pulling from the
 *   vault would need a signed retrieval-token dance that adds no value
 *   for test cards whose PAN is already in test-fixtures/e2e-cards-seeded.txt.
 *
 * Usage:
 *   tsx scripts/regen-sad-e2e.ts \
 *     --card-ref e2e_fi_2590 \
 *     --pan 4580483507983243 \
 *     --expiry 2912               # YYMM
 *     [--csn 01]
 *     [--service-code 201]
 *
 * Env:
 *   DATABASE_URL — Postgres connection string for the target env.
 */

import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';
import {
  SADBuilder,
  ChipProfile,
  encryptSadDev,
  SAD_KEY_VERSION_DEV_AES_ECB,
} from '@palisade/emv';
import type { CardData, IssuerProfileForSad } from '@palisade/emv';
// The mock-mode EmvDerivationService is dependency-free (no AWS clients
// constructed if mockMode=true is enforced at the callsite).  Importing it
// from the service package keeps the iCVV derivation in lock-step with what
// data-prep itself would produce for this card.
// Import from dist/ rather than src/ so the script is usable inside the
// production runtime image (which only ships dist/), not just against a
// local repo that's been `pnpm build`-ed.
import { EmvDerivationService } from '../services/data-prep/dist/services/emv-derivation.js';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseCli(): {
  cardRef: string;
  pan: string;
  expiryYymm: string;
  csn: string;
  serviceCode: string;
} {
  const { values } = parseArgs({
    options: {
      'card-ref':     { type: 'string' },
      pan:            { type: 'string' },
      expiry:         { type: 'string' }, // YYMM
      csn:            { type: 'string' },
      'service-code': { type: 'string' },
    },
  });

  const cardRef = values['card-ref'];
  const pan = values.pan;
  const expiry = values.expiry;

  if (!cardRef || !pan || !expiry) {
    console.error('Usage:');
    console.error(
      '  tsx scripts/regen-sad-e2e.ts --card-ref <ref> --pan <digits> --expiry YYMM ' +
      '[--csn 01] [--service-code 201]',
    );
    process.exit(2);
  }

  if (!/^\d{13,19}$/.test(pan)) {
    console.error(`Invalid --pan: must be 13–19 digits, got "${pan.length}" chars`);
    process.exit(2);
  }
  if (!/^\d{4}$/.test(expiry)) {
    console.error(`Invalid --expiry: must be 4 digits YYMM, got "${expiry}"`);
    process.exit(2);
  }

  return {
    cardRef,
    pan,
    expiryYymm: expiry,
    csn: values.csn ?? '01',
    serviceCode: values['service-code'] ?? '201',
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function computeEffectiveDate(expiryYymm: string): string {
  const yy = parseInt(expiryYymm.slice(0, 2), 10);
  const mm = expiryYymm.slice(2, 4);
  const effectiveYy = Math.max(0, yy - 5);
  return `${effectiveYy.toString().padStart(2, '0')}${mm}`;
}

function toSadProfile(ip: {
  scheme: string;
  cvn: number;
  aip: string;
  afl: string;
  cvmList: string;
  pdol: string;
  cdol1: string;
  cdol2: string;
  iacDefault: string;
  iacDenial: string;
  iacOnline: string;
  appUsageControl: string;
  currencyCode: string;
  currencyExponent: string;
  countryCode: string;
  sdaTagList: string;
  appVersionNumber: string;
  appPriority: string;
  aid: string;
  appLabel: string;
  appPreferredName: string;
  issuerPkCertificate: string;
  issuerPkRemainder: string;
  issuerPkExponent: string;
  caPkIndex: string;
}): IssuerProfileForSad {
  return {
    scheme: ip.scheme,
    cvn: ip.cvn,
    aip: ip.aip || undefined,
    afl: ip.afl || undefined,
    cvmList: ip.cvmList || undefined,
    pdol: ip.pdol || undefined,
    cdol1: ip.cdol1 || undefined,
    cdol2: ip.cdol2 || undefined,
    iacDefault: ip.iacDefault || undefined,
    iacDenial: ip.iacDenial || undefined,
    iacOnline: ip.iacOnline || undefined,
    appUsageControl: ip.appUsageControl || undefined,
    currencyCode: ip.currencyCode || undefined,
    currencyExponent: ip.currencyExponent || undefined,
    countryCode: ip.countryCode || undefined,
    sdaTagList: ip.sdaTagList || undefined,
    appVersionNumber: ip.appVersionNumber || undefined,
    appPriority: ip.appPriority || undefined,
    aid: ip.aid || undefined,
    appLabel: ip.appLabel || undefined,
    appPreferredName: ip.appPreferredName || undefined,
    issuerPkCertificate: ip.issuerPkCertificate || undefined,
    issuerPkRemainder: ip.issuerPkRemainder || undefined,
    issuerPkExponent: ip.issuerPkExponent || undefined,
    caPkIndex: ip.caPkIndex || undefined,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { cardRef, pan, expiryYymm, csn, serviceCode } = parseCli();
  const prisma = new PrismaClient();

  try {
    const card = await prisma.card.findUnique({
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
      console.error(`Card not found: cardRef=${cardRef}`);
      process.exit(1);
    }
    const program = card.program;
    if (!program) {
      console.error(
        `Card ${cardRef} has no linked Program.  Set Card.programId before regen.`,
      );
      process.exit(1);
    }
    const issuerProfile = program.issuerProfile;
    if (!issuerProfile) {
      console.error(
        `Program ${program.id} has no IssuerProfile.  Run:\n` +
        `  tsx scripts/seed-karta-platinum-issuer-profile.ts`,
      );
      process.exit(1);
    }
    const chipProfileRow = issuerProfile.chipProfile;

    console.log(`[regen] card:     ${cardRef} (id=${card.id})`);
    console.log(`[regen] program:  ${program.id}`);
    console.log(`[regen] profile:  ${issuerProfile.id} (scheme=${issuerProfile.scheme}, cvn=${issuerProfile.cvn})`);
    console.log(`[regen] chip:     ${chipProfileRow.id} (${chipProfileRow.name})`);

    // Build the @palisade/emv ChipProfile from the DB row.
    const chipProfile = ChipProfile.fromJson({
      profile_id: chipProfileRow.id,
      profile_name: chipProfileRow.name,
      scheme: chipProfileRow.scheme,
      applet_vendor: chipProfileRow.vendor,
      cvn: chipProfileRow.cvn,
      dgi_definitions: chipProfileRow.dgiDefinitions,
      elf_aid: chipProfileRow.elfAid ?? '',
      module_aid: chipProfileRow.moduleAid ?? '',
      pa_aid: chipProfileRow.paAid,
      fido_aid: chipProfileRow.fidoAid,
      icc_private_key_dgi: chipProfileRow.iccPrivateKeyDgi,
      icc_private_key_tag: chipProfileRow.iccPrivateKeyTag,
      mk_ac_dgi: chipProfileRow.mkAcDgi,
      mk_smi_dgi: chipProfileRow.mkSmiDgi,
      mk_smc_dgi: chipProfileRow.mkSmcDgi,
    });

    // Mock-mode EMV derivation — deterministic iCVV from PAN+expiry, no
    // AWS calls.  Structurally valid; not cryptographically meaningful.
    // The constructor took (region, mockMode: boolean) in the old API;
    // now it takes a UdkDeriver directly.  Use the mock backend via
    // the static fromBackend() helper.
    const emv = EmvDerivationService.fromBackend('mock');
    const icvv = await emv.deriveIcvv('unused-arn', pan, expiryYymm);

    const cardData: CardData = {
      pan,
      expiryDate: expiryYymm,
      effectiveDate: computeEffectiveDate(expiryYymm),
      serviceCode,
      cardSequenceNumber: csn,
      icvv,
    };

    const dgis = SADBuilder.buildSad(
      toSadProfile(issuerProfile),
      chipProfile,
      cardData,
    );
    const sadBytes = SADBuilder.serialiseDgis(dgis);
    const encrypted = encryptSadDev(sadBytes);

    console.log(
      `[regen] built SAD:  ${dgis.length} DGIs, plaintext ${sadBytes.length} bytes, ` +
      `ciphertext ${encrypted.length} bytes`,
    );
    console.log(`[regen] plaintext first 64 bytes (hex):`);
    console.log('  ' + sadBytes.subarray(0, Math.min(64, sadBytes.length)).toString('hex'));
    console.log(`[regen] ciphertext first 64 bytes (hex):`);
    console.log('  ' + encrypted.subarray(0, Math.min(64, encrypted.length)).toString('hex'));

    // Reuse proxyCardId if already on the card — matches the RCA lookup
    // path.  Otherwise mint a dev-style one that's readable in logs.
    const proxyCardId = card.proxyCardId ?? `proxy_${cardRef}`;

    const existing = await prisma.sadRecord.findUnique({
      where: { proxyCardId },
    });
    const expiresAt = new Date(Date.now() + 30 * 86400_000);

    if (existing) {
      console.log(`[regen] updating existing SadRecord id=${existing.id} ` +
        `(old keyVersion=${existing.sadKeyVersion}, old bytes=${existing.sadEncrypted.length})`);
      await prisma.sadRecord.update({
        where: { id: existing.id },
        data: {
          sadEncrypted: encrypted,
          sadKeyVersion: SAD_KEY_VERSION_DEV_AES_ECB,
          chipSerial: card.chipSerial ?? existing.chipSerial,
          status: 'READY',
          expiresAt,
        },
      });
    } else {
      console.log(`[regen] creating new SadRecord for proxyCardId=${proxyCardId}`);
      await prisma.sadRecord.create({
        data: {
          cardId: card.id,
          proxyCardId,
          sadEncrypted: encrypted,
          sadKeyVersion: SAD_KEY_VERSION_DEV_AES_ECB,
          chipSerial: card.chipSerial,
          status: 'READY',
          expiresAt,
        },
      });
    }

    // Link the card if it isn't already.
    if (!card.proxyCardId) {
      await prisma.card.update({
        where: { id: card.id },
        data: { proxyCardId },
      });
      console.log(`[regen] linked Card.proxyCardId=${proxyCardId}`);
    }

    console.log('[regen] done.');
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('[regen] FAILED:', err);
  process.exit(1);
});
