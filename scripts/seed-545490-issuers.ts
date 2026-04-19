#!/usr/bin/env tsx
/**
 * Seed: 545490 Pty Ltd (Mastercard AU) + Karta USA Inc (Visa US).
 *
 * Staging home: Vera scratch/ (gitignored).  Will be copied to
 * /Users/danderson/Palisade/scripts/ once the Palisade port agent's
 * port branch is merged — at that point the Palisade DB is the source
 * of truth for all card-domain tables and this script targets it.
 *
 * Values below were extracted from:
 *   /Users/danderson/Vera/scratch/profiles/mc_au_extract/{profile,answers}.xml
 *   /Users/danderson/Vera/scratch/profiles/visa_us_extract/OutputFileReport_*.xml
 *
 * User-locked decisions (2026-04-19):
 *   - M/Chip Advance v1.2.3 treated as CVN 18 by default.  Flip to 17 by
 *     setting MCA_CVN=17 if NXP specifies otherwise.
 *   - Dual-scheme from day 1: both IssuerProfile rows seeded together.
 *   - 545490 Pty Ltd is the Mastercard-scheme entity (AU).  Karta USA Inc
 *     is a separate legal entity for the Visa-scheme (US) program.
 *
 * Missing today (filled via follow-up tasks, NOT this script):
 *   - APC key ARNs (tmk, imk_ac, imk_smi, imk_smc, issuer_rsa) — come from
 *     the AWS Payment Cryptography ceremony; left empty strings.  Set via
 *     admin UI or a targeted UPDATE once the ceremony key ARNs are in hand.
 *   - GP SCP03 master key ARNs (gpEncKeyArn/gpMacKeyArn/gpDekKeyArn) — come
 *     from CPI manufacturing bureau; left empty for dev, CARD_OPS_USE_TEST_KEYS=1
 *     falls back to the GP 40..4F test triplet.
 *   - DGI definitions on ChipProfile — come from the NXP M/Chip Advance
 *     Common Personalisation Spec (CPS) and Visa VSDC PPS docs.  Left as
 *     empty array.  Card-ops install_payment_applet op + data-prep SAD
 *     builder both depend on these being populated before a payment applet
 *     can be loaded with real issuer keys.
 *
 * Run:
 *   DATABASE_URL=... tsx scripts/seed-545490-issuers.ts
 *   DATABASE_URL=... tsx scripts/seed-545490-issuers.ts --dry-run
 *
 * Idempotent — uses Prisma upserts keyed by FI.code, Program.urlCode, and
 * IssuerProfile.programId so re-running is safe.
 */

import { PrismaClient } from '@prisma/client';
import { parseArgs } from 'node:util';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const { values: cli } = parseArgs({
  options: {
    'dry-run': { type: 'boolean', default: false },
  },
});

const mcCvn = parseInt(process.env.MCA_CVN ?? '18', 10);
if (mcCvn !== 17 && mcCvn !== 18) {
  console.error(`Invalid MCA_CVN=${mcCvn}; expected 17 or 18`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// 545490 Pty Ltd — Mastercard AU Contactless Sticker (prepaid, domestic)
//
// Source: scratch/profiles/mc_au_extract/{profile,answers}.xml
// ---------------------------------------------------------------------------

const FI_545490 = {
  code: '545490-au',
  legalName: '545490 Pty. Ltd.',
  displayName: '545490 Pty Ltd',
  country: 'AU',
  countryCode: '0036',
  // BID not in the MC profile — MC doesn't use a BID concept like Visa does.
  // Leave null; we use programId / BIN at Program level.
};

const PROGRAM_MC_AU = {
  urlCode: 'mcau1',          // 5-char tap.karta.cards/{urlCode} slug
  name: 'Mastercard AU Prepaid Sticker',
  scheme: 'mastercard' as const,
  description: 'Non-reloadable contactless prepaid sticker, domestic-only',
};

const CHIPPROFILE_MCA_V123 = {
  name: `mchip_advance_v1.2.3_nxp_p71_cvn${mcCvn}`,
  scheme: 'mchip_advance',
  vendor: 'nxp',
  cvn: mcCvn,
  // JavaCard AIDs on P71 — these are for the payment applet, NOT the Palisade PA.
  // The payment applet AID is the EMV AID (5F tag on SELECT); the ELF AID and
  // module AID come from the NXP CAP file.  Populate these when the CAP lands.
  elfAid: '',
  moduleAid: '',
  paAid: 'A00000006250414C',        // Palisade PA applet AID (same for both schemes)
  fidoAid: 'A0000006472F0001',      // FIDO2 applet AID (same for both schemes)
  iccPrivateKeyDgi: 0x8001,
  iccPrivateKeyTag: 0x9F48,
  mkAcDgi:  0x8002,
  mkSmiDgi: 0x8003,
  mkSmcDgi: 0x8004,
  // TODO(applet-arrival): populate from NXP M/Chip Advance Common Perso Spec.
  // Typical M/Chip Advance v1.2.3 DGIs: 0x0101 (FCI), 0x0102-0x010C (records),
  // 0x0201 (AC/SMI/SMC keys), 0x9102 (issuer PK cert), etc.
  dgiDefinitions: [] as unknown[],
};

const ISSUERPROFILE_MC_AU = {
  scheme: 'mchip_advance',
  cvn: mcCvn,
  // EMV constants lifted verbatim from MastercardAU.profile profile.xml.
  // All HEX values; empty string ("") for per-card fields populated by
  // data-prep at perso time (AIP, AFL, PAN, etc.).
  aid:          'A0000000041010',
  appLabel:     'Mastercard',                // ASCII, not hex here
  appPreferredName: '',                      // not in profile
  appPriority:  '01',
  appVersionNumber: '0002',
  aip:          '',                          // per-card
  afl:          '',                          // per-card
  cvmList:      '000000000000000042031F03',  // Online PIN (apply next), No CVM
  pdol:         '',                          // contactless uses GPO directly
  cdol1:        '9F02069F03069F1A0295055F2A029A039C019F37049F35019F45029F4C089F34039F21039F7C14',
  cdol2:        '910A8A0295059F37049F4C08',
  iacDefault:   'B450840000',
  iacDenial:    '0000000000',
  iacOnline:    'B470848000',
  // M/Chip contactless CIAC bytes — not in the AID set above but carried on the profile:
  // CIAC-Decline (tag CF): 000000
  // CIAC-Default (tag CD): 060000
  // CIAC-Online  (tag CE): 060000
  // Schema doesn't have dedicated columns for these today; if added later,
  // populate from here.  For now they'll be applied via the chip perso DGIs.
  appUsageControl: '2900',
  currencyCode:    '0036',                   // AUD
  currencyExponent: '02',                    // standard 2-dp for AUD
  countryCode:     '0036',                   // AU
  sdaTagList:      '',                       // no SDA; CDA only
  caPkIndex:       '',                       // TODO: populate once cert chain chosen
  issuerPkCertificate: '',                   // per-card, from APC issuer_rsa key
  issuerPkRemainder:   '',
  issuerPkExponent:    '',

  // bankId / progId — Track 2 added these as Int fields on IssuerProfile.
  // Mastercard doesn't carry a per-FI "bankId" on the card the way Visa does
  // (Visa has a BID); for MC we use the BIN registry range assigned by MC.
  // Leaving as a locally-chosen integer per issuer is fine — the PA applet
  // just writes the bytes to NVM.  Pick stable values unique within our env.
  bankId: 0x545490,                           // vanity; decimal 5526160
  progId: 0x00000001,                         // first MC AU program

  // postProvisionUrl — hostname only, no protocol.  The PA writes this to
  // NVM and the chip bakes it into its post-activation NDEF URL.
  postProvisionUrl: 'tap.karta.cards',

  // Key ARNs — populated by ceremony follow-up, not here.
  tmkKeyArn:         '',
  imkAcKeyArn:       '',
  imkSmiKeyArn:      '',
  imkSmcKeyArn:      '',
  issuerRsaKeyArn:   '',
  gpEncKeyArn:       '',
  gpMacKeyArn:       '',
  gpDekKeyArn:       '',
};

// ---------------------------------------------------------------------------
// Karta USA Inc — Visa US Contactless Gift Card (VSDC 2.9.2, CVN 22)
//
// Source: scratch/profiles/visa_us_extract/OutputFileReport_*.xml
// ---------------------------------------------------------------------------

const FI_KARTA_USA = {
  code: 'karta-usa',
  legalName: 'Karta USA Inc.',
  displayName: 'Karta USA Inc',
  country: 'US',
  countryCode: '0840',
  // Visa BID from the Visa profile:
  issuerBid: '10094526',
};

const PROGRAM_VISA_US = {
  urlCode: 'visus',
  name: 'US Gift Card',
  scheme: 'visa' as const,
  description: 'Contactless qVSDC gift card, online-decline, signature CVM',
};

const CHIPPROFILE_VSDC_V292 = {
  name: 'vsdc_v2.9.2_nxp_p71_cvn22',
  scheme: 'vsdc',
  vendor: 'nxp',
  cvn: 22,
  elfAid: '',                                 // from Visa CAP file when it arrives
  moduleAid: '',
  paAid: 'A00000006250414C',                  // same Palisade PA
  fidoAid: 'A0000006472F0001',                // same FIDO2
  iccPrivateKeyDgi: 0x8001,
  iccPrivateKeyTag: 0x9F48,
  mkAcDgi:  0x8002,
  mkSmiDgi: 0x8003,
  mkSmcDgi: 0x8004,
  // TODO(applet-arrival): populate from Visa VSDC PPS (Personalisation
  // Preparation Specification) for VSDC 2.9.2.  Visa DGIs differ from MC;
  // e.g. 0x0201 and 0x0202 structures carry the Track 2 Equivalent + PAN
  // differently.  Visa also uses SFI-based record layouts not DGI inside
  // STORE DATA — but the card-side perso still receives DGI-style encoded
  // TLVs via the PA's TRANSFER_SAD → STORE DATA bridge.
  dgiDefinitions: [] as unknown[],
};

const ISSUERPROFILE_VISA_US = {
  scheme: 'vsdc',
  cvn: 22,
  aid:          'A0000000031010',
  appLabel:     'VISA DEBIT',
  appPreferredName: '',
  appPriority:  '01',
  appVersionNumber: '',                       // Visa uses 9F08 differently; populate if needed
  aip:          '',                           // per-card
  afl:          '',                           // per-card
  cvmList:      '',                           // Signature CVM — encoded at perso, not static here
  pdol:         '',                           // qVSDC gets PDOL via GPO
  cdol1:        '',                           // qVSDC doesn't use CDOL1 the same way
  cdol2:        '',
  iacDefault:   '',                           // Visa uses TVR/TSI differently from MC IACs
  iacDenial:    '',
  iacOnline:    '',
  appUsageControl: '',                        // not applicable the same way for VSDC
  currencyCode:    '0840',                    // USD
  currencyExponent: '02',
  countryCode:     '0840',                    // US
  sdaTagList:      '',
  caPkIndex:       '',
  issuerPkCertificate: '',
  issuerPkRemainder:   '',
  issuerPkExponent:    '',

  bankId: 0x10094526,                          // Visa issuer BID from profile
  progId: 0x00000001,                          // first Visa US program
  postProvisionUrl: 'tap.karta.cards',

  tmkKeyArn:         '',
  imkAcKeyArn:       '',
  imkSmiKeyArn:      '',
  imkSmcKeyArn:      '',
  issuerRsaKeyArn:   '',
  gpEncKeyArn:       '',
  gpMacKeyArn:       '',
  gpDekKeyArn:       '',
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const prisma = new PrismaClient();
  const dryRun = cli['dry-run'] ?? false;

  console.log(`[seed-545490] MC AU CVN=${mcCvn}, Visa US CVN=22, dry-run=${dryRun}`);

  if (dryRun) {
    console.log('[seed-545490] DRY-RUN — would upsert:');
    console.log('  FinancialInstitution:', FI_545490.code, FI_KARTA_USA.code);
    console.log('  Program:', PROGRAM_MC_AU.urlCode, PROGRAM_VISA_US.urlCode);
    console.log('  ChipProfile:', CHIPPROFILE_MCA_V123.name, CHIPPROFILE_VSDC_V292.name);
    console.log('  IssuerProfile linked to both programs');
    await prisma.$disconnect();
    return;
  }

  // 1. FinancialInstitutions
  const fi545490 = await prisma.financialInstitution.upsert({
    where: { code: FI_545490.code },
    create: FI_545490,
    update: { legalName: FI_545490.legalName, displayName: FI_545490.displayName },
  });
  const fiKartaUsa = await prisma.financialInstitution.upsert({
    where: { code: FI_KARTA_USA.code },
    create: { ...FI_KARTA_USA, issuerBid: FI_KARTA_USA.issuerBid },
    update: { legalName: FI_KARTA_USA.legalName, displayName: FI_KARTA_USA.displayName },
  });
  console.log(`[seed-545490] FI 545490 ${fi545490.id} + Karta USA ${fiKartaUsa.id}`);

  // 2. ChipProfiles (upsert by name)
  const cpMc = await prisma.chipProfile.upsert({
    where: { name: CHIPPROFILE_MCA_V123.name },
    create: CHIPPROFILE_MCA_V123 as never,
    update: { cvn: CHIPPROFILE_MCA_V123.cvn },
  });
  const cpVisa = await prisma.chipProfile.upsert({
    where: { name: CHIPPROFILE_VSDC_V292.name },
    create: CHIPPROFILE_VSDC_V292 as never,
    update: { cvn: CHIPPROFILE_VSDC_V292.cvn },
  });
  console.log(`[seed-545490] ChipProfile MC=${cpMc.id} Visa=${cpVisa.id}`);

  // 3. Programs
  const programMc = await prisma.program.upsert({
    where: { urlCode: PROGRAM_MC_AU.urlCode },
    create: { ...PROGRAM_MC_AU, financialInstitutionId: fi545490.id },
    update: { name: PROGRAM_MC_AU.name, description: PROGRAM_MC_AU.description },
  });
  const programVisa = await prisma.program.upsert({
    where: { urlCode: PROGRAM_VISA_US.urlCode },
    create: { ...PROGRAM_VISA_US, financialInstitutionId: fiKartaUsa.id },
    update: { name: PROGRAM_VISA_US.name, description: PROGRAM_VISA_US.description },
  });
  console.log(`[seed-545490] Program MC=${programMc.id} Visa=${programVisa.id}`);

  // 4. IssuerProfiles (one per program)
  const ipMc = await prisma.issuerProfile.upsert({
    where: { programId: programMc.id },
    create: {
      ...ISSUERPROFILE_MC_AU,
      programId: programMc.id,
      chipProfileId: cpMc.id,
    },
    update: {
      ...ISSUERPROFILE_MC_AU,
      chipProfileId: cpMc.id,
    },
  });
  const ipVisa = await prisma.issuerProfile.upsert({
    where: { programId: programVisa.id },
    create: {
      ...ISSUERPROFILE_VISA_US,
      programId: programVisa.id,
      chipProfileId: cpVisa.id,
    },
    update: {
      ...ISSUERPROFILE_VISA_US,
      chipProfileId: cpVisa.id,
    },
  });
  console.log(`[seed-545490] IssuerProfile MC=${ipMc.id} Visa=${ipVisa.id}`);

  console.log('[seed-545490] done.  Follow-ups:');
  console.log('  1. Populate the 5 APC key ARNs (tmk/imk_ac/imk_smi/imk_smc/issuer_rsa)');
  console.log('     once the AWS PC ceremony lands — via admin UI or UPDATE sql.');
  console.log('  2. Populate the 3 GP ARNs (gpEncKeyArn/gpMacKeyArn/gpDekKeyArn)');
  console.log('     once CPI provides the SCP03 masters for each FI.');
  console.log('  3. Populate ChipProfile.dgiDefinitions once NXP CPS docs arrive.');
  console.log('  4. Flip DATA_PREP_MOCK_EMV=false in the data-prep env once (1) is done.');

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error('[seed-545490] FAILED:', err);
  process.exit(1);
});
