#!/usr/bin/env tsx
/**
 * Seed IssuerProfile (+ ChipProfile if needed) for the karta_platinum
 * program so data-prep can build a real SAD for e2e_fi_2590 (and any
 * future FI-lane test card).
 *
 * This is the Phase-1 dev-mode seed.  All AWS Payment Cryptography key
 * ARN fields are stubbed with `arn:stub:pending-phase2` — they're not
 * dereferenced by the SAD builder itself (the builder only needs TLV
 * constants + CVN + scheme).  The real key ARNs land via
 * scripts/import-issuer-keys.ts once Phase-2 HSM keys are provisioned.
 *
 * Idempotent:
 *   - If a ChipProfile with the expected name/CVN/scheme exists, reuse
 *     it.  Otherwise create one from the M/Chip Advance CVN-18 defaults
 *     below.
 *   - If an IssuerProfile already exists for karta_platinum, update
 *     mutable fields in place.  Otherwise create it.
 *
 * Usage:
 *   tsx scripts/seed-karta-platinum-issuer-profile.ts
 *
 * Env:
 *   DATABASE_URL — Postgres connection string for the target env.
 */

import { PrismaClient } from '@prisma/client';

const KARTA_PLATINUM_PROGRAM_ID = 'karta_platinum';

// ---------------------------------------------------------------------------
// ChipProfile — M/Chip Advance CVN-18 DGI layout matching test-fixtures/
//              chip-profile-mchip-cvn18.json
// ---------------------------------------------------------------------------

// Tag numbers expressed in decimal to match @palisade/emv's ChipProfile.fromJson
// which reads them as integers.  Snake_case keys on the DGI objects match
// what ChipProfile.fromJson expects (it does `d.dgi_number` on each entry).
// These are the reference values from test-fixtures/chip-profile-mchip-cvn18.json,
// translated into the shape fromJson consumes.
const MCHIP_CVN18_DGI_DEFS = [
  {
    dgi_number: 32513,
    name: 'Application FCI',
    tags: [80, 16720, 40706, 40712, 40720, 36],
    mandatory: true,
    source: 'per_profile',
  },
  {
    dgi_number: 36864,
    name: 'Static Application Data',
    tags: [130, 148, 40711, 40706, 40712, 90, 24364, 24368],
    mandatory: true,
    source: 'per_card',
  },
  {
    dgi_number: 36865,
    name: 'Card Risk Management Object 1',
    tags: [40733, 40734, 40719, 40717, 40718, 40729, 40724, 40725],
    mandatory: true,
    source: 'per_profile',
  },
  {
    dgi_number: 2048,
    name: 'MK-AC (Issuer Master Key — Application Cryptogram)',
    tags: [],
    mandatory: true,
    source: 'per_card',
  },
  {
    dgi_number: 2049,
    name: 'MK-SMI (Issuer Master Key — Secure Messaging Integrity)',
    tags: [],
    mandatory: true,
    source: 'per_card',
  },
  {
    dgi_number: 2050,
    name: 'MK-SMC (Issuer Master Key — Secure Messaging Confidentiality)',
    tags: [],
    mandatory: true,
    source: 'per_card',
  },
  {
    dgi_number: 32769,
    name: 'ICC Private Key',
    tags: [40776],
    mandatory: true,
    source: 'per_card',
  },
  {
    dgi_number: 36873,
    name: 'PIN Try Counter',
    tags: [40711],
    mandatory: false,
    source: 'per_profile',
  },
];

const CHIP_PROFILE_NAME = 'M/Chip Advance CVN 18 (JCOP5, karta_platinum seed)';

// ---------------------------------------------------------------------------
// IssuerProfile defaults — published M/Chip Advance CVN-18 values.
// Sourced from palisade-data-prep/tests/conftest.py which in turn are the
// reference vectors Mastercard publishes for perso test fixtures.
// Currency is AUD (0036) because karta_platinum trades in AUD.
// Country is AU (0036 in the ISO-3166 numeric).
// Nothing in these constants is PAN- or card-specific.
// ---------------------------------------------------------------------------

const ISSUER_PROFILE_DEFAULTS = {
  scheme: 'mchip_advance',
  cvn: 18,
  imkAlgorithm: 'TDES_2KEY',
  derivationMethod: 'METHOD_A',

  // AWS Payment Cryptography ARNs — stubs.  Real ARNs land via
  // scripts/import-issuer-keys.ts during the Phase-2 key ceremony.
  tmkKeyArn: 'arn:stub:pending-phase2-tmk',
  imkAcKeyArn: 'arn:stub:pending-phase2-imk-ac',
  imkSmiKeyArn: 'arn:stub:pending-phase2-imk-smi',
  imkSmcKeyArn: 'arn:stub:pending-phase2-imk-smc',
  imkIdnKeyArn: '',
  issuerPkKeyArn: 'arn:stub:pending-phase2-issuer-pk',

  // CA / Issuer PK cert stubs.  1024-bit test value is enough to round-trip
  // the SAD builder's TLV emission; the chip's PA does NOT verify the cert
  // during TRANSFER_SAD — that happens at transaction time with a real CA.
  caPkIndex: '05',
  issuerPkCertificate: ('AABBCCDD'.repeat(32)), // 128 bytes — a plausible size
  issuerPkRemainder: '11223344',
  issuerPkExponent: '03',

  // EMV application parameters — M/Chip Advance CVN-18 reference values.
  aid: 'A0000000041010', // Mastercard M/Chip
  appLabel: 'KARTA PLATINUM',
  appPreferredName: 'KARTA',
  appPriority: '01',
  appVersionNumber: '0002',
  aip: '1C00', // CDA-capable
  afl: '08010100100101001801020020010200',
  cvmList: '000000000000000042035E031F03',
  pdol: '9F66049F02069F03069F1A0295055F2A029A039C019F3704',
  cdol1: '9F02069F03069F1A0295055F2A029A039C019F37049F3501',
  cdol2: '8A02',
  iacDefault: 'F040FC8000',
  iacDenial: '0400000000',
  iacOnline: 'F040FC8000',
  appUsageControl: 'FF00',
  currencyCode: '0036', // AUD
  currencyExponent: '02',
  countryCode: '0036', // AU
  sdaTagList: '82',
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const prisma = new PrismaClient();

  try {
    const program = await prisma.program.findUnique({
      where: { id: KARTA_PLATINUM_PROGRAM_ID },
    });
    if (!program) {
      console.error(
        `Program ${KARTA_PLATINUM_PROGRAM_ID} not found.  Seed the program first ` +
        `(Karta Australia FI + platinum product).`,
      );
      process.exit(1);
    }

    // --- 1. Ensure a ChipProfile exists ------------------------------------
    let chipProfile = await prisma.chipProfile.findFirst({
      where: {
        scheme: 'mchip_advance',
        cvn: 18,
      },
      orderBy: { createdAt: 'asc' },
    });
    if (!chipProfile) {
      console.log('[seed] Creating ChipProfile (M/Chip Advance CVN 18)…');
      chipProfile = await prisma.chipProfile.create({
        data: {
          name: CHIP_PROFILE_NAME,
          scheme: 'mchip_advance',
          vendor: 'nxp',
          cvn: 18,
          dgiDefinitions: MCHIP_CVN18_DGI_DEFS,
          elfAid: 'A0000000041010',
          moduleAid: 'A0000000041010',
          paAid: 'A00000006250414C', // PA applet AID (tool perso traces)
          fidoAid: 'A0000006472F0001',
          iccPrivateKeyDgi: 32769,
          iccPrivateKeyTag: 40776,
          mkAcDgi: 2048,
          mkSmiDgi: 2049,
          mkSmcDgi: 2050,
        },
      });
      console.log(`[seed]   created ChipProfile id=${chipProfile.id}`);
    } else {
      console.log(
        `[seed] Reusing existing ChipProfile id=${chipProfile.id} ` +
        `(name="${chipProfile.name}")`,
      );
    }

    // --- 2. Upsert IssuerProfile for karta_platinum ------------------------
    const existing = await prisma.issuerProfile.findUnique({
      where: { programId: KARTA_PLATINUM_PROGRAM_ID },
    });

    if (!existing) {
      console.log('[seed] Creating IssuerProfile for karta_platinum…');
      const created = await prisma.issuerProfile.create({
        data: {
          programId: KARTA_PLATINUM_PROGRAM_ID,
          chipProfileId: chipProfile.id,
          ...ISSUER_PROFILE_DEFAULTS,
        },
      });
      console.log(`[seed]   created IssuerProfile id=${created.id}`);
    } else {
      console.log(
        `[seed] IssuerProfile exists (id=${existing.id}) — updating mutable fields…`,
      );
      const updated = await prisma.issuerProfile.update({
        where: { id: existing.id },
        data: {
          chipProfileId: chipProfile.id,
          ...ISSUER_PROFILE_DEFAULTS,
        },
      });
      console.log(`[seed]   updated IssuerProfile id=${updated.id}`);
    }

    console.log('[seed] Done.');
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('[seed] FAILED:', err);
  process.exit(1);
});
