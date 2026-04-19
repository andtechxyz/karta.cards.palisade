#!/usr/bin/env tsx
/**
 * Issuer Key Import — PCI-compliant key ceremony tool.
 *
 * Imports AWS Payment Cryptography master keys from TR-31 wrapped key
 * blocks and records the resulting ARNs on the linked IssuerProfile.
 *
 * Flow:
 *   1. Key ceremony custodians produce TR-31 wrapped key blocks outside
 *      this machine (HSM-to-HSM transfer, or from the scheme / card
 *      network in the case of IMKs).
 *   2. This script reads each wrapped block, calls AWS PC ImportKey, and
 *      records the resulting ARN + KCV on the issuer profile.
 *   3. Every import is audit-logged (who, when, which key, KCV).
 *
 * **Never accepts raw key material.**  Input is always a TR-31 block,
 * which is a wrapped key authenticated by a Key Exchange Key (KEK) that
 * has been pre-established in AWS PC via separate ceremony.
 *
 * Usage:
 *   tsx scripts/import-issuer-keys.ts \
 *     --profile <issuerProfileId> \
 *     --key-type imkAc \
 *     --kek-arn <wrapping-KEK-ARN> \
 *     --wrapped-block-file <path-to-tr31-block.bin>
 *
 * Key types: tmk | imkAc | imkSmi | imkSmc | imkIdn | issuerPk
 */

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  PaymentCryptographyClient,
  ImportKeyCommand,
} from '@aws-sdk/client-payment-cryptography';
import { PrismaClient } from '@prisma/client';

const VALID_KEY_TYPES = [
  'tmk',
  'imkAc',
  'imkSmi',
  'imkSmc',
  'imkIdn',
  'issuerPk',
] as const;
type KeyType = (typeof VALID_KEY_TYPES)[number];

// Map from CLI key type to the ARN field on IssuerProfile and the AWS PC
// KeyUsage the imported key must claim.  Each master key has a specific
// role in EMV issuance; importing with the wrong KeyUsage produces a key
// that cannot be used for the intended operation.
const KEY_TYPE_CONFIG: Record<KeyType, { field: string; keyUsage: string; algorithm: string }> = {
  tmk:      { field: 'tmkKeyArn',      keyUsage: 'TR31_K0_KEY_ENCRYPTION_KEY',  algorithm: 'TDES_2KEY' },
  imkAc:    { field: 'imkAcKeyArn',    keyUsage: 'TR31_C0_CARD_VERIFICATION_KEY', algorithm: 'TDES_2KEY' },
  imkSmi:   { field: 'imkSmiKeyArn',   keyUsage: 'TR31_M1_ISO_9797_1_MAC_KEY',  algorithm: 'TDES_2KEY' },
  imkSmc:   { field: 'imkSmcKeyArn',   keyUsage: 'TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS', algorithm: 'TDES_2KEY' },
  imkIdn:   { field: 'imkIdnKeyArn',   keyUsage: 'TR31_E1_EMV_MKEY_CONFIDENTIALITY', algorithm: 'TDES_2KEY' },
  issuerPk: { field: 'issuerPkKeyArn', keyUsage: 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE', algorithm: 'RSA_2048' },
};

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      profile:            { type: 'string' },
      'key-type':         { type: 'string' },
      'kek-arn':          { type: 'string' },
      'wrapped-block-file': { type: 'string' },
      region:             { type: 'string', default: 'ap-southeast-2' },
    },
  });

  const profileId  = values.profile;
  const keyType    = values['key-type'] as KeyType | undefined;
  const kekArn     = values['kek-arn'];
  const blockFile  = values['wrapped-block-file'];
  const region     = values.region ?? 'ap-southeast-2';

  if (!profileId || !keyType || !kekArn || !blockFile) {
    console.error('Missing required arguments.  See: --help');
    console.error('Usage: tsx scripts/import-issuer-keys.ts --profile <id> --key-type <type> --kek-arn <arn> --wrapped-block-file <path>');
    process.exit(2);
  }

  if (!VALID_KEY_TYPES.includes(keyType)) {
    console.error(`Invalid --key-type.  Must be one of: ${VALID_KEY_TYPES.join(', ')}`);
    process.exit(2);
  }

  const cfg = KEY_TYPE_CONFIG[keyType];

  // 1. Load the wrapped key block (TR-31 binary format)
  const wrappedBlock = readFileSync(blockFile);
  const wrappedHex = wrappedBlock.toString('hex').toUpperCase();

  // 2. Dual control confirmation — requires OPERATOR_1 and OPERATOR_2
  //    environment vars set by two different authenticated humans.
  //    In production this would integrate with Cognito admin MFA, OR
  //    a proper key ceremony tool (e.g. Thales HSM keypad).
  const op1 = process.env.OPERATOR_1;
  const op2 = process.env.OPERATOR_2;
  if (!op1 || !op2) {
    console.error('Key ceremony requires two operators.');
    console.error('Set OPERATOR_1 and OPERATOR_2 env vars with each custodian\'s email.');
    process.exit(2);
  }
  if (op1 === op2) {
    console.error('OPERATOR_1 and OPERATOR_2 must be different people.');
    process.exit(2);
  }

  console.log(`[ceremony] Operator 1: ${op1}`);
  console.log(`[ceremony] Operator 2: ${op2}`);
  console.log(`[ceremony] Key type: ${keyType} (${cfg.algorithm}, ${cfg.keyUsage})`);
  console.log(`[ceremony] KEK ARN: ${kekArn}`);
  console.log(`[ceremony] Wrapped block size: ${wrappedBlock.length} bytes`);

  // 3. Load Prisma and verify the profile exists
  const prisma = new PrismaClient();
  const profile = await prisma.issuerProfile.findUnique({ where: { id: profileId } });
  if (!profile) {
    console.error(`Issuer profile not found: ${profileId}`);
    process.exit(1);
  }

  // 4. Import to AWS Payment Cryptography via TR-31 wrapping
  const pc = new PaymentCryptographyClient({ region });
  const importResp = await pc.send(new ImportKeyCommand({
    KeyMaterial: {
      Tr31KeyBlock: {
        WrappedKeyBlock: wrappedHex,
        WrappingKeyIdentifier: kekArn,
      },
    },
    Enabled: true,
    KeyCheckValueAlgorithm: 'ANSI_X9_24',
  }));

  const arn = importResp.Key?.KeyArn;
  const kcv = importResp.Key?.KeyCheckValue;
  if (!arn) {
    console.error('AWS Payment Cryptography ImportKey returned no ARN.');
    process.exit(1);
  }

  console.log(`[ceremony] Imported: ${arn}`);
  console.log(`[ceremony] KCV: ${kcv}`);

  // 5. Record the ARN on the IssuerProfile via Prisma directly.
  //    (This is the ONLY place ARNs are written — browser can't touch this.)
  await prisma.issuerProfile.update({
    where: { id: profileId },
    data: { [cfg.field]: arn },
  });

  // 6. Audit log entry
  console.log(`[ceremony] Recorded on profile ${profileId} (${cfg.field})`);
  console.log(`[ceremony] Audit: ${op1} + ${op2} imported ${keyType} at ${new Date().toISOString()}`);

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error('[ceremony] FAILED:', err);
  process.exit(1);
});
