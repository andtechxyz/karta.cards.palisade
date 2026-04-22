#!/usr/bin/env tsx
/**
 * Regenerate a ParamRecord for an e2e card so the PA v3 applet sees a
 * real ECDH-wrapped ParamBundle on TRANSFER_PARAMS, sibling of
 * regen-sad-e2e.ts.
 *
 * Unlike regen-sad-e2e which builds the SAD in-process with mock APC
 * keys, this script uses the REAL DataPrepService (which calls AWS
 * Payment Cryptography for per-card key derivation).  Runs best
 * inside the palisade-data-prep ECS image where the APC IAM role is
 * already available.
 *
 * Prerequisites:
 *   - DATABASE_URL set
 *   - AWS creds that can call the IssuerProfile's imk* ARNs
 *   - ChipProfile.provisioningMode must be PARAM_BUNDLE for the
 *     card's programId (use flip-card-to-pa-v3.ts first if it isn't)
 *
 * Usage:
 *   tsx scripts/regen-param-bundle-e2e.ts \
 *     --card-ref e2e_fi_2590 \
 *     --pan 4580483507983243 \
 *     --expiry 2912              # YYMM
 *     [--csn 01]
 *     [--service-code 201]
 */

import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';
import { DataPrepService } from '@palisade/data-prep/services/data-prep.service.js';

const { values } = parseArgs({
  options: {
    'card-ref':     { type: 'string' },
    pan:            { type: 'string' },
    expiry:         { type: 'string' },
    csn:            { type: 'string', default: '01' },
    'service-code': { type: 'string', default: '201' },
  },
});

const cardRef = values['card-ref'];
const pan = values.pan;
const expiry = values.expiry;
if (!cardRef || !pan || !expiry) {
  console.error('Usage: tsx scripts/regen-param-bundle-e2e.ts --card-ref <ref> --pan <digits> --expiry YYMM');
  process.exit(2);
}

const prisma = new PrismaClient();

async function main(): Promise<void> {
  const card = await prisma.card.findFirst({
    where: { cardRef },
    select: { id: true, cardRef: true, programId: true, paramRecordId: true, chipSerial: true },
  });
  if (!card) {
    console.error(`[regen-param] card.cardRef='${cardRef}' not found`);
    process.exit(1);
  }
  if (!card.programId) {
    console.error(`[regen-param] card '${cardRef}' has no programId — can't resolve IssuerProfile`);
    process.exit(1);
  }

  console.log(`[regen-param] card=${card.cardRef} (id=${card.id}) program=${card.programId}`);

  // If a ParamRecord already exists, mark it REVOKED so we don't orphan it,
  // then clear the Card.paramRecordId pointer so prepareParamBundle's
  // atomic create-link succeeds.
  if (card.paramRecordId) {
    console.log(`[regen-param] existing ParamRecord ${card.paramRecordId} — revoking first`);
    await prisma.$transaction([
      prisma.paramRecord.update({
        where: { id: card.paramRecordId },
        data: { status: 'REVOKED' },
      }),
      prisma.card.update({
        where: { id: card.id },
        data: { paramRecordId: null },
      }),
    ]);
  }

  const service = new DataPrepService();
  const result = await service.prepareParamBundle({
    cardId: card.id,
    pan,
    expiryYymm: expiry,
    serviceCode: values['service-code'],
    cardSequenceNumber: values.csn,
    chipSerial: card.chipSerial ?? undefined,
    programId: card.programId,
  });

  console.log(`[regen-param] wrote ParamRecord`);
  console.log(`[regen-param]   proxyCardId  = ${result.proxyCardId}`);
  console.log(`[regen-param]   sadRecordId  = ${result.sadRecordId}  (really paramRecordId)`);
  console.log(`[regen-param]   status       = ${result.status}`);

  const updated = await prisma.card.findUnique({
    where: { id: card.id },
    select: { paramRecordId: true, proxyCardId: true },
  });
  console.log(`[regen-param] card after:`);
  console.log(`[regen-param]   Card.paramRecordId = ${updated?.paramRecordId}`);
  console.log(`[regen-param]   Card.proxyCardId   = ${updated?.proxyCardId}`);
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
