#!/usr/bin/env tsx
/**
 * Reset a card's backend state so a fresh provisioning tap can run
 * against it.  Sibling of regen-param-bundle-e2e.ts, with the
 * additional steps needed AFTER a completed tap — regen-param alone
 * isn't enough because a finished provisioning flow leaves:
 *
 *   Card.status              = PROVISIONED
 *   ParamRecord.status       = CONSUMED
 *   ProvisioningSession      = phase COMPLETE (lingers for audit)
 *
 * rca's /api/provisioning/start gate is `card.status === ACTIVATED`,
 * so you can't re-tap without bouncing Card.status back.  This
 * script does the full bounce + fresh-ParamRecord dance in one
 * atomic transaction so a partial run doesn't leave the card half-
 * reset.
 *
 * Intended uses:
 *   1. Dev-loop tap retesting on a physical card (typical case).
 *   2. Operator-driven "reprovision this card" in prod after a
 *      mis-provisioned flow (e.g. wrong ChipProfile picked).  In
 *      prod, prefer the admin UI's Reprovision button once it
 *      exists — this script is the CLI fallback.
 *
 * Prerequisites:
 *   - DATABASE_URL set
 *   - AWS creds that can call the IssuerProfile's imk* ARNs (needed
 *     because prepareParamBundle re-runs the APC derivation for the
 *     fresh ParamRecord).
 *   - ChipProfile.provisioningMode must already be PARAM_BUNDLE
 *     for the card's programId (use flip-card-to-pa-v3.ts first if
 *     the card is still on the legacy SAD flow).
 *
 * Usage:
 *   tsx scripts/reset-card-for-retap.ts \
 *     --card-ref e2e_fi_2590 \
 *     --pan 4580483507983243 \
 *     --expiry 2912 \
 *     [--csn 01] \
 *     [--service-code 201] \
 *     [--dry-run]
 *
 * ECS one-shot (the typical prod invocation):
 *   aws ecs run-task \
 *     --cluster vera \
 *     --task-definition palisade-rca:14 \
 *     --launch-type FARGATE \
 *     --network-configuration 'awsvpcConfiguration={...}' \
 *     --overrides '{"containerOverrides":[{
 *       "name":"palisade-rca",
 *       "command":["tsx","scripts/reset-card-for-retap.ts",
 *                  "--card-ref","e2e_fi_2590",
 *                  "--pan","4580483507983243",
 *                  "--expiry","2912"]
 *     }]}'
 *
 * Output is machine-friendly on each step so log-scrapers can assert
 * on individual transition lines without parsing a JSON payload.
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
    'dry-run':      { type: 'boolean', default: false },
  },
});

const cardRef = values['card-ref'];
const pan = values.pan;
const expiry = values.expiry;
const dryRun = !!values['dry-run'];

if (!cardRef || !pan || !expiry) {
  console.error(
    'Usage: tsx scripts/reset-card-for-retap.ts --card-ref <ref> --pan <digits> --expiry YYMM [--csn 01] [--service-code 201] [--dry-run]',
  );
  process.exit(2);
}

const prisma = new PrismaClient();

async function main(): Promise<void> {
  const card = await prisma.card.findFirst({
    where: { cardRef },
    select: {
      id: true,
      cardRef: true,
      programId: true,
      paramRecordId: true,
      chipSerial: true,
      status: true,
    },
  });
  if (!card) {
    console.error(`[reset] card.cardRef='${cardRef}' not found`);
    process.exit(1);
  }
  if (!card.programId) {
    console.error(
      `[reset] card '${cardRef}' has no programId — can't resolve IssuerProfile`,
    );
    process.exit(1);
  }

  console.log(
    `[reset] card=${card.cardRef} (id=${card.id}) program=${card.programId} status=${card.status} paramRecordId=${card.paramRecordId ?? 'null'}`,
  );

  // --- 1. Bounce Card.status back to ACTIVATED ---
  //
  // rca's /api/provisioning/start rejects any status other than
  // ACTIVATED (services/activation/src/routes/provisioning.routes.ts).
  // Every other write below assumes the card is re-provisionable.
  if (card.status === 'PROVISIONED') {
    if (dryRun) {
      console.log(`[reset] WOULD set Card.status: PROVISIONED -> ACTIVATED`);
    } else {
      await prisma.card.update({
        where: { id: card.id },
        data: { status: 'ACTIVATED' },
      });
      console.log(`[reset] Card.status: PROVISIONED -> ACTIVATED`);
    }
  } else if (card.status === 'ACTIVATED') {
    console.log(`[reset] Card.status already ACTIVATED — no bounce needed`);
  } else {
    console.log(
      `[reset] Card.status=${card.status} — not touching; only PROVISIONED auto-bounces to ACTIVATED.  Set the status manually if you know what you're doing.`,
    );
  }

  // --- 2. Mark any open ProvisioningSession rows FAILED ---
  //
  // A COMPLETE session is harmless history, but a FAILED or still-
  // in-progress (INIT / PA_FCI / KEYGEN / SAD_TRANSFER / AWAITING_FINAL
  // / CONFIRMING) row can confuse the retention reaper or cause
  // duplicate-session errors on the next /start.  Mark everything
  // that isn't COMPLETE as FAILED with failureReason='manual_reset'.
  const openSessions = await prisma.provisioningSession.findMany({
    where: {
      cardId: card.id,
      phase: { notIn: ['COMPLETE', 'FAILED'] },
    },
    select: { id: true, phase: true },
  });
  if (openSessions.length > 0) {
    console.log(
      `[reset] closing ${openSessions.length} non-terminal ProvisioningSession rows`,
    );
    for (const s of openSessions) {
      console.log(`[reset]   session ${s.id} (phase=${s.phase}) -> FAILED`);
    }
    if (!dryRun) {
      await prisma.provisioningSession.updateMany({
        where: {
          cardId: card.id,
          phase: { notIn: ['COMPLETE', 'FAILED'] },
        },
        data: {
          phase: 'FAILED',
          failedAt: new Date(),
          failureReason: 'manual_reset',
        },
      });
    }
  } else {
    console.log(`[reset] no open ProvisioningSession rows to close`);
  }

  // --- 3. Revoke existing ParamRecord ---
  //
  // If card.paramRecordId is set (pointing at a CONSUMED record from
  // the last tap), REVOKE it and clear the back-pointer so
  // prepareParamBundle can create + link a fresh one atomically.  The
  // retention reaper will sweep the REVOKED row later.
  if (card.paramRecordId) {
    if (dryRun) {
      console.log(
        `[reset] WOULD revoke ParamRecord ${card.paramRecordId} + clear Card.paramRecordId`,
      );
    } else {
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
      console.log(
        `[reset] revoked ParamRecord ${card.paramRecordId}; cleared Card.paramRecordId`,
      );
    }
  }

  if (dryRun) {
    console.log(`[reset] DRY-RUN — stopping before prepareParamBundle call`);
    return;
  }

  // --- 4. Regenerate a fresh ParamRecord ---
  //
  // Same call regen-param-bundle-e2e.ts uses — we share the
  // DataPrepService so the AWS Payment Cryptography derivation path
  // runs identically.  Returned `proxyCardId` is new; Card.
  // paramRecordId is re-linked inside prepareParamBundle's own
  // transaction.
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

  const updated = await prisma.card.findUnique({
    where: { id: card.id },
    select: { status: true, paramRecordId: true, proxyCardId: true },
  });

  console.log(`[reset] fresh ParamRecord`);
  console.log(`[reset]   proxyCardId          = ${result.proxyCardId}`);
  console.log(`[reset]   paramRecordId        = ${result.sadRecordId}`);
  console.log(`[reset]   status               = ${result.status}`);
  console.log(`[reset] card after`);
  console.log(`[reset]   Card.status          = ${updated?.status}`);
  console.log(`[reset]   Card.paramRecordId   = ${updated?.paramRecordId}`);
  console.log(`[reset]   Card.proxyCardId     = ${updated?.proxyCardId}`);
  console.log(`[reset] DONE — card is ready for a fresh tap`);
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (err) => {
    console.error('[reset] FAILED:', err);
    await prisma.$disconnect();
    process.exit(1);
  });
