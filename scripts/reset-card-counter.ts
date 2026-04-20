#!/usr/bin/env tsx
/**
 * reset-card-counter — reset a Card's SUN replay counter and lifecycle status
 * back to ACTIVATED for repeat-provisioning E2E testing.
 *
 * Unlike reset-card-uid, this does NOT touch the encrypted UID — we just move
 * `lastReadCounter → 0` and `status → ACTIVATED`. Use when the physical chip
 * is the same (no re-perso of SDM keys) but a previous provisioning attempt
 * already advanced the server-side counter past where the chip is now, or the
 * status is stuck at PROVISIONED so the activation provision-complete
 * callback would 400.
 *
 * Usage:
 *   DATABASE_URL=... tsx scripts/reset-card-counter.ts --card-ref e2e_fi_2590
 *   DATABASE_URL=... tsx scripts/reset-card-counter.ts --card-ref e2e_fi_2590 --dry-run
 *
 * Safe to run against prod: no crypto key material is touched, and the card
 * row remains linked to the same Vault entry + proxyCardId — only the reset
 * cycle is replayable.
 */

import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      'card-ref': { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
    },
  });
  const cardRef = values['card-ref'];
  const dryRun = values['dry-run'] ?? false;
  if (!cardRef) {
    console.error('usage: tsx scripts/reset-card-counter.ts --card-ref <ref> [--dry-run]');
    process.exit(2);
  }

  const prisma = new PrismaClient();

  const before = await prisma.card.findUnique({
    where: { cardRef },
    select: {
      id: true,
      cardRef: true,
      status: true,
      lastReadCounter: true,
      provisionedAt: true,
      chipSerial: true,
      proxyCardId: true,
    },
  });
  if (!before) {
    console.error(`card not found: ${cardRef}`);
    process.exit(1);
  }
  console.log('BEFORE:', JSON.stringify(before, null, 2));

  if (dryRun) {
    console.log('(dry-run: no write performed)');
    await prisma.$disconnect();
    return;
  }

  const after = await prisma.card.update({
    where: { cardRef },
    data: {
      lastReadCounter: 0,
      status: 'ACTIVATED',
      // Clear provisionedAt so the timeline reflects the new attempt.
      provisionedAt: null,
    },
    select: {
      id: true,
      cardRef: true,
      status: true,
      lastReadCounter: true,
      provisionedAt: true,
      chipSerial: true,
      proxyCardId: true,
    },
  });
  console.log('AFTER: ', JSON.stringify(after, null, 2));

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : err);
  process.exit(1);
});
