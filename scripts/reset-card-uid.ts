#!/usr/bin/env tsx
/**
 * reset-card-uid — update a Card row's encrypted UID + fingerprint, reset
 * the SUN counter, and set status = ACTIVATED.
 *
 * Dev + test-fixture tool.  Run whenever a chip's physical UID changes
 * (re-perso to a new UID, or a chip swap behind the same cardRef) so the
 * backend can find the card on the next SUN tap.  Uses the activation
 * service's encrypt(uid) + fingerprintUid(uid) helpers — i.e. the SAME
 * envelope the register flow produces — so tap's find-card trial-decrypt
 * path sees the right shape.
 *
 * Usage:
 *   tsx scripts/reset-card-uid.ts \
 *     --card-ref e2e_fi_2590 \
 *     --uid c74d303b4739c8          # 7 bytes / 14 hex chars
 *
 * Env (must match the running tap + activation services):
 *   DATABASE_URL
 *   CARD_FIELD_DEK_V1
 *   CARD_FIELD_DEK_ACTIVE_VERSION
 *   CARD_UID_FINGERPRINT_KEY
 */

import { parseArgs } from 'node:util';
import { createHmac } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { encrypt, EnvKeyProvider } from '@palisade/core';

const HEX_14 = /^[0-9a-fA-F]{14}$/;

function fingerprintUid(uidHex: string, fpKeyHex: string): string {
  const key = Buffer.from(fpKeyHex, 'hex');
  return createHmac('sha256', key)
    .update('uid:')
    .update(uidHex.toLowerCase())
    .digest('hex');
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      'card-ref': { type: 'string' },
      uid: { type: 'string' },
    },
  });
  const cardRef = values['card-ref'];
  const uid = values.uid;
  if (!cardRef || !uid) {
    console.error('usage: tsx scripts/reset-card-uid.ts --card-ref <ref> --uid <14-hex>');
    process.exit(2);
  }
  if (!HEX_14.test(uid)) {
    console.error(`error: uid "${uid}" is not 14 hex chars (got ${uid.length})`);
    process.exit(2);
  }

  const dekV1 = process.env.CARD_FIELD_DEK_V1;
  const dekVersion = parseInt(process.env.CARD_FIELD_DEK_ACTIVE_VERSION ?? '1', 10);
  const fpKey = process.env.CARD_UID_FINGERPRINT_KEY;
  if (!dekV1) throw new Error('CARD_FIELD_DEK_V1 env is required');
  if (!fpKey) throw new Error('CARD_UID_FINGERPRINT_KEY env is required');

  const kp = new EnvKeyProvider({
    activeVersion: dekVersion,
    keys: { [dekVersion]: dekV1 },
  });

  const uidLower = uid.toLowerCase();
  const uidEnc = encrypt(uidLower, kp);
  const fp = fingerprintUid(uidLower, fpKey);

  const prisma = new PrismaClient();

  const before = await prisma.card.findUnique({
    where: { cardRef },
    select: {
      id: true,
      cardRef: true,
      status: true,
      lastReadCounter: true,
      keyVersion: true,
      uidFingerprint: true,
    },
  });
  if (!before) {
    console.error(`card not found: ${cardRef}`);
    process.exit(1);
  }
  console.log('BEFORE:', JSON.stringify(before, null, 2));

  const after = await prisma.card.update({
    where: { cardRef },
    data: {
      uidEncrypted: uidEnc.ciphertext,
      uidFingerprint: fp,
      keyVersion: uidEnc.keyVersion,
      lastReadCounter: 0,
      status: 'ACTIVATED',
    },
    select: {
      id: true,
      cardRef: true,
      status: true,
      lastReadCounter: true,
      keyVersion: true,
      uidFingerprint: true,
    },
  });
  console.log('AFTER:', JSON.stringify(after, null, 2));

  await prisma.$disconnect();
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : err);
  process.exit(1);
});
