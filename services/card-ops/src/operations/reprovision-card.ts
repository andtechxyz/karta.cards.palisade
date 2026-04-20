/**
 * reprovision_card — patent C10/C24 post-issuance re-provisioning.
 *
 * Takes a card that has already been PROVISIONED and resets it to a
 * state where a fresh provisioning session can re-establish a new SAD
 * (new EMV keys, new ICC private key pair, same cardRef).  Used for:
 *   - Rolling DAM (Dynamic Authentication Material) on a suspected
 *     compromise — see patent claim C10's "rotate the DAM without
 *     physical re-issuance".
 *   - Recovering from a partial provisioning failure without re-perso.
 *   - Expiration / renewal flows where the card stays with the
 *     cardholder but the backing EMV credentials refresh.
 *
 * Flow:
 *   1. SELECT the PA applet.
 *   2. Send INS_WIPE (CLA=80 INS=EA) — the PA zeroizes its EEPROM state
 *      (ICC priv key, stored SAD, session keys, etc.) and returns to
 *      STATE_IDLE.  Provenance log is preserved per applet design.
 *   3. Mark the current SadRecord CONSUMED (no longer usable even if
 *      it was READY).
 *   4. Flip Card.status PROVISIONED → ACTIVATED so the next tap routes
 *      to a fresh /provision session.  data-prep will generate a new
 *      SAD lazily when the mobile app next hits /api/provisioning/start.
 *
 * What this doesn't do:
 *   - Rotate the per-card SDM keys (those stay — the chip's NDEF applet
 *     is untouched; SUN-tap verify continues to work across the
 *     re-provisioning).  Rotating SDM keys is an NDEF/T4T-applet
 *     re-personalisation, which is a separate card-op.
 *   - Revoke the card for good.  See revoke-card.ts (karta-se v1) for
 *     that path.
 *
 * Prerequisites:
 *   - Card.status must be PROVISIONED or ACTIVATED.  SHIPPED/BLANK
 *     cards never had a SAD to wipe; REVOKED cards must not be
 *     re-provisioned without explicit unrevoke.
 */

import type { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';
import { buildSelectByAid } from '../gp/apdu-builder.js';
import { sendAndRecv, type DriveIO } from './scp03-drive.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

const PA_INSTANCE_AID = Buffer.from('A00000006250414C', 'hex');

// Proprietary PA APDU: CLA=0x80 INS_WIPE=0xEA P1=0x00 P2=0x00 Lc=0
// Success SW=9000 means state → IDLE + EEPROM zeroized.  Any other SW is
// a hard failure — we refuse to commit the DB state change so operator
// can diagnose the card.
function buildWipeApdu(): Buffer {
  return Buffer.from([0x80, 0xEA, 0x00, 0x00, 0x00]);
}

export async function runReprovisionCard(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  const card = session.card;
  if (!card) {
    throw new Error('reprovision_card: session has no linked card');
  }
  if (card.status !== 'PROVISIONED' && card.status !== 'ACTIVATED') {
    throw new Error(
      `reprovision_card: refusing to reprovision card in status=${card.status} (allowed: PROVISIONED, ACTIVATED)`,
    );
  }

  // Phase 1: SELECT PA.
  const selApdu = buildSelectByAid(PA_INSTANCE_AID);
  const selResp = await sendAndRecv(io, selApdu, 'SELECT_PA', 0.2);
  const selSw = (selResp[selResp.length - 2] << 8) | selResp[selResp.length - 1];
  if (selSw !== 0x9000) {
    throw new Error(`SELECT PA failed SW=${selSw.toString(16).toUpperCase()}`);
  }

  // Phase 2: INS_WIPE.
  const wipeApdu = buildWipeApdu();
  const wipeResp = await sendAndRecv(io, wipeApdu, 'WIPE_PA', 0.5);
  const wipeSw = (wipeResp[wipeResp.length - 2] << 8) | wipeResp[wipeResp.length - 1];
  if (wipeSw !== 0x9000) {
    throw new Error(`WIPE PA failed SW=${wipeSw.toString(16).toUpperCase()}`);
  }

  // Phase 3+4: commit DB state atomically so a crash can't leave a
  // wiped chip with a still-READY SAD record in DB.
  await prisma.$transaction(async (tx) => {
    // Any READY SAD for this card becomes CONSUMED — the chip no longer
    // holds the plaintext, so the SAD can't be completed anyway.
    await tx.sadRecord.updateMany({
      where: { cardId: card.id, status: 'READY' },
      data: { status: 'CONSUMED' },
    });

    // PROVISIONED → ACTIVATED so the next tap gets a fresh provision flow.
    // Leave ACTIVATED cards untouched (already in the right state).
    if (card.status === 'PROVISIONED') {
      await tx.card.update({
        where: { id: card.id },
        data: {
          status: 'ACTIVATED',
          provisionedAt: null,
        },
      });
    }

    await tx.cardOpSession.update({
      where: { id: session.id },
      data: {
        phase: 'COMPLETE',
        completedAt: new Date(),
      },
    });
  });

  return { type: 'complete', phase: 'DONE', progress: 1.0 };
}
