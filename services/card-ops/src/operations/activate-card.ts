/**
 * activate_card — patent C5 (explicit pending → committed transitions).
 *
 * Sends the pav2-applet INS_ACTIVATE (CLA=0x80, INS=0xEB, P1=0x00, P2=0x00)
 * to flip the T4T applet's state from SHIPPED to ACTIVATED.  Replaces the
 * odd/even WebAuthn-ceremony dance from v1 — now state moves are driven
 * by authenticated backend APDUs via card-ops (Cognito-gated).
 *
 * Idempotent: the applet no-ops if already ACTIVATED.  Hard-fails with
 * SW 6985 if the card is BLOCKED (revoked).
 *
 * Only runs against pav2+ T4T applets.  v1 cards don't implement this
 * INS — the chip returns SW 6D00 (INS not supported) and the operation
 * fails.  Caller should check `ChipProfile.t4tVersion` or similar
 * before dispatching.
 */

import type { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';
import { buildSelectByAid } from '../gp/apdu-builder.js';
import { sendAndRecv, type DriveIO } from './scp03-drive.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

/** T4T applet instance AID — NFC Forum NDEF Tag Application. */
const T4T_INSTANCE_AID = Buffer.from('D2760000850101', 'hex');

/** INS_ACTIVATE APDU: CLA=0x80 INS=0xEB P1=P2=0 Lc=0.  Pure trigger — no body. */
function buildActivateApdu(): Buffer {
  return Buffer.from([0x80, 0xEB, 0x00, 0x00, 0x00]);
}

export async function runActivateCard(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  // 1. SELECT the T4T applet.
  const selApdu = buildSelectByAid(T4T_INSTANCE_AID);
  const selResp = await sendAndRecv(io, selApdu, 'SELECT_T4T', 0.2);
  const selSw = (selResp[selResp.length - 2] << 8) | selResp[selResp.length - 1];
  if (selSw !== 0x9000) {
    throw new Error(`SELECT T4T failed SW=${selSw.toString(16).toUpperCase()}`);
  }

  // 2. INS_ACTIVATE.
  const actResp = await sendAndRecv(io, buildActivateApdu(), 'ACTIVATE', 0.6);
  const actSw = (actResp[actResp.length - 2] << 8) | actResp[actResp.length - 1];
  if (actSw === 0x6985) {
    // Applet returns SW_CONDITIONS_NOT_SATISFIED for BLOCKED cards.
    throw new Error(
      'ACTIVATE refused: card is BLOCKED.  Hard revoke requires full ' +
        're-personalisation to recover.',
    );
  }
  if (actSw === 0x6D00) {
    // INS not supported — v1 applet without pav2 upgrade.
    throw new Error(
      'ACTIVATE not supported by this T4T applet version.  Install pav2.cap ' +
        '(INS 0xEB) before retrying.',
    );
  }
  if (actSw !== 0x9000) {
    throw new Error(`ACTIVATE failed SW=${actSw.toString(16).toUpperCase()}`);
  }

  // 3. Commit the card-op session.  No Card.status mutation — the chip
  //    moving to ACTIVATED doesn't change the DB's lifecycle model;
  //    Card.status transitions on Card register / SUN verify / provision
  //    complete as usual.  This operation is purely a chip-side state
  //    prep for reliable tap-serves-SUN behavior.
  await prisma.cardOpSession.update({
    where: { id: session.id },
    data: { phase: 'COMPLETE', completedAt: new Date() },
  });

  return { type: 'complete', phase: 'DONE', progress: 1.0 };
}
