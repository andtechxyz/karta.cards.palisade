/**
 * revoke_card — patent C11 (on-chip revocation enforcement).
 *
 * Sends the pav2-applet INS_REVOKE (CLA=0x80, INS=0xED) which:
 *   - Flips the T4T applet's cardState to STATE_BLOCKED (0x03).
 *   - Zeroes both AES-128 keys (piccEncKey, macKey) inside the
 *     applet's EEPROM.  Post-revoke, any PICC decrypt attempt
 *     by the backend would return garbage (key is zero); MAC verify
 *     would fail.  No further SUN URL can be produced.
 *
 * Irreversible on the chip.  Recovery requires full T4T applet
 * re-personalisation (delete + re-install with fresh keys).
 *
 * Also marks Card.status=REVOKED in the DB so the tap service rejects
 * the card at the find-card phase too — defence in depth if somehow
 * the chip's NDEF file is still readable (it shouldn't be; SELECT will
 * fail with SW 6A81).
 */

import type { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';
import { buildSelectByAid } from '../gp/apdu-builder.js';
import { sendAndRecv, type DriveIO } from './scp03-drive.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

const T4T_INSTANCE_AID = Buffer.from('D2760000850101', 'hex');

/** INS_REVOKE APDU: CLA=0x80 INS=0xED P1=P2=0 Lc=0.  Irreversible trigger. */
function buildRevokeApdu(): Buffer {
  return Buffer.from([0x80, 0xED, 0x00, 0x00, 0x00]);
}

export async function runRevokeCard(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  if (!session.card) {
    throw new Error('revoke_card: session has no linked card');
  }

  // 1. SELECT T4T.
  const selApdu = buildSelectByAid(T4T_INSTANCE_AID);
  const selResp = await sendAndRecv(io, selApdu, 'SELECT_T4T', 0.2);
  const selSw = (selResp[selResp.length - 2] << 8) | selResp[selResp.length - 1];
  if (selSw !== 0x9000) {
    // If the card is ALREADY BLOCKED, SELECT returns SW 6A81 (function
    // not supported).  Treat that as a successful revoke-is-idempotent
    // and skip the REVOKE APDU — the chip is already done.  Still set
    // DB REVOKED to converge state.
    if (selSw === 0x6A81) {
      await commitRevokeDbState(session);
      return { type: 'complete', phase: 'DONE', progress: 1.0 };
    }
    throw new Error(`SELECT T4T failed SW=${selSw.toString(16).toUpperCase()}`);
  }

  // 2. INS_REVOKE.  No response body — SW 9000 means done.
  const revResp = await sendAndRecv(io, buildRevokeApdu(), 'REVOKE', 0.6);
  const revSw = (revResp[revResp.length - 2] << 8) | revResp[revResp.length - 1];
  if (revSw === 0x6D00) {
    throw new Error(
      'REVOKE not supported by this T4T applet version.  Install pav2.cap ' +
        '(INS 0xED) before using this op.',
    );
  }
  if (revSw !== 0x9000) {
    throw new Error(`REVOKE failed SW=${revSw.toString(16).toUpperCase()}`);
  }

  await commitRevokeDbState(session);
  return { type: 'complete', phase: 'DONE', progress: 1.0 };
}

/**
 * Atomically commit DB state for a revoked card:
 *   - Card.status = REVOKED (tap service rejects at find-card).
 *   - Any READY SadRecords → REVOKED (can't be redeemed on the chip anyway).
 *   - Active ProvisioningSessions → FAILED so they don't hang.
 *   - CardOpSession → COMPLETE.
 */
async function commitRevokeDbState(session: CardOpSessionWithCard): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.card.update({
      where: { id: session.cardId },
      data: { status: 'REVOKED' },
    });
    await tx.sadRecord.updateMany({
      where: { cardId: session.cardId, status: 'READY' },
      data: { status: 'REVOKED' },
    });
    await tx.provisioningSession.updateMany({
      where: {
        cardId: session.cardId,
        phase: { notIn: ['COMPLETE', 'FAILED'] },
      },
      data: { phase: 'FAILED', failedAt: new Date(), failureReason: 'card-revoked' },
    });
    await tx.cardOpSession.update({
      where: { id: session.id },
      data: { phase: 'COMPLETE', completedAt: new Date() },
    });
  });
}
