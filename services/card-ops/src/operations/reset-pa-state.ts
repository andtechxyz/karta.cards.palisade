/**
 * reset_pa_state — trigger the PA applet's IDLE-on-SELECT reset.
 *
 * Per the PA applet design (noted in session context), SELECTing the
 * PA by instance AID resets its internal state to IDLE.  We exploit
 * that: this operation sends a single SELECT APDU and trusts the 9000
 * response as confirmation.  No SCP03 needed — SELECT is available to
 * anyone who knows the AID, and this is an idempotent, non-destructive
 * nudge.
 *
 * If a future PA build tightens the reset semantics (e.g. requires
 * SCP03-authenticated access), upgrade this to the `install_pa` style.
 */

import type { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';
import { buildSelectByAid } from '../gp/apdu-builder.js';
import { sendAndRecv, type DriveIO } from './scp03-drive.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

const PA_INSTANCE_AID = Buffer.from('A00000006250414C', 'hex');

export async function runResetPaState(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  const apdu = buildSelectByAid(PA_INSTANCE_AID);
  const resp = await sendAndRecv(io, apdu, 'SELECT_PA', 0.5);
  const sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
  if (sw !== 0x9000) {
    throw new Error(`SELECT PA failed SW=${sw.toString(16).toUpperCase()}`);
  }

  await prisma.cardOpSession.update({
    where: { id: session.id },
    data: {
      phase: 'COMPLETE',
      completedAt: new Date(),
    },
  });

  return { type: 'complete', phase: 'DONE', progress: 1.0 };
}
