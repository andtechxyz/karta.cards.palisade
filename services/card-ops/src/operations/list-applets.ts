/**
 * list_applets — enumerate applets/packages installed on the card.
 *
 * Flow:
 *   1. Establish SCP03 session (C-MAC only is sufficient for read ops).
 *   2. Send GET STATUS (P1=0x40, P2=0x02) — list applications, TLV form.
 *   3. Parse response; on SW=6310 send again with P2=0x03 (next).
 *   4. Also collect exec load files (packages) via GET STATUS P1=0x20.
 *   5. Emit `{type:'complete', applets:[...], packages:[...]}`.
 */

import { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';
import {
  buildGetStatus,
  parseGetStatusResponse,
  type AppEntry,
} from '../gp/apdu-builder.js';
import { establishScp03, type DriveIO } from './scp03-drive.js';
import { getGpStaticKeys } from '../gp/static-keys.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

export async function runListApplets(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  const keys = await getGpStaticKeys(session.cardId);
  const { send, scrub } = await establishScp03(io, keys, { phasePrefix: 'SCP03' });

  try {
    const applets: AppEntry[] = [];
    const packages: AppEntry[] = [];

    // Applications (installed applets + SSDs)
    applets.push(...await drainGetStatus(send, 0x40));
    // Exec load files (packages)
    packages.push(...await drainGetStatus(send, 0x20));

    await prisma.cardOpSession.update({
      where: { id: session.id },
      data: {
        phase: 'COMPLETE',
        completedAt: new Date(),
        scpState: Prisma.DbNull,
      },
    });

    return {
      type: 'complete',
      applets,
      packages,
      progress: 1.0,
    };
  } finally {
    // PCI 3.5 / audit S-3: zero SCP03 S-ENC/S-MAC/S-RMAC + MAC chain.
    scrub();
  }
}

async function drainGetStatus(
  send: (input: { cla: number; ins: number; p1: number; p2: number; data: Buffer; le?: number }) => Promise<{ data: Buffer; sw: number }>,
  p1: number,
): Promise<AppEntry[]> {
  const out: AppEntry[] = [];
  let next = false;
  // Loop bound: GET STATUS pagination should terminate in a few rounds;
  // 32 is a generous upper bound that still catches a stuck-cycle bug.
  for (let round = 0; round < 32; round++) {
    const apdu = buildGetStatus(p1, next);
    // Wrap at the APDU layer — but buildGetStatus already returns the
    // full plaintext APDU.  We feed the body portion into wrapper via
    // the driver's send helper which recomputes header/Lc.
    const body = apdu.subarray(5, 5 + apdu[4]);
    const result = await send({
      cla: apdu[0],
      ins: apdu[1],
      p1: apdu[2],
      p2: apdu[3],
      data: body,
    });
    if (result.sw === 0x9000) {
      if (result.data.length > 0) out.push(...parseGetStatusResponse(result.data));
      return out;
    }
    if (result.sw === 0x6310) {
      if (result.data.length > 0) out.push(...parseGetStatusResponse(result.data));
      next = true;
      continue;
    }
    if (result.sw === 0x6A88) {
      // No more data — OK, just return what we have.
      return out;
    }
    throw new Error(`GET STATUS failed SW=${result.sw.toString(16).toUpperCase()}`);
  }
  throw new Error('GET STATUS pagination did not terminate');
}
