/**
 * install_pa — deploy the Palisade Provisioning Agent applet.
 *
 * Flow:
 *   1. Establish SCP03 with full C-MAC + C-DECRYPTION (INSTALL [load]
 *      carries data that we want protected end-to-end even if the
 *      transport is already confidential).
 *   2. DELETE the existing PA instance AID (ignore SW=6A88).
 *   3. DELETE the existing PA package AID (ignore SW=6A88).
 *   4. Parse pa.cap to extract package AID, applet AIDs, Load File Data Block.
 *   5. INSTALL [load] to declare the load.
 *   6. LOAD blocks in 240-byte chunks.
 *   7. INSTALL [install+selectable] to activate the applet.
 *   8. Emit `{type:'complete'}`.
 *
 * Progress mileposts: 0.10 post-SCP03, 0.20 post-DELETE, 0.50 post-load,
 * 0.90 post-install, 1.00 at complete.
 */

import { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';
import {
  buildDelete,
  buildInstallForLoad,
  buildInstallForInstall,
  chunkLoadBlock,
} from '../gp/apdu-builder.js';
import { establishScp03, type DriveIO } from './scp03-drive.js';
import { getGpStaticKeys } from '../gp/static-keys.js';
import { loadCap, CapFileMissingError } from '../gp/cap-loader.js';
import { SECURITY_LEVEL } from '../gp/scp03.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

const PA_PACKAGE_AID = Buffer.from('A0000000625041', 'hex');
const PA_INSTANCE_AID = Buffer.from('A00000006250414C', 'hex');

export async function runInstallPa(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  // Guard: CAP file must be present.
  let cap;
  try {
    cap = loadCap('pa');
  } catch (err) {
    if (err instanceof CapFileMissingError) {
      return {
        type: 'error',
        code: 'CAP_FILE_MISSING',
        message: err.message,
      };
    }
    throw err;
  }

  const keys = await getGpStaticKeys(session.cardId);
  // INSTALL [load] and LOAD blocks benefit from C-DECRYPTION because the
  // load file bytes shouldn't leak to the WS relay layer.  Keep R-MAC
  // off (SL_CMAC | C_DECRYPTION = 0x03) — R-MAC adds verify cost without
  // a clear win for this admin path.
  const { send } = await establishScp03(io, keys, {
    securityLevel: SECURITY_LEVEL.C_MAC | SECURITY_LEVEL.C_DECRYPTION,
    phasePrefix: 'SCP03',
  });

  io.send({ type: 'apdu', hex: '', phase: 'DELETE_OLD', progress: 0.1 });

  // Best-effort DELETE of old instance + package.  6A88 (referenced
  // data not found) is the card's way of saying "it wasn't there" —
  // acceptable for us, since install_pa is idempotent.
  const delInstance = buildDelete(PA_INSTANCE_AID);
  const r1 = await send({
    cla: delInstance[0], ins: delInstance[1], p1: delInstance[2], p2: delInstance[3],
    data: delInstance.subarray(5, 5 + delInstance[4]),
  });
  if (r1.sw !== 0x9000 && r1.sw !== 0x6A88) {
    throw new Error(`DELETE instance failed SW=${r1.sw.toString(16).toUpperCase()}`);
  }

  const delPkg = buildDelete(PA_PACKAGE_AID);
  const r2 = await send({
    cla: delPkg[0], ins: delPkg[1], p1: delPkg[2], p2: delPkg[3],
    data: delPkg.subarray(5, 5 + delPkg[4]),
  });
  if (r2.sw !== 0x9000 && r2.sw !== 0x6A88) {
    throw new Error(`DELETE package failed SW=${r2.sw.toString(16).toUpperCase()}`);
  }

  io.send({ type: 'apdu', hex: '', phase: 'INSTALL_LOAD', progress: 0.2 });

  // INSTALL [load]
  const loadFileAidBuf = Buffer.from(cap.packageAid, 'hex');
  const installLoad = buildInstallForLoad(loadFileAidBuf);
  const r3 = await send({
    cla: installLoad[0], ins: installLoad[1], p1: installLoad[2], p2: installLoad[3],
    data: installLoad.subarray(5, 5 + installLoad[4]),
  });
  if (r3.sw !== 0x9000) {
    throw new Error(`INSTALL [load] failed SW=${r3.sw.toString(16).toUpperCase()}`);
  }

  io.send({ type: 'apdu', hex: '', phase: 'LOADING', progress: 0.3 });

  // LOAD blocks.  The chunker outputs the plaintext LOAD APDUs; we
  // forward the data portion through the SCP03 wrapper which adds the
  // C-MAC and applies C-DECRYPTION to the payload bytes.
  const blocks = chunkLoadBlock(cap.loadFileDataBlock, 240);
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const result = await send({
      cla: block[0], ins: block[1], p1: block[2], p2: block[3],
      data: block.subarray(5, 5 + block[4]),
    });
    if (result.sw !== 0x9000) {
      throw new Error(`LOAD block ${i} failed SW=${result.sw.toString(16).toUpperCase()}`);
    }
    io.send({
      type: 'apdu', hex: '', phase: 'LOADING',
      progress: 0.3 + (0.2 * (i + 1) / blocks.length),
    });
  }

  io.send({ type: 'apdu', hex: '', phase: 'INSTALL_INSTALL', progress: 0.6 });

  // INSTALL [install+selectable].  Use the PA instance AID A00000006250414C
  // which is what the RCA provisioning SELECTs — matches the module AID
  // the JC converter assigns (package || 0x4C).
  const moduleAid = PA_INSTANCE_AID; // convention, per rca relay-handler comment
  const installInstall = buildInstallForInstall(
    loadFileAidBuf,
    moduleAid,
    PA_INSTANCE_AID,
  );
  const r4 = await send({
    cla: installInstall[0], ins: installInstall[1], p1: installInstall[2], p2: installInstall[3],
    data: installInstall.subarray(5, 5 + installInstall[4]),
  });
  if (r4.sw !== 0x9000) {
    throw new Error(`INSTALL [install+selectable] failed SW=${r4.sw.toString(16).toUpperCase()}`);
  }

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
    phase: 'DONE',
    progress: 1.0,
    packageAid: cap.packageAid,
    instanceAid: PA_INSTANCE_AID.toString('hex').toUpperCase(),
  };
}
