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
import { loadCap, CapFileMissingError, type CapKey } from '../gp/cap-loader.js';
import { SECURITY_LEVEL } from '../gp/scp03.js';
import { getCardOpsConfig } from '../env.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

const PA_PACKAGE_AID = Buffer.from('A0000000625041', 'hex');
const PA_INSTANCE_AID = Buffer.from('A00000006250414C', 'hex');

/**
 * Decide which PA CAP to install on this card.
 *
 * Priority (highest → lowest):
 *   1. Card → Program → IssuerProfile → ChipProfile.provisioningMode.
 *      Same field that gates the server-side RCA dispatch (SAD_LEGACY
 *      vs PARAM_BUNDLE).  Tying the CAP choice to this field means the
 *      applet bytecode and the server flow can't drift — an admin who
 *      flips the ChipProfile to PARAM_BUNDLE also gets the pa-v3 applet
 *      installed next time they hit "install PA".
 *   2. CARD_OPS_DEFAULT_PA_CAP env var — fleet-wide default for cards
 *      that don't yet have a ChipProfile row (or whose ChipProfile
 *      predates the field).  Defaults to 'pa' (legacy).
 *
 * Returns the CAP key to pass to `loadCap()`.  Throws only on an
 * internal contract break (unknown enum value).
 */
export async function resolvePaCapKey(cardId: string): Promise<CapKey> {
  // One hop: Card → Program → IssuerProfile → ChipProfile.  We don't
  // need the full ChipProfile payload, just the enum.
  const row = await prisma.card.findUnique({
    where: { id: cardId },
    select: {
      program: {
        select: {
          issuerProfile: {
            select: {
              chipProfile: { select: { provisioningMode: true } },
            },
          },
        },
      },
    },
  });
  const mode = row?.program?.issuerProfile?.chipProfile?.provisioningMode;
  if (mode === 'PARAM_BUNDLE') return 'pa-v3';
  if (mode === 'SAD_LEGACY') return 'pa';

  // No ChipProfile on the chain — fall back to the env default.  Covers
  // the migration window when some programs haven't been backfilled.
  return getCardOpsConfig().CARD_OPS_DEFAULT_PA_CAP === 'pa-v3' ? 'pa-v3' : 'pa';
}

export async function runInstallPa(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  // Guard: CAP file must be present.
  const capKey = await resolvePaCapKey(session.cardId);
  let cap;
  try {
    cap = loadCap(capKey);
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
  const { send, scrub } = await establishScp03(io, keys, {
    securityLevel: SECURITY_LEVEL.C_MAC | SECURITY_LEVEL.C_DECRYPTION,
    phasePrefix: 'SCP03',
  });

  // PCI 3.5 / audit S-3: zero the SCP03 session keys + MAC chain the
  // moment the op body finishes, regardless of success/failure path.
  // `scrub()` is idempotent, so calling it here is safe even though the
  // operation-runner's terminal write also clears `scpState` in the DB.
  try {
    // Emit the chosen CAP early so the admin's WS log shows it even
    // on failure.  `phase: 'CAP_SELECTED'` is observational — the
    // actual first APDU is the DELETE below.
    io.send({ type: 'apdu', hex: '', phase: 'CAP_SELECTED', progress: 0.05, capKey });

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
      // Which CAP actually ended up on the card — pa (legacy, TRANSFER_SAD)
      // or pa-v3 (dual-mode, accepts both TRANSFER_SAD and
      // TRANSFER_PARAMS).  Admin UI surfaces this so operators see which
      // flavour is running before kicking off provisioning.
      capKey,
    };
  } finally {
    scrub();
  }
}
