/**
 * install_payment_applet — deploy a payment scheme applet (NXP M/Chip
 * Advance or Visa VSDC) to the card.
 *
 * This is the generic vendor-agnostic install driver.  Per-applet
 * specifics (exact CAP filename + module AID + install parameters) are
 * resolved from the card's Program → IssuerProfile → ChipProfile chain:
 *
 *   ChipProfile.paymentAppletCapFilename
 *       -- filename under services/card-ops/cap-files/, e.g.
 *          "mchip_advance_v1.2.3.cap" or "vsdc_v2.9.2.cap".
 *   IssuerProfile.aid
 *       -- EMV AID (9F06).  Used as the INSTALL [install+selectable]
 *          INSTANCE AID — this is what GET STATUS + SELECT-by-AID will
 *          return for the installed applet.
 *
 * Flow (same shape as install_pa):
 *   1. Load the ChipProfile + IssuerProfile; guard that both the CAP
 *      filename and EMV AID are populated.
 *   2. Read + parse the CAP off disk.  The package AID and applet class
 *      (module) AID come from the parsed CAP header + Applet component.
 *   3. Establish SCP03 with C-MAC + C-DECRYPTION (same security level as
 *      install_pa — the LOAD bytes shouldn't leak to the relay layer).
 *   4. Best-effort DELETE of any existing instance at the EMV AID and
 *      the package AID.  6A88 ("referenced data not found") is treated
 *      as "already absent" to keep this op idempotent.
 *   5. INSTALL [load].
 *   6. LOAD blocks in 240-byte chunks.
 *   7. INSTALL [install+selectable] — instance AID = EMV AID, module
 *      AID = first applet AID from the CAP (or the package AID + 0x00
 *      terminator for single-class CAPs; the CAP parser returns what the
 *      JC converter emitted).
 *   8. Emit `{type:'complete'}`.
 *
 * Progress mileposts: 0.10 post-SCP03, 0.20 post-DELETE, 0.50 post-load
 * start, 0.90 post-install-install, 1.00 at complete.  Mirrors the
 * install_pa scale so the admin UI can render a single-bar progress
 * indicator for any install operation without per-op branching.
 *
 * Not in scope (yet): per-applet INSTALL [install+selectable] install
 * parameters.  Real M/Chip / VSDC CPS-driven install params (e.g.
 * application-specific privileges, volatile memory reservation) will be
 * added when the vendor CAP + CPS guide arrive.  For now the op uses
 * the default parameters (C9 00 — empty install params) which works
 * for most reference builds.
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
import { loadCapByFilename, CapFileMissingError } from '../gp/cap-loader.js';
import { SECURITY_LEVEL } from '../gp/scp03.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

export async function runInstallPaymentApplet(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  // Resolve Card → Program → IssuerProfile → ChipProfile.  One query;
  // if any link is missing or the CAP filename is null we bail with
  // NOT_PROVISIONED so the admin UI can render a clear "upload the CAP
  // + link it on the ChipProfile" remediation prompt.
  const card = await prisma.card.findUnique({
    where: { id: session.cardId },
    select: {
      program: {
        select: {
          issuerProfile: {
            select: {
              aid: true,
              chipProfile: {
                select: { paymentAppletCapFilename: true, name: true },
              },
            },
          },
        },
      },
    },
  });

  const issuerProfile = card?.program?.issuerProfile ?? null;
  const chipProfile = issuerProfile?.chipProfile ?? null;
  const capFilename = chipProfile?.paymentAppletCapFilename ?? null;
  const emvAidHex = issuerProfile?.aid ?? '';

  if (!chipProfile || !capFilename) {
    return {
      type: 'error',
      code: 'NOT_PROVISIONED',
      message:
        'ChipProfile.paymentAppletCapFilename is not set — upload the payment applet CAP and link it on the ChipProfile before running install_payment_applet.',
    };
  }
  if (!emvAidHex || !/^[0-9A-Fa-f]+$/.test(emvAidHex) || emvAidHex.length % 2 !== 0) {
    return {
      type: 'error',
      code: 'NOT_PROVISIONED',
      message:
        'IssuerProfile.aid is missing or malformed — populate the EMV AID (Tag 9F06) before running install_payment_applet.',
    };
  }

  // Parse the CAP off disk.  Fails fast with CAP_FILE_MISSING when the
  // vendor file hasn't been dropped into cap-files/ yet.
  let cap;
  try {
    cap = loadCapByFilename(capFilename);
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
  const { send, scrub } = await establishScp03(io, keys, {
    securityLevel: SECURITY_LEVEL.C_MAC | SECURITY_LEVEL.C_DECRYPTION,
    phasePrefix: 'SCP03',
  });

  try {
    const loadFileAidBuf = Buffer.from(cap.packageAid, 'hex');
    const instanceAidBuf = Buffer.from(emvAidHex, 'hex');
    // Module AID = first applet AID declared in the CAP.  Fall back to
    // the package AID if the CAP has no Applet component (shouldn't
    // happen for MChip / VSDC, but keeps parsing defensive for odd
    // vendor builds where the applet class AID is implicit).
    const moduleAidHex = cap.appletAids[0] ?? cap.packageAid;
    const moduleAidBuf = Buffer.from(moduleAidHex, 'hex');

    io.send({ type: 'apdu', hex: '', phase: 'DELETE_OLD', progress: 0.1 });

    // Best-effort DELETE of any existing applet at the EMV AID and the
    // package AID.  Two APDUs because install_pa already models it this
    // way — avoids the "delete related objects" bit (P2=0x80) so we don't
    // accidentally nuke dependents if a vendor CAP got reused across
    // programs.  6A88 = absent = fine.
    const delInstance = buildDelete(instanceAidBuf);
    const r1 = await send({
      cla: delInstance[0], ins: delInstance[1], p1: delInstance[2], p2: delInstance[3],
      data: delInstance.subarray(5, 5 + delInstance[4]),
    });
    if (r1.sw !== 0x9000 && r1.sw !== 0x6A88) {
      throw new Error(`DELETE instance failed SW=${r1.sw.toString(16).toUpperCase()}`);
    }

    const delPkg = buildDelete(loadFileAidBuf);
    const r2 = await send({
      cla: delPkg[0], ins: delPkg[1], p1: delPkg[2], p2: delPkg[3],
      data: delPkg.subarray(5, 5 + delPkg[4]),
    });
    if (r2.sw !== 0x9000 && r2.sw !== 0x6A88) {
      throw new Error(`DELETE package failed SW=${r2.sw.toString(16).toUpperCase()}`);
    }

    io.send({ type: 'apdu', hex: '', phase: 'INSTALL_LOAD', progress: 0.2 });

    // INSTALL [load]
    const installLoad = buildInstallForLoad(loadFileAidBuf);
    const r3 = await send({
      cla: installLoad[0], ins: installLoad[1], p1: installLoad[2], p2: installLoad[3],
      data: installLoad.subarray(5, 5 + installLoad[4]),
    });
    if (r3.sw !== 0x9000) {
      throw new Error(`INSTALL [load] failed SW=${r3.sw.toString(16).toUpperCase()}`);
    }

    io.send({ type: 'apdu', hex: '', phase: 'LOADING', progress: 0.3 });

    // LOAD blocks.
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

    // INSTALL [install+selectable] — instance AID = EMV AID so SELECT + GET
    // STATUS returns the standardised payment-scheme AID.
    const installInstall = buildInstallForInstall(
      loadFileAidBuf,
      moduleAidBuf,
      instanceAidBuf,
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
      moduleAid: moduleAidHex.toUpperCase(),
      instanceAid: emvAidHex.toUpperCase(),
      capFilename,
    };
  } finally {
    // PCI 3.5 / audit S-3: zero SCP03 S-ENC/S-MAC/S-RMAC + MAC chain.
    scrub();
  }
}
