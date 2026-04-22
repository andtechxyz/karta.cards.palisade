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
  buildSelectByAid,
  chunkLoadBlock,
} from '../gp/apdu-builder.js';
import { establishScp03, sendAndRecv, type DriveIO } from './scp03-drive.js';
import { getGpStaticKeys } from '../gp/static-keys.js';
import { loadCap, CapFileMissingError, type CapKey } from '../gp/cap-loader.js';
import { SECURITY_LEVEL } from '../gp/scp03.js';
import { getCardOpsConfig } from '../env.js';
import {
  issueCardCert,
  makeKmsIssuerSigner,
  CPLC_LEN as ATTEST_CPLC_LEN,
} from '@palisade/data-prep/services/attestation-issuer';
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

    // -----------------------------------------------------------------
    // Patent C16/C23 — load per-card attestation material.
    //
    // Post-install, before returning complete, we:
    //   (a) fetch CPLC via GET DATA 9F7F on the ISD (SCP03-wrapped)
    //   (b) mint {privKey, cardCert} via issueCardCert(cplc, kmsSigner)
    //   (c) close SCP03 + SELECT PA (the freshly-installed applet)
    //   (d) emit three STORE_ATTESTATION APDUs (CLA=80 INS=EC):
    //         P1=0x01  raw 32-byte priv scalar  (DGI A001)
    //         P1=0x02  card cert blob           (DGI A002)
    //         P1=0x03  42-byte CPLC             (DGI A003)
    //
    // Gated on:
    //   - capKey === 'pa-v3' — only the v3 bytecode has the 0xEC
    //     handler; legacy pa returns 6D00 and would abort install.
    //   - KMS_ATTESTATION_ISSUER_ARN non-empty — dev installs without
    //     the key proceed to complete without attestation; strict-
    //     mode verify at tap time will then reject the card with a
    //     clear warning and the operator re-runs install-pa.
    //
    // On any failure during the attestation phase we throw — the
    // applet is installed-but-not-attested, which is benign (strict
    // mode catches it at the next tap).  Operator retries install-pa
    // to try again; per-card keypairs are cheap to remint.
    // -----------------------------------------------------------------
    const cfg = getCardOpsConfig();
    const attestArn = cfg.KMS_ATTESTATION_ISSUER_ARN;
    if (capKey === 'pa-v3' && attestArn) {
      io.send({ type: 'apdu', hex: '', phase: 'ATTESTATION_FETCH_CPLC', progress: 0.92 });

      // GET DATA 9F7F returns TLV `9F 7F 2A || 42-byte CPLC`.  Still
      // SCP03-wrapped because we haven't scrubbed the session yet.
      // Wrap's case-2 handling: passing `data: Buffer.alloc(0)` with
      // p1/p2=9F/7F produces the minimal APDU the ISD expects.  The
      // wrap driver adds its own MAC then reads the response.
      const cplcResp = await send({
        cla: 0x80, ins: 0xCA, p1: 0x9F, p2: 0x7F, data: Buffer.alloc(0),
      });
      if (cplcResp.sw !== 0x9000) {
        throw new Error(
          `GET DATA 9F7F (CPLC) failed SW=${cplcResp.sw.toString(16).toUpperCase()}`,
        );
      }
      // Strip the 3-byte TLV header: 9F 7F 2A (42 decimal = length).
      // The remaining 42 bytes are the CPLC payload.
      if (cplcResp.data.length < 3 + ATTEST_CPLC_LEN) {
        throw new Error(
          `CPLC response too short: ${cplcResp.data.length} bytes ` +
            `(expected at least ${3 + ATTEST_CPLC_LEN})`,
        );
      }
      const cplc = cplcResp.data.subarray(3, 3 + ATTEST_CPLC_LEN);

      // Mint the per-card keypair + sign the cert body via KMS.  This
      // is the only synchronous AWS call in the install path — ~80 ms
      // tail latency on a warm KMS client, which lands before the
      // operator's admin UI has even re-rendered the progress bar.
      const signer = makeKmsIssuerSigner(attestArn, cfg.AWS_REGION);
      const attestBundle = await issueCardCert(cplc, signer);

      // Close SCP03 before the raw STORE_ATTESTATION APDUs.  Those go
      // to the PA applet (not the ISD), so SCP03's ISD-scoped MAC
      // chain doesn't cover them; scrub ends the cryptographic
      // session cleanly and the subsequent SELECT PA takes us out of
      // ISD context at the card level.
      scrub();

      io.send({ type: 'apdu', hex: '', phase: 'ATTESTATION_SELECT_PA', progress: 0.94 });
      const selectPaApdu = buildSelectByAid(PA_INSTANCE_AID);
      const selectPaResp = await sendAndRecv(io, selectPaApdu, 'ATTESTATION_SELECT_PA');
      const selectPaSw =
        (selectPaResp[selectPaResp.length - 2] << 8) | selectPaResp[selectPaResp.length - 1];
      if (selectPaSw !== 0x9000) {
        throw new Error(
          `SELECT PA for STORE_ATTESTATION failed SW=${selectPaSw.toString(16).toUpperCase()}`,
        );
      }

      // Three STORE_ATTESTATION APDUs, one per DGI.  CLA=0x80 is the
      // proprietary PA CLA; INS=0xEC is INS_STORE_ATTESTATION; P1
      // selects the payload type per applet Constants.ATTEST_P1_*.
      //
      // Order doesn't matter at the applet level (flags track per-
      // DGI completion) but we choose priv-key → cert → cplc so that
      // if a later step fails the applet has the least amount of
      // partial material — and the operator's error line identifies
      // the exact DGI that failed.
      const steps: ReadonlyArray<{ p1: number; phase: string; payload: Buffer }> = [
        { p1: 0x01, phase: 'ATTESTATION_STORE_PRIV', payload: attestBundle.cardAttestPrivRaw },
        { p1: 0x02, phase: 'ATTESTATION_STORE_CERT', payload: attestBundle.cardCert },
        { p1: 0x03, phase: 'ATTESTATION_STORE_CPLC', payload: cplc },
      ];
      let stepIdx = 0;
      for (const step of steps) {
        stepIdx += 1;
        io.send({
          type: 'apdu', hex: '', phase: step.phase,
          progress: 0.94 + 0.02 * stepIdx,
        });
        if (step.payload.length > 0xff) {
          throw new Error(
            `STORE_ATTESTATION P1=${step.p1.toString(16)} payload ` +
              `${step.payload.length}B exceeds single-APDU max 255B — ` +
              `applet build needs chained-APDU support`,
          );
        }
        const apdu = Buffer.concat([
          Buffer.from([0x80, 0xEC, step.p1, 0x00, step.payload.length]),
          step.payload,
        ]);
        const resp = await sendAndRecv(io, apdu, step.phase);
        const sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
        if (sw !== 0x9000) {
          throw new Error(
            `STORE_ATTESTATION P1=${step.p1.toString(16).padStart(2, '0')} ` +
              `failed SW=${sw.toString(16).toUpperCase()}`,
          );
        }
      }

      // Scrub the in-memory private scalar immediately.  The Buffer
      // came from issueCardCert — fill(0) is all the cleanup we can
      // do at the JS layer; the original allocation from
      // generateKeyPairSync's JWK export was already released when
      // issueCardCert returned.
      attestBundle.cardAttestPrivRaw.fill(0);
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
