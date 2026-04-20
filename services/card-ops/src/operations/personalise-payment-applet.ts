/**
 * personalise_payment_applet — stream STORE DATA APDUs to the installed
 * payment applet.
 *
 * This is a scaffold for the post-install perso path.  Once
 * install_payment_applet has loaded + instantiated the applet (NXP
 * M/Chip Advance, Visa VSDC), the card has a blank EMV app with no
 * scheme data.  data-prep pre-builds the SAD (DGI list) and hands
 * Palisade an encrypted blob via SadRecord.  This op streams each DGI
 * to the card as a STORE DATA APDU so the applet can write it into NVM.
 *
 * Flow:
 *   1. Establish SCP03 with C-MAC + C-DECRYPTION (STORE DATA payloads
 *      are card personalisation data — must not leak to the relay).
 *   2. SELECT the payment applet by IssuerProfile.aid (the EMV AID).
 *   3. Read the encrypted SAD from SadRecord via card.proxyCardId.
 *   4. Decrypt with DataPrepService.decryptSad — same code path RCA
 *      uses.  Plaintext is a serialised DGI list.
 *   5. Deserialise to [dgiNumber, dgiContainerBytes][] via
 *      SADBuilder.deserialiseDgis.
 *   6. For each DGI, build + send a STORE DATA APDU.  See the STORE
 *      DATA structural assumptions notes below.
 *   7. Flip SadRecord.status to CONSUMED.
 *   8. Emit `{type:'complete'}`.
 *
 * STORE DATA structural assumptions (documented until vendor CPS
 * arrives, at which point the CAP-provider agent will tighten these):
 *
 *   APDU header:   80 E2 P1 P2 Lc <data>
 *   P1 (flags):
 *     bit 7 (0x80) — set on the LAST block; clear on all others.
 *     bit 6 (0x40) — encryption indicator (0 = plaintext).  We send
 *                    plaintext because SCP03's C-DECRYPTION already
 *                    wraps the bytes on the wire; the applet sees
 *                    the plaintext DGI after SCP03 unwrap.
 *     bit 5 (0x20) — MAC indicator (0 = not separately MACed).  SCP03
 *                    C-MAC already covers every wrapped APDU.
 *   P2:            block index, 0..N-1 (wrap at 256 for now — both
 *                  M/Chip and VSDC personalisation specs describe <256
 *                  DGIs per applet, which is fine; if that changes in
 *                  practice we'll flip to the P2=index&0xFF +
 *                  chained-INS scheme used elsewhere).
 *   data:          the raw DGI container bytes emitted by SADBuilder,
 *                  i.e. `dgi-number(2) || length-byte(s) || value`.
 *
 * These defaults match the de-facto convention used by reference
 * Mastercard CPS tooling (M/Chip Advance Personalization Guide v1.2, §5)
 * and by reference Visa VPA tooling.  The CAP-provider agent will
 * refine them per-applet — in particular the P1 encryption/MAC bits may
 * shift depending on whether the applet expects application-layer
 * encryption on top of SCP03 (M/Chip: usually no; VSDC: depends on
 * personalization profile).
 */

import { Prisma } from '@prisma/client';
import { prisma } from '@palisade/db';
import { SADBuilder } from '@palisade/emv';
import { DataPrepService } from '@palisade/data-prep/services/data-prep.service';
import { buildSelectByAid } from '../gp/apdu-builder.js';
import { establishScp03, type DriveIO } from './scp03-drive.js';
import { getGpStaticKeys } from '../gp/static-keys.js';
import { SECURITY_LEVEL } from '../gp/scp03.js';
import { getCardOpsConfig } from '../env.js';
import type { WSMessage } from '../ws/messages.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

export async function runPersonalisePaymentApplet(
  session: CardOpSessionWithCard,
  io: DriveIO,
): Promise<WSMessage> {
  // --- 1. Resolve card + issuer AID + proxyCardId --------------------------
  const card = await prisma.card.findUnique({
    where: { id: session.cardId },
    select: {
      proxyCardId: true,
      program: {
        select: {
          issuerProfile: { select: { aid: true } },
        },
      },
    },
  });

  const emvAidHex = card?.program?.issuerProfile?.aid ?? '';
  const proxyCardId = card?.proxyCardId ?? '';

  if (!emvAidHex || !/^[0-9A-Fa-f]+$/.test(emvAidHex) || emvAidHex.length % 2 !== 0) {
    return {
      type: 'error',
      code: 'NOT_PROVISIONED',
      message:
        'IssuerProfile.aid is missing or malformed — the payment applet EMV AID must be set before personalisation.',
    };
  }
  if (!proxyCardId) {
    return {
      type: 'error',
      code: 'NOT_PROVISIONED',
      message:
        'Card.proxyCardId is not set — no SAD record can exist without a proxyCardId.',
    };
  }

  // --- 2. Load the SAD record ---------------------------------------------
  const sadRecord = await prisma.sadRecord.findUnique({
    where: { proxyCardId },
  });
  if (!sadRecord) {
    return {
      type: 'error',
      code: 'SAD_RECORD_MISSING',
      message: `No SadRecord for proxyCardId=${proxyCardId}`,
    };
  }
  if (sadRecord.status !== 'READY') {
    return {
      type: 'error',
      code: 'SAD_RECORD_NOT_READY',
      message: `SadRecord.status=${sadRecord.status}, expected READY`,
    };
  }

  // --- 3. SCP03 handshake -------------------------------------------------
  const keys = await getGpStaticKeys(session.cardId);
  const { send, scrub } = await establishScp03(io, keys, {
    securityLevel: SECURITY_LEVEL.C_MAC | SECURITY_LEVEL.C_DECRYPTION,
    phasePrefix: 'SCP03',
  });

  try {
    // --- 4. SELECT the payment applet -------------------------------------
    io.send({ type: 'apdu', hex: '', phase: 'SELECT_APPLET', progress: 0.12 });

    const emvAidBuf = Buffer.from(emvAidHex, 'hex');
    const selectApdu = buildSelectByAid(emvAidBuf);
    const sel = await send({
      cla: selectApdu[0], ins: selectApdu[1], p1: selectApdu[2], p2: selectApdu[3],
      data: selectApdu.subarray(5, 5 + selectApdu[4]),
    });
    if (sel.sw !== 0x9000) {
      throw new Error(`SELECT payment applet failed SW=${sel.sw.toString(16).toUpperCase()}`);
    }

    // --- 5. Decrypt SAD + deserialise into DGI list ----------------------
    io.send({ type: 'apdu', hex: '', phase: 'DECRYPT_SAD', progress: 0.18 });

    const config = getCardOpsConfig();
    const encryptedBuf = Buffer.isBuffer(sadRecord.sadEncrypted)
      ? sadRecord.sadEncrypted
      : Buffer.from(sadRecord.sadEncrypted);
    const sadPlaintext = await DataPrepService.decryptSad(
      encryptedBuf,
      config.KMS_SAD_KEY_ARN,
      sadRecord.sadKeyVersion,
    );
    const dgis = SADBuilder.deserialiseDgis(sadPlaintext);
    if (dgis.length === 0) {
      return {
        type: 'error',
        code: 'SAD_EMPTY',
        message: 'Decrypted SAD contained zero DGIs — refusing to personalise an empty applet',
      };
    }
    if (dgis.length > 256) {
      // Our P2 = block-index scheme only has a single byte.  If some
      // pathological profile needs more, we'll need the chained-APDU
      // INS pattern — flag early so the op doesn't half-run.
      return {
        type: 'error',
        code: 'SAD_TOO_MANY_DGIS',
        message: `SAD has ${dgis.length} DGIs; STORE DATA scaffold caps at 256 blocks`,
      };
    }

    // --- 6. STORE DATA streaming -----------------------------------------
    io.send({ type: 'apdu', hex: '', phase: 'STORE_DATA', progress: 0.20 });

    const total = dgis.length;
    try {
      for (let i = 0; i < total; i++) {
        const [, dgiBytes] = dgis[i];
        const isLast = i === total - 1;
        const p1 = isLast ? 0x80 : 0x00;
        const p2 = i & 0xFF;

        // Body safety: a DGI that blows past a single short-APDU payload
        // can't go in one STORE DATA under this scaffold.  data-prep
        // already chunks below 255 B in practice; if a real vendor CAP
        // emits a larger container we'll need extended-length APDUs.
        if (dgiBytes.length > 255) {
          return {
            type: 'error',
            code: 'DGI_TOO_LARGE',
            message: `DGI index ${i} is ${dgiBytes.length} bytes; STORE DATA scaffold requires <=255`,
          };
        }

        const result = await send({
          cla: 0x80, ins: 0xE2, p1, p2,
          data: dgiBytes,
        });
        if (result.sw !== 0x9000) {
          throw new Error(`STORE DATA block ${i} failed SW=${result.sw.toString(16).toUpperCase()}`);
        }

        io.send({
          type: 'apdu', hex: '', phase: 'STORE_DATA',
          // 0.20 → 0.95 across the STORE DATA stream; the last 5% covers
          // the SadRecord status update + audit flush.
          progress: 0.20 + (0.75 * (i + 1) / total),
        });
      }
    } finally {
      // Per-DGI plaintext fragments held in `dgis` still reference the
      // decrypted SAD buffer.  Zero it now — the payment-applet APDUs
      // are already in transit so we don't need the plaintext again.
      for (const [, dgiBytes] of dgis) dgiBytes.fill(0);
      sadPlaintext.fill(0);
    }

    // --- 7. Consume the SAD record ---------------------------------------
    await prisma.sadRecord.update({
      where: { id: sadRecord.id },
      data: { status: 'CONSUMED' },
    });

    // Flush the APDU audit buffer explicitly — personalisation leaves a
    // fully-populated transcript that compliance wants on disk before
    // we touch the session row's COMPLETE transition (the runner will
    // flush again as part of its terminal path, but this tightens the
    // crash window).
    await io.audit?.flush();

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
      instanceAid: emvAidHex.toUpperCase(),
      dgiCount: total,
      proxyCardId,
    };
  } finally {
    // PCI 3.5 / audit S-3: zero SCP03 S-ENC/S-MAC/S-RMAC + MAC chain.
    scrub();
  }
}
