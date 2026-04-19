/**
 * Provisioning session lifecycle management.
 *
 * Coordinates the complete provisioning flow through 6 phases:
 *   Phase 0: PA SELECT + FCI validation
 *   Phase 1: SCP11c session establishment
 *   Phase 2: Key generation + attestation
 *   Phase 3: SAD transfer
 *   Phase 4: Awaiting final status
 *   Phase 5: CONFIRM + callback
 *
 * Ported from palisade-rca/app/services/session_manager.py.
 */

import { prisma } from '@palisade/db';
import { APDUBuilder } from '@palisade/emv';

import { getRcaConfig } from '../env.js';
import { buildProvisioningPlan, type Plan, type PlanStep } from './plan-builder.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WSMessage {
  type: 'apdu' | 'response' | 'complete' | 'error' | 'pa_fci' | 'plan';
  hex?: string;
  sw?: string;
  phase?: string;
  progress?: number;
  code?: string;
  message?: string;
  proxyCardId?: string;

  // Plan-mode fields -------------------------------------------------------
  /**
   * Step index.
   *   - Outbound (server→app) on a 'plan' message: unused (steps carry their
   *     own `i` on each PlanStep).
   *   - Inbound (app→server) on a 'response' message: which plan step this
   *     response belongs to.  Presence of `i` is how handleMessage
   *     distinguishes plan-mode responses from classical-mode phase-driven
   *     responses.
   */
  i?: number;
  /** On a 'plan' message: the ordered list of APDU steps to execute. */
  steps?: PlanStep[];
  /** On a 'plan' message: plan schema version (1 today). */
  version?: number;
}

interface SessionState {
  sessionId: string;
  proxyCardId: string;
  cardId: string;
  sadRecordId: string;
  phase: string;
}

// ---------------------------------------------------------------------------
// Session Manager
// ---------------------------------------------------------------------------

export class SessionManager {
  /**
   * Start a provisioning session.
   * Validates the card has a READY SAD record, creates a ProvisioningSession.
   */
  async startSession(proxyCardId: string): Promise<SessionState> {
    // Find the SAD record
    const sadRecord = await prisma.sadRecord.findUnique({
      where: { proxyCardId },
    });
    if (!sadRecord || sadRecord.status !== 'READY') {
      throw new Error(`No READY SAD record for proxyCardId: ${proxyCardId}`);
    }

    // Create provisioning session
    const session = await prisma.provisioningSession.create({
      data: {
        cardId: sadRecord.cardId,
        sadRecordId: sadRecord.id,
        phase: 'INIT',
      },
    });

    console.log(`[rca] session created: ${session.id} for card ${sadRecord.cardId}`);

    return {
      sessionId: session.id,
      proxyCardId,
      cardId: sadRecord.cardId,
      sadRecordId: sadRecord.id,
      phase: 'INIT',
    };
  }

  /**
   * Process an incoming WebSocket message and return response messages.
   *
   * Two protocols coexist:
   *
   *   - **Classical** (phase-driven): server sends one APDU per round-trip,
   *     tracked via `ProvisioningSession.phase`.  Entered when the mobile
   *     app connects without `?mode=plan` and emits a `pa_fci` message
   *     after running SELECT PA locally.
   *   - **Plan** (pre-computed): server ships all 5 APDUs up front on WS
   *     open and the phone streams responses back indexed by step number.
   *     Entered when `?mode=plan` is on the WS URL; the initial message
   *     sent to the phone is `{type:'plan', steps: [...]}`.  Inbound
   *     responses carry the step `i` — handleMessage routes those through
   *     {@link handlePlanResponse} instead of the classical phase machine.
   *
   * Plan mode trims 2 s off the tap on 500 ms-RTT connections by removing
   * the 4 server-waits embedded in classical mode.  See plan-builder.ts
   * for the protocol rationale.
   */
  async handleMessage(sessionId: string, message: WSMessage): Promise<WSMessage[]> {
    if (message.type === 'pa_fci') {
      return this.handlePaFci(sessionId);
    }

    if (message.type === 'response') {
      // Plan-mode responses carry `i` (the step index).  Classical-mode
      // responses don't — they're phase-driven and read only hex/sw.
      if (typeof message.i === 'number') {
        return this.handlePlanResponse(sessionId, message);
      }
      return this.handleCardResponse(sessionId, message);
    }

    if (message.type === 'error') {
      await this.handleError(sessionId, message);
      return [];
    }

    return [];
  }

  /**
   * Plan-mode entry point: load the session's chip-profile inputs and
   * assemble the full APDU plan.
   *
   * Called from the WebSocket relay handler on connection open when the
   * client requested `?mode=plan`.  The relay sends the returned plan
   * over the wire and transitions the session's phase to PLAN_SENT.
   *
   * Falls back to the M/Chip-CVN18 defaults when the chipProfile isn't
   * wired on the session's card — matches the classical-path tolerance in
   * handleKeygenResponse where unset values read as 0x8001/0x9F48.
   */
  async buildPlanForSession(sessionId: string): Promise<Plan> {
    const session = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
      include: {
        card: {
          include: {
            program: {
              include: { issuerProfile: { include: { chipProfile: true } } },
            },
          },
        },
      },
    });
    if (!session) {
      throw new Error(`Unknown session: ${sessionId}`);
    }

    const chipProfile = session.card?.program?.issuerProfile?.chipProfile;
    return buildProvisioningPlan({
      iccPrivateKeyDgi: chipProfile?.iccPrivateKeyDgi ?? 0x8001,
      iccPrivateKeyTag: chipProfile?.iccPrivateKeyTag ?? 0x9F48,
    });
  }

  // -----------------------------------------------------------------------
  // Phase handlers
  // -----------------------------------------------------------------------

  /**
   * Phase 0: PA FCI received → send GENERATE_KEYS directly (no SCP11).
   *
   * Palisade dropped SCP11c entirely (it never worked end-to-end with the
   * real PA applet — see palisade/tools/test_ssd_e2e.py which is the
   * working reference flow).  The sequence is:
   *   SELECT PA → FCI → GENERATE_KEYS → TRANSFER_SAD (direct delivery)
   *               → re-SELECT PA → FINAL_STATUS → CONFIRM
   *
   * No PSO, no ECDH, no script wrapping.  The SAD is transferred as
   * cleartext over the WebSocket relay because the relay is already
   * inside our trust boundary (HMAC-signed APDU stream from the mobile
   * app the cardholder is logged into).
   */
  private async handlePaFci(sessionId: string): Promise<WSMessage[]> {
    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: { phase: 'KEYGEN' },
    });

    // GENERATE_KEYS = 80 E0 00 00 01 01 — single-byte payload `01`
    // means "ECC P-256 keypair please".  No session ID — passing one
    // appends 16 bytes the PA discards (or worse).  Matches the exact
    // hex in the Palisade SSD e2e trace.
    const keygenHex = APDUBuilder.generateKeys();

    return [{
      type: 'apdu',
      hex: keygenHex,
      phase: 'key_generation',
      progress: 0.1,
    }];
  }

  /**
   * Route card responses based on the current phase.
   *
   * The mobile app's WS message shape for a card response is:
   *   { type:'response', hex:'<full response including SW>', sw:'<last 4 hex chars>' }
   *
   * `hex` already contains the full response bytes *including* the trailing
   * SW, so `sw` is a duplicate of the last 2 bytes of `hex`.  We read SW
   * from `sw` directly (authoritative, always 4 hex chars when well-formed)
   * and slice the data portion off `hex`.  An older version of this handler
   * concatenated `hex + sw` and parsed last-2-bytes-of-that as SW, which
   * worked but left phase-handler callers with a buffer that still had SW
   * bytes glued on the end.
   *
   * Empty/missing fields: the app sometimes emits `{hex:'', sw:''}` after a
   * native NFC transceive failure.  Distinguish that from a real chip error
   * so the logs point at the right layer.
   */
  private async handleCardResponse(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const rawHex = msg.hex ?? '';
    const rawSw = msg.sw ?? '';
    const appErrored = rawSw.length !== 4 && rawHex.length < 4;

    let sw: number;
    if (rawSw.length === 4) {
      sw = parseInt(rawSw, 16);
    } else if (rawHex.length >= 4) {
      // Fallback — sw field wasn't populated but full response landed in hex.
      sw = parseInt(rawHex.slice(-4), 16);
    } else {
      sw = 0x6f00;
    }

    // Strip trailing SW from data so phase handlers get clean bytes.
    // If hex already ended in the SW (expected shape), drop those 4 chars.
    const dataHex =
      rawHex.length >= 4 && rawHex.slice(-4).toLowerCase() === rawSw.toLowerCase()
        ? rawHex.slice(0, -4)
        : rawHex;
    const normalizedMsg: WSMessage = { ...msg, hex: dataHex, sw: rawSw };

    // Check for card error
    if (sw !== 0x9000) {
      const swStr = sw.toString(16).padStart(4, '0').toUpperCase();
      if (appErrored) {
        console.warn(
          `[rca] mobile-side NFC failure (empty response) in session ${sessionId}: ` +
          `msg={type:"${msg.type}", hex.len=${rawHex.length}, sw="${rawSw}", phase:"${msg.phase ?? ''}"}.`
          + ` RCA is synthesizing SW=6F00 but the chip never responded.`,
        );
      } else {
        console.warn(
          `[rca] chip card error SW=${swStr} in session ${sessionId} ` +
          `(response was data.len=${dataHex.length / 2}B, sw="${rawSw}")`,
        );
      }
      return [{
        type: 'error',
        code: appErrored ? 'NFC_ERROR' : 'CARD_ERROR',
        message: appErrored
          ? `Mobile NFC transceive failed — no chip response received`
          : `Card returned error SW=${swStr}`,
      }];
    }

    const session = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
    });
    if (!session) return [];

    switch (session.phase) {
      case 'KEYGEN':
        return this.handleKeygenResponse(sessionId, normalizedMsg);
      case 'SAD_TRANSFER':
        return this.handleSadResponse(sessionId);
      case 'AWAITING_FINAL':
        return this.handleFinalStatus(sessionId, normalizedMsg);
      default:
        return [];
    }
  }

  /**
   * Phase 2: Process keygen response, store ICC public key, send TRANSFER_SAD.
   * Response: ICC_PubKey(65) || Attest_Sig(~72) || CPLC(42)
   */
  private async handleKeygenResponse(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const respData = Buffer.from(msg.hex ?? '', 'hex');
    const iccPubkey = respData.subarray(0, Math.min(65, respData.length));

    // Load session with SAD record and card's program/chip profile
    const session = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
      include: {
        sadRecord: true,
        card: {
          include: {
            program: {
              include: { issuerProfile: { include: { chipProfile: true } } },
            },
          },
        },
      },
    });

    if (!session) return [];

    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: { phase: 'SAD_TRANSFER', iccPublicKey: iccPubkey },
    });

    // Build TRANSFER_SAD payload in the exact layout the PA applet's
    // processTransferSad() parses (palisade-pa/src/com/palisade/pa/
    // ProvisioningAgent.java:481).  PA parses from the END of the buffer:
    //
    //   [SAD_DGIs:var] [bank_id:4] [prog_id:4] [scheme:1] [ts:4]
    //     [url:var] [url_len:1] [iccPrivDgi:2] [iccPrivEmvTag:2]
    //
    // The "SAD_DGIs" portion here is a minimal in-applet-consumable record
    // list — [dgi_tag:2][len:1][data]* — NOT the full EMV-structured SAD
    // that @palisade/emv's SAD builder produces (that heavier format is for
    // the payment applet's own STORE DATA and is built separately by
    // data-prep; it's not what the PA's processTransferSad consumes).
    //
    // Mirror palisade-rca/app/services/session_manager.py:227 — a single
    // DGI 0x0101 with TLV tag 0x50 (App Label) is enough to get the PA
    // to 9000 on TRANSFER_SAD and advance state to PERSO_IN_PROGRESS.
    // Replace the minimal SAD with real DGIs sourced from data-prep once
    // we need the payment applet to actually hold per-card EMV data.
    const chipProfile = session.card?.program?.issuerProfile?.chipProfile;
    const iccPrivDgi = chipProfile?.iccPrivateKeyDgi ?? 0x8001;
    const iccPrivTag = chipProfile?.iccPrivateKeyTag ?? 0x9F48;

    // Minimal SAD — one DGI 0x0101 carrying TLV 0x50 (App Label) "PALISADE"
    const appLabel = Buffer.from('PALISADE', 'ascii');
    const tlv50 = Buffer.concat([Buffer.from([0x50, appLabel.length]), appLabel]);
    const dgi0101 = Buffer.concat([Buffer.from([0x01, 0x01, tlv50.length]), tlv50]);
    const sadPayload = dgi0101;

    // Metadata tail — keep these as placeholders until data-prep starts
    // sourcing real per-FI values from IssuerProfile.  PA only writes the
    // bytes to NVM; it doesn't enforce structure on bank_id / prog_id /
    // scheme / url beyond length.
    const bankId = Buffer.from([0x00, 0x00, 0x00, 0x01]);
    const progId = Buffer.from([0x00, 0x00, 0x00, 0x01]);
    const scheme = Buffer.from([0x01]); // 0x01 = Mastercard, 0x02 = Visa
    const timestamp = Math.floor(Date.now() / 1000);
    const tsBuf = Buffer.alloc(4);
    tsBuf.writeUInt32BE(timestamp, 0);
    const bankUrl = Buffer.from('mobile.karta.cards', 'ascii');
    const urlLen = Buffer.from([bankUrl.length]);
    const dgiTag = Buffer.alloc(2);
    dgiTag.writeUInt16BE(iccPrivDgi, 0);
    const emvTag = Buffer.alloc(2);
    emvTag.writeUInt16BE(iccPrivTag, 0);

    const transferData = Buffer.concat([
      sadPayload,
      bankId,
      progId,
      scheme,
      tsBuf,
      bankUrl,
      urlLen,
      dgiTag,
      emvTag,
    ]);

    const lc = transferData.length;
    let transferApdu: Buffer;
    if (lc <= 255) {
      transferApdu = Buffer.concat([
        Buffer.from([0x80, 0xE2, 0x00, 0x00, lc]),
        transferData,
      ]);
    } else {
      // Extended APDU for large SAD
      const lcBuf = Buffer.alloc(2);
      lcBuf.writeUInt16BE(lc, 0);
      transferApdu = Buffer.concat([
        Buffer.from([0x80, 0xE2, 0x00, 0x00, 0x00]),
        lcBuf,
        transferData,
      ]);
    }

    return [{
      type: 'apdu',
      hex: transferApdu.toString('hex').toUpperCase(),
      phase: 'provisioning',
      progress: 0.55,
    }];
  }

  /**
   * Phase 3: SAD transfer complete → send FINAL_STATUS.
   */
  private async handleSadResponse(sessionId: string): Promise<WSMessage[]> {
    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: { phase: 'AWAITING_FINAL' },
    });

    return [{
      type: 'apdu',
      hex: APDUBuilder.finalStatus(),
      phase: 'finalizing',
      progress: 0.80,
    }];
  }

  /**
   * Phase 4-5: Process final status, send CONFIRM, fire callback.
   */
  private async handleFinalStatus(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const respData = Buffer.from(msg.hex ?? '', 'hex');
    const statusByte = respData.length > 0 ? respData[0] : 0;
    const success = statusByte === 0x01;

    if (!success) {
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'FAILED', failedAt: new Date(), failureReason: 'PA_FAILED' },
      });
      return [{
        type: 'error',
        code: 'PA_FAILED',
        message: 'Provisioning failed on card',
      }];
    }

    // Extract provenance hash (32 bytes) + FIDO data
    const provHash = respData.length > 33 ? respData.subarray(1, 33).toString('hex') : '';
    let fidoCredData = '';
    if (respData.length > 66) {
      const credIdLen = respData[65];
      const credId = respData.subarray(66, 66 + credIdLen);
      fidoCredData = credId.toString('base64url');
    }

    // Update session to COMPLETE
    const session = await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'COMPLETE',
        completedAt: new Date(),
        provenance: provHash,
        fidoCredData,
      },
      include: { card: true, sadRecord: true },
    });

    // Update card status to PROVISIONED
    await prisma.card.update({
      where: { id: session.cardId },
      data: { status: 'PROVISIONED', provisionedAt: new Date() },
    });

    // Mark SAD as consumed
    await prisma.sadRecord.update({
      where: { id: session.sadRecordId },
      data: { status: 'CONSUMED' },
    });

    console.log(`[rca] provisioning complete: session=${sessionId}, card=${session.cardId}`);

    // Fire callback to activation service (async, non-blocking)
    this.fireCallback(session.card.cardRef, session.card.chipSerial ?? '').catch((err) =>
      console.error('[rca] callback failed:', err),
    );

    return [
      { type: 'apdu', hex: APDUBuilder.confirm(), phase: 'confirming', progress: 0.95 },
      { type: 'complete', proxyCardId: session.sadRecord.proxyCardId },
    ];
  }

  // -----------------------------------------------------------------------
  // Plan-mode response handlers
  //
  // The 5 plan steps correspond to the classical phases 1:1 (SELECT PA,
  // GENERATE_KEYS, TRANSFER_SAD, FINAL_STATUS, CONFIRM) but execute
  // without a server round-trip between them.  We still run the same
  // artefact-capture and DB-commit logic, just keyed off the response
  // `i` index rather than the session `phase`.
  // -----------------------------------------------------------------------

  /**
   * Route an indexed plan-mode response to the per-step handler.
   *
   * SW decoding matches the classical {@link handleCardResponse} exactly:
   * prefer `sw` when well-formed (4 hex chars), fall back to
   * last-4-hex-chars of `hex`, and synthesize 6F00 only if both are empty
   * (mobile-side NFC failure, not a chip error).  The critical difference
   * from classical mode: any non-9000 SW at ANY step is fatal, because
   * the phone has already committed to executing the subsequent steps.
   * We mark the session FAILED with a step-specific reason and rely on
   * the phone to abort remaining steps when it receives the {type:'error'}
   * reply.
   */
  private async handlePlanResponse(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const rawHex = msg.hex ?? '';
    const rawSw = msg.sw ?? '';
    const i = msg.i ?? -1;
    const appErrored = rawSw.length !== 4 && rawHex.length < 4;

    let sw: number;
    if (rawSw.length === 4) {
      sw = parseInt(rawSw, 16);
    } else if (rawHex.length >= 4) {
      sw = parseInt(rawHex.slice(-4), 16);
    } else {
      sw = 0x6f00;
    }

    const dataHex =
      rawHex.length >= 4 && rawHex.slice(-4).toLowerCase() === rawSw.toLowerCase()
        ? rawHex.slice(0, -4)
        : rawHex;
    const data = Buffer.from(dataHex, 'hex');

    if (sw !== 0x9000) {
      const swStr = sw.toString(16).padStart(4, '0').toUpperCase();
      if (appErrored) {
        console.warn(
          `[rca] plan-mode mobile NFC failure at step ${i} in session ${sessionId}: ` +
          `empty hex + empty sw.  Synthesizing 6F00.`,
        );
      } else {
        console.warn(
          `[rca] plan-mode chip error SW=${swStr} at step ${i} in session ${sessionId}`,
        );
      }
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: {
          phase: 'FAILED',
          failedAt: new Date(),
          failureReason: appErrored ? `NFC_ERROR_step_${i}` : `CARD_ERROR_${swStr}_step_${i}`,
        },
      });
      return [{
        type: 'error',
        code: appErrored ? 'NFC_ERROR' : 'CARD_ERROR',
        message: appErrored
          ? `Mobile NFC transceive failed at plan step ${i}`
          : `Card returned error SW=${swStr} at plan step ${i}`,
      }];
    }

    switch (i) {
      case 0: return []; // SELECT PA — phone parsed FCI locally; nothing to do server-side
      case 1: return this.handlePlanKeygen(sessionId, data);
      case 2: return []; // TRANSFER_SAD — PA returns STATUS bytes; no server action
      case 3: return this.handlePlanFinalStatus(sessionId, data);
      case 4: return this.handlePlanConfirm(sessionId);
      default:
        console.warn(`[rca] unexpected plan step index ${i} in session ${sessionId}`);
        return [];
    }
  }

  /**
   * Step 1: GENERATE_KEYS response — capture the chip's ECC P-256 public
   * key.  In the classical path this is handleKeygenResponse; plan mode
   * skips the state-machine transitions (no phase updates) because the
   * phone is already executing subsequent steps.
   *
   * Response body: ICC_PubKey(65) || Attest_Sig(~72) || CPLC(42).  We
   * store the first 65 bytes (uncompressed SEC1 pubkey 0x04 || X || Y)
   * for audit and future attestation verification.
   */
  private async handlePlanKeygen(sessionId: string, data: Buffer): Promise<WSMessage[]> {
    const iccPubkey = data.subarray(0, Math.min(65, data.length));
    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: { iccPublicKey: iccPubkey },
    });
    return [];
  }

  /**
   * Step 3: FINAL_STATUS response — the PA's success/fail verdict.
   *
   * Response byte layout:
   *   [0]           status — 0x01 = success, anything else = failure
   *   [1..33]       provenance hash (32 bytes)
   *   [65]          FIDO credId length
   *   [66..66+len]  FIDO credId
   *
   * SW=9000 only tells us the APDU was well-formed; the semantic success
   * signal is data[0] == 0x01.  On failure we mark the session FAILED
   * and emit {type:'error'} so the phone aborts before step 4 (CONFIRM).
   * On success we extract provenance + FIDO data and transition to
   * AWAITING_CONFIRM — the actual card/SAD commit happens in step 4
   * once CONFIRM lands 9000 (matches classical semantics: step 4 is
   * what latches the chip to COMMITTED state).
   */
  private async handlePlanFinalStatus(sessionId: string, data: Buffer): Promise<WSMessage[]> {
    const statusByte = data.length > 0 ? data[0] : 0;

    if (statusByte !== 0x01) {
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'FAILED', failedAt: new Date(), failureReason: 'PA_FAILED' },
      });
      return [{
        type: 'error',
        code: 'PA_FAILED',
        message: 'Provisioning failed on card',
      }];
    }

    const provHash = data.length > 33 ? data.subarray(1, 33).toString('hex') : '';
    let fidoCredData = '';
    if (data.length > 66) {
      const credIdLen = data[65];
      const credId = data.subarray(66, 66 + credIdLen);
      fidoCredData = credId.toString('base64url');
    }

    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'AWAITING_CONFIRM',
        provenance: provHash,
        fidoCredData,
      },
    });

    // No outbound message — phone is already executing step 4 locally.
    return [];
  }

  /**
   * Step 4: CONFIRM response — the chip has latched to COMMITTED.
   *
   * This is where we actually finalize the session: mark it COMPLETE,
   * flip Card.status to PROVISIONED, consume the SAD record, and fire
   * the async callback to the activation service.  The `complete`
   * response tells the phone the session ended successfully.
   *
   * Matches handleFinalStatus in the classical path, minus the CONFIRM
   * APDU send (phone already executed it before we got here).
   */
  private async handlePlanConfirm(sessionId: string): Promise<WSMessage[]> {
    const session = await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'COMPLETE',
        completedAt: new Date(),
      },
      include: { card: true, sadRecord: true },
    });

    await prisma.card.update({
      where: { id: session.cardId },
      data: { status: 'PROVISIONED', provisionedAt: new Date() },
    });

    await prisma.sadRecord.update({
      where: { id: session.sadRecordId },
      data: { status: 'CONSUMED' },
    });

    console.log(
      `[rca] plan-mode provisioning complete: session=${sessionId}, card=${session.cardId}`,
    );

    // Fire callback to activation service (async, non-blocking).
    this.fireCallback(session.card.cardRef, session.card.chipSerial ?? '').catch((err) =>
      console.error('[rca] callback failed:', err),
    );

    return [{
      type: 'complete',
      proxyCardId: session.sadRecord.proxyCardId,
    }];
  }

  /**
   * Handle app-reported error (NFC lost, etc.)
   */
  private async handleError(sessionId: string, msg: WSMessage): Promise<void> {
    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'FAILED',
        failedAt: new Date(),
        failureReason: msg.code ?? 'APP_ERROR',
      },
    });
    console.warn(
      `[rca] session error: ${sessionId} — ${msg.code}` +
      (msg.message ? `: ${msg.message}` : ''),
    );
  }

  /**
   * Fire HMAC-signed callback to the activation service.
   */
  private async fireCallback(cardRef: string, chipSerial: string): Promise<void> {
    const config = getRcaConfig();
    const { signRequest } = await import('@palisade/service-auth');
    const { request } = await import('undici');

    const path = `/api/cards/${encodeURIComponent(cardRef)}/provision-complete`;
    const body = JSON.stringify({ chipSerial });
    const bodyBuf = Buffer.from(body, 'utf8');

    const authorization = signRequest({
      method: 'POST',
      pathAndQuery: path,
      body: bodyBuf,
      keyId: 'rca',
      secret: config.CALLBACK_HMAC_SECRET,
    });

    await request(`${config.ACTIVATION_CALLBACK_URL}${path}`, {
      method: 'POST',
      headers: {
        authorization,
        'content-type': 'application/json',
      },
      body: bodyBuf,
    });
  }
}
