/**
 * Plan-mode APDU sequence builder.
 *
 * The legacy "classical" relay protocol sends one APDU per server-to-phone
 * round trip: pa_fci → GENERATE_KEYS → TRANSFER_SAD → FINAL_STATUS →
 * CONFIRM.  That's four sequential server-waits embedded in the NFC tap.
 * On bad connections (300-600 ms phone↔CloudFront RTT) each wait becomes a
 * stall measured in seconds.
 *
 * Plan mode: the server computes the entire APDU sequence up front and
 * ships it as a single {type:'plan'} message when the WebSocket opens.
 * The phone queues the plan locally, executes each step against the chip
 * as soon as NFC proximity holds, and streams responses back indexed by
 * step number.  The server validates responses asynchronously and only
 * sends one more message — `complete` on success or `error` on failure.
 *
 * This works today because every APDU in the provisioning chain is
 * server-known before the NFC exchange begins:
 *
 *   - SELECT PA: constant (AID A00000006250414C)
 *   - GENERATE_KEYS: constant (80E000000101 — no session-ID payload)
 *   - TRANSFER_SAD: computed from PlanContext (chipProfile DGI/tag, the
 *     IssuerProfile's bankId/progId/scheme/postProvisionUrl, plus the
 *     plaintext SAD bytes decrypted from SadRecord.sadEncrypted).  Does
 *     NOT depend on the chip's keygen response.
 *   - FINAL_STATUS: constant (80E6000000)
 *   - CONFIRM: constant (80E8000000)
 *
 * When we later need attestation verification BEFORE TRANSFER_SAD (today
 * it's stubbed to accept all NXP/Infineon silicon) we'll add a checkpoint
 * field to the plan: `{checkpointAfter: 1}` tells the phone to pause
 * after step 1 and await a server `continue` message before executing
 * step 2.  Deferred; not needed yet.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * One step in the provisioning plan.
 *
 * `expectSw` is the phone-side fail-fast hint — if the chip returns any
 * other status word, the phone aborts the plan and emits an error back to
 * the server.  It is NOT the only success signal: step 3 (FINAL_STATUS)
 * returns SW=9000 even when the PA's semantic status byte says "failed",
 * so the server checks data[0]===0x01 before committing.
 */
export interface PlanStep {
  /** Zero-based step index; also the key used on inbound response messages. */
  i: number;
  /** Uppercase hex of the full APDU (header + data + Le as applicable). */
  apdu: string;
  /** Human-readable phase name, surfaced in the mobile UI progress strip. */
  phase: string;
  /** 0.0–1.0 progress for the mobile UI after this step completes. */
  progress: number;
  /** Expected status word as uppercase 4-hex (e.g. "9000"). */
  expectSw: string;
}

export interface Plan {
  /** Message discriminator — WS sends as JSON. */
  type: 'plan';
  /** Bumped when the schema changes in a non-backward-compatible way. */
  version: 1;
  /** Steps, ordered.  Phone executes in `i`-ascending order. */
  steps: PlanStep[];
}

/**
 * Per-card inputs needed to assemble the TRANSFER_SAD APDU.  Sourced from
 * the session's linked ChipProfile, IssuerProfile, and decrypted SadRecord.
 *
 * All fields are required — callers that can't populate one should either
 * throw `issuer_profile_incomplete` before reaching this layer or fall
 * back to {@link minimalSadContext} behind the RCA_ALLOW_MINIMAL_SAD dev
 * flag.  We no longer tolerate hardcoded defaults here because the PA
 * writes these bytes to chip NVM verbatim; incorrect values silently
 * corrupt the card's post-personalisation state.
 */
export interface PlanContext {
  /** DGI tag the PA uses to address the ICC private key slot. */
  iccPrivateKeyDgi: number;
  /** EMV tag for the ICC private key (e.g. 0x9F48). */
  iccPrivateKeyTag: number;
  /** 4-byte big-endian bank identifier.  From IssuerProfile.bankId. */
  bankId: number;
  /** 4-byte big-endian program identifier.  From IssuerProfile.progId. */
  progId: number;
  /**
   * 1-byte scheme code the PA applet stores in NVM.
   *   0x01 = Mastercard (mchip_advance)
   *   0x02 = Visa (vsdc)
   * Resolve from IssuerProfile.scheme via {@link schemeByteForIssuer}.
   */
  scheme: number;
  /** Hostname (no protocol) the chip bakes into post-activation NDEF URLs. */
  postProvisionUrl: string;
  /**
   * Real plaintext SAD bytes.  Decrypted from SadRecord.sadEncrypted by
   * {@link SessionManager.buildPlanForSession} via
   * `DataPrepService.decryptSad`.  In dev-fallback mode this instead holds
   * the minimal in-applet-consumable [DGI(2)|len(1)|TLV 0x50 "PALISADE"]
   * blob.  Layout at the wire level is opaque to this module — we just
   * bolt the bytes in front of the metadata tail and let the PA parse.
   */
  sadPayload: Buffer;
}

// ---------------------------------------------------------------------------
// Constants (uppercase so the wire format is easy to grep in logs)
// ---------------------------------------------------------------------------

/**
 * SELECT the Palisade Provisioning Agent applet.  AID A00000006250414C is
 * the JavaCard converter default for com.palisade.pa (package AID
 * A0000000625041 + 1-byte module tag 0x4C).  Matches what Palisade's own
 * reference perso installs via `gp --install pa.cap` with no --create
 * override, and what the RCA relay-handler's classical-mode first APDU
 * sends today.
 */
const SELECT_PA_APDU = '00A4040008A00000006250414C';

/**
 * GENERATE_KEYS with a single-byte payload 0x01 ("ECC P-256 keypair").
 * Passing a session-ID payload appends bytes the PA discards (or worse —
 * returns 6D00).  Matches the exact bytes in Palisade's SSD e2e trace.
 */
const GENERATE_KEYS_APDU = '80E000000101';

/** FINAL_STATUS — zero-data case-2-style query. */
const FINAL_STATUS_APDU = '80E6000000';

/** CONFIRM — zero-data commit. */
const CONFIRM_APDU = '80E8000000';

/**
 * Minimal "PALISADE" SAD blob — one DGI 0x0101 carrying TLV 0x50
 * (App Label).  Structurally enough to get the PA to SW=9000 on
 * TRANSFER_SAD but writes no real EMV content; only used behind
 * RCA_ALLOW_MINIMAL_SAD=1 when the IssuerProfile is incomplete.
 */
export function buildMinimalSadPayload(): Buffer {
  const appLabel = Buffer.from('PALISADE', 'ascii');
  const tlv50 = Buffer.concat([Buffer.from([0x50, appLabel.length]), appLabel]);
  return Buffer.concat([Buffer.from([0x01, 0x01, tlv50.length]), tlv50]);
}

/**
 * Map an IssuerProfile.scheme string to the 1-byte scheme code the PA
 * applet's processTransferSad() records in chip NVM.
 *
 *   "mchip_advance" → 0x01 (Mastercard)
 *   "vsdc"          → 0x02 (Visa)
 *
 * Throws for any other value so a misconfigured profile fails loudly at
 * plan build time rather than writing 0x00 into the chip.
 */
export function schemeByteForIssuer(scheme: string): number {
  switch (scheme) {
    case 'mchip_advance': return 0x01;
    case 'vsdc':          return 0x02;
    default:
      throw new Error(
        `plan-builder: unknown IssuerProfile.scheme='${scheme}' ` +
        `(expected 'mchip_advance' or 'vsdc')`,
      );
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build the full 5-step provisioning plan for a session.
 *
 * Pure function — takes only the context assembled by the caller.  Callers
 * that need a session-scoped plan (e.g. {@link buildPlanForSession}) load
 * the context from the database first and then delegate here.  This split
 * keeps the APDU-assembly code unit-testable without a DB.
 */
export function buildProvisioningPlan(ctx: PlanContext): Plan {
  const transferSadApdu = buildTransferSadApdu(ctx).toString('hex').toUpperCase();

  const steps: PlanStep[] = [
    { i: 0, apdu: SELECT_PA_APDU,     phase: 'select_pa',      progress: 0.05, expectSw: '9000' },
    { i: 1, apdu: GENERATE_KEYS_APDU, phase: 'key_generation', progress: 0.25, expectSw: '9000' },
    { i: 2, apdu: transferSadApdu,    phase: 'provisioning',   progress: 0.55, expectSw: '9000' },
    { i: 3, apdu: FINAL_STATUS_APDU,  phase: 'finalizing',     progress: 0.80, expectSw: '9000' },
    { i: 4, apdu: CONFIRM_APDU,       phase: 'confirming',     progress: 0.95, expectSw: '9000' },
  ];

  return { type: 'plan', version: 1, steps };
}

// ---------------------------------------------------------------------------
// TRANSFER_SAD assembly
// ---------------------------------------------------------------------------

/**
 * Build the TRANSFER_SAD command APDU (CLA=80, INS=E2).
 *
 * Data layout is PA-specific — the applet parses the buffer from the end
 * (palisade-pa/src/com/palisade/pa/ProvisioningAgent.java:481):
 *
 *   [SAD_DGIs:var] [bank_id:4] [prog_id:4] [scheme:1] [ts:4]
 *     [url:var] [url_len:1] [iccPrivDgi:2] [iccPrivEmvTag:2]
 *
 * The SAD_DGIs here can be either:
 *   - real plaintext SAD bytes decrypted from SadRecord.sadEncrypted
 *     (production / e2e once the IssuerProfile is fully populated), or
 *   - the minimal DGI 0x0101 + TLV 0x50 "PALISADE" stub
 *     (dev-fallback under RCA_ALLOW_MINIMAL_SAD=1).
 *
 * bank_id / prog_id / scheme / url are now sourced from the IssuerProfile
 * row — they land in chip NVM verbatim, so passing placeholders here
 * would corrupt the card's post-personalisation identity.
 */
export function buildTransferSadApdu(ctx: PlanContext): Buffer {
  const sadPayload = ctx.sadPayload;

  const bankId = Buffer.alloc(4);
  bankId.writeUInt32BE(ctx.bankId >>> 0, 0);
  const progId = Buffer.alloc(4);
  progId.writeUInt32BE(ctx.progId >>> 0, 0);
  const scheme = Buffer.from([ctx.scheme & 0xff]);

  const timestamp = Math.floor(Date.now() / 1000);
  const tsBuf = Buffer.alloc(4);
  tsBuf.writeUInt32BE(timestamp, 0);

  const bankUrl = Buffer.from(ctx.postProvisionUrl, 'ascii');
  if (bankUrl.length > 0xff) {
    throw new Error(
      `plan-builder: postProvisionUrl too long (${bankUrl.length} bytes, max 255)`,
    );
  }
  const urlLen = Buffer.from([bankUrl.length]);

  const dgiTag = Buffer.alloc(2);
  dgiTag.writeUInt16BE(ctx.iccPrivateKeyDgi, 0);
  const emvTag = Buffer.alloc(2);
  emvTag.writeUInt16BE(ctx.iccPrivateKeyTag, 0);

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
  if (lc <= 255) {
    return Buffer.concat([
      Buffer.from([0x80, 0xE2, 0x00, 0x00, lc]),
      transferData,
    ]);
  }

  // Extended-length APDU path — kicks in once real SAD bytes push the
  // payload past 255.  Header becomes 80 E2 00 00 00 Lc-hi Lc-lo.
  const lcBuf = Buffer.alloc(2);
  lcBuf.writeUInt16BE(lc, 0);
  return Buffer.concat([
    Buffer.from([0x80, 0xE2, 0x00, 0x00, 0x00]),
    lcBuf,
    transferData,
  ]);
}
