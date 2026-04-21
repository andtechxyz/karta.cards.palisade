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
 *   - GENERATE_KEYS: constant (80E00000010100 — no session-ID payload, case-4)
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

import { wrapParamBundle, serializeWrappedBundle } from '@palisade/emv-ecdh';

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
 * SELECT the Palisade T4T applet (pav2).  AID D2760000850101 is the NFC
 * Forum Type 4 Tag standard AID and is what the chip SELECTs by default
 * on a bare NDEF tap.  Used by the optional chip-challenge plan-step
 * sequence (see `includeChipChallenge` below).
 */
const SELECT_PAV2_APDU = '00A4040007D2760000850101';

/**
 * GET_CHALLENGE on pav2: CLA=80 INS=EC P1=00 P2=00 Le=10 (16 bytes).
 * Returns 16 bytes of on-chip RNG + SW=9000.  Part of the optional
 * chip-challenge path — see `includeChipChallenge` below for the full
 * rationale.
 */
const GET_CHALLENGE_APDU = '80EC000010';

/**
 * GENERATE_KEYS with a single-byte payload 0x01 ("ECC P-256 keypair").
 * Passing a session-ID payload appends bytes the PA discards (or worse —
 * returns 6D00).  Trailing 00 is Le for the 65-byte pubkey response;
 * pa-v3 rejects case-3 form (no Le) with SW=6700 when
 * setOutgoingAndSend tries to emit the pubkey.  pa-v1 typically got
 * the Le added by its reader, but phones don't, so we send case-4
 * explicitly.
 */
const GENERATE_KEYS_APDU = '80E00000010100';

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
 * Opt-in flags for the plan builder.  Defaults preserve the 5-step
 * sequence so existing provisioning flows are unchanged.
 *
 * `includeChipChallenge` — when set, prepend SELECT pav2 +
 *    GET_CHALLENGE to the plan.  The returned 16-byte nonce is
 *    recorded in the session audit trail.
 *
 *    **Not needed for SAD replay prevention.**  Replay is already
 *    enforced server-side via the `SadRecord.status: READY → CONSUMED`
 *    transition inside the provisioning `$transaction` — a consumed
 *    SAD cannot be re-emitted by /api/provisioning/start, so there's
 *    nothing for the mobile to relay on a replay attempt.
 *
 *    The flag exists for an optional chip-side defence-in-depth path:
 *    once the PA applet is updated to look up a pav2 Shareable
 *    Interface Object and verify the SAD's trailing 16 bytes against
 *    the last issued challenge, enabling this flag closes the
 *    narrow "compromised backend replays old SAD" threat model.
 *    Until that applet work + fleet re-perso ships, the chip side
 *    doesn't consume the nonce, so turning this on today adds 2 NFC
 *    RTTs of latency for audit-trail enrichment only.  Default off.
 */
export interface PlanOptions {
  includeChipChallenge?: boolean;
}

/**
 * Build the full provisioning plan for a session.  The canonical
 * sequence is 5 steps (SELECT_PA → GENERATE_KEYS → TRANSFER_SAD →
 * FINAL_STATUS → CONFIRM); with `includeChipChallenge` set it becomes
 * 7 steps (SELECT_PAV2 → GET_CHALLENGE → SELECT_PA → …).
 *
 * Pure function — takes only the context assembled by the caller.  Callers
 * that need a session-scoped plan (e.g. {@link buildPlanForSession}) load
 * the context from the database first and then delegate here.  This split
 * keeps the APDU-assembly code unit-testable without a DB.
 */
export function buildProvisioningPlan(
  ctx: PlanContext,
  options: PlanOptions = {},
): Plan {
  const transferSadApdu = buildTransferSadApdu(ctx).toString('hex').toUpperCase();

  const steps: PlanStep[] = [];
  let i = 0;

  if (options.includeChipChallenge) {
    // Chip-challenge defence-in-depth path (off by default).  Audit-
    // trail-only today: the 16-byte nonce is captured in the session's
    // apduLog but not consumed by the chip.  Becomes enforcement when
    // the PA applet is updated to look up pav2's Shareable Interface
    // and compare against the SAD's trailing bytes.  See PlanOptions
    // docstring + applets/pav2/README.md for the full rationale.
    steps.push({
      i: i++, apdu: SELECT_PAV2_APDU,  phase: 'chip_challenge_select', progress: 0.02, expectSw: '9000',
    });
    steps.push({
      i: i++, apdu: GET_CHALLENGE_APDU, phase: 'chip_challenge_fetch',  progress: 0.04, expectSw: '9000',
    });
  }

  steps.push(
    { i: i++, apdu: SELECT_PA_APDU,     phase: 'select_pa',      progress: 0.05, expectSw: '9000' },
    { i: i++, apdu: GENERATE_KEYS_APDU, phase: 'key_generation', progress: 0.25, expectSw: '9000' },
    { i: i++, apdu: transferSadApdu,    phase: 'provisioning',   progress: 0.55, expectSw: '9000' },
    { i: i++, apdu: FINAL_STATUS_APDU,  phase: 'finalizing',     progress: 0.80, expectSw: '9000' },
    { i: i++, apdu: CONFIRM_APDU,       phase: 'confirming',     progress: 0.95, expectSw: '9000' },
  );

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

  // Extended-length APDU path.  See buildParamBundleApdu for the
  // rationale on the trailing Le=0x0000 (case-4 extended) — iOS CoreNFC
  // rejects case-3 extended at the ISO-DEP transmit layer.  pa-v1 never
  // hit this branch in production (SAD blobs stayed under 255 B), so
  // the code was right-looking but untested via real NFC.
  const lcBuf = Buffer.alloc(2);
  lcBuf.writeUInt16BE(lc, 0);
  return Buffer.concat([
    Buffer.from([0x80, 0xE2, 0x00, 0x00, 0x00]),  // 5 B header + ext marker
    lcBuf,                                         // 2 B Lc-hi Lc-lo
    transferData,                                  // N B body
    Buffer.from([0x00, 0x00]),                     // 2 B Le = "max"
  ]);
}

// ---------------------------------------------------------------------------
// TRANSFER_PARAMS assembly (chip-computed-DGI prototype)
// ---------------------------------------------------------------------------

/**
 * Build the TRANSFER_PARAMS APDU for pa-v3.  Same CLA/INS (0x80 0xE2)
 * as TRANSFER_SAD but with a wholly different body: an ECDH-wrapped
 * ParamBundle instead of a pre-built DGI stream.
 *
 * Wire body:
 *   server_ephemeral_pub_uncompressed (65 B)
 *   || nonce (12 B)
 *   || ciphertext (variable — ~400 B for a full MChip CVN 18 bundle)
 *   || gcm_tag (16 B)
 *
 * Total body length is typically ~500 B, which forces extended-APDU
 * encoding (Lc = 0x00 Lc-hi Lc-lo) for most real bundles.
 *
 * Inputs:
 *   - plaintextBundle: the TLV ParamBundle bytes produced by
 *     @palisade/emv's buildMChipParamBundle (server-side at
 *     data-prep.prepareParamBundle time), decrypted from
 *     ParamRecord.bundleEncrypted just before we get here.
 *   - chipPubUncompressed: the 65-byte SEC1 pubkey returned in the
 *     GENERATE_KEYS response immediately prior.
 *   - sessionId: the ProvisioningSession.id — mixed into HKDF info
 *     so the bundle is bound to a specific session.
 *
 * Caller is responsible for scrubbing `plaintextBundle` after this
 * function returns — same pattern as `buildTransferSadApdu` scrubbing
 * `ctx.sadPayload` in the rca handler.
 */
export function buildParamBundleApdu(input: {
  plaintextBundle: Buffer;
  chipPubUncompressed: Buffer;
  sessionId: string;
}): Buffer {
  const chunks = buildParamBundleApduChunks(input);
  // Back-compat: single APDU callers still get a single Buffer.
  // Multi-chunk callers (session-manager handleKeygenResponse) should
  // call buildParamBundleApduChunks directly.
  if (chunks.length !== 1) {
    throw new Error(
      `buildParamBundleApdu: wire body ${/* computed inside */''} bytes split into ${chunks.length} chunks; caller must use buildParamBundleApduChunks`,
    );
  }
  return chunks[0];
}

/**
 * Maximum body bytes per chained short APDU chunk.  Per ISO 7816-4 a
 * short APDU body maxes at 255 B; leaving 15 B of headroom for future
 * per-chunk metadata (chunk index, total count) if we ever need it —
 * negligible wire overhead given a full 721 B body fits in 4 chunks
 * either way (721 / 240 = 4 chunks vs 721 / 255 = 3 chunks).
 */
const TRANSFER_PARAMS_CHUNK_SIZE = 240;

/**
 * Build the TRANSFER_PARAMS APDU(s) for pa-v3.  Returns an ordered
 * array that the caller emits one at a time over the WS.
 *
 * Framing decision is driven by wire body size:
 *
 *   - wire <= 255 B  → single short APDU, CLA=0x80
 *   - wire  > 255 B  → N chained short APDUs, 240 B max body each,
 *                      CLA=0x90 for all non-final chunks (bit 4 set
 *                      = "more data follows"), CLA=0x80 for the last.
 *
 * Why not case-4 extended (Lc = 00 Lc-hi Lc-lo + Le = 00 00)?
 * iOS CoreNFC + JCOP 5 JC 3.0.4 silicon reject that framing at the
 * ISO-DEP transmit layer (observed SW=6700 across four consecutive
 * real-card taps).  Chained short APDUs work on the same stack that
 * carries pa-v1's TRANSFER_SAD, so this is the strictly-safer
 * framing.  pa-v3's processTransferParams handles both (extended via
 * receiveBytes loop, chained via chainOff accumulator) — we pick the
 * chained form here because it's the one actually verified on-wire.
 */
export function buildParamBundleApduChunks(input: {
  plaintextBundle: Buffer;
  chipPubUncompressed: Buffer;
  sessionId: string;
}): Buffer[] {
  const wrapped = wrapParamBundle({
    chipPubUncompressed: input.chipPubUncompressed,
    plaintext: input.plaintextBundle,
    sessionId: input.sessionId,
  });
  const wire = serializeWrappedBundle(wrapped);

  // Single short APDU — use the ≤255 path.
  if (wire.length <= 255) {
    return [
      Buffer.concat([
        Buffer.from([0x80, 0xE2, 0x00, 0x00, wire.length]),
        wire,
      ]),
    ];
  }

  // Chain the wire body into N chunks.  All chunks share INS/P1/P2;
  // CLA is 0x90 (chain bit on) for all but the last, 0x80 (chain
  // bit off) for the last.  Last chunk is CASE-4 (trailing Le) so the
  // chip has an outgoing slot for the IV-mismatch diagnostic blob
  // (32 B: chip_iv || wire_iv) — a harmless ~32-byte bump when
  // everything's working, invaluable when they don't match.
  const chunks: Buffer[] = [];
  let off = 0;
  while (off < wire.length) {
    const remaining = wire.length - off;
    const thisLen = Math.min(TRANSFER_PARAMS_CHUNK_SIZE, remaining);
    const isLast = off + thisLen >= wire.length;
    const cla = isLast ? 0x80 : 0x90;
    const parts: Buffer[] = [
      Buffer.from([cla, 0xE2, 0x00, 0x00, thisLen]),
      wire.subarray(off, off + thisLen),
    ];
    if (isLast) {
      // Le=0x20 (32 B — exactly what EcdhUnwrapper.DBG_IV_DIAG_LEN
      // emits on IV mismatch).  Chip returns 0 bytes on success with
      // this Le; returns 32 B + SW=6AE4 on mismatch.
      parts.push(Buffer.from([0x20]));
    }
    chunks.push(Buffer.concat(parts));
    off += thisLen;
  }
  return chunks;
}
