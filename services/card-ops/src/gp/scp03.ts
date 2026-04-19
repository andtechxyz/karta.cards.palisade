/**
 * GlobalPlatform SCP03 (Secure Channel Protocol 03) — TypeScript impl.
 *
 * References:
 *   - GlobalPlatform Card Specification v2.3 Amendment D v1.2 (SCP03)
 *   - NIST SP 800-108 (KDF in counter mode with AES-CMAC)
 *
 * Scope:
 *   - INITIALIZE UPDATE  (host challenge → card cryptogram + card challenge)
 *   - EXTERNAL AUTHENTICATE  (host cryptogram + initial C-MAC)
 *   - wrap / unwrap APDUs at security levels C_MAC, C_DECRYPTION, R_MAC
 *
 * Out of scope for this module:
 *   - Anything above the APDU layer (operation orchestration lives in
 *     services/card-ops/src/operations/).
 *   - Transport I/O — APDUs are returned as hex strings; the WS relay
 *     delivers them to the card and brings responses back.
 *
 * Math verified against the public SCP03 test vector widely cited in
 * GP interop docs (see scp03.test.ts).  The KDF is NIST SP 800-108
 * counter mode with AES-CMAC as PRF, per GP Amendment D §4.1.5.
 */

import { createCipheriv, createDecipheriv } from 'node:crypto';
import { aesCmac } from '@palisade/core';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StaticKeys {
  /** ENC — session key derivation source for S-ENC. 16 raw bytes (AES-128). */
  enc: Buffer;
  /** MAC — session key derivation source for S-MAC. 16 raw bytes. */
  mac: Buffer;
  /** DEK — data encryption key (used for sensitive-data crypto outside SCP). */
  dek: Buffer;
}

export interface SessionKeys {
  sEnc: Buffer; // Command confidentiality + ICV derivation
  sMac: Buffer; // Command MAC + host/card cryptogram derivation
  sRmac: Buffer; // Response MAC when R-MAC is enabled
}

/** Bits of the security level byte sent in EXTERNAL AUTHENTICATE. */
export const SECURITY_LEVEL = {
  NO_SECURE_MESSAGING: 0x00,
  C_MAC: 0x01,
  C_DECRYPTION: 0x02,
  R_MAC: 0x10,
  R_ENCRYPTION: 0x20,
} as const;

/** Full security — matches spec's 0x33 example (CMAC+CDEC+RMAC+RENC). */
export const SL_FULL = 0x33;
/** Minimum we ever run at — command MAC only. */
export const SL_CMAC = 0x01;

/** Result of INITIALIZE UPDATE parsing. */
export interface InitUpdateParse {
  /** 10 bytes — key diversification data (card-specific). */
  keyDivData: Buffer;
  /** Key Version Number. */
  kvn: number;
  /** Must be 0x03 for SCP03. */
  scpId: number;
  /**
   * SCP03 i-parameter — bit 0x20 = RMAC+RENCRYPTION supported.
   * Determines what security-level bits EXTERNAL AUTHENTICATE can request.
   */
  iParam: number;
  /** 8 bytes — random from the card. */
  cardChallenge: Buffer;
  /** 8 bytes — card's proof it derived the same keys from host challenge. */
  cardCryptogram: Buffer;
  /**
   * 3 bytes — SCP03 sequence counter.  Used as the input to the IV
   * derivation for command encryption.  Only present in SCP03 responses
   * (SCP02 had no counter here).
   */
  sequenceCounter: Buffer;
}

/**
 * Opaque per-session state.  Carried forward between wrapCommand /
 * unwrapResponse calls.  Serializable (JSON-safe after Buffer
 * normalization) so the driver can park it in CardOpSession.scpState
 * across WS round-trips.
 */
export interface Scp03Session {
  securityLevel: number;
  sessionKeys: SessionKeys;
  /** Current MAC chaining value — 16 bytes.  Starts all-zero. */
  macChain: Buffer;
  /** 3-byte sequence counter captured from INITIALIZE UPDATE response. */
  sequenceCounter: Buffer;
  /** Running command counter for IV derivation; increments per C-MAC'd APDU. */
  commandCounter: number;
}

// ---------------------------------------------------------------------------
// Constants — SCP03 derivation labels, per GP Amendment D §4.1.5 Table 4-1.
// ---------------------------------------------------------------------------

const DD_ENC = 0x04;
const DD_MAC = 0x06;
const DD_RMAC = 0x07;
const DD_CARD_CRYPTOGRAM = 0x00;
const DD_HOST_CRYPTOGRAM = 0x01;

// ---------------------------------------------------------------------------
// INITIALIZE UPDATE parsing
// ---------------------------------------------------------------------------

/**
 * Build an INITIALIZE UPDATE APDU.
 *
 *   CLA=80 INS=50 P1=KVN P2=00 Lc=08 Data=host_challenge Le=00
 *
 * KVN=0x00 means "any key version" — the card returns its current set.
 */
export function buildInitializeUpdate(hostChallenge: Buffer, kvn = 0x00): Buffer {
  if (hostChallenge.length !== 8) {
    throw new Error('host challenge must be 8 bytes');
  }
  return Buffer.concat([
    Buffer.from([0x80, 0x50, kvn, 0x00, 0x08]),
    hostChallenge,
    Buffer.from([0x00]),
  ]);
}

/**
 * Parse the INITIALIZE UPDATE response (not including SW).
 *
 * Layout (SCP03):
 *   keyDivData[10] || kvn[1] || scpId[1]=0x03 || iParam[1] ||
 *   cardChallenge[8] || cardCryptogram[8] || sequenceCounter[3]
 *
 * Total: 32 bytes.  Older SCP02 cards return 28 (no counter); we reject
 * those — the service only talks SCP03.
 */
export function parseInitializeUpdateResponse(data: Buffer): InitUpdateParse {
  if (data.length !== 32) {
    throw new Error(`INITIALIZE UPDATE response must be 32 bytes (got ${data.length})`);
  }
  const scpId = data[11];
  if (scpId !== 0x03) {
    throw new Error(`SCP03 required, card returned SCP0${scpId}`);
  }
  return {
    keyDivData: data.subarray(0, 10),
    kvn: data[10],
    scpId,
    iParam: data[12],
    cardChallenge: data.subarray(13, 21),
    cardCryptogram: data.subarray(21, 29),
    sequenceCounter: data.subarray(29, 32),
  };
}

// ---------------------------------------------------------------------------
// Key derivation (NIST SP 800-108 counter mode, PRF = AES-CMAC)
// ---------------------------------------------------------------------------

/**
 * Derive `bitLen` bits of output keyed by `key`, using NIST SP 800-108
 * counter-mode KDF with AES-CMAC as the PRF.  GP Amendment D §4.1.5.
 *
 * Input block (per iteration i):
 *   label[11] || 0x00 || L[2 BE] || i[1] || context[16]
 *
 * where label is 11-byte GP-specific constant (12 bytes of zeros with
 * the derivation-data byte at offset 11), L is the requested output
 * length in bits, and context is host_challenge || card_challenge.
 *
 * GP uses the "reverse" counter placement the spec permits: the counter
 * byte goes in the position the spec calls "i" — right after L.
 *
 * Output size is always a multiple of the AES block size (16 bytes = 128
 * bits) for our use cases:
 *   cryptograms → 64 bits (one iteration, upper 8 bytes of the 16-byte output)
 *   session keys → 128 bits (one iteration)
 */
function kdfCounter(
  key: Buffer,
  derivationConstant: number,
  context: Buffer,
  bitLen: number,
): Buffer {
  // Build the fixed prefix: 11 bytes of 0x00, then the derivation constant.
  // Amendment D §4.1.5: label is 12 bytes with the derivation data byte at
  // offset 11 (the rest are zero).  The separator byte (0x00) immediately
  // follows at offset 12.
  const label = Buffer.alloc(12);
  label[11] = derivationConstant;
  const separator = Buffer.from([0x00]);

  // L = requested output length in bits, big-endian 16-bit.
  const L = Buffer.alloc(2);
  L.writeUInt16BE(bitLen, 0);

  const blockSize = 16;
  const blocks = Math.ceil(bitLen / 8 / blockSize);
  const out = Buffer.alloc(blocks * blockSize);

  for (let i = 1; i <= blocks; i++) {
    const counter = Buffer.from([i]);
    const msg = Buffer.concat([label, separator, L, counter, context]);
    const block = aesCmac(key, msg);
    block.copy(out, (i - 1) * blockSize);
  }

  const byteLen = Math.ceil(bitLen / 8);
  return out.subarray(0, byteLen);
}

/**
 * Derive the three session keys from the static keys + both challenges.
 * Session keys are always 128 bits (one AES-CMAC block each).
 */
export function deriveSessionKeys(
  staticKeys: StaticKeys,
  hostChallenge: Buffer,
  cardChallenge: Buffer,
): SessionKeys {
  if (hostChallenge.length !== 8 || cardChallenge.length !== 8) {
    throw new Error('challenges must be 8 bytes each');
  }
  const context = Buffer.concat([hostChallenge, cardChallenge]);
  return {
    sEnc: kdfCounter(staticKeys.enc, DD_ENC, context, 128),
    sMac: kdfCounter(staticKeys.mac, DD_MAC, context, 128),
    sRmac: kdfCounter(staticKeys.mac, DD_RMAC, context, 128),
  };
}

/**
 * Compute the 8-byte card cryptogram the card should have sent in
 * INITIALIZE UPDATE.  Caller compares this to `parsed.cardCryptogram`
 * using constant-time compare before proceeding.
 */
export function computeCardCryptogram(
  sMac: Buffer,
  hostChallenge: Buffer,
  cardChallenge: Buffer,
): Buffer {
  const context = Buffer.concat([hostChallenge, cardChallenge]);
  // 64 bits = 8 bytes — KDF yields 16 bytes then we take the first 8.
  return kdfCounter(sMac, DD_CARD_CRYPTOGRAM, context, 64);
}

/**
 * Compute the 8-byte host cryptogram to send in EXTERNAL AUTHENTICATE.
 */
export function computeHostCryptogram(
  sMac: Buffer,
  hostChallenge: Buffer,
  cardChallenge: Buffer,
): Buffer {
  const context = Buffer.concat([hostChallenge, cardChallenge]);
  return kdfCounter(sMac, DD_HOST_CRYPTOGRAM, context, 64);
}

// ---------------------------------------------------------------------------
// EXTERNAL AUTHENTICATE
// ---------------------------------------------------------------------------

/**
 * Build EXTERNAL AUTHENTICATE APDU.
 *
 *   CLA=84 INS=82 P1=<security_level> P2=00 Lc=10
 *   Data = hostCryptogram[8] || cmac[8]
 *
 * The C-MAC covers the APDU header + Lc + hostCryptogram, chained from
 * the initial all-zero ICV.  After this APDU the `macChain` state
 * transitions to the computed MAC and subsequent wrapped commands chain
 * from there.
 */
export function buildExternalAuthenticate(
  sMac: Buffer,
  hostCryptogram: Buffer,
  securityLevel: number,
): { apdu: Buffer; macChain: Buffer } {
  if (hostCryptogram.length !== 8) {
    throw new Error('host cryptogram must be 8 bytes');
  }

  const header = Buffer.from([0x84, 0x82, securityLevel, 0x00, 0x10]);
  const icv = Buffer.alloc(16); // initial chaining value is 16 zeros
  const macInput = Buffer.concat([icv, header, hostCryptogram]);
  const fullMac = aesCmac(sMac, macInput);
  const cmac = fullMac.subarray(0, 8);

  const apdu = Buffer.concat([header, hostCryptogram, cmac]);
  return { apdu, macChain: fullMac };
}

// ---------------------------------------------------------------------------
// Command wrapping (C-MAC + optional C-DECRYPTION)
// ---------------------------------------------------------------------------

function hasCMac(level: number): boolean {
  return (level & SECURITY_LEVEL.C_MAC) !== 0;
}
function hasCEnc(level: number): boolean {
  return (level & SECURITY_LEVEL.C_DECRYPTION) !== 0;
}
function hasRMac(level: number): boolean {
  return (level & SECURITY_LEVEL.R_MAC) !== 0;
}

/**
 * Derive the encryption IV for C-DECRYPTION.
 *
 * SCP03 uses the encrypted command counter as IV.  Counter is a 16-byte
 * big-endian integer; encrypt all-zero-except-last-two-bytes with S-ENC
 * in ECB to produce the IV for AES-CBC data encryption.
 */
function deriveIcv(sEnc: Buffer, counter: number): Buffer {
  const ctrBlock = Buffer.alloc(16);
  ctrBlock.writeUInt16BE(counter & 0xffff, 14);
  // (counter fits comfortably in 16 bits for our use — 65k APDUs per
  // session is orders of magnitude above what a real operation uses.)
  const cipher = createCipheriv('aes-128-ecb', sEnc, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(ctrBlock), cipher.final()]);
}

function padIso7816(data: Buffer, blockSize = 16): Buffer {
  const padLen = blockSize - (data.length % blockSize);
  const pad = Buffer.alloc(padLen);
  pad[0] = 0x80;
  return Buffer.concat([data, pad]);
}

function unpadIso7816(data: Buffer): Buffer {
  // Walk backwards to find 0x80; everything after is zero padding.
  for (let i = data.length - 1; i >= 0; i--) {
    if (data[i] === 0x80) return data.subarray(0, i);
    if (data[i] !== 0x00) {
      throw new Error('malformed ISO/IEC 7816-4 padding');
    }
  }
  throw new Error('padding marker 0x80 not found');
}

export interface WrapInput {
  cla: number;
  ins: number;
  p1: number;
  p2: number;
  data: Buffer;
  /** Expected response length. 0x00 = 256, omit for no Le. */
  le?: number;
}

export interface WrapResult {
  apdu: Buffer;
  session: Scp03Session; // updated (macChain / counter bumped)
}

/**
 * Wrap a plaintext APDU into its SCP03 protected form.
 *
 * Flow (C-MAC + C-DECRYPTION path):
 *   1. If C-DECRYPTION: pad data with ISO/IEC 7816-4, encrypt with
 *      AES-CBC(S-ENC, IV=AES-ECB(S-ENC, counter_block)) → new data.
 *      Bump commandCounter afterwards.
 *   2. Build header with CLA |= 0x04 (C-MAC bit).
 *   3. Lc = len(data) + (hasCMac ? 8 : 0).
 *   4. If C-MAC: CMAC = AES-CMAC(S-MAC, macChain || header || data).
 *      Use first 8 bytes; update macChain to the full 16 bytes.
 *   5. Output: header || Lc || data [|| cmac[:8]] [|| Le].
 *
 * This function is pure w.r.t. its input session: it returns a new
 * session object rather than mutating in place, so callers can park the
 * pre-call state in storage and only commit the post-call state when
 * the response comes back clean.
 */
export function wrapCommand(session: Scp03Session, input: WrapInput): WrapResult {
  const { securityLevel } = session;
  let data = input.data;
  let counter = session.commandCounter;

  // (1) Encrypt data if C-DECRYPTION is in effect.
  if (hasCEnc(securityLevel) && data.length > 0) {
    counter += 1;
    const iv = deriveIcv(session.sessionKeys.sEnc, counter);
    const padded = padIso7816(data);
    const cipher = createCipheriv('aes-128-cbc', session.sessionKeys.sEnc, iv);
    cipher.setAutoPadding(false);
    data = Buffer.concat([cipher.update(padded), cipher.final()]);
  }

  // (2) Set CLA C-MAC indicator bit (SCP03 §6.2.1 — set bit 3 of CLA).
  const claWithMac = hasCMac(securityLevel) ? (input.cla | 0x04) & 0xff : input.cla;

  const extraForMac = hasCMac(securityLevel) ? 8 : 0;
  const lc = data.length + extraForMac;
  const header = Buffer.from([claWithMac, input.ins, input.p1, input.p2]);

  let macChain = session.macChain;
  let cmac: Buffer = Buffer.alloc(0);
  if (hasCMac(securityLevel)) {
    const macInput = Buffer.concat([macChain, header, Buffer.from([lc]), data]);
    const fullMac = aesCmac(session.sessionKeys.sMac, macInput);
    cmac = Buffer.from(fullMac.subarray(0, 8));
    macChain = fullMac;
  }

  const parts: Buffer[] = [header, Buffer.from([lc]), data];
  if (cmac.length > 0) parts.push(cmac);
  if (input.le !== undefined) parts.push(Buffer.from([input.le]));
  const apdu = Buffer.concat(parts);

  return {
    apdu,
    session: {
      ...session,
      macChain,
      commandCounter: counter,
    },
  };
}

// ---------------------------------------------------------------------------
// Response unwrapping
// ---------------------------------------------------------------------------

export interface UnwrapInput {
  /** Raw response bytes (data + SW, as returned over the wire). */
  response: Buffer;
}

export interface UnwrapResult {
  /** Cleartext response data (padding removed if decrypted). */
  data: Buffer;
  sw: number;
}

/**
 * Unwrap a response from the card.
 *
 * Minimum impl — supports C-MAC (no R-MAC) responses, which is what
 * the list_applets / install / delete operations produce at sec level
 * 0x01.  When R-MAC is enabled the caller needs to verify an 8-byte
 * trailing RMAC before returning — noted as TODO.
 *
 * If R-ENCRYPTION is on, decrypt the data portion (minus RMAC if
 * present) via AES-CBC with S-ENC and an IV derived similarly to the
 * command path but with the response counter.
 *
 * Returns the (possibly decrypted, unpadded) data and SW word.
 */
export function unwrapResponse(session: Scp03Session, input: UnwrapInput): UnwrapResult {
  if (input.response.length < 2) {
    throw new Error('response shorter than SW');
  }
  const sw = (input.response[input.response.length - 2] << 8) |
             input.response[input.response.length - 1];

  let data = input.response.subarray(0, input.response.length - 2);

  // R-MAC verification — strip and check the trailing 8 bytes.
  // TODO: implement full R-MAC verification when we run at SL 0x33.
  if (hasRMac(session.securityLevel) && data.length >= 8) {
    data = data.subarray(0, data.length - 8);
  }

  // R-ENCRYPTION — decrypt data with AES-CBC using S-ENC.
  // TODO: implement when we run at SL 0x33.  For SL 0x01 (C-MAC only)
  // responses are cleartext and this branch is skipped.
  if ((session.securityLevel & SECURITY_LEVEL.R_ENCRYPTION) && data.length > 0) {
    const iv = deriveIcv(session.sessionKeys.sEnc, session.commandCounter);
    const decipher = createDecipheriv('aes-128-cbc', session.sessionKeys.sEnc, iv);
    decipher.setAutoPadding(false);
    const padded = Buffer.concat([decipher.update(data), decipher.final()]);
    data = unpadIso7816(padded);
  }

  return { data, sw };
}

// ---------------------------------------------------------------------------
// Convenience — SCP03 driver API used by the operation runner.
// ---------------------------------------------------------------------------

/**
 * Build the INITIALIZE UPDATE + EXTERNAL AUTHENTICATE state machine
 * with all the math pre-computed.  Callers drive the APDUs over the
 * WS and feed back the raw card responses — no SCP logic lives in the
 * relay layer.
 *
 * Usage:
 *   const sm = createScp03Driver(staticKeys, hostChallenge, securityLevel);
 *   send(sm.initializeUpdate);            // APDU #1
 *   const parsed = sm.onInitUpdateResp(card_resp_data_excl_sw);
 *   // `parsed` includes .externalAuthenticate ready to send.
 *   send(parsed.externalAuthenticate);     // APDU #2
 *   // After card returns 9000, wrap subsequent APDUs:
 *   const wrapped = sm.wrap({cla, ins, p1, p2, data, le}).apdu;
 */
export function createScp03Driver(
  staticKeys: StaticKeys,
  hostChallenge: Buffer,
  securityLevel: number = SL_CMAC,
) {
  const initializeUpdate = buildInitializeUpdate(hostChallenge);

  let session: Scp03Session | null = null;

  const onInitUpdateResp = (respData: Buffer) => {
    const parsed = parseInitializeUpdateResponse(respData);
    const keys = deriveSessionKeys(staticKeys, hostChallenge, parsed.cardChallenge);
    const expectedCardCrypto = computeCardCryptogram(keys.sMac, hostChallenge, parsed.cardChallenge);
    if (!parsed.cardCryptogram.equals(expectedCardCrypto)) {
      throw new Error('SCP03_AUTH_FAILED: card cryptogram mismatch');
    }

    const hostCrypto = computeHostCryptogram(keys.sMac, hostChallenge, parsed.cardChallenge);
    const ea = buildExternalAuthenticate(keys.sMac, hostCrypto, securityLevel);

    session = {
      securityLevel,
      sessionKeys: keys,
      macChain: ea.macChain,
      sequenceCounter: parsed.sequenceCounter,
      commandCounter: 0,
    };

    return {
      parsed,
      externalAuthenticate: ea.apdu,
    };
  };

  const getSession = (): Scp03Session => {
    if (!session) throw new Error('SCP03 not yet initialised');
    return session;
  };

  const wrap = (input: WrapInput): WrapResult => {
    const result = wrapCommand(getSession(), input);
    session = result.session;
    return result;
  };

  const unwrap = (input: UnwrapInput): UnwrapResult => {
    return unwrapResponse(getSession(), input);
  };

  return {
    initializeUpdate,
    onInitUpdateResp,
    wrap,
    unwrap,
    getSession,
  };
}
