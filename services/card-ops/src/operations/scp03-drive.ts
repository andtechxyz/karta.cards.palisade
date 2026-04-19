/**
 * Small helper around the SCP03 driver for use inside operation bodies.
 *
 * Wraps:
 *   - Generating the host challenge
 *   - SELECTing the ISD first (required before INITIALIZE UPDATE)
 *   - Running INITIALIZE UPDATE + EXTERNAL AUTHENTICATE
 *   - Exposing `sendWrapped({...APDU fields})` that round-trips one
 *     C-MAC wrapped APDU and returns the plaintext response.
 *
 * Hides the state-machine wiring so the operation code reads as a
 * straight line of "send this, got that" steps.
 */

import { randomBytes } from 'node:crypto';
import {
  createScp03Driver,
  SL_CMAC,
  type StaticKeys,
  type WrapInput,
} from '../gp/scp03.js';
import { buildSelectByAid } from '../gp/apdu-builder.js';
import type { WSMessage } from '../ws/messages.js';
import type { ApduAuditLogger } from '../ws/apdu-audit.js';

// ISD (Issuer Security Domain) AID — standard GP value for JCOP cards.
// A0000001510000 = 1-2-3-4-5 prefix? Actually A000000151 00 00 is the
// GlobalPlatform Executable Load File AID.  ISDs on most JCOP products
// are at AID A000000151000000.  Use the widely-deployed default here.
const DEFAULT_ISD_AID = Buffer.from('A000000151000000', 'hex');

export interface DriveResult {
  /** Full response including SW (plaintext after unwrap). */
  response: Buffer;
  /** data portion (no SW). */
  data: Buffer;
  /** 2-byte SW as an integer. */
  sw: number;
}

export interface DriveIO {
  send: (msg: WSMessage) => void;
  next: () => Promise<WSMessage>;
  /**
   * Optional PCI-audit sink.  When present, every APDU command we emit
   * and every response we receive is appended to the logger.  Operation
   * handlers don't need to care about the logger's internals — the
   * drive helpers below own the instrumentation.
   */
  audit?: ApduAuditLogger;
}

/**
 * Round-trip one APDU over the WS relay.  Returns the raw plaintext
 * response (data + SW).  Leaves higher-level semantics (SW-based
 * branching, decoding) to the caller.
 */
export async function sendAndRecv(
  io: DriveIO,
  apdu: Buffer,
  phase?: string,
  progress?: number,
): Promise<Buffer> {
  const apduHex = apdu.toString('hex').toUpperCase();
  io.send({
    type: 'apdu',
    hex: apduHex,
    ...(phase ? { phase } : {}),
    ...(progress !== undefined ? { progress } : {}),
  });
  io.audit?.recordCommand(apduHex, phase);

  const msg = await io.next();
  if (msg.type === 'error') {
    throw new Error(`client_error:${msg.code ?? 'unknown'}:${msg.message ?? ''}`);
  }
  if (msg.type !== 'response') {
    throw new Error(`unexpected client message type: ${msg.type}`);
  }

  // Normalise: client may send either full hex (ending in SW) or data+sw.
  const hex = (msg.hex ?? '').toLowerCase();
  const sw = (msg.sw ?? '').toLowerCase();

  let full: Buffer;
  if (hex.length >= 4 && hex.endsWith(sw) && sw.length === 4) {
    full = Buffer.from(hex, 'hex');
  } else if (sw.length === 4) {
    full = Buffer.concat([Buffer.from(hex, 'hex'), Buffer.from(sw, 'hex')]);
  } else {
    // Last-ditch: assume hex already carries SW.
    full = Buffer.from(hex, 'hex');
  }

  const fullHex = full.toString('hex').toUpperCase();
  const swHex = full.length >= 2
    ? full.subarray(full.length - 2).toString('hex').toUpperCase()
    : undefined;
  io.audit?.recordResponse(fullHex, swHex, phase);

  return full;
}

/**
 * Drive SCP03 from first SELECT through EXTERNAL AUTHENTICATE.
 * Returns a `wrap` helper for subsequent wrapped APDUs, plus the
 * current security level so callers can branch (e.g. R-MAC handling).
 */
export async function establishScp03(
  io: DriveIO,
  staticKeys: StaticKeys,
  opts: {
    isdAid?: Buffer;
    securityLevel?: number;
    phasePrefix?: string;
  } = {},
): Promise<{
  send: (input: WrapInput) => Promise<DriveResult>;
}> {
  const isdAid = opts.isdAid ?? DEFAULT_ISD_AID;
  const securityLevel = opts.securityLevel ?? SL_CMAC;
  const phase = opts.phasePrefix ?? 'SCP03_INIT';

  // SELECT ISD — ensures subsequent APDUs hit the card manager.
  const selResp = await sendAndRecv(io, buildSelectByAid(isdAid), `${phase}:SELECT_ISD`, 0.02);
  const selSw = (selResp[selResp.length - 2] << 8) | selResp[selResp.length - 1];
  if (selSw !== 0x9000) {
    throw new Error(`SELECT ISD failed SW=${selSw.toString(16).toUpperCase()}`);
  }

  const hostChallenge = randomBytes(8);
  const driver = createScp03Driver(staticKeys, hostChallenge, securityLevel);

  // INITIALIZE UPDATE
  const iuResp = await sendAndRecv(io, driver.initializeUpdate, `${phase}:INIT_UPDATE`, 0.05);
  const iuSw = (iuResp[iuResp.length - 2] << 8) | iuResp[iuResp.length - 1];
  if (iuSw !== 0x9000) {
    throw new Error(`INITIALIZE UPDATE failed SW=${iuSw.toString(16).toUpperCase()}`);
  }
  const iuData = iuResp.subarray(0, iuResp.length - 2);
  const { externalAuthenticate } = driver.onInitUpdateResp(iuData);

  // EXTERNAL AUTHENTICATE
  const eaResp = await sendAndRecv(io, externalAuthenticate, `${phase}:EXT_AUTH`, 0.1);
  const eaSw = (eaResp[eaResp.length - 2] << 8) | eaResp[eaResp.length - 1];
  if (eaSw !== 0x9000) {
    throw new Error(`EXTERNAL AUTHENTICATE failed SW=${eaSw.toString(16).toUpperCase()}`);
  }

  // Subsequent APDUs go through the driver's wrap/unwrap.
  const send = async (input: WrapInput): Promise<DriveResult> => {
    const { apdu } = driver.wrap(input);
    const raw = await sendAndRecv(io, apdu);
    const { data, sw } = driver.unwrap({ response: raw });
    const fullResp = Buffer.concat([
      data,
      Buffer.from([(sw >> 8) & 0xFF, sw & 0xFF]),
    ]);
    return { response: fullResp, data, sw };
  };

  return { send };
}
