import crypto from 'node:crypto';
import { aesCmac } from './cmac.js';
import { decryptPiccData, type PiccData } from './picc.js';
import { deriveSessionKeys } from './sessionKeys.js';

// SDMMAC verification + full SUN-URL verification per AN14683 p.6.

/**
 * Compute SDMMAC.
 *
 *   full   = AES-CMAC(macSessionKey, macInputData)             // 16 bytes
 *   SDMMAC = bytes at 0-indexed positions {1,3,5,...,15}        // 8 bytes
 *
 * AN14683's "even indices, 1-based" is "odd indices, 0-based".
 */
export function computeSdmmac(macSessionKey: Buffer, macInputData: Buffer): Buffer {
  const full = aesCmac(macSessionKey, macInputData);
  const out = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) out[i] = full[1 + i * 2];
  return out;
}

export function verifySdmmac(
  macSessionKey: Buffer,
  macInputData: Buffer,
  receivedMacHex: string,
): boolean {
  const received = Buffer.from(receivedMacHex, 'hex');
  if (received.length !== 8) return false;
  return crypto.timingSafeEqual(computeSdmmac(macSessionKey, macInputData), received);
}

/**
 * Extract the SDMMAC input from a SUN URL.
 *
 * AN14683: SDMMAC covers the URL substring from `sdmmacOffset` (default 7,
 * the NDEF header size) up to and including `&m=`.  The offset is relative to
 * the URL with the scheme stripped.
 */
export function extractSdmmacInput(url: string, sdmmacOffset: number = 7): Buffer {
  // Order matters: longer prefixes first so 'http://www.' wins over 'http://'.
  const SCHEMES = ['https://www.', 'http://www.', 'https://', 'http://'];
  let stripped = url;
  for (const s of SCHEMES) {
    if (url.toLowerCase().startsWith(s)) {
      stripped = url.slice(s.length);
      break;
    }
  }
  const NDEF_HEADER_SIZE = 7;
  const effectiveOffset = Math.max(0, sdmmacOffset - NDEF_HEADER_SIZE);
  const after = stripped.slice(effectiveOffset);
  const mIdx = after.lastIndexOf('&m=');
  if (mIdx === -1) throw new Error("Could not find '&m=' delimiter in URL");
  return Buffer.from(after.slice(0, mIdx + 3), 'ascii');
}

export interface VerifySunUrlInput {
  url: string;
  sdmMetaReadKey: Buffer;
  sdmFileReadKey: Buffer;
  /** 'e' = encrypted PICC (default); 'p' = plaintext (test/debug). */
  piccParam?: 'e' | 'p';
  sdmmacOffset?: number;
}

export interface SunVerificationOk {
  valid: true;
  uid: Buffer;
  uidHex: string;
  counter: number;
  picc: PiccData;
}

export interface SunVerificationFail {
  valid: false;
  errors: string[];
  uid?: Buffer;
  uidHex?: string;
  counter?: number;
  piccValid?: boolean;
  macValid?: boolean;
}

export type SunVerificationResult = SunVerificationOk | SunVerificationFail;

/**
 * Full SUN URL verification per AN14683.
 *
 * URL form: `https://<host>/<path>?e=<EncPICC>&m=<SDMMAC>`
 * (The SDM read counter lives inside the encrypted PICC; there is no
 * separate `c=` query parameter.)
 */
export function verifySunUrl(input: VerifySunUrlInput): SunVerificationResult {
  const piccParam = input.piccParam ?? 'e';
  let parsed: URL;
  try {
    parsed = new URL(input.url);
  } catch {
    return { valid: false, errors: ['Malformed URL'] };
  }
  const piccHex = parsed.searchParams.get(piccParam);
  const macHex = parsed.searchParams.get('m');
  if (!piccHex || !macHex) {
    return { valid: false, errors: [`Missing URL parameters (need ${piccParam}, m)`] };
  }

  let picc: PiccData;
  try {
    picc = decryptPiccData(input.sdmMetaReadKey, piccHex);
  } catch (e) {
    return { valid: false, errors: [`PICC decrypt failed: ${(e as Error).message}`] };
  }
  if (!picc.valid) {
    return {
      valid: false,
      errors: [
        `Invalid PICC tag: 0x${picc.tag.toString(16).toUpperCase().padStart(2, '0')}`,
      ],
      piccValid: false,
    };
  }

  const uidHex = picc.uid.toString('hex').toUpperCase();

  const { mac: macSessionKey } = deriveSessionKeys(
    input.sdmFileReadKey,
    picc.uid,
    picc.sdmReadCounter,
  );

  let macInput: Buffer;
  try {
    macInput = extractSdmmacInput(input.url, input.sdmmacOffset ?? 7);
  } catch (e) {
    return {
      valid: false,
      errors: [(e as Error).message],
      piccValid: true,
      uid: picc.uid,
      uidHex,
      counter: picc.counter,
    };
  }

  if (!verifySdmmac(macSessionKey, macInput, macHex)) {
    return {
      valid: false,
      errors: ['SDMMAC mismatch — data has been tampered with'],
      piccValid: true,
      macValid: false,
      uid: picc.uid,
      uidHex,
      counter: picc.counter,
    };
  }

  return { valid: true, uid: picc.uid, uidHex, counter: picc.counter, picc };
}
