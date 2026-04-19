/**
 * GlobalPlatform APDU builders.
 *
 * High-level, stateless helpers for building the APDUs used by card-ops
 * operations.  Output is the raw plaintext APDU — the SCP03 wrapper
 * (when SC is live) is a separate step.
 */

// ---------------------------------------------------------------------------
// SELECT
// ---------------------------------------------------------------------------

/**
 * SELECT AID — the standard ISO 7816-4 SELECT by AID.
 * Used for plain (no-SCP) operations like reset_pa_state and as the
 * first APDU inside a new NFC session to pick the ISD.
 *
 *   00 A4 04 00 Lc <AID>
 */
export function buildSelectByAid(aid: Buffer): Buffer {
  if (aid.length < 5 || aid.length > 16) {
    throw new Error(`AID length ${aid.length} out of range`);
  }
  return Buffer.concat([
    Buffer.from([0x00, 0xA4, 0x04, 0x00, aid.length]),
    aid,
  ]);
}

// ---------------------------------------------------------------------------
// GET STATUS (applications)
// ---------------------------------------------------------------------------

/**
 * GET STATUS for applications (installed applets + SDs + packages).
 *   80 F2 P1 P2 Lc=02 Data=4F 00  Le=00
 *
 * P1 bit mask per GP spec:
 *   0x80 = ISD        (the card manager)
 *   0x40 = applications + SSD
 *   0x20 = exec load files
 *   0x10 = exec load files + modules
 *
 * P2:
 *   0x00 = list first occurrence (truncate at ~240B and expect 6310)
 *   0x01 = next occurrence — send after SW=6310 to continue paginating
 *   0x02 = return TLV format (vs legacy)
 *
 * We call with P1=0x40 P2=0x02 (applications, TLV).  On SW=6310 we
 * re-send with P2=0x03 (TLV + next).
 */
export function buildGetStatus(p1: number, next = false): Buffer {
  const p2 = next ? 0x03 : 0x02;
  return Buffer.from([0x80, 0xF2, p1, p2, 0x02, 0x4F, 0x00, 0x00]);
}

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

/**
 * DELETE applet/package by AID.
 *   80 E4 00 00 Lc 4F <aidLen> <aid>
 *
 * On success returns 9000.  If the applet isn't installed the card
 * typically returns 6A88 (Referenced data not found) — the caller treats
 * that as "already absent, continue".
 *
 * P2=0x00 — delete an installed applet / package.  P2=0x80 would also
 * delete related objects; unused here because install_pa does the
 * applet+package in two steps explicitly for clarity.
 */
export function buildDelete(aid: Buffer): Buffer {
  const tlv = Buffer.concat([
    Buffer.from([0x4F, aid.length]),
    aid,
  ]);
  return Buffer.concat([
    Buffer.from([0x80, 0xE4, 0x00, 0x00, tlv.length]),
    tlv,
  ]);
}

// ---------------------------------------------------------------------------
// INSTALL [load]
// ---------------------------------------------------------------------------

/**
 * INSTALL [for load] — prepares the card to receive a LOAD block sequence.
 *
 *   80 E6 02 00 Lc
 *     <loadFileAid_len> <loadFileAid>
 *     <sdAid_len>       <sdAid>
 *     <dataBlockHash_len>  <dataBlockHash>
 *     <loadParamField_len> <loadParamField>
 *     <loadToken_len>      <loadToken>
 *
 * For a dev install against an ISD (security domain = current): SD AID,
 * hash, params, token can all be length 0 (empty).  That's what we do
 * here — production tokens would be added by a keyed attestation flow.
 */
export function buildInstallForLoad(
  loadFileAid: Buffer,
  sdAid: Buffer = Buffer.alloc(0),
  loadParamField: Buffer = Buffer.alloc(0),
  loadToken: Buffer = Buffer.alloc(0),
  dataBlockHash: Buffer = Buffer.alloc(0),
): Buffer {
  const body = Buffer.concat([
    Buffer.from([loadFileAid.length]),
    loadFileAid,
    Buffer.from([sdAid.length]),
    sdAid,
    Buffer.from([dataBlockHash.length]),
    dataBlockHash,
    Buffer.from([loadParamField.length]),
    loadParamField,
    Buffer.from([loadToken.length]),
    loadToken,
  ]);
  return Buffer.concat([
    Buffer.from([0x80, 0xE6, 0x02, 0x00, body.length]),
    body,
  ]);
}

// ---------------------------------------------------------------------------
// LOAD (data blocks)
// ---------------------------------------------------------------------------

/**
 * Chunk the Load File Data Block into LOAD APDUs.
 *
 * Each APDU:
 *   80 E8 <P1> <blockIndex> <Lc> <data>
 *
 * P1 = 0x00 for all but the last block, 0x80 for the last (terminator bit).
 * blockIndex increments from 0 and wraps at 256.  We target 240-byte
 * plaintext chunks so the SCP03-wrapped wire APDU (MAC+ENC padding)
 * comfortably fits under the 255-byte short-APDU limit.
 *
 * Passing the raw loadFileDataBlock — NOT a DGI-wrapped form.  GP doesn't
 * add any framing; it just concatenates the bytes and hands them to the
 * JC loader on the card side.
 */
export function chunkLoadBlock(
  loadFileDataBlock: Buffer,
  chunkSize = 240,
): Buffer[] {
  if (chunkSize < 1 || chunkSize > 255) {
    throw new Error(`chunkSize must be 1..255, got ${chunkSize}`);
  }
  const apdus: Buffer[] = [];
  let index = 0;
  for (let offset = 0; offset < loadFileDataBlock.length; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, loadFileDataBlock.length);
    const chunk = loadFileDataBlock.subarray(offset, end);
    const isLast = end === loadFileDataBlock.length;
    const p1 = isLast ? 0x80 : 0x00;
    apdus.push(Buffer.concat([
      Buffer.from([0x80, 0xE8, p1, index & 0xFF, chunk.length]),
      chunk,
    ]));
    index += 1;
  }
  return apdus;
}

// ---------------------------------------------------------------------------
// INSTALL [install+selectable]
// ---------------------------------------------------------------------------

/**
 * INSTALL [for install + selectable] — create an applet instance from
 * a previously-loaded package and mark it selectable.
 *
 *   80 E6 0C 00 Lc
 *     <loadFileAid_len>    <loadFileAid>      (package AID)
 *     <moduleAid_len>      <moduleAid>        (applet class AID in CAP)
 *     <appletAid_len>      <appletAid>        (instance AID — what SELECT uses)
 *     <privileges_len=01>  <privileges>       (0x00 = none)
 *     <installParams_len>  <installParams>    (C9 00 = empty params)
 *     <installToken_len>   <installToken>     (empty for dev)
 *
 * The module AID and applet AID are usually the same for simple
 * single-instance applets — the JC converter emits the applet class
 * AID as the package AID + 1-byte module tag, and palisade-pa's
 * reference perso installs with no --create override so the module
 * AID is also the instance AID.  Callers can override either.
 */
export function buildInstallForInstall(
  loadFileAid: Buffer,
  moduleAid: Buffer,
  appletAid: Buffer,
  privileges: Buffer = Buffer.from([0x00]),
  installParams: Buffer = Buffer.from([0xC9, 0x00]),
  installToken: Buffer = Buffer.alloc(0),
): Buffer {
  const body = Buffer.concat([
    Buffer.from([loadFileAid.length]),
    loadFileAid,
    Buffer.from([moduleAid.length]),
    moduleAid,
    Buffer.from([appletAid.length]),
    appletAid,
    Buffer.from([privileges.length]),
    privileges,
    Buffer.from([installParams.length]),
    installParams,
    Buffer.from([installToken.length]),
    installToken,
  ]);
  return Buffer.concat([
    Buffer.from([0x80, 0xE6, 0x0C, 0x00, body.length]),
    body,
  ]);
}

// ---------------------------------------------------------------------------
// GET STATUS response parser — simple-TLV decode
// ---------------------------------------------------------------------------

export interface AppEntry {
  aid: string;
  lifeCycle: number;
  privileges: string;
}

/**
 * Decode a GET STATUS response body (APPLICATIONS, TLV form).
 *
 * Format per GP §11.4.2.2:
 *   repeated:
 *     61 <len>
 *       4F <aidLen> <aid>
 *       9F70 02 <lifecycle[2]>
 *       C5 <privLen> <privileges>
 *
 * Returns one AppEntry per 61 tag, with hex-stringified fields.
 */
export function parseGetStatusResponse(body: Buffer): AppEntry[] {
  const out: AppEntry[] = [];
  let i = 0;
  while (i < body.length) {
    const tag = body[i];
    if (tag !== 0x61) {
      throw new Error(`expected application tag 0x61 at offset ${i}, got 0x${tag.toString(16)}`);
    }
    i += 1;
    const totalLen = body[i];
    i += 1;
    const end = i + totalLen;
    let aid = '';
    let lifeCycle = 0;
    let privileges = '';
    while (i < end) {
      const t = body[i];
      i += 1;
      // 9F70 is a 2-byte tag; everything else here is single-byte.
      let innerTag = t;
      if (t === 0x9F) {
        innerTag = (t << 8) | body[i];
        i += 1;
      }
      const len = body[i];
      i += 1;
      const val = body.subarray(i, i + len);
      i += len;
      switch (innerTag) {
        case 0x4F:
          aid = val.toString('hex').toUpperCase();
          break;
        case 0x9F70:
          lifeCycle = val.length >= 1 ? val[0] : 0;
          break;
        case 0xC5:
          privileges = val.toString('hex').toUpperCase();
          break;
        // 0xCC / 0xCE etc. may appear on some card OSes; skip unknown tags.
        default:
          break;
      }
    }
    out.push({ aid, lifeCycle, privileges });
  }
  return out;
}
