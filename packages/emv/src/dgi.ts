/**
 * DGI (Data Grouping Identifier) container builder, parser, and
 * STORE DATA APDU construction.
 *
 * Ported from palisade-tlv/dgi.py.
 */

import { decodeLength, encodeLength } from './encoding.js';

export const DGI = {
  /**
   * Build a DGI container.
   *
   * Format: DGI(2 bytes big-endian) || Length(1–3 bytes) || Data
   */
  build(dgiNumber: number, data: Buffer): Buffer {
    const header = Buffer.alloc(2);
    header.writeUInt16BE(dgiNumber, 0);
    return Buffer.concat([header, encodeLength(data.length), data]);
  },

  /**
   * Build a complete STORE DATA APDU containing a DGI container.
   *
   * CLA: 80, INS: E2
   * P1: (isLast << 7) | (blockNum & 0x1F)
   * P2: 00
   * Lc: length of DGI container
   * Data: DGI container
   *
   * Returns complete APDU bytes (without C-MAC — added by SCP layer externally).
   */
  buildStoreDataApdu(
    dgiNumber: number,
    data: Buffer,
    blockNum = 0,
    isLast = true,
  ): Buffer {
    const container = DGI.build(dgiNumber, data);
    const p1 = ((isLast ? 1 : 0) << 7) | (blockNum & 0x1f);
    const lc = container.length;

    return Buffer.concat([Buffer.from([0x80, 0xe2, p1, 0x00, lc]), container]);
  },

  /**
   * Parse a byte sequence into a list of [dgiNumber, data] tuples.
   */
  parse(data: Buffer): Array<[number, Buffer]> {
    const result: Array<[number, Buffer]> = [];
    let offset = 0;

    while (offset < data.length) {
      if (offset + 2 > data.length) {
        throw new RangeError('Unexpected end of data while reading DGI number');
      }

      const dgiNumber = data.readUInt16BE(offset);
      offset += 2;

      const [length, lenSize] = decodeLength(data, offset);
      offset += lenSize;

      if (offset + length > data.length) {
        throw new RangeError(
          `DGI data extends beyond buffer: need ${length} bytes at offset ${offset}, ` +
            `but only ${data.length - offset} available`,
        );
      }
      const value = Buffer.from(data.subarray(offset, offset + length));
      offset += length;

      result.push([dgiNumber, value]);
    }

    return result;
  },
} as const;
