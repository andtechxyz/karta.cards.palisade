/**
 * BER-TLV encoder, decoder, and search utilities for EMV data objects.
 *
 * Ported from palisade-tlv/tlv.py.
 */

import { decodeLength, encodeLength } from './encoding.js';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Read a BER-TLV tag starting at offset.
 *
 * Tag encoding per ISO 8825-1 / EMV Book 3:
 * - If bits 1-5 of the first byte are all set (0x1F), the tag continues.
 * - Subsequent bytes: bit 8 (0x80) set means another byte follows.
 *
 * @returns [tagAsInt, bytesConsumed]
 */
function readTag(data: Buffer, offset: number): [number, number] {
  if (offset >= data.length) {
    throw new RangeError('Unexpected end of data while reading tag');
  }

  const first = data[offset];
  if ((first & 0x1f) !== 0x1f) {
    // Single-byte tag
    return [first, 1];
  }

  // Multi-byte tag
  let tag = first;
  let pos = offset + 1;
  while (pos < data.length) {
    tag = (tag << 8) | data[pos];
    if (!(data[pos] & 0x80)) {
      // Last byte of tag (bit 8 not set)
      return [tag, pos - offset + 1];
    }
    pos++;
  }

  throw new RangeError('Unexpected end of data in multi-byte tag');
}

function findInParsed(parsed: Array<[number, Buffer]>, targetTag: number): Buffer | null {
  for (const [tag, value] of parsed) {
    if (tag === targetTag) return value;
    if (TLV.isConstructed(tag)) {
      try {
        const nested = TLV.parse(value);
        const result = findInParsed(nested, targetTag);
        if (result !== null) return result;
      } catch {
        // Value doesn't parse as valid TLV — skip
        continue;
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export const TLV = {
  /**
   * Convert an integer tag to its minimal big-endian byte representation.
   */
  tagToBytes(tag: number): Buffer {
    if (tag <= 0xff) return Buffer.from([tag]);
    if (tag <= 0xffff) {
      const buf = Buffer.alloc(2);
      buf.writeUInt16BE(tag, 0);
      return buf;
    }
    if (tag <= 0xffffff) {
      const buf = Buffer.alloc(3);
      buf[0] = (tag >> 16) & 0xff;
      buf[1] = (tag >> 8) & 0xff;
      buf[2] = tag & 0xff;
      return buf;
    }
    throw new RangeError(`Tag 0x${tag.toString(16).toUpperCase()} exceeds 3 bytes`);
  },

  /**
   * Check if a tag is constructed (bit 6 of the first byte is set).
   * Constructed tags contain nested TLV objects as their value.
   */
  isConstructed(tag: number): boolean {
    let firstByte: number;
    if (tag > 0xffff) firstByte = (tag >> 16) & 0xff;
    else if (tag > 0xff) firstByte = (tag >> 8) & 0xff;
    else firstByte = tag & 0xff;
    return Boolean(firstByte & 0x20);
  },

  /**
   * Construct a BER-TLV object: tag || length || value.
   *
   * Handles 1, 2, and 3-byte tags and variable-length encoding.
   */
  build(tag: number, value: Buffer): Buffer {
    return Buffer.concat([TLV.tagToBytes(tag), encodeLength(value.length), value]);
  },

  /**
   * Build a constructed TLV (e.g., Tag 70 template).
   * Children are pre-built TLV objects, concatenated as the value.
   */
  buildConstructed(tag: number, children: Buffer[]): Buffer {
    const value = Buffer.concat(children);
    return TLV.build(tag, value);
  },

  /**
   * Parse a byte sequence into a list of [tag, value] tuples.
   *
   * Handles nested constructed tags recursively.
   * Skips 0x00 padding bytes per BER-TLV.
   */
  parse(data: Buffer): Array<[number, Buffer]> {
    const result: Array<[number, Buffer]> = [];
    let offset = 0;

    while (offset < data.length) {
      // Skip padding bytes
      if (data[offset] === 0x00) {
        offset++;
        continue;
      }

      // Read tag
      const [tag, tagLen] = readTag(data, offset);
      offset += tagLen;

      // Read length
      const [length, lenSize] = decodeLength(data, offset);
      offset += lenSize;

      // Extract value
      if (offset + length > data.length) {
        throw new RangeError(
          `TLV value extends beyond data: need ${length} bytes at offset ${offset}, ` +
            `but only ${data.length - offset} available`,
        );
      }
      const value = data.subarray(offset, offset + length);
      offset += length;

      result.push([tag, Buffer.from(value)]);
    }

    return result;
  },

  /**
   * Find a specific tag in TLV data, searching recursively into constructed tags.
   * Returns the value bytes or null if not found.
   */
  find(data: Buffer, targetTag: number): Buffer | null {
    const parsed = TLV.parse(data);
    return findInParsed(parsed, targetTag);
  },
} as const;
