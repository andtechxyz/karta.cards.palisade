/**
 * Shared BER-TLV / DGI length encoding and decoding utilities.
 *
 * Ported from palisade-tlv/_encoding.py.
 */

/**
 * Encode a length value using BER-TLV length encoding.
 *
 * - 0x00–0x7F: single byte
 * - 0x80–0xFF: 0x81 prefix + 1 byte
 * - 0x100–0xFFFF: 0x82 prefix + 2 bytes big-endian
 */
export function encodeLength(length: number): Buffer {
  if (length < 0) throw new RangeError('Length must be non-negative');
  if (length <= 0x7f) return Buffer.from([length]);
  if (length <= 0xff) return Buffer.from([0x81, length]);
  if (length <= 0xffff) {
    const buf = Buffer.alloc(3);
    buf[0] = 0x82;
    buf.writeUInt16BE(length, 1);
    return buf;
  }
  throw new RangeError(`Length ${length} exceeds maximum supported (0xFFFF)`);
}

/**
 * Decode a BER-TLV length at the given offset.
 *
 * @returns [lengthValue, bytesConsumed]
 */
export function decodeLength(data: Buffer, offset: number): [number, number] {
  if (offset >= data.length) {
    throw new RangeError('Unexpected end of data while decoding length');
  }

  const first = data[offset];

  if (first <= 0x7f) return [first, 1];

  if (first === 0x81) {
    if (offset + 1 >= data.length) {
      throw new RangeError('Unexpected end of data in 2-byte length');
    }
    return [data[offset + 1], 2];
  }

  if (first === 0x82) {
    if (offset + 2 >= data.length) {
      throw new RangeError('Unexpected end of data in 3-byte length');
    }
    return [data.readUInt16BE(offset + 1), 3];
  }

  throw new RangeError(`Unsupported length encoding: 0x${first.toString(16).padStart(2, '0')}`);
}
