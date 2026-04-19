/**
 * Track 2 Equivalent Data (Tag 57) builder and parser for EMV chip transactions.
 *
 * Ported from palisade-tlv/track2.py.
 */

export const Track2 = {
  /**
   * Construct Track 2 Equivalent Data (Tag 57).
   *
   * Format: PAN || 'D' || Expiry(YYMM) || ServiceCode(3) ||
   *         DiscretionaryData || pad to even nibble count with 'F'
   *
   * @returns Packed BCD bytes.
   */
  build(
    pan: string,
    expiryYymm: string,
    serviceCode: string,
    discretionaryData = '',
  ): Buffer {
    if (!/^\d{4}$/.test(expiryYymm)) {
      throw new Error('Expiry must be exactly 4 digits (YYMM)');
    }
    if (!/^\d{3}$/.test(serviceCode)) {
      throw new Error('Service code must be exactly 3 digits');
    }
    if (discretionaryData && !/^[0-9A-Fa-f]*$/.test(discretionaryData)) {
      throw new Error('Discretionary data must be valid hex characters');
    }

    let track2Str = pan + 'D' + expiryYymm + serviceCode + discretionaryData;

    // Pad to even nibble count
    if (track2Str.length % 2 !== 0) track2Str += 'F';

    return Buffer.from(track2Str, 'hex');
  },

  /**
   * Parse Track 2 Equivalent Data into components.
   */
  parse(data: Buffer): {
    pan: string;
    expiry: string;
    serviceCode: string;
    discretionary: string;
  } {
    const hexStr = data.toString('hex').toUpperCase();

    const sepIdx = hexStr.indexOf('D');
    if (sepIdx === -1) throw new Error('No field separator (D) found in Track 2 data');

    const pan = hexStr.substring(0, sepIdx);
    const afterSep = hexStr.substring(sepIdx + 1);
    const expiry = afterSep.substring(0, 4);
    const serviceCode = afterSep.substring(4, 7);
    const discretionary = afterSep.substring(7).replace(/F+$/, '');

    return { pan, expiry, serviceCode, discretionary };
  },
} as const;
