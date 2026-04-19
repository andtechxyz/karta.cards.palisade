/**
 * PAN (Primary Account Number) utilities — Luhn check, masking, BCD padding, validation.
 *
 * Ported from palisade-tlv/pan.py.
 */

export const PANUtils = {
  /**
   * Standard Luhn mod-10 algorithm. Returns true if the PAN check digit is valid.
   */
  luhnCheck(pan: string): boolean {
    let total = 0;
    for (let i = pan.length - 1, alt = false; i >= 0; i--, alt = !alt) {
      let digit = Number(pan[i]);
      if (alt) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      total += digit;
    }
    return total % 10 === 0;
  },

  /**
   * Pad PAN to even nibble count with trailing 'F' and convert to packed BCD bytes.
   *
   * e.g. "5412345678901234" → Buffer<54 12 34 56 78 90 12 34>
   *      "541234567890123"  → Buffer<54 12 34 56 78 90 12 3F>
   */
  padPan(pan: string): Buffer {
    const padded = pan.length % 2 === 0 ? pan : pan + 'F';
    return Buffer.from(padded, 'hex');
  },

  /**
   * Return masked PAN showing only the last 4 digits: '****1234'.
   */
  mask(pan: string): string {
    if (pan.length <= 4) return pan;
    return '****' + pan.slice(-4);
  },

  /**
   * Validate PAN format: 13–19 digits, passes Luhn check.
   *
   * Throws with a safe message (no PAN in error text) if invalid.
   * Returns true if valid.
   */
  validate(pan: string): true {
    if (!/^\d+$/.test(pan)) {
      throw new Error('Invalid card number format: must contain only digits');
    }
    if (pan.length < 13 || pan.length > 19) {
      throw new Error('Invalid card number format: invalid length');
    }
    if (!PANUtils.luhnCheck(pan)) {
      throw new Error('Invalid card number format: check digit failed');
    }
    return true;
  },
} as const;
