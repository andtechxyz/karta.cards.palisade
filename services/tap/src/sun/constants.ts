// NXP AN14683 Section 2.5.2 (p.5) — SUN / SDM constants.
//
// Re-exported through ./index.ts.  All callers should import from the barrel,
// not this file directly, so the constant set stays in one place.

export const SC_SDMENC = Buffer.from([0xc3, 0x3c]);
export const SC_SDMMAC = Buffer.from([0x3c, 0xc3]);

export const SCT_1 = Buffer.from([0x00, 0x01]);
export const SCT_2 = Buffer.from([0x00, 0x02]);

export const SKL_128 = Buffer.from([0x00, 0x80]);
export const SKL_256 = Buffer.from([0x01, 0x00]);

/** First byte of a correctly-decrypted PICC payload. */
export const PICC_DATA_TAG = 0xc7;
