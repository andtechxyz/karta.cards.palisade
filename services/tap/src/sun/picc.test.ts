import { describe, it, expect } from 'vitest';
import { decryptPiccData } from './picc.js';

// Known-card PICC vector — same one palisade-sun ships as its smoke test.
// If decryptPiccData regresses, SUN-tap fails before MAC verification.

const META_KEY = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex');
const PICC_HEX = '38CEEC923BF52F4CA4048B9CDB223265';
const EXPECTED_UID = '042F455A482180';

describe('decryptPiccData — known card vector', () => {
  const r = decryptPiccData(META_KEY, PICC_HEX);

  it('marks the PICC tag as valid', () => {
    expect(r.valid).toBe(true);
  });

  it('recovers the expected UID', () => {
    expect(r.uid.toString('hex').toUpperCase()).toBe(EXPECTED_UID);
  });

  it('returns a non-negative SDM read counter (parsed from LSB-first bytes)', () => {
    expect(r.counter).toBeGreaterThanOrEqual(0);
    expect(r.sdmReadCounter.length).toBe(3);
  });

  it('rejects ciphertext under a different key', () => {
    const wrong = Buffer.alloc(16, 0xff);
    const bad = decryptPiccData(wrong, PICC_HEX);
    // Decrypt may not throw, but the tag byte will not match the PICC marker.
    expect(bad.valid).toBe(false);
  });
});
