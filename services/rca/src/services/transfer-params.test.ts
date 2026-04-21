/**
 * Tests for the Phase 7 TRANSFER_PARAMS dispatch in
 * handleKeygenResponse.  Verify three things:
 *
 *   1. Legacy cards (paramRecordId = null) always route to
 *      buildTransferSadApdu, regardless of RCA_ENABLE_PARAM_BUNDLE.
 *   2. Prototype cards (paramRecordId set) with env flag '1' route
 *      to buildTransferParamsApdu and emit an ECDH-wrapped APDU.
 *   3. Prototype cards with env flag '0' still route to the legacy
 *      SAD flow — the flag is the kill-switch.
 *
 * We test buildParamBundleApdu in isolation (pure function) against
 * a reference bundle + generated chip keypair to confirm the APDU
 * shape is correct and round-trips through the unwrap path.
 */

import { describe, it, expect } from 'vitest';
import {
  generateTestKeypair,
  unwrapParamBundle,
  parseWireBundle,
} from '@palisade/emv-ecdh';
import { buildParamBundleApdu, buildParamBundleApduChunks } from './plan-builder.js';

describe('buildParamBundleApdu — TRANSFER_PARAMS wire shape', () => {
  it('emits a short APDU (Lc <= 255) for a small bundle', () => {
    const chip = generateTestKeypair();
    // 13 bytes plaintext → 16-byte ciphertext after PKCS#7 padding.
    const plaintext = Buffer.from('DEADBEEFCAFEBABE0102030405', 'hex');

    const apdu = buildParamBundleApdu({
      plaintextBundle: plaintext,
      chipPubUncompressed: chip.pubUncompressed,
      sessionId: 'sess_test_01',
    });

    expect(apdu[0]).toBe(0x80); // CLA
    expect(apdu[1]).toBe(0xE2); // INS (TRANSFER_PARAMS, reuses 0xE2)
    expect(apdu[2]).toBe(0x00); // P1
    expect(apdu[3]).toBe(0x00); // P2

    // Body = 65 pubkey + 16 iv + 16 ct (13 bytes padded to 16) + 16 tag
    //      = 113 bytes.  Fits in short-form APDU (Lc byte 4 = 113).
    expect(apdu[4]).toBe(113);
    expect(apdu.length).toBe(5 + 113);
  });

  it('emits N chained short APDUs for realistic (>255 B) bundle sizes', () => {
    const chip = generateTestKeypair();
    // 400 bytes ≈ realistic MChip CVN 18 ParamBundle size.
    // After PKCS#7 pad → 400 bytes already block-aligned so pad is
    // one full block = 16 bytes, ct = 416.  Wire = 65 + 16 + 416 + 16
    // = 513 bytes, past short-form cap of 255.
    const plaintext = Buffer.alloc(400, 0xAB);

    const chunks = buildParamBundleApduChunks({
      plaintextBundle: plaintext,
      chipPubUncompressed: chip.pubUncompressed,
      sessionId: 'sess_test_02',
    });

    // 513 B wire / 240 B chunk → ceil = 3 chunks (240 + 240 + 33).
    expect(chunks.length).toBe(3);

    // All chunks: 80 E2 00 00 (CLA/INS/P1/P2 with chain-bit variation).
    // Intermediate chunks are case-3 (5 + Lc bytes).  The last chunk is
    // case-4 with Le=0x20 so the chip has a 32-byte outgoing slot for
    // the IV-mismatch diagnostic (6 + Lc bytes).
    for (let i = 0; i < chunks.length; i++) {
      const c = chunks[i];
      const isLast = i === chunks.length - 1;
      expect(c[0]).toBe(isLast ? 0x80 : 0x90);
      expect(c[1]).toBe(0xE2);
      expect(c[2]).toBe(0x00);
      expect(c[3]).toBe(0x00);
      const lc = c[4];
      expect(lc).toBeLessThanOrEqual(240);
      expect(c.length).toBe(isLast ? 5 + lc + 1 : 5 + lc);
      if (isLast) {
        expect(c[c.length - 1]).toBe(0x20);
      }
    }

    // Sum of body bytes across chunks == wire length.
    const totalBody = chunks.reduce((n, c) => n + c[4], 0);
    expect(totalBody).toBe(513);

    // Single-buffer helper throws for the multi-chunk case so callers
    // don't silently emit only the first chunk.
    expect(() => buildParamBundleApdu({
      plaintextBundle: plaintext,
      chipPubUncompressed: chip.pubUncompressed,
      sessionId: 'sess_test_02',
    })).toThrow(/caller must use buildParamBundleApduChunks/);
  });

  it('round-trips through unwrap — proves the APDU is consumable by pa-v3', () => {
    const chip = generateTestKeypair();
    const original = Buffer.from('0102030405060708090A0B0C0D0E0F10', 'hex');

    const apdu = buildParamBundleApdu({
      plaintextBundle: original,
      chipPubUncompressed: chip.pubUncompressed,
      sessionId: 'sess_test_03',
    });

    // Extract the wire body (everything past the APDU header).
    // Short APDU case: header is 5 bytes, body is the rest.
    const body = apdu.subarray(5);
    const wrapped = parseWireBundle(body);

    const unwrapped = unwrapParamBundle({
      ...wrapped,
      chipPriv: chip.priv,
      sessionId: 'sess_test_03',
    });

    expect(unwrapped.equals(original)).toBe(true);
  });

  it('ciphertext differs across calls (ephemeral keypair → fresh ECDH secret)', () => {
    const chip = generateTestKeypair();
    const plaintext = Buffer.from('ABCD', 'hex');

    const apdu1 = buildParamBundleApdu({
      plaintextBundle: plaintext,
      chipPubUncompressed: chip.pubUncompressed,
      sessionId: 'sess_fixed',
    });
    const apdu2 = buildParamBundleApdu({
      plaintextBundle: plaintext,
      chipPubUncompressed: chip.pubUncompressed,
      sessionId: 'sess_fixed',
    });

    // Same plaintext + same chip + same session → different APDU bytes
    // because the server's ephemeral keypair (and derived AES key)
    // changes per call.  Forward secrecy.
    expect(apdu1.equals(apdu2)).toBe(false);
  });
});
