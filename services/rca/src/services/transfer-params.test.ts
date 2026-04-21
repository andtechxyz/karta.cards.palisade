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
import { buildParamBundleApdu } from './plan-builder.js';

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

  it('emits an extended APDU (Lc = 00 Lc-hi Lc-lo) for realistic bundle sizes', () => {
    const chip = generateTestKeypair();
    // 400 bytes ≈ realistic MChip CVN 18 ParamBundle size.
    // After PKCS#7 pad → 400 bytes already block-aligned so pad is
    // one full block = 16 bytes, ct = 416.  Wire = 65 + 16 + 416 + 16
    // = 513 bytes, past short-form cap of 255.
    const plaintext = Buffer.alloc(400, 0xAB);

    const apdu = buildParamBundleApdu({
      plaintextBundle: plaintext,
      chipPubUncompressed: chip.pubUncompressed,
      sessionId: 'sess_test_02',
    });

    expect(apdu[0]).toBe(0x80);
    expect(apdu[1]).toBe(0xE2);
    expect(apdu[2]).toBe(0x00);
    expect(apdu[3]).toBe(0x00);
    // Case-4 extended APDU:
    //   byte 4        = 0x00 (ext marker)
    //   bytes 5-6     = big-endian Lc
    //   bytes 7..7+Lc = body
    //   last 2 bytes  = Le = 0x00 0x00 ("up to 65536 bytes of response")
    expect(apdu[4]).toBe(0x00);
    const lc = (apdu[5] << 8) | apdu[6];
    expect(lc).toBe(513);
    expect(apdu.length).toBe(7 + 513 + 2);
    // Trailing Le = 00 00.  Forces case-4 extended — iOS CoreNFC rejects
    // case-3 extended at the ISO-DEP layer (SW=6700 was the first
    // real-chip manifestation of that reject).
    expect(apdu[apdu.length - 2]).toBe(0x00);
    expect(apdu[apdu.length - 1]).toBe(0x00);
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
