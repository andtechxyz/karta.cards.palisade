import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  AttestationVerifier,
  STUB_MODE_WARNING,
  ICC_PUBKEY_LEN,
  CPLC_LEN,
} from './attestation-verifier.js';

describe('AttestationVerifier.extract', () => {
  it('splits a well-formed response into pubkey(65) + attestation(var) + cplc(42)', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const sig = Buffer.from('3045022100' + 'AA'.repeat(32) + '022000' + 'BB'.repeat(30), 'hex');
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const full = Buffer.concat([pub, sig, cplc]);

    const { iccPubkey, attestation, cplc: cplcOut } = AttestationVerifier.extract(full);

    expect(iccPubkey.length).toBe(ICC_PUBKEY_LEN);
    expect(iccPubkey.equals(pub)).toBe(true);
    expect(attestation.length).toBe(sig.length);
    expect(attestation.equals(sig)).toBe(true);
    expect(cplcOut.length).toBe(CPLC_LEN);
    expect(cplcOut.equals(cplc)).toBe(true);
  });

  it('handles the typical 72-byte attestation signature length', () => {
    // DER ECDSA-P256 canonical worst case — r and s both require a
    // leading 0x00 byte because their top bit is set.
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const sig = Buffer.alloc(72, 0x30); // not real DER, just the length we care about here
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const full = Buffer.concat([pub, sig, cplc]);

    const { attestation } = AttestationVerifier.extract(full);
    expect(attestation.length).toBe(72);
  });

  it('returns empty attestation when the response is exactly pubkey + cplc', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const cplc = Buffer.alloc(CPLC_LEN, 0xCC);
    const full = Buffer.concat([pub, cplc]);

    const { iccPubkey, attestation, cplc: cplcOut } = AttestationVerifier.extract(full);
    expect(iccPubkey.length).toBe(ICC_PUBKEY_LEN);
    expect(attestation.length).toBe(0);
    expect(cplcOut.length).toBe(CPLC_LEN);
  });

  it('tolerates a truncated buffer: short response → partial pubkey, empty trailers', () => {
    // 40-byte buffer — less than a full pubkey.  Don't throw; return
    // what we have.  NFC sometimes truncates mid-transceive.
    const truncated = Buffer.alloc(40, 0xEE);
    const { iccPubkey, attestation, cplc } = AttestationVerifier.extract(truncated);
    expect(iccPubkey.length).toBe(40);
    expect(attestation.length).toBe(0);
    expect(cplc.length).toBe(0);
  });

  it('tolerates a buffer that has pubkey + a short attestation but no full CPLC', () => {
    const pub = Buffer.alloc(ICC_PUBKEY_LEN, 0x04);
    const partial = Buffer.alloc(20, 0xAA); // not enough to be a complete cplc
    const full = Buffer.concat([pub, partial]);

    const { iccPubkey, attestation, cplc } = AttestationVerifier.extract(full);
    expect(iccPubkey.length).toBe(ICC_PUBKEY_LEN);
    // Degraded case: remainder goes to `attestation`; cplc is empty.
    expect(attestation.length).toBe(20);
    expect(cplc.length).toBe(0);
  });
});

describe('AttestationVerifier.verify (stub mode)', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    logSpy.mockRestore();
  });

  it('always returns ok=true with a warning, regardless of input bytes', () => {
    expect(AttestationVerifier.verify(Buffer.alloc(72, 0xAA), 'nxp')).toEqual({
      ok: true,
      warning: 'attestation verification not yet implemented',
    });
    expect(AttestationVerifier.verify(Buffer.alloc(0), 'infineon')).toEqual({
      ok: true,
      warning: 'attestation verification not yet implemented',
    });
    expect(AttestationVerifier.verify(Buffer.from('DEADBEEF', 'hex'), 'unknown')).toEqual({
      ok: true,
      warning: 'attestation verification not yet implemented',
    });
  });

  it('emits the STUB_MODE_WARNING banner on every call', () => {
    AttestationVerifier.verify(Buffer.alloc(0), 'nxp');
    AttestationVerifier.verify(Buffer.alloc(10), 'infineon');
    AttestationVerifier.verify(Buffer.alloc(72), 'unknown');

    // Every call fires the banner — no rate-limiting, because we WANT
    // this to be impossible to ignore.
    expect(warnSpy).toHaveBeenCalledTimes(3);
    for (const call of warnSpy.mock.calls) {
      expect(call[0]).toBe(STUB_MODE_WARNING);
    }
  });

  it('logs a 16-byte sample of the attestation bytes so logs stay small', () => {
    const sig = Buffer.from('30450221' + '00'.repeat(60), 'hex');
    AttestationVerifier.verify(sig, 'nxp');

    // console.log fires once with the sample.
    expect(logSpy).toHaveBeenCalledTimes(1);
    const logged = logSpy.mock.calls[0][0] as string;
    expect(logged).toContain('vendor=nxp');
    expect(logged).toContain(`len=${sig.length}`);
    // Only the first 16 bytes appear — 32 hex chars.
    expect(logged).toMatch(/first16=[0-9A-F]{32}/);
    // And the 16-byte prefix should be the first 16 bytes of `sig`.
    const prefix = sig.subarray(0, 16).toString('hex').toUpperCase();
    expect(logged).toContain(`first16=${prefix}`);
  });

  it('handles an empty attestation buffer gracefully', () => {
    AttestationVerifier.verify(Buffer.alloc(0), 'unknown');
    const logged = logSpy.mock.calls[0][0] as string;
    expect(logged).toContain('len=0');
    expect(logged).toContain('first16=(empty)');
  });
});
