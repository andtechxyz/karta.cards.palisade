/**
 * apdu-audit.test.ts — unit tests for the APDU audit buffer, focused on
 * the redaction policy (INS-based + SCP03-wrap CLA-based).  The flush
 * path touches Prisma so it's exercised via the operation-runner tests;
 * here we stick to the in-memory snapshot.
 */

import { describe, it, expect } from 'vitest';
import { ApduAuditLogger } from './apdu-audit.js';

describe('ApduAuditLogger — redaction policy', () => {
  it('records a plain SELECT unredacted', () => {
    const log = new ApduAuditLogger('sid_1');
    log.recordCommand('00A404000AA000000151000000');
    log.recordResponse('9000', '9000');
    const snap = log.snapshot();
    expect(snap).toHaveLength(2);
    expect(snap[0]).toMatchObject({ direction: 'cmd', hex: '00A404000AA000000151000000' });
    expect(snap[0].redacted).toBeUndefined();
    expect(snap[1]).toMatchObject({ direction: 'rsp', hex: '9000' });
  });

  it('redacts STORE DATA body + subsequent response', () => {
    const log = new ApduAuditLogger('sid_2');
    // CLA=80 (proprietary, no SM), INS=E2 (STORE DATA) — triggers
    // INS-based redaction.  Body (after header) is not exposed in
    // the audit log.
    log.recordCommand('80E28000100102030405060708090A0B0C0D0E0F10');
    log.recordResponse('9000', '9000');
    const snap = log.snapshot();
    expect(snap[0].redacted).toBe(true);
    expect(snap[0].hex).toBe('80E28000-REDACTED');
    // Response after a sensitive command is also redacted — SW preserved.
    expect(snap[1].redacted).toBe(true);
    expect(snap[1].hex).toBe('REDACTED-9000');
  });

  it('redacts any SCP03-wrapped APDU regardless of INS (P-3)', () => {
    const log = new ApduAuditLogger('sid_3');
    // CLA=84 → bit 0x04 set → SCP03 C-MAC wrap.  INS=F2 is "GET DATA"
    // which on its own isn't in SENSITIVE_INS, but the wrap mask still
    // triggers redaction because the body carries an 8-byte C-MAC we
    // don't want leaking into audit logs.
    log.recordCommand('84F200000400AABBCCDD');
    log.recordResponse('9000', '9000');
    const snap = log.snapshot();
    expect(snap[0].redacted).toBe(true);
    expect(snap[0].hex).toBe('84F20000-REDACTED');
    expect(snap[1].redacted).toBe(true);
  });

  it('redacts SCP03 C-ENC wrapped APDU (CLA=8C, bit 0x0C set)', () => {
    const log = new ApduAuditLogger('sid_4');
    // CLA=8C → bits 0x04 + 0x08 set → SCP03 C-MAC + C-DECRYPTION wrap.
    log.recordCommand('8CE20000100123456789ABCDEF0123456789ABCDEF');
    const snap = log.snapshot();
    expect(snap[0].redacted).toBe(true);
    expect(snap[0].hex).toBe('8CE20000-REDACTED');
  });

  it('does not redact a non-sensitive plain APDU following a sensitive one', () => {
    const log = new ApduAuditLogger('sid_5');
    // Sensitive command + its response (both redacted).
    log.recordCommand('80D80000080102030405060708'); // PUT KEY
    log.recordResponse('9000', '9000');
    // Follow-up: plain SELECT should record normally.
    log.recordCommand('00A40400060102030405060');
    log.recordResponse('6F00', '6F00');
    const snap = log.snapshot();
    expect(snap[0].redacted).toBe(true);
    expect(snap[1].redacted).toBe(true);
    expect(snap[2].redacted).toBeUndefined();
    expect(snap[3].redacted).toBeUndefined();
  });
});
