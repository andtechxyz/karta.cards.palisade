import { describe, it, expect } from 'vitest';
import { CredentialKind } from '@palisade/db';
import {
  buildNfcCardRegistrationOptions,
  buildPlatformRegistrationOptions,
  buildAuthenticationOptions,
} from './config.js';

// These option builders are the SINGLE source of truth for what we send to
// the browser.  The plan ("WebAuthn/NFC requirements — copy verbatim from
// New T4T") calls out each setting as non-negotiable — so we assert each
// one explicitly.  Any loosening should be a visible test failure here.

describe('buildNfcCardRegistrationOptions (Tier 2 — CTAP1 over NFC)', () => {
  const opts = buildNfcCardRegistrationOptions({
    userHandle: 'card_cuid_12345',
    userLabel: 'card_cuid_1',
  });

  it('uses ES256 only (COSE alg = -7)', () => {
    expect(opts.supportedAlgorithmIDs).toEqual([-7]);
  });

  it('requests attestation: none (CTAP1 attestation is unparseable as packed)', () => {
    expect(opts.attestationType).toBe('none');
  });

  it('sets authenticatorAttachment: cross-platform', () => {
    expect(opts.authenticatorSelection?.authenticatorAttachment).toBe('cross-platform');
  });

  it('sets residentKey: discouraged and requireResidentKey: false', () => {
    expect(opts.authenticatorSelection?.residentKey).toBe('discouraged');
    expect(opts.authenticatorSelection?.requireResidentKey).toBe(false);
  });

  it('sets userVerification: discouraged (card has no PIN/UV — required would refuse)', () => {
    expect(opts.authenticatorSelection?.userVerification).toBe('discouraged');
  });

  it('derives rpID from WEBAUTHN_RP_ID env, not inferred', () => {
    expect(opts.rpID).toBe('pay.karta.cards');
    expect(opts.rpName).toBe('Palisade Pay');
  });

  it('uses the userHandle as userID bytes (never the PICC UID)', () => {
    expect(Buffer.from(opts.userID!).toString('utf8')).toBe('card_cuid_12345');
  });

  it('maps excludeCredentials to transports: [nfc] for existing NFC creds', () => {
    const withExcl = buildNfcCardRegistrationOptions({
      userHandle: 'h',
      userLabel: 'l',
      excludeCredentialIds: ['cred_abc'],
    });
    expect(withExcl.excludeCredentials).toEqual([
      { id: 'cred_abc', transports: ['nfc'] },
    ]);
  });

  it('uses a 120s timeout to match Android Chrome\'s NFC-tap UX', () => {
    expect(opts.timeout).toBe(120_000);
  });
});

describe('buildPlatformRegistrationOptions (Tier 1/3 — Face ID / Hello / Touch ID)', () => {
  const opts = buildPlatformRegistrationOptions({
    userHandle: 'card_cuid_1',
    userLabel: 'card_cuid_1',
  });

  it('sets authenticatorAttachment: platform', () => {
    expect(opts.authenticatorSelection?.authenticatorAttachment).toBe('platform');
  });

  it('allows RS256 fallback (-257) alongside ES256 for Windows Hello legacy', () => {
    expect(opts.supportedAlgorithmIDs).toEqual([-7, -257]);
  });

  it('sets residentKey: preferred and userVerification: preferred', () => {
    expect(opts.authenticatorSelection?.residentKey).toBe('preferred');
    expect(opts.authenticatorSelection?.userVerification).toBe('preferred');
  });

  it('maps excludeCredentials to transports: [internal, hybrid]', () => {
    const withExcl = buildPlatformRegistrationOptions({
      userHandle: 'h',
      userLabel: 'l',
      excludeCredentialIds: ['cred_plat'],
    });
    expect(withExcl.excludeCredentials).toEqual([
      { id: 'cred_plat', transports: ['internal', 'hybrid'] },
    ]);
  });
});

describe('buildAuthenticationOptions', () => {
  it('userVerification: discouraged so NFC-only creds can auth', () => {
    const opts = buildAuthenticationOptions({
      credentials: [
        { id: 'cred_nfc', kind: CredentialKind.CROSS_PLATFORM, transports: [] },
      ],
    });
    expect(opts.userVerification).toBe('discouraged');
  });

  it('forces transports: [nfc] on CROSS_PLATFORM creds regardless of stored transports', () => {
    const opts = buildAuthenticationOptions({
      credentials: [
        // Pretend the stored row carried ['usb'] — we still send only nfc.
        { id: 'cred_nfc', kind: CredentialKind.CROSS_PLATFORM, transports: ['usb'] },
      ],
    });
    expect(opts.allowCredentials).toEqual([
      { id: 'cred_nfc', transports: ['nfc'] },
    ]);
  });

  it('preserves stored transports on PLATFORM creds when present', () => {
    const opts = buildAuthenticationOptions({
      credentials: [
        { id: 'cred_plat', kind: CredentialKind.PLATFORM, transports: ['internal'] },
      ],
    });
    expect(opts.allowCredentials?.[0]?.transports).toEqual(['internal']);
  });

  it('defaults PLATFORM creds with no stored transports to [internal, hybrid]', () => {
    const opts = buildAuthenticationOptions({
      credentials: [
        { id: 'cred_plat', kind: CredentialKind.PLATFORM, transports: [] },
      ],
    });
    expect(opts.allowCredentials?.[0]?.transports).toEqual(['internal', 'hybrid']);
  });

  it('emits one allowCredentials entry per passed-in credential, in order', () => {
    const opts = buildAuthenticationOptions({
      credentials: [
        { id: 'a', kind: CredentialKind.PLATFORM, transports: ['internal'] },
        { id: 'b', kind: CredentialKind.CROSS_PLATFORM, transports: [] },
      ],
    });
    const ids = opts.allowCredentials?.map((c) => c.id);
    expect(ids).toEqual(['a', 'b']);
  });

  it('propagates rpID from env', () => {
    const opts = buildAuthenticationOptions({
      credentials: [{ id: 'x', kind: CredentialKind.PLATFORM, transports: [] }],
    });
    expect(opts.rpID).toBe('pay.karta.cards');
  });
});
