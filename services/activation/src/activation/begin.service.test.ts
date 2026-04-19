import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@palisade/db', () => ({
  prisma: {
    card: { findUnique: vi.fn() },
    activationSession: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
  },
}));

vi.mock('@palisade/webauthn', () => ({
  buildNfcCardRegistrationOptions: vi.fn(() => ({ rpName: 'test' })),
  buildAuthenticationOptions: vi.fn(() => ({ rpID: 'karta.cards' })),
}));

vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: vi.fn(async () => ({
    challenge: 'REG_CHALLENGE',
    rp: { id: 'test', name: 'test' },
    user: { id: 'u', name: 'u', displayName: 'u' },
    pubKeyCredParams: [],
  })),
  generateAuthenticationOptions: vi.fn(async () => ({
    challenge: 'ASSERT_CHALLENGE',
    rpId: 'karta.cards',
    allowCredentials: [{ id: 'EXTENDED', type: 'public-key', transports: ['nfc'] }],
  })),
}));

// Core: mock decrypt + aesCmac, keep everything else real.
vi.mock('@palisade/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@palisade/core')>();
  return {
    ...actual,
    decrypt: vi.fn(() => '04aabbccddeeff'), // 7-byte NTAG424 UID
    aesCmac: vi.fn(() => Buffer.from('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'hex')),
  };
});

vi.mock('../cards/key-provider.js', () => ({
  getCardFieldKeyProvider: vi.fn(() => ({})),
}));

// Stub the SDM deriver — begin.service calls deriveFileReadKey(uid) to get the
// 16-byte CMAC key.  The real deriver requires DEV_SDM_ROOT_SEED env + deps we
// don't want in unit tests, so we replace it with a fake that returns a
// deterministic buffer.  aesCmac is separately mocked above, so the return
// value here is just what gets passed (and then zeroed).
vi.mock('../cards/sdm-deriver.js', () => ({
  getSdmDeriver: vi.fn(() => ({
    deriveMetaReadKey: vi.fn(async () => Buffer.alloc(16, 0xaa)),
    deriveFileReadKey: vi.fn(async () => Buffer.alloc(16, 0xaa)),
  })),
}));

vi.mock('../programs/ndef.js', () => ({
  renderNdefUrls: vi.fn(() => ({
    preActivation: null,
    postActivation: 'https://tap.karta.cards/pay/card_1?e={PICCData}&m={CMAC}',
  })),
}));

import { prisma } from '@palisade/db';
import { generateRegistrationOptions, generateAuthenticationOptions } from '@simplewebauthn/server';
import { buildAuthenticationOptions } from '@palisade/webauthn';
import { beginActivationRegistration } from './begin.service.js';

const cardFind = () => prisma.card.findUnique as unknown as ReturnType<typeof vi.fn>;
const sessFind = () => prisma.activationSession.findUnique as unknown as ReturnType<typeof vi.fn>;
const sessUpdate = () => prisma.activationSession.update as unknown as ReturnType<typeof vi.fn>;

const FRESH_SESSION = {
  id: 'sess_1',
  cardId: 'card_1',
  consumedAt: null,
  expiresAt: new Date(Date.now() + 60_000),
  challenge: null,
};

beforeEach(() => {
  vi.resetAllMocks();
  sessFind().mockResolvedValue(FRESH_SESSION);
  sessUpdate().mockResolvedValue({});
});

describe('beginActivationRegistration', () => {
  it('register mode: no preregistered cred → returns registration options', async () => {
    cardFind().mockResolvedValue({
      id: 'card_1', cardRef: 'kc_1', status: 'SHIPPED',
      uidEncrypted: 'enc_uid', keyVersion: 1,
      program: { preActivationNdefUrlTemplate: null, postActivationNdefUrlTemplate: 'X' },
      credentials: [],
    });

    const r = await beginActivationRegistration('sess_1');

    expect(r.mode).toBe('register');
    expect(generateRegistrationOptions).toHaveBeenCalled();
    expect(generateAuthenticationOptions).not.toHaveBeenCalled();
    expect(sessUpdate()).toHaveBeenCalledWith({
      where: { id: 'sess_1' },
      data: { challenge: 'REG_CHALLENGE' },
    });
  });

  it('assert mode: preregistered cred present → returns assertion options with extended cred ID', async () => {
    const realCredBytes = Buffer.from('realcred', 'ascii').toString('base64url');
    cardFind().mockResolvedValue({
      id: 'card_1', cardRef: 'kc_1', status: 'SHIPPED',
      uidEncrypted: 'enc_uid',
      keyVersion: 1,
      program: {
        preActivationNdefUrlTemplate: null,
        postActivationNdefUrlTemplate: 'https://tap.karta.cards/pay/{cardRef}?e={PICCData}&m={CMAC}',
      },
      credentials: [
        { credentialId: realCredBytes, kind: 'CROSS_PLATFORM', preregistered: true, transports: ['nfc'] },
      ],
    });

    const r = await beginActivationRegistration('sess_1');

    expect(r.mode).toBe('assert');
    expect(generateAuthenticationOptions).toHaveBeenCalled();
    expect(generateRegistrationOptions).not.toHaveBeenCalled();

    // buildAuthenticationOptions must have been given an extended credential ID
    // (real bytes + url + 16-byte cmac) — verify length is at least real+url+16.
    const opts = vi.mocked(buildAuthenticationOptions).mock.calls[0][0];
    const extendedId = opts.credentials[0].id;
    const extBytes = Buffer.from(extendedId, 'base64url');
    const realBytes = Buffer.from(realCredBytes, 'base64url');
    expect(extBytes.length).toBeGreaterThan(realBytes.length + 16);
    // First portion equals the stored cred
    expect(extBytes.subarray(0, realBytes.length)).toEqual(realBytes);
    // Last 16 bytes are the (mocked) cmac
    expect(extBytes.subarray(-16).toString('hex')).toBe('a'.repeat(32));
  });

  it('assert mode: also attaches `karta-url` extension carrying url||cmac (channel B)', async () => {
    const realCredBytes = Buffer.from('realcred', 'ascii').toString('base64url');
    cardFind().mockResolvedValue({
      id: 'card_1', cardRef: 'kc_1', status: 'SHIPPED',
      uidEncrypted: 'enc_uid', keyVersion: 1,
      program: {
        preActivationNdefUrlTemplate: null,
        postActivationNdefUrlTemplate: 'https://tap.karta.cards/pay/{cardRef}?e={PICCData}&m={CMAC}',
      },
      credentials: [
        { credentialId: realCredBytes, kind: 'CROSS_PLATFORM', preregistered: true, transports: ['nfc'] },
      ],
    });

    const r = await beginActivationRegistration('sess_1');
    if (r.mode !== 'assert') throw new Error('expected assert');

    const ext = r.options.extensions as Record<string, string> | undefined;
    expect(ext).toBeDefined();
    expect(typeof ext!['karta-url']).toBe('string');

    const payload = Buffer.from(ext!['karta-url'], 'base64url');
    // <url(N)> || <cmac(16)>; the url portion must be the bare host+path,
    // and the trailing 16 bytes must equal the (mocked) CMAC.
    const url = payload.subarray(0, payload.length - 16).toString('utf8');
    expect(url).toBe('tap.karta.cards/pay/card_1');
    expect(payload.subarray(-16).toString('hex')).toBe('a'.repeat(32));
  });

  it('assert mode: strips https:// and ?e=... from post-activation URL before CMAC', async () => {
    const realCredBytes = Buffer.from('realcred', 'ascii').toString('base64url');
    cardFind().mockResolvedValue({
      id: 'card_1', cardRef: 'kc_1', status: 'SHIPPED',
      uidEncrypted: 'enc_uid', keyVersion: 1,
      program: {
        preActivationNdefUrlTemplate: null,
        postActivationNdefUrlTemplate: 'X',
      },
      credentials: [
        { credentialId: realCredBytes, kind: 'CROSS_PLATFORM', preregistered: true, transports: ['nfc'] },
      ],
    });

    await beginActivationRegistration('sess_1');
    const opts = vi.mocked(buildAuthenticationOptions).mock.calls[0][0];
    const extBytes = Buffer.from(opts.credentials[0].id, 'base64url');
    const realBytes = Buffer.from(realCredBytes, 'base64url');
    // URL portion = extBytes between realBytes and the trailing 16-byte cmac.
    const urlBytes = extBytes.subarray(realBytes.length, extBytes.length - 16);
    const url = urlBytes.toString('utf8');
    // Must NOT include scheme or query.
    expect(url).not.toMatch(/^https?:\/\//);
    expect(url).not.toContain('?');
    expect(url).toBe('tap.karta.cards/pay/card_1');
  });

  it('throws when card is already activated', async () => {
    cardFind().mockResolvedValue({
      id: 'card_1', cardRef: 'kc_1', status: 'ACTIVATED',
      uidEncrypted: 'enc_uid', keyVersion: 1,
      program: null, credentials: [],
    });
    await expect(beginActivationRegistration('sess_1')).rejects.toMatchObject({
      code: 'card_already_activated',
    });
  });

  it('throws when card row is missing for the session', async () => {
    cardFind().mockResolvedValue(null);
    await expect(beginActivationRegistration('sess_1')).rejects.toMatchObject({
      code: 'card_not_found',
    });
  });
});
