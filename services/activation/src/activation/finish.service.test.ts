import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@palisade/db', () => ({
  prisma: {
    activationSession: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    card: {
      update: vi.fn(),
    },
    webAuthnCredential: {
      findMany: vi.fn(),
      update: vi.fn(),
      create: vi.fn(),
    },
    // $transaction with an array: returns each op resolved.
    $transaction: vi.fn((ops: Promise<unknown>[]) => Promise.all(ops)),
  },
}));

vi.mock('@palisade/webauthn', () => ({
  verifyRegistration: vi.fn(),
  verifyAuthentication: vi.fn(),
}));

vi.mock('../env.js', () => ({
  getActivationConfig: vi.fn(() => ({
    MICROSITE_CDN_URL: 'https://microsite.karta.cards',
  })),
}));

vi.mock('../programs/ndef.js', () => ({
  renderNdefUrls: vi.fn(() => ({ preActivation: null, postActivation: 'POST_NDEF_URL' })),
}));

import { prisma } from '@palisade/db';
import { verifyRegistration, verifyAuthentication } from '@palisade/webauthn';
import { finishActivationRegistration } from './finish.service.js';

const sessFind = () => prisma.activationSession.findUnique as unknown as ReturnType<typeof vi.fn>;
const sessUpd  = () => prisma.activationSession.update     as unknown as ReturnType<typeof vi.fn>;
const cardUpd  = () => prisma.card.update                  as unknown as ReturnType<typeof vi.fn>;
const credMany = () => prisma.webAuthnCredential.findMany  as unknown as ReturnType<typeof vi.fn>;
const credUpd  = () => prisma.webAuthnCredential.update    as unknown as ReturnType<typeof vi.fn>;
const credCreate = () => prisma.webAuthnCredential.create  as unknown as ReturnType<typeof vi.fn>;

const SESSION_WITH_CHALLENGE = {
  id: 'sess_1',
  cardId: 'card_1',
  consumedAt: null,
  expiresAt: new Date(Date.now() + 60_000),
  challenge: 'CHALLENGE_BYTES',
};
const CARD_UPDATE_RESULT = {
  cardRef: 'kc_test',
  program: {
    id: 'p_1',
    preActivationNdefUrlTemplate: null,
    postActivationNdefUrlTemplate: 'X',
    micrositeEnabled: false,
    micrositeActiveVersion: null,
  },
};

beforeEach(() => {
  vi.resetAllMocks();
  sessUpd().mockResolvedValue({});
  cardUpd().mockResolvedValue(CARD_UPDATE_RESULT);
  credUpd().mockResolvedValue({});
});

// ---------------------------------------------------------------------------
// Register path (attestation response)
// ---------------------------------------------------------------------------

describe('finishActivationRegistration — register mode', () => {
  it('verifies attestation, inserts cred, flips ACTIVATED', async () => {
    sessFind().mockResolvedValueOnce(SESSION_WITH_CHALLENGE);
    vi.mocked(verifyRegistration).mockResolvedValueOnce({
      verified: true,
      registrationInfo: {
        credentialID: 'NEW_CRED',
        credentialPublicKey: new Uint8Array([1, 2, 3]),
        counter: 0,
      },
    } as any);
    credCreate().mockResolvedValueOnce({});

    const r = await finishActivationRegistration({
      sessionToken: 'sess_1',
      // RegistrationResponseJSON — has attestationObject, no signature
      response: {
        id: 'NEW_CRED',
        rawId: 'NEW_CRED',
        response: { attestationObject: 'AAA', clientDataJSON: 'BBB', transports: ['nfc'] },
        type: 'public-key',
        clientExtensionResults: {},
      } as any,
      deviceLabel: 'Pixel 9',
    });

    expect(r.mode).toBe('register');
    expect(r.credentialId).toBe('NEW_CRED');
    expect(verifyRegistration).toHaveBeenCalled();
    expect(verifyAuthentication).not.toHaveBeenCalled();
  });

  it('throws when attestation fails to verify', async () => {
    sessFind().mockResolvedValueOnce(SESSION_WITH_CHALLENGE);
    vi.mocked(verifyRegistration).mockResolvedValueOnce({ verified: false } as any);
    await expect(finishActivationRegistration({
      sessionToken: 'sess_1',
      response: {
        id: 'x', rawId: 'x',
        response: { attestationObject: 'A', clientDataJSON: 'B', transports: ['nfc'] },
        type: 'public-key', clientExtensionResults: {},
      } as any,
    })).rejects.toMatchObject({ code: 'registration_verify_failed' });
  });
});

// ---------------------------------------------------------------------------
// Assert path (authentication response — preregistered cred + extended cred ID)
// ---------------------------------------------------------------------------

describe('finishActivationRegistration — assert mode', () => {
  const STORED_CRED = {
    id: 'cred_1',
    credentialId: 'PREREG_ID',
    publicKey: 'COSEPUB',
    counter: BigInt(0),
    transports: ['nfc'],
    preregistered: true,
  };

  it('matches the preregistered credential exactly and verifies', async () => {
    sessFind().mockResolvedValueOnce(SESSION_WITH_CHALLENGE);
    credMany().mockResolvedValueOnce([STORED_CRED]);
    vi.mocked(verifyAuthentication).mockResolvedValueOnce({
      verified: true,
      authenticationInfo: { newCounter: 3 },
    } as any);

    const r = await finishActivationRegistration({
      sessionToken: 'sess_1',
      response: {
        id: 'PREREG_ID', rawId: 'PREREG_ID',
        response: {
          authenticatorData: 'AD',
          clientDataJSON: 'CD',
          signature: 'SIG',
          userHandle: 'UH',
        },
        type: 'public-key', clientExtensionResults: {},
      } as any,
    });

    expect(r.mode).toBe('assert');
    expect(r.credentialId).toBe('PREREG_ID');
    expect(verifyAuthentication).toHaveBeenCalled();
    expect(verifyRegistration).not.toHaveBeenCalled();
    // Counter bumped on the cred row.
    expect(credUpd()).toHaveBeenCalledWith(expect.objectContaining({
      where: { id: 'cred_1' },
    }));
  });

  it('matches when authenticator returned the extended credential ID (prefix match)', async () => {
    sessFind().mockResolvedValueOnce(SESSION_WITH_CHALLENGE);
    credMany().mockResolvedValueOnce([STORED_CRED]);
    vi.mocked(verifyAuthentication).mockResolvedValueOnce({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    } as any);

    // Returned id is PREREG_ID + tail bytes (encoded as base64url).
    const realBytes = Buffer.from('PREREG_ID', 'base64url');
    const extendedBytes = Buffer.concat([realBytes, Buffer.from('url', 'ascii'), Buffer.alloc(16)]);
    const returned = extendedBytes.toString('base64url');

    const r = await finishActivationRegistration({
      sessionToken: 'sess_1',
      response: {
        id: returned, rawId: returned,
        response: {
          authenticatorData: 'AD',
          clientDataJSON: 'CD',
          signature: 'SIG',
          userHandle: null,
        },
        type: 'public-key', clientExtensionResults: {},
      } as any,
    });

    expect(r.mode).toBe('assert');
    // Response shape handler normalized the id before passing to verify.
    expect(vi.mocked(verifyAuthentication).mock.calls[0][0].response.id).toBe('PREREG_ID');
  });

  it('refuses when no matching credential exists', async () => {
    sessFind().mockResolvedValueOnce(SESSION_WITH_CHALLENGE);
    credMany().mockResolvedValueOnce([]);
    await expect(finishActivationRegistration({
      sessionToken: 'sess_1',
      response: {
        id: 'GHOST_CRED', rawId: 'GHOST_CRED',
        response: { authenticatorData: 'AD', clientDataJSON: 'CD', signature: 'SIG', userHandle: null },
        type: 'public-key', clientExtensionResults: {},
      } as any,
    })).rejects.toMatchObject({ code: 'credential_not_found' });
  });

  it('refuses when signature verification fails', async () => {
    sessFind().mockResolvedValueOnce(SESSION_WITH_CHALLENGE);
    credMany().mockResolvedValueOnce([STORED_CRED]);
    vi.mocked(verifyAuthentication).mockResolvedValueOnce({ verified: false } as any);
    await expect(finishActivationRegistration({
      sessionToken: 'sess_1',
      response: {
        id: 'PREREG_ID', rawId: 'PREREG_ID',
        response: { authenticatorData: 'AD', clientDataJSON: 'CD', signature: 'SIG', userHandle: null },
        type: 'public-key', clientExtensionResults: {},
      } as any,
    })).rejects.toMatchObject({ code: 'assertion_verify_failed' });
  });
});

// ---------------------------------------------------------------------------
// Shape sniffing edge cases
// ---------------------------------------------------------------------------

describe('finishActivationRegistration — input validation', () => {
  it('errors when challenge is missing on the session (no /begin called)', async () => {
    sessFind().mockResolvedValueOnce({ ...SESSION_WITH_CHALLENGE, challenge: null });
    await expect(finishActivationRegistration({
      sessionToken: 'sess_1',
      response: {
        id: 'x', rawId: 'x',
        response: { signature: 'S', authenticatorData: 'A', clientDataJSON: 'C', userHandle: null },
        type: 'public-key', clientExtensionResults: {},
      } as any,
    })).rejects.toMatchObject({ code: 'no_pending_challenge' });
  });

  it('errors when the response body is missing entirely', async () => {
    sessFind().mockResolvedValueOnce(SESSION_WITH_CHALLENGE);
    await expect(finishActivationRegistration({
      sessionToken: 'sess_1',
      response: undefined as any,
    })).rejects.toMatchObject({ code: 'missing_response' });
  });
});
