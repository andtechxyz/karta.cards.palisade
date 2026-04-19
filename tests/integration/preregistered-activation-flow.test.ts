/**
 * Integration test — full preregistered-credential activation flow using the
 * real WebAuthn assertion path (replaces the old confirm-mode short-circuit).
 *
 * Walks:
 *   1. Admin POSTs a preregistered credential against a PERSONALISED card.
 *   2. Activation /begin sees the cred, returns assertion options whose
 *      allowCredentials[0].id is the extended blob (cred || url || cmac).
 *   3. Frontend "does WebAuthn assertion" (mocked via verifyAuthentication
 *      returning verified=true) and POSTs the response to /finish.
 *   4. /finish flips the card to ACTIVATED and bumps the credential's counter.
 *
 * The chip-side SIO interaction (setUrlWithMac) is not exercised here —
 * tested separately at the applet level.  This test validates the server-
 * side contract: extended cred ID shape, assertion acceptance, state flip.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express, { type Express } from 'express';
import 'express-async-errors';

// ---------------------------------------------------------------------------
// In-memory store shared across routes.
// ---------------------------------------------------------------------------

interface FakeCard {
  id: string;
  cardRef: string;
  status: string;
  uidEncrypted: string;
  keyVersion: number;
  programId: string | null;
  program?: {
    id: string;
    preActivationNdefUrlTemplate: string | null;
    postActivationNdefUrlTemplate: string | null;
    micrositeEnabled: boolean;
    micrositeActiveVersion: string | null;
  } | null;
}

interface FakeCred {
  id: string;
  credentialId: string;
  publicKey: string;
  cardId: string;
  kind: string;
  transports: string[];
  deviceName: string | null;
  preregistered: boolean;
  counter: bigint;
  createdAt: Date;
  lastUsedAt: Date | null;
}

interface FakeSession {
  id: string;
  cardId: string;
  challenge: string | null;
  consumedAt: Date | null;
  consumedDeviceLabel: string | null;
  expiresAt: Date;
  createdAt: Date;
}

const store = vi.hoisted(() => ({
  cards: new Map<string, any>(),
  credentials: new Map<string, any>(),
  sessions: new Map<string, any>(),
}));

const mockPrisma = vi.hoisted(() => ({
  card: {
    findUnique: vi.fn(async ({ where, select }: any) => {
      const id = where.id ?? Array.from(store.cards.values()).find((c: FakeCard) => c.cardRef === where.cardRef)?.id;
      const c = id ? store.cards.get(id) : undefined;
      if (!c) return null;
      if (select?.credentials) {
        return {
          ...c,
          credentials: Array.from(store.credentials.values()).filter((cr: FakeCred) => cr.cardId === c.id),
        };
      }
      return c;
    }),
    update: vi.fn(async ({ where, data, select }: any) => {
      const c = store.cards.get(where.id);
      if (!c) throw new Error('card_not_found');
      Object.assign(c, data);
      return select ? { ...c, program: c.program ?? null } : c;
    }),
  },
  webAuthnCredential: {
    findFirst: vi.fn(async ({ where }: any) => {
      return Array.from(store.credentials.values()).find((c: FakeCred) =>
        c.cardId === where.cardId
        && (where.preregistered === undefined || c.preregistered === where.preregistered),
      ) ?? null;
    }),
    findUnique: vi.fn(async ({ where }: any) => store.credentials.get(where.id) ?? null),
    findMany: vi.fn(async ({ where }: any) => {
      return Array.from(store.credentials.values()).filter((c: FakeCred) => c.cardId === where.cardId);
    }),
    create: vi.fn(async ({ data, select }: any) => {
      const id = `cred_${store.credentials.size + 1}`;
      const row: FakeCred = {
        id,
        credentialId: data.credentialId,
        publicKey: data.publicKey,
        cardId: data.cardId,
        kind: data.kind,
        transports: data.transports ?? ['nfc'],
        deviceName: data.deviceName ?? null,
        preregistered: data.preregistered ?? false,
        counter: BigInt(data.counter ?? 0),
        createdAt: new Date(),
        lastUsedAt: null,
      };
      store.credentials.set(id, row);
      return select ? Object.fromEntries(Object.keys(select).map((k) => [k, (row as any)[k]])) : row;
    }),
    update: vi.fn(async ({ where, data }: any) => {
      const c = store.credentials.get(where.id);
      if (!c) throw new Error('cred_not_found');
      Object.assign(c, data);
      return c;
    }),
    delete: vi.fn(async ({ where }: any) => {
      store.credentials.delete(where.id);
      return {} as any;
    }),
  },
  activationSession: {
    findUnique: vi.fn(async ({ where }: any) => store.sessions.get(where.id) ?? null),
    update: vi.fn(async ({ where, data }: any) => {
      const s = store.sessions.get(where.id);
      if (!s) throw new Error('session_not_found');
      Object.assign(s, data);
      return s;
    }),
  },
  $transaction: vi.fn(async (ops: any[]) => Promise.all(ops)),
}));

vi.mock('@palisade/db', () => ({ prisma: mockPrisma }));

// Core: decrypt returns a fake 7-byte NTAG424 UID hex; aesCmac returns 16 zero bytes.
vi.mock('@palisade/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@palisade/core')>();
  return {
    ...actual,
    decrypt: vi.fn(() => '04aabbccddeeff'),
    aesCmac: vi.fn(() => Buffer.alloc(16)),
  };
});

// Stub the activation-side SDM deriver — begin.service calls
// deriveFileReadKey(uid) to get the CMAC key for the karta-url extension.
vi.mock('../../services/activation/src/cards/sdm-deriver.js', () => ({
  getSdmDeriver: vi.fn(() => ({
    deriveMetaReadKey: vi.fn(async () => Buffer.alloc(16, 0xbb)),
    deriveFileReadKey: vi.fn(async () => Buffer.alloc(16, 0xbb)),
  })),
}));

vi.mock('@palisade/webauthn', () => ({
  buildNfcCardRegistrationOptions: vi.fn(() => ({ rpName: 'test' })),
  buildAuthenticationOptions: vi.fn((input: any) => ({
    rpID: 'karta.cards',
    allowCredentials: input.credentials,
  })),
  verifyRegistration: vi.fn(),
  verifyAuthentication: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: vi.fn(async () => ({ challenge: 'REG_CH', rp: {}, user: {}, pubKeyCredParams: [] })),
  generateAuthenticationOptions: vi.fn(async (opts: any) => ({
    challenge: 'ASSERT_CH',
    rpId: 'karta.cards',
    allowCredentials: opts.allowCredentials,
  })),
}));

vi.mock('../../services/activation/src/env.js', () => ({
  getActivationConfig: vi.fn(() => ({ MICROSITE_CDN_URL: 'https://microsite.karta.cards' })),
}));

vi.mock('../../services/activation/src/cards/key-provider.js', () => ({
  getCardFieldKeyProvider: vi.fn(() => ({})),
}));

import { errorMiddleware } from '@palisade/core';
import { verifyAuthentication, verifyRegistration } from '@palisade/webauthn';
import activationRouter from '../../services/activation/src/routes/activation.routes.js';

// Admin's credential-preregistration endpoint lives on Vera until Phase 4
// splits services/admin between the two repos.  Inline the behaviour we need
// (insert a FakeCred + enforce the "card must be SHIPPED" check) so this
// integration test can exercise the Palisade activation flow on its own.
function buildAdminCardsRouter() {
  const router = express.Router({ mergeParams: true });
  router.post('/:cardRef/credentials', (req, res) => {
    const card = Array.from(store.cards.values()).find((c: FakeCard) => c.cardRef === req.params.cardRef);
    if (!card) return res.status(404).json({ error: { code: 'card_not_found' } });
    if (card.status !== 'SHIPPED') {
      return res.status(409).json({ error: { code: 'card_not_shipped' } });
    }
    const id = `cred_${store.credentials.size + 1}`;
    const row: FakeCred = {
      id,
      credentialId: req.body.credentialId,
      publicKey: req.body.publicKey,
      cardId: card.id,
      kind: req.body.kind ?? 'CROSS_PLATFORM',
      transports: req.body.transports ?? ['nfc'],
      deviceName: req.body.deviceName ?? null,
      preregistered: true,
      counter: 0n,
      createdAt: new Date(),
      lastUsedAt: null,
    };
    store.credentials.set(id, row);
    return res.status(201).json({ id, credentialId: row.credentialId });
  });
  return router;
}

function buildApp(): Express {
  const app = express();
  app.use(express.json({ limit: '64kb' }));
  app.use('/api/cards', buildAdminCardsRouter());
  app.use('/api/activation', activationRouter);
  app.use(errorMiddleware);
  return app;
}

function seedCard(): FakeCard {
  const c: FakeCard = {
    id: 'card_1',
    cardRef: 'kc_e2e_1',
    status: 'SHIPPED',
    uidEncrypted: 'enc_uid',
    keyVersion: 1,
    programId: 'p_1',
    program: {
      id: 'p_1',
      preActivationNdefUrlTemplate: null,
      postActivationNdefUrlTemplate: 'https://tap.karta.cards/pay/{cardRef}?e={PICCData}&m={CMAC}',
      micrositeEnabled: false,
      micrositeActiveVersion: null,
    },
  };
  store.cards.set(c.id, c);
  return c;
}

function seedSession(cardId: string): FakeSession {
  const s: FakeSession = {
    id: 'sess_1',
    cardId,
    challenge: null,
    consumedAt: null,
    consumedDeviceLabel: null,
    expiresAt: new Date(Date.now() + 60_000),
    createdAt: new Date(),
  };
  store.sessions.set(s.id, s);
  return s;
}

beforeEach(() => {
  store.cards.clear();
  store.credentials.clear();
  store.sessions.clear();
  vi.mocked(verifyAuthentication).mockReset();
  vi.mocked(verifyRegistration).mockReset();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Preregistered FIDO credential — full assertion flow', () => {
  it('happy path: inject cred → /begin returns assert + extended id → /finish ACTIVATED', async () => {
    const card = seedCard();
    const sess = seedSession(card.id);
    const app = buildApp();

    // 1. Admin pre-registers a credential.
    const realCredId = 'realcredentialbytes';
    const realCredB64u = Buffer.from(realCredId, 'ascii').toString('base64url');
    const inject = await request(app)
      .post(`/api/cards/${card.cardRef}/credentials`)
      .send({
        credentialId: realCredB64u,
        publicKey: 'pAEDAzkBACBYIBfgEHRkBQ-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        transports: ['nfc'],
        deviceName: 'E2E perso',
      });
    expect(inject.status).toBe(201);

    // 2. /begin returns assert mode with an extended credential ID.
    const begin = await request(app).post(`/api/activation/sessions/${sess.id}/begin`);
    expect(begin.status).toBe(200);
    expect(begin.body.mode).toBe('assert');
    const extendedId = begin.body.options.allowCredentials[0].id;
    const extendedBytes = Buffer.from(extendedId, 'base64url');
    const realBytes = Buffer.from(realCredB64u, 'base64url');
    // Extended ID starts with the real cred bytes, then url, then 16-byte cmac.
    expect(extendedBytes.subarray(0, realBytes.length)).toEqual(realBytes);
    expect(extendedBytes.length).toBeGreaterThan(realBytes.length + 16);

    // Challenge stashed on session.
    expect(store.sessions.get(sess.id)!.challenge).toBe('ASSERT_CH');

    // 3. /finish with an assertion response — verifyAuthentication returns verified.
    vi.mocked(verifyAuthentication).mockResolvedValueOnce({
      verified: true,
      authenticationInfo: { newCounter: 5 },
    } as any);

    const finish = await request(app)
      .post(`/api/activation/sessions/${sess.id}/finish`)
      .send({
        response: {
          id: realCredB64u,
          rawId: realCredB64u,
          response: {
            authenticatorData: 'AD',
            clientDataJSON: 'CD',
            signature: 'SIG',
            userHandle: null,
          },
          type: 'public-key',
          clientExtensionResults: {},
        },
        deviceLabel: 'Pixel 9',
      });

    expect(finish.status).toBe(200);
    expect(finish.body.cardActivated).toBe(true);
    expect(finish.body.mode).toBe('assert');

    // Card is ACTIVATED in the store.
    expect(store.cards.get(card.id)!.status).toBe('ACTIVATED');
    // Session consumed.
    expect(store.sessions.get(sess.id)!.consumedAt).not.toBeNull();
    // Credential counter advanced.
    const cred = Array.from(store.credentials.values())[0] as FakeCred;
    expect(cred.counter).toBe(BigInt(5));
    expect(cred.lastUsedAt).not.toBeNull();
  });

  it('register mode is preserved when no preregistered cred exists', async () => {
    const card = seedCard();
    const sess = seedSession(card.id);
    const app = buildApp();

    const begin = await request(app).post(`/api/activation/sessions/${sess.id}/begin`);
    expect(begin.status).toBe(200);
    expect(begin.body.mode).toBe('register');
    expect(begin.body.options.challenge).toBe('REG_CH');
    expect(store.sessions.get(sess.id)!.challenge).toBe('REG_CH');
  });

  it('accepts the extended credential ID echoed back by the authenticator', async () => {
    const card = seedCard();
    const sess = seedSession(card.id);
    const app = buildApp();

    const realCredId = 'realx';
    const realCredB64u = Buffer.from(realCredId, 'ascii').toString('base64url');
    await request(app)
      .post(`/api/cards/${card.cardRef}/credentials`)
      .send({
        credentialId: realCredB64u,
        publicKey: 'pAEDAzkBACBYIBfgEHRkBQ-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      });
    await request(app).post(`/api/activation/sessions/${sess.id}/begin`);

    // Authenticator returns the FULL extended blob (realCred || url || cmac).
    const realBytes = Buffer.from(realCredB64u, 'base64url');
    const extBytes = Buffer.concat([realBytes, Buffer.from('tap.karta.cards/pay/kc_e2e_1'), Buffer.alloc(16)]);
    const returned = extBytes.toString('base64url');

    vi.mocked(verifyAuthentication).mockResolvedValueOnce({
      verified: true,
      authenticationInfo: { newCounter: 1 },
    } as any);

    const finish = await request(app)
      .post(`/api/activation/sessions/${sess.id}/finish`)
      .send({
        response: {
          id: returned, rawId: returned,
          response: { authenticatorData: 'AD', clientDataJSON: 'CD', signature: 'SIG', userHandle: null },
          type: 'public-key', clientExtensionResults: {},
        },
      });
    expect(finish.status).toBe(200);
    expect(finish.body.mode).toBe('assert');
    expect(store.cards.get(card.id)!.status).toBe('ACTIVATED');

    // verifyAuthentication was called with a normalized id (the real stored one).
    const verifyArgs = vi.mocked(verifyAuthentication).mock.calls[0][0];
    expect(verifyArgs.response.id).toBe(realCredB64u);
  });

  it('rejects pre-registration after card is ACTIVATED', async () => {
    const card = seedCard();
    card.status = 'ACTIVATED';
    const app = buildApp();
    const inject = await request(app)
      .post(`/api/cards/${card.cardRef}/credentials`)
      .send({
        credentialId: 'AAECAwQFBgcICQoLDA0ODw',
        publicKey: 'pAEDAzkBACBYIBfgEHRkBQ-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      });
    expect(inject.status).toBe(409);
    expect(inject.body.error.code).toBe('card_not_shipped');
  });
});
