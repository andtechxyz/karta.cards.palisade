import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CardStatus } from '@prisma/client';
import type { StoreCardInput, StoreCardResult, VaultClient } from '@palisade/vault-client';

vi.mock('@palisade/db', () => ({
  prisma: {
    card: {
      findUnique: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
    },
    program: {
      // register.service looks up program.programType so it can default
      // retail cards to retailSaleStatus=SHIPPED.  Tests that don't set up
      // a program mock get a null (→ non-retail path).
      findUnique: vi.fn().mockResolvedValue(null),
    },
  },
}));

vi.mock('@palisade/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@palisade/core')>();
  return {
    ...actual,
    encrypt: vi.fn(),
  };
});

import { prisma } from '@palisade/db';
import { encrypt } from '@palisade/core';
import { registerCard, _setVaultClient } from './register.service.js';
import { fingerprintUid } from './fingerprint.js';

type Mocked<T> = ReturnType<typeof vi.fn> & T;
const findCard = () =>
  prisma.card.findUnique as unknown as Mocked<typeof prisma.card.findUnique>;
const createCard = () =>
  prisma.card.create as unknown as Mocked<typeof prisma.card.create>;

const storeCardMock = vi.fn<(input: StoreCardInput) => Promise<StoreCardResult>>();
const fakeVaultClient: VaultClient = {
  storeCard: storeCardMock,
  mintToken: vi.fn(),
  consumeToken: vi.fn(),
  proxy: vi.fn(),
  listCards: vi.fn(),
  listAudit: vi.fn(),
};

const VALID_INPUT = {
  cardRef: 'ref_1',
  uid: 'AABBCCDDEEFF11',
  chipSerial: 'JCOP5_UNIT',
  sdmMetaReadKey: '00112233445566778899aabbccddeeff',
  sdmFileReadKey: '112233445566778899aabbccddeeff00',
  programId: 'prog_x',
  batchId: 'batch_x',
  card: {
    pan: '4242424242424242',
    cvc: '123',
    expiryMonth: '12',
    expiryYear: '28',
    cardholderName: 'Unit Tester',
  },
};

beforeEach(() => {
  vi.mocked(findCard()).mockReset();
  vi.mocked(createCard()).mockReset();
  storeCardMock.mockReset().mockResolvedValue({
    vaultEntryId: 've_1',
    panLast4: '4242',
    deduped: false,
  });
  vi.mocked(encrypt).mockReset().mockImplementation((plaintext: string) => ({
    ciphertext: `enc(${plaintext})`,
    keyVersion: 1,
  } as never));
  _setVaultClient(fakeVaultClient);
});

describe('registerCard — conflict checks (fail before vault writes)', () => {
  it('throws 409 card_ref_taken when cardRef is already registered', async () => {
    vi.mocked(findCard())
      .mockResolvedValueOnce({ id: 'existing_ref' } as never)
      .mockResolvedValueOnce(null);

    await expect(registerCard(VALID_INPUT)).rejects.toMatchObject({
      name: 'ApiError',
      status: 409,
      code: 'card_ref_taken',
    });
    expect(storeCardMock).not.toHaveBeenCalled();
    expect(createCard()).not.toHaveBeenCalled();
  });

  it('throws 409 card_uid_taken when UID fingerprint collides', async () => {
    vi.mocked(findCard())
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ id: 'existing_uid' } as never);

    await expect(registerCard(VALID_INPUT)).rejects.toMatchObject({
      name: 'ApiError',
      status: 409,
      code: 'card_uid_taken',
    });
    expect(storeCardMock).not.toHaveBeenCalled();
    expect(createCard()).not.toHaveBeenCalled();
  });

  it('looks up UID via fingerprint, not plaintext', async () => {
    vi.mocked(findCard()).mockResolvedValue(null);
    vi.mocked(createCard()).mockResolvedValue({
      id: 'card_new',
      cardRef: VALID_INPUT.cardRef,
      status: CardStatus.SHIPPED,
    } as never);

    await registerCard(VALID_INPUT);

    const lookups = vi.mocked(findCard()).mock.calls.map((c) => c[0]!.where);
    expect(lookups).toContainEqual({ cardRef: VALID_INPUT.cardRef });
    const fp = fingerprintUid(VALID_INPUT.uid);
    expect(lookups).toContainEqual({ uidFingerprint: fp });
  });
});

describe('registerCard — happy path', () => {
  it('vaults the PAN with onDuplicate=error and the registration purpose', async () => {
    vi.mocked(findCard()).mockResolvedValue(null);
    vi.mocked(createCard()).mockResolvedValue({
      id: 'card_new',
      cardRef: VALID_INPUT.cardRef,
      status: CardStatus.SHIPPED,
    } as never);

    await registerCard({ ...VALID_INPUT, ip: '1.2.3.4', ua: 'test-agent' });

    expect(storeCardMock).toHaveBeenCalledWith(
      expect.objectContaining({
        pan: VALID_INPUT.card.pan,
        cvc: VALID_INPUT.card.cvc,
        expiryMonth: VALID_INPUT.card.expiryMonth,
        expiryYear: VALID_INPUT.card.expiryYear,
        cardholderName: VALID_INPUT.card.cardholderName,
        purpose: `card register ${VALID_INPUT.cardRef}`,
        onDuplicate: 'error',
        ip: '1.2.3.4',
        ua: 'test-agent',
      }),
    );
    expect(storeCardMock.mock.calls[0][0]).not.toHaveProperty('actor');
  });

  it('encrypts UID and both SDM keys in lowercase', async () => {
    vi.mocked(findCard()).mockResolvedValue(null);
    vi.mocked(createCard()).mockResolvedValue({
      id: 'card_new',
      cardRef: VALID_INPUT.cardRef,
      status: CardStatus.SHIPPED,
    } as never);

    await registerCard(VALID_INPUT);

    const plaintexts = vi.mocked(encrypt).mock.calls.map((c) => c[0]);
    expect(plaintexts).toHaveLength(3);
    expect(plaintexts).toContain(VALID_INPUT.uid.toLowerCase());
    expect(plaintexts).toContain(VALID_INPUT.sdmMetaReadKey.toLowerCase());
    expect(plaintexts).toContain(VALID_INPUT.sdmFileReadKey.toLowerCase());
  });

  it('creates a SHIPPED Card linked to the vault entry', async () => {
    vi.mocked(findCard()).mockResolvedValue(null);
    vi.mocked(createCard()).mockResolvedValue({
      id: 'card_new',
      cardRef: VALID_INPUT.cardRef,
      status: CardStatus.SHIPPED,
    } as never);

    const result = await registerCard(VALID_INPUT);

    expect(result).toEqual({
      cardId: 'card_new',
      cardRef: VALID_INPUT.cardRef,
      status: CardStatus.SHIPPED,
      vaultEntryId: 've_1',
      panLast4: '4242',
    });

    const data = vi.mocked(createCard()).mock.calls[0]![0]!.data as Record<string, unknown>;
    expect(data.cardRef).toBe(VALID_INPUT.cardRef);
    expect(data.status).toBe(CardStatus.SHIPPED);
    expect(data.vaultEntryId).toBe('ve_1');
    expect(data.uidEncrypted).toBe(`enc(${VALID_INPUT.uid.toLowerCase()})`);
    expect(data.sdmMetaReadKeyEncrypted).toBe(`enc(${VALID_INPUT.sdmMetaReadKey.toLowerCase()})`);
    expect(data.sdmFileReadKeyEncrypted).toBe(`enc(${VALID_INPUT.sdmFileReadKey.toLowerCase()})`);
    expect(data.keyVersion).toBe(1);
    expect(data.programId).toBe(VALID_INPUT.programId);
    expect(data.batchId).toBe(VALID_INPUT.batchId);
    expect(data.uidFingerprint).toBe(fingerprintUid(VALID_INPUT.uid));
  });
});

describe('registerCard — vault key drift guard', () => {
  it('throws 500 vault_key_drift if any of the three encrypts use a different key version', async () => {
    vi.mocked(findCard()).mockResolvedValue(null);
    let n = 0;
    vi.mocked(encrypt).mockImplementation((plaintext: string) => {
      n += 1;
      return { ciphertext: `enc(${plaintext})`, keyVersion: n === 3 ? 2 : 1 } as never;
    });

    await expect(registerCard(VALID_INPUT)).rejects.toMatchObject({
      name: 'ApiError',
      status: 500,
      code: 'vault_key_drift',
    });
    expect(createCard()).not.toHaveBeenCalled();
  });
});
