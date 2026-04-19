import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CardStatus } from '@prisma/client';
import type { RegisterCardInput, RegisterCardResult, VaultClient } from '@palisade/vault-client';

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

const registerCardMock = vi.fn<(input: RegisterCardInput) => Promise<RegisterCardResult>>();
const fakeVaultClient: VaultClient = {
  storeCard: vi.fn(),
  registerCard: registerCardMock,
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
  registerCardMock.mockReset().mockResolvedValue({
    vaultToken: 've_1',
    panLast4: '4242',
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
    expect(registerCardMock).not.toHaveBeenCalled();
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
    expect(registerCardMock).not.toHaveBeenCalled();
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
  it('calls vault.registerCard with cardRef as the idempotency key', async () => {
    vi.mocked(findCard()).mockResolvedValue(null);
    vi.mocked(createCard()).mockResolvedValue({
      id: 'card_new',
      cardRef: VALID_INPUT.cardRef,
      status: CardStatus.SHIPPED,
    } as never);

    await registerCard({ ...VALID_INPUT, ip: '1.2.3.4', ua: 'test-agent' });

    expect(registerCardMock).toHaveBeenCalledWith(
      expect.objectContaining({
        pan: VALID_INPUT.card.pan,
        cvc: VALID_INPUT.card.cvc,
        expiryMonth: VALID_INPUT.card.expiryMonth,
        expiryYear: VALID_INPUT.card.expiryYear,
        cardholderName: VALID_INPUT.card.cardholderName,
        idempotencyKey: VALID_INPUT.cardRef,
        ip: '1.2.3.4',
        ua: 'test-agent',
      }),
    );
    // Register surface is deliberately narrow — the legacy storeCard params
    // (actor, purpose, onDuplicate, cardId) are NOT part of it.
    expect(registerCardMock.mock.calls[0][0]).not.toHaveProperty('actor');
    expect(registerCardMock.mock.calls[0][0]).not.toHaveProperty('purpose');
    expect(registerCardMock.mock.calls[0][0]).not.toHaveProperty('onDuplicate');
    expect(registerCardMock.mock.calls[0][0]).not.toHaveProperty('cardId');
  });

  it('encrypts UID in lowercase (and only UID — SDM keys are HSM-derived, never stored)', async () => {
    vi.mocked(findCard()).mockResolvedValue(null);
    vi.mocked(createCard()).mockResolvedValue({
      id: 'card_new',
      cardRef: VALID_INPUT.cardRef,
      status: CardStatus.SHIPPED,
    } as never);

    await registerCard(VALID_INPUT);

    const plaintexts = vi.mocked(encrypt).mock.calls.map((c) => c[0]);
    expect(plaintexts).toEqual([VALID_INPUT.uid.toLowerCase()]);
  });

  it('creates a SHIPPED Card with the opaque vaultToken and mirrored PAN metadata', async () => {
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
      vaultToken: 've_1',
      panLast4: '4242',
    });

    const data = vi.mocked(createCard()).mock.calls[0]![0]!.data as Record<string, unknown>;
    expect(data.cardRef).toBe(VALID_INPUT.cardRef);
    expect(data.status).toBe(CardStatus.SHIPPED);
    expect(data.vaultToken).toBe('ve_1');
    // Mirrored PAN metadata so /cards/mine doesn't need to join the vault.
    expect(data.panLast4).toBe('4242');
    expect(data.panBin).toBe('424242');
    expect(data.cardholderName).toBe(VALID_INPUT.card.cardholderName);
    expect(data.panExpiryMonth).toBe(VALID_INPUT.card.expiryMonth);
    expect(data.panExpiryYear).toBe(VALID_INPUT.card.expiryYear);
    expect(data.uidEncrypted).toBe(`enc(${VALID_INPUT.uid.toLowerCase()})`);
    expect(data).not.toHaveProperty('sdmMetaReadKeyEncrypted');
    expect(data).not.toHaveProperty('sdmFileReadKeyEncrypted');
    expect(data.keyVersion).toBe(1);
    expect(data.programId).toBe(VALID_INPUT.programId);
    expect(data.batchId).toBe(VALID_INPUT.batchId);
    expect(data.uidFingerprint).toBe(fingerprintUid(VALID_INPUT.uid));
    // FK is gone — the old vaultEntryId field must not be written.
    expect(data).not.toHaveProperty('vaultEntryId');
  });
});

