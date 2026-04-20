/**
 * personalise_payment_applet tests.
 *
 * Scaffold verification — the real CAP-dependent refinements land when
 * the vendor specs arrive.  What we verify here:
 *
 *   - NOT_PROVISIONED fires when IssuerProfile.aid or Card.proxyCardId
 *     is missing.
 *   - SAD_RECORD_MISSING / SAD_RECORD_NOT_READY surface correctly.
 *   - The op drives SCP03 handshake, SELECT by EMV AID, decrypts the
 *     SAD, and emits a STORE DATA APDU per DGI in order.
 *   - P1 = 0x00 on all blocks except the last (0x80).
 *   - P2 = block index (0, 1, 2, ...).
 *   - INS = 0xE2, CLA = 0x80.
 *   - SadRecord.status flips to CONSUMED.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks — vi.hoisted runs first so the mock factories below can close
// over the shared fn refs.
// ---------------------------------------------------------------------------

const mocks = vi.hoisted(() => ({
  cardFindUnique: vi.fn(),
  sadRecordFindUnique: vi.fn(),
  sadRecordUpdate: vi.fn().mockResolvedValue({}),
  cardOpSessionUpdate: vi.fn().mockResolvedValue({}),
  decryptSad: vi.fn(),
}));

vi.mock('@palisade/db', () => ({
  prisma: {
    card: { findUnique: mocks.cardFindUnique },
    sadRecord: {
      findUnique: mocks.sadRecordFindUnique,
      update: mocks.sadRecordUpdate,
    },
    cardOpSession: { update: mocks.cardOpSessionUpdate },
  },
}));

vi.mock('../env.js', () => ({
  getCardOpsConfig: vi.fn().mockReturnValue({
    GP_MASTER_KEY: JSON.stringify({
      enc: '404142434445464748494A4B4C4D4E4F',
      mac: '404142434445464748494A4B4C4D4E4F',
      dek: '404142434445464748494A4B4C4D4E4F',
    }),
    CAP_FILES_DIR: '',
    CARD_OPS_USE_TEST_KEYS: '1',
    KMS_SAD_KEY_ARN: '',
  }),
}));

vi.mock('@palisade/data-prep/services/data-prep.service', () => ({
  DataPrepService: {
    decryptSad: mocks.decryptSad,
  },
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { runPersonalisePaymentApplet } from './personalise-payment-applet.js';
import { _resetGpStaticKeysCache } from '../gp/static-keys.js';
import { SADBuilder } from '@palisade/emv';
import {
  deriveSessionKeys,
  computeCardCryptogram,
  type StaticKeys,
} from '../gp/scp03.js';
import type { WSMessage } from '../ws/messages.js';

const TEST_KEY = Buffer.from('404142434445464748494A4B4C4D4E4F', 'hex');
const STATIC_KEYS: StaticKeys = { enc: TEST_KEY, mac: TEST_KEY, dek: TEST_KEY };

const MC_EMV_AID_HEX = 'A0000000041010';

beforeEach(() => {
  _resetGpStaticKeysCache();
  mocks.cardFindUnique.mockReset();
  mocks.sadRecordFindUnique.mockReset();
  mocks.sadRecordUpdate.mockReset();
  mocks.sadRecordUpdate.mockResolvedValue({});
  mocks.cardOpSessionUpdate.mockReset();
  mocks.cardOpSessionUpdate.mockResolvedValue({});
  mocks.decryptSad.mockReset();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scriptedIo(script: Array<(apdu: Buffer) => Buffer>) {
  const outbound: WSMessage[] = [];
  let step = 0;

  return {
    send: (msg: WSMessage) => {
      outbound.push(msg);
    },
    next: async (): Promise<WSMessage> => {
      let last: WSMessage | undefined;
      for (let i = outbound.length - 1; i >= 0; i--) {
        if (outbound[i].type === 'apdu' && outbound[i].hex) {
          last = outbound[i];
          break;
        }
      }
      if (!last) throw new Error('next() called before any APDU sent');

      const apduBuf = Buffer.from(last.hex!, 'hex');
      const handler = script[step++];
      if (!handler) throw new Error(`script exhausted at step ${step}`);
      const resp = handler(apduBuf);
      return {
        type: 'response',
        hex: resp.toString('hex').toUpperCase(),
        sw: resp.subarray(resp.length - 2).toString('hex').toUpperCase(),
      };
    },
    outbound,
  };
}

function scp03Opener(): Array<(apdu: Buffer) => Buffer> {
  const cardChallenge = Buffer.from('08090A0B0C0D0E0F', 'hex');
  return [
    () => Buffer.from([0x90, 0x00]), // SELECT ISD
    (apdu) => {
      const hostChallenge = apdu.subarray(5, 13);
      const keys = deriveSessionKeys(STATIC_KEYS, hostChallenge, cardChallenge);
      const cryptogram = computeCardCryptogram(keys.sMac, hostChallenge, cardChallenge);
      const body = Buffer.concat([
        Buffer.alloc(10, 0xAA),
        Buffer.from([0x30]),
        Buffer.from([0x03]),
        Buffer.from([0x00]),
        cardChallenge,
        cryptogram,
        Buffer.from('000001', 'hex'),
      ]);
      return Buffer.concat([body, Buffer.from([0x90, 0x00])]);
    },
    () => Buffer.from([0x90, 0x00]), // EXTERNAL AUTHENTICATE
  ];
}

const OK = () => Buffer.from([0x90, 0x00]);

/** Build a 3-DGI test SAD payload + its serialised form. */
function threeDgiSadPlaintext(): Buffer {
  // DGI 0x0101: 4 bytes 'AABBCCDD' — synthetic, not a real tag layout.
  // We only care that serialise / deserialise roundtrips cleanly.
  const dgis: Array<[number, Buffer]> = [
    [0x0101, Buffer.from('AABBCCDD', 'hex')],
    [0x0102, Buffer.from('DEADBEEF', 'hex')],
    [0x0103, Buffer.from('CAFEBABE', 'hex')],
  ];
  return SADBuilder.serialiseDgis(dgis);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('runPersonalisePaymentApplet', () => {
  it('NOT_PROVISIONED when IssuerProfile.aid is missing', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      proxyCardId: 'pcx_1',
      program: { issuerProfile: { aid: '' } },
    });

    const io = scriptedIo([]);
    const session = { id: 's1', cardId: 'c1', operation: 'personalise_payment_applet' } as any;
    const terminal = await runPersonalisePaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('NOT_PROVISIONED');
  });

  it('NOT_PROVISIONED when Card.proxyCardId is missing', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      proxyCardId: null,
      program: { issuerProfile: { aid: MC_EMV_AID_HEX } },
    });

    const io = scriptedIo([]);
    const session = { id: 's1', cardId: 'c1', operation: 'personalise_payment_applet' } as any;
    const terminal = await runPersonalisePaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('NOT_PROVISIONED');
  });

  it('SAD_RECORD_MISSING when no SadRecord exists for the proxyCardId', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      proxyCardId: 'pcx_1',
      program: { issuerProfile: { aid: MC_EMV_AID_HEX } },
    });
    mocks.sadRecordFindUnique.mockResolvedValue(null);

    const io = scriptedIo([]);
    const session = { id: 's1', cardId: 'c1', operation: 'personalise_payment_applet' } as any;
    const terminal = await runPersonalisePaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('SAD_RECORD_MISSING');
  });

  it('SAD_RECORD_NOT_READY when status is CONSUMED', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      proxyCardId: 'pcx_1',
      program: { issuerProfile: { aid: MC_EMV_AID_HEX } },
    });
    mocks.sadRecordFindUnique.mockResolvedValue({
      id: 'sad_1',
      status: 'CONSUMED',
      sadEncrypted: Buffer.alloc(8),
      sadKeyVersion: 1,
    });

    const io = scriptedIo([]);
    const session = { id: 's1', cardId: 'c1', operation: 'personalise_payment_applet' } as any;
    const terminal = await runPersonalisePaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('SAD_RECORD_NOT_READY');
  });

  it('streams STORE DATA APDUs, marks SAD CONSUMED, emits complete', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      proxyCardId: 'pcx_1',
      program: { issuerProfile: { aid: MC_EMV_AID_HEX } },
    });
    const plaintext = threeDgiSadPlaintext();
    mocks.sadRecordFindUnique.mockResolvedValue({
      id: 'sad_1',
      status: 'READY',
      sadEncrypted: Buffer.from('deadbeef', 'hex'),
      sadKeyVersion: 1,
    });
    mocks.decryptSad.mockResolvedValue(plaintext);

    // Script: 3 SCP03 + 1 SELECT + 3 STORE DATA.
    const io = scriptedIo([
      ...scp03Opener(),
      OK, // SELECT payment applet
      OK, // STORE DATA block 0
      OK, // STORE DATA block 1
      OK, // STORE DATA block 2 (last)
    ]);
    const session = { id: 's1', cardId: 'c1', operation: 'personalise_payment_applet' } as any;
    const terminal = await runPersonalisePaymentApplet(session, io);

    expect(terminal.type).toBe('complete');
    expect((terminal as any).instanceAid).toBe(MC_EMV_AID_HEX.toUpperCase());
    expect((terminal as any).dgiCount).toBe(3);
    expect((terminal as any).proxyCardId).toBe('pcx_1');

    // SadRecord.status flipped to CONSUMED.
    expect(mocks.sadRecordUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'sad_1' },
        data: { status: 'CONSUMED' },
      }),
    );

    // Verify STORE DATA APDU sequencing.  The first 3 APDUs are the
    // SCP03 handshake; the 4th is the SELECT by AID; subsequent APDUs
    // are the STORE DATA commands.
    const apdus = io.outbound
      .filter((m) => m.type === 'apdu' && m.hex)
      .map((m) => Buffer.from(m.hex!, 'hex'));

    // SELECT APDU at index 3: CLA=04 (00 | 0x04 C-MAC bit) INS=A4 P1=04 P2=00.
    // Note: SCP03 C-MAC security level sets the secure-messaging bit
    // (0x04) on the CLA byte, so the APDU on the wire has CLA=0x04
    // rather than the plaintext CLA=0x00 the caller passed in.
    expect(apdus[3][0]).toBe(0x04);
    expect(apdus[3][1]).toBe(0xA4);
    expect(apdus[3][2]).toBe(0x04);
    expect(apdus[3][3]).toBe(0x00);

    // STORE DATA APDUs at index 4, 5, 6.  CLA=0x84 (0x80 | 0x04 C-MAC bit),
    // INS=0xE2.
    const storeDataApdus = apdus.slice(4, 7);
    expect(storeDataApdus).toHaveLength(3);
    for (const a of storeDataApdus) {
      expect(a[0]).toBe(0x84);
      expect(a[1]).toBe(0xE2);
    }
    // P1: 0x00 on first two, 0x80 on last.
    expect(storeDataApdus[0][2]).toBe(0x00);
    expect(storeDataApdus[1][2]).toBe(0x00);
    expect(storeDataApdus[2][2]).toBe(0x80);
    // P2: block index 0, 1, 2.
    expect(storeDataApdus[0][3]).toBe(0x00);
    expect(storeDataApdus[1][3]).toBe(0x01);
    expect(storeDataApdus[2][3]).toBe(0x02);
  });

  it('SAD_EMPTY when the decrypted SAD has zero DGIs', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      proxyCardId: 'pcx_1',
      program: { issuerProfile: { aid: MC_EMV_AID_HEX } },
    });
    mocks.sadRecordFindUnique.mockResolvedValue({
      id: 'sad_1',
      status: 'READY',
      sadEncrypted: Buffer.from('deadbeef', 'hex'),
      sadKeyVersion: 1,
    });
    // PA wire format: zero DGIs = empty buffer.
    mocks.decryptSad.mockResolvedValue(Buffer.alloc(0));

    const io = scriptedIo([
      ...scp03Opener(),
      OK, // SELECT payment applet
    ]);
    const session = { id: 's1', cardId: 'c1', operation: 'personalise_payment_applet' } as any;
    const terminal = await runPersonalisePaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('SAD_EMPTY');
    expect(mocks.sadRecordUpdate).not.toHaveBeenCalled();
  });
});
