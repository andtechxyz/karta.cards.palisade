/**
 * install_payment_applet tests.
 *
 * Scripted-IO integration shape mirrors list-applets.test.ts — we
 * pretend to be the card and reply to each APDU in the expected
 * sequence.  What we verify:
 *
 *   - Card → Program → IssuerProfile → ChipProfile lookup happens and
 *     NOT_PROVISIONED fires when paymentAppletCapFilename is null or
 *     IssuerProfile.aid is empty.
 *   - CAP is loaded off disk via loadCapByFilename — mocked here to
 *     return a synthetic CAP so we don't need a real vendor binary.
 *   - SCP03 handshake runs (SELECT ISD + INITIALIZE UPDATE + EXTERNAL
 *     AUTHENTICATE).
 *   - The on-wire sequence contains DELETE instance, DELETE package,
 *     INSTALL [load], N×LOAD, INSTALL [install+selectable].
 *   - INSTALL [install+selectable] target AID is IssuerProfile.aid
 *     (the EMV AID), NOT the package+module AID.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks — vi.hoisted() runs BEFORE vi.mock() factories (which themselves
// get hoisted to the top of the file), so the shared mock fns are safe
// to reference from inside the factory.
// ---------------------------------------------------------------------------

const mocks = vi.hoisted(() => ({
  cardFindUnique: vi.fn(),
  cardOpSessionUpdate: vi.fn().mockResolvedValue({}),
  loadCapByFilename: vi.fn(),
}));

vi.mock('@palisade/db', () => ({
  prisma: {
    card: { findUnique: mocks.cardFindUnique },
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

vi.mock('../gp/cap-loader.js', async (orig) => {
  const actual = await orig<typeof import('../gp/cap-loader.js')>();
  return {
    ...actual,
    loadCapByFilename: mocks.loadCapByFilename,
  };
});

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { runInstallPaymentApplet } from './install-payment-applet.js';
import { _resetGpStaticKeysCache } from '../gp/static-keys.js';
import {
  deriveSessionKeys,
  computeCardCryptogram,
  type StaticKeys,
} from '../gp/scp03.js';
import type { WSMessage } from '../ws/messages.js';

const TEST_KEY = Buffer.from('404142434445464748494A4B4C4D4E4F', 'hex');
const STATIC_KEYS: StaticKeys = { enc: TEST_KEY, mac: TEST_KEY, dek: TEST_KEY };

const MC_EMV_AID_HEX = 'A0000000041010';
const MC_PACKAGE_AID_HEX = 'A0000000041011'; // synthetic; package != instance
const MC_MODULE_AID_HEX = 'A000000004101101';

beforeEach(() => {
  _resetGpStaticKeysCache();
  mocks.cardFindUnique.mockReset();
  mocks.cardOpSessionUpdate.mockReset();
  mocks.cardOpSessionUpdate.mockResolvedValue({});
  mocks.loadCapByFilename.mockReset();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Shape of the IO bridge the op drives.  For test purposes each
 * handler below inspects the last `apdu` message sent, and returns the
 * APDU the "card" would emit in response.  SCP03-wrapped APDUs are
 * decoded by the driver, so the handlers only care about the APDU
 * header that the driver produced.
 */
function scriptedIo(script: Array<(apdu: Buffer) => Buffer>) {
  const outbound: WSMessage[] = [];
  let step = 0;

  return {
    send: (msg: WSMessage) => {
      outbound.push(msg);
    },
    next: async (): Promise<WSMessage> => {
      // Find the most recent outbound 'apdu' with non-empty hex.
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

/** Build the synthetic CAP the mocked loader returns. */
function fakeCap(): {
  packageAid: string;
  appletAids: string[];
  loadFileDataBlock: Buffer;
} {
  // 300-byte block so chunkLoadBlock(240) emits 2 LOAD APDUs, letting
  // us verify the chunker actually fires.
  return {
    packageAid: MC_PACKAGE_AID_HEX,
    appletAids: [MC_MODULE_AID_HEX],
    loadFileDataBlock: Buffer.alloc(300, 0xAB),
  };
}

/** Standard 5-APDU SCP03 opening script.  Card challenge is fixed. */
function scp03Opener(): Array<(apdu: Buffer) => Buffer> {
  const cardChallenge = Buffer.from('08090A0B0C0D0E0F', 'hex');
  return [
    // 1) SELECT ISD
    () => Buffer.from([0x90, 0x00]),
    // 2) INITIALIZE UPDATE
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
    // 3) EXTERNAL AUTHENTICATE
    () => Buffer.from([0x90, 0x00]),
  ];
}

const OK = () => Buffer.from([0x90, 0x00]);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('runInstallPaymentApplet', () => {
  it('NOT_PROVISIONED when ChipProfile.paymentAppletCapFilename is null', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          aid: MC_EMV_AID_HEX,
          chipProfile: {
            paymentAppletCapFilename: null,
            name: 'mchip_advance_v1.2.3',
          },
        },
      },
    });

    const io = scriptedIo([]);
    const session = { id: 's1', cardId: 'c1', operation: 'install_payment_applet' } as any;
    const terminal = await runInstallPaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('NOT_PROVISIONED');
    // No APDUs should have been sent — we bail before SCP03.
    expect(io.outbound.filter((m) => m.type === 'apdu' && m.hex)).toHaveLength(0);
  });

  it('NOT_PROVISIONED when IssuerProfile.aid is empty', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          aid: '',
          chipProfile: {
            paymentAppletCapFilename: 'mchip_advance_v1.2.3.cap',
            name: 'mchip_advance_v1.2.3',
          },
        },
      },
    });

    const io = scriptedIo([]);
    const session = { id: 's1', cardId: 'c1', operation: 'install_payment_applet' } as any;
    const terminal = await runInstallPaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('NOT_PROVISIONED');
  });

  it('drives SCP03 + DELETE + INSTALL [load] + LOAD*N + INSTALL [install+selectable]', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          aid: MC_EMV_AID_HEX,
          chipProfile: {
            paymentAppletCapFilename: 'mchip_advance_v1.2.3.cap',
            name: 'mchip_advance_v1.2.3',
          },
        },
      },
    });
    mocks.loadCapByFilename.mockReturnValue(fakeCap());

    // Total script: 3 SCP03 + 2 DELETE + 1 INSTALL-LOAD + 2 LOAD (300B / 240) + 1 INSTALL-INSTALL = 9
    const io = scriptedIo([
      ...scp03Opener(),
      OK, // DELETE instance
      OK, // DELETE package
      OK, // INSTALL [load]
      OK, // LOAD block 0
      OK, // LOAD block 1 (last)
      OK, // INSTALL [install+selectable]
    ]);

    const session = { id: 's1', cardId: 'c1', operation: 'install_payment_applet' } as any;
    const terminal = await runInstallPaymentApplet(session, io);

    expect(terminal.type).toBe('complete');
    expect((terminal as any).instanceAid).toBe(MC_EMV_AID_HEX.toUpperCase());
    expect((terminal as any).packageAid).toBe(MC_PACKAGE_AID_HEX.toUpperCase());
    expect((terminal as any).moduleAid).toBe(MC_MODULE_AID_HEX.toUpperCase());
    expect((terminal as any).capFilename).toBe('mchip_advance_v1.2.3.cap');

    // Verify the APDU sequence on the wire.  The SCP03 wrap means the
    // APDU header bytes are visible in plain even though the body is
    // encrypted — CLA/INS/P1/P2 are enough for us to check sequencing.
    const apdus = io.outbound
      .filter((m) => m.type === 'apdu' && m.hex)
      .map((m) => Buffer.from(m.hex!, 'hex'));

    // Filter out the SCP03 handshake APDUs (SELECT, INITIALIZE UPDATE,
    // EXTERNAL AUTHENTICATE — CLA 00 and 80 with specific INS) to
    // focus on the install flow.
    const afterHandshake = apdus.slice(3);

    // Find expected INS bytes.  DELETE = 0xE4, INSTALL = 0xE6, LOAD = 0xE8.
    const insSequence = afterHandshake.map((a) => a[1]);
    expect(insSequence).toEqual([
      0xE4, // DELETE instance
      0xE4, // DELETE package
      0xE6, // INSTALL [load]
      0xE8, // LOAD block 0
      0xE8, // LOAD block 1
      0xE6, // INSTALL [install+selectable]
    ]);

    // INSTALL [load] has P1=0x02, INSTALL [install+selectable] has P1=0x0C.
    expect(afterHandshake[2][2]).toBe(0x02);
    expect(afterHandshake[5][2]).toBe(0x0C);

    // LOAD blocks: first is P1=0x00, second (last) is P1=0x80.  Block
    // index increments: 0 then 1.
    expect(afterHandshake[3][2]).toBe(0x00);
    expect(afterHandshake[3][3]).toBe(0x00);
    expect(afterHandshake[4][2]).toBe(0x80);
    expect(afterHandshake[4][3]).toBe(0x01);

    // cardOpSession.update was called to transition to COMPLETE.
    expect(mocks.cardOpSessionUpdate).toHaveBeenCalled();
  });

  it('CAP_FILE_MISSING when the CAP filename exists in DB but file is absent', async () => {
    mocks.cardFindUnique.mockResolvedValue({
      program: {
        issuerProfile: {
          aid: MC_EMV_AID_HEX,
          chipProfile: {
            paymentAppletCapFilename: 'totally_missing.cap',
            name: 'mchip_advance_v1.2.3',
          },
        },
      },
    });
    const { CapFileMissingError } = await import('../gp/cap-loader.js');
    mocks.loadCapByFilename.mockImplementation(() => {
      throw new CapFileMissingError('totally_missing.cap' as never, '/tmp/totally_missing.cap');
    });

    const io = scriptedIo([]);
    const session = { id: 's1', cardId: 'c1', operation: 'install_payment_applet' } as any;
    const terminal = await runInstallPaymentApplet(session, io);

    expect(terminal.type).toBe('error');
    expect(terminal.code).toBe('CAP_FILE_MISSING');
  });
});
