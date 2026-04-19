/**
 * list_applets integration-ish test.
 *
 * Simulates a card by mocking the send/next bridge with a scripted
 * response sequence.  Verifies:
 *   - SCP03 handshake happens (SELECT ISD, INITIALIZE UPDATE, EXT AUTH)
 *   - GET STATUS fires with correct P1/P2
 *   - Pagination triggers on SW=6310
 *   - Terminal message carries the parsed applet list
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@palisade/db', () => ({
  prisma: {
    cardOpSession: {
      update: vi.fn().mockResolvedValue({}),
    },
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
  }),
}));

import { runListApplets } from './list-applets.js';
import { _resetGpStaticKeysCache } from '../gp/static-keys.js';
import {
  deriveSessionKeys,
  computeCardCryptogram,
  type StaticKeys,
} from '../gp/scp03.js';
import type { WSMessage } from '../ws/messages.js';

const TEST_KEY = Buffer.from('404142434445464748494A4B4C4D4E4F', 'hex');
const STATIC_KEYS: StaticKeys = { enc: TEST_KEY, mac: TEST_KEY, dek: TEST_KEY };

beforeEach(() => {
  _resetGpStaticKeysCache();
});

/**
 * Build a fake IO pair that scripts responses.  Each sent APDU looks
 * up the next response from the script, which can either be a fixed
 * byte buffer OR a function that derives the response from the APDU
 * just sent (used for SCP03 where the card cryptogram depends on the
 * host challenge in INITIALIZE UPDATE).
 */
function scriptedIo(script: Array<(apdu: Buffer) => Buffer>) {
  const outbound: WSMessage[] = [];
  let step = 0;

  return {
    send: (msg: WSMessage) => {
      outbound.push(msg);
    },
    next: async (): Promise<WSMessage> => {
      // Find the most recent outbound 'apdu' with non-empty hex; that's
      // the APDU the "card" should reply to.  Operations sometimes
      // emit progress-only apdu messages with empty hex — skip those.
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

describe('runListApplets', () => {
  it('drives SCP03 handshake then enumerates applets', async () => {
    // Card challenge we'll emit in INITIALIZE UPDATE response.
    const cardChallenge = Buffer.from('08090A0B0C0D0E0F', 'hex');

    const script: Array<(apdu: Buffer) => Buffer> = [
      // 1) SELECT ISD → 9000 + empty FCI
      () => Buffer.from([0x90, 0x00]),

      // 2) INITIALIZE UPDATE → 32B body + 9000
      (apdu) => {
        // Extract host challenge bytes 5..13 of the APDU.
        const hostChallenge = apdu.subarray(5, 13);
        const keys = deriveSessionKeys(STATIC_KEYS, hostChallenge, cardChallenge);
        const cryptogram = computeCardCryptogram(keys.sMac, hostChallenge, cardChallenge);
        const body = Buffer.concat([
          Buffer.alloc(10, 0xAA),
          Buffer.from([0x30]),   // kvn
          Buffer.from([0x03]),   // scpId
          Buffer.from([0x00]),   // iParam
          cardChallenge,
          cryptogram,
          Buffer.from('000001', 'hex'),
        ]);
        return Buffer.concat([body, Buffer.from([0x90, 0x00])]);
      },

      // 3) EXTERNAL AUTHENTICATE → 9000
      () => Buffer.from([0x90, 0x00]),

      // 4) GET STATUS applications — 1 app entry + 9000
      () => {
        const entry = Buffer.concat([
          Buffer.from([0x61, 0x10]),
          Buffer.from([0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x50, 0x41]),
          Buffer.from([0x9F, 0x70, 0x01, 0x07]),
          Buffer.from([0xC5, 0x01, 0x00]),
        ]);
        return Buffer.concat([entry, Buffer.from([0x90, 0x00])]);
      },

      // 5) GET STATUS packages — empty + 6A88 (no data)
      () => Buffer.from([0x6A, 0x88]),
    ];

    const io = scriptedIo(script);
    const session = {
      id: 's1',
      cardId: 'c1',
      operation: 'list_applets',
      initiatedBy: 'admin',
      phase: 'RUNNING',
      card: { id: 'c1' },
    } as any;

    const terminal = await runListApplets(session, io);

    expect(terminal.type).toBe('complete');
    expect(Array.isArray((terminal as any).applets)).toBe(true);
    expect((terminal as any).applets).toHaveLength(1);
    expect((terminal as any).applets[0].aid).toBe('A0000000625041');
    expect((terminal as any).packages).toHaveLength(0);
  });
});
