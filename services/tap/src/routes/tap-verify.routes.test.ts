import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'express-async-errors';
import express from 'express';
import http from 'node:http';
import { createCipheriv } from 'node:crypto';
import { aesCmac } from '@palisade/core';

// ---------------------------------------------------------------------------
// Mocks — Prisma + KeyProvider.  We use the REAL SUN crypto (picc, sessionKeys,
// verify) so the test exercises the full decrypt + MAC verify path end-to-end.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    program: { findUnique: vi.fn() },
    card: {
      findMany: vi.fn(),
      updateMany: vi.fn(),
    },
  },
}));

vi.mock('../env.js', () => ({
  getTapConfig: vi.fn(() => ({
    TAP_HANDOFF_SECRET: 'a'.repeat(64),
    PORT: 3001,
  })),
}));

vi.mock('../key-provider.js', () => ({
  // Identity provider — encrypted blobs in the mocks ARE the plaintext hex.
  // Avoids needing AES-GCM envelope test vectors.
  getCardFieldKeyProvider: vi.fn(() => ({})),
}));

vi.mock('@palisade/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@palisade/core')>();
  return {
    ...actual,
    // Identity decrypt — `ciphertext` IS the plaintext hex.
    decrypt: vi.fn((payload: { ciphertext: string }) => payload.ciphertext),
  };
});

// The route now asks the sdm-deriver singleton for per-UID meta/file keys
// instead of reading them out of the DB.  We register a per-UID lookup
// table up-front; each test populates it with the UIDs it cares about.
const deriverTable = new Map<string, { meta: Buffer; file: Buffer }>();
vi.mock('../sdm-deriver.js', () => ({
  getSdmDeriver: vi.fn(() => ({
    deriveMetaReadKey: vi.fn(async (uid: Buffer) => {
      const entry = deriverTable.get(uid.toString('hex'));
      if (!entry) return Buffer.alloc(16, 0); // non-match
      return Buffer.from(entry.meta);
    }),
    deriveFileReadKey: vi.fn(async (uid: Buffer) => {
      const entry = deriverTable.get(uid.toString('hex'));
      if (!entry) return Buffer.alloc(16, 0);
      return Buffer.from(entry.file);
    }),
  })),
}));

import { prisma } from '@palisade/db';
import tapVerifyRouter from './tap-verify.routes.js';
import { errorMiddleware } from '@palisade/core';
import { PICC_DATA_TAG, SC_SDMMAC, SCT_1, SKL_128 } from '../sun/index.js';

// ---------------------------------------------------------------------------
// Test harness — same pattern as services/admin/src/routes/cards.routes.test.ts
// ---------------------------------------------------------------------------

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/tap', tapVerifyRouter);
  app.use(errorMiddleware);
  return app;
}

let activeServer: http.Server | null = null;

async function inject(
  app: express.Express,
  method: string,
  path: string,
  body?: Record<string, unknown>,
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    activeServer = server;
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;
      const bodyStr = body ? JSON.stringify(body) : undefined;
      const req = http.request(url, {
        method,
        headers: {
          'content-type': 'application/json',
          ...(bodyStr ? { 'content-length': String(Buffer.byteLength(bodyStr)) } : {}),
        },
      }, (res) => {
        let data = '';
        res.on('data', (c: string) => { data += c; });
        res.on('end', () => {
          server.close();
          activeServer = null;
          let parsed: any = null;
          try { parsed = data ? JSON.parse(data) : null; } catch { parsed = data; }
          resolve({ status: res.statusCode!, body: parsed });
        });
      });
      req.on('error', (e) => { server.close(); activeServer = null; reject(e); });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  });
}

afterEach(() => {
  if (activeServer) { activeServer.close(); activeServer = null; }
});

beforeEach(() => {
  vi.resetAllMocks();
  deriverTable.clear();
});

const programFind = () => prisma.program.findUnique as unknown as ReturnType<typeof vi.fn>;
const cardFindMany = () => prisma.card.findMany as unknown as ReturnType<typeof vi.fn>;
const cardUpdateMany = () => prisma.card.updateMany as unknown as ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// Fixture builder — mints a real (PICC, MAC) pair the way the chip would.
// ---------------------------------------------------------------------------

interface ChipFixture {
  metaKeyHex: string;
  fileKeyHex: string;
  uid: Buffer;
  counter: number;
  piccHex: string;
  macHex: string;
  fullUrl: string;
}

function makeChipFixture(opts: {
  urlCode: string;
  uid?: Buffer;
  counter?: number;
  metaKey?: Buffer;
  fileKey?: Buffer;
}): ChipFixture {
  const uid = opts.uid ?? Buffer.from('c74d303b4739c8', 'hex');
  const counter = opts.counter ?? 7;
  const metaKey = opts.metaKey ?? Buffer.from('5d96c37909d28826549373b7ac96dbe5', 'hex');
  const fileKey = opts.fileKey ?? Buffer.from('b29849cb018bb50d95ce396e1fc1a28f', 'hex');

  // PICC plaintext: tag(1) | uid(7) | counter LE(3) | padding(5)
  const plaintext = Buffer.concat([
    Buffer.from([PICC_DATA_TAG]),
    uid,
    Buffer.from([counter & 0xff, (counter >> 8) & 0xff, (counter >> 16) & 0xff]),
    Buffer.alloc(5, 0),
  ]);
  const cipher = createCipheriv('aes-128-cbc', metaKey, Buffer.alloc(16));
  cipher.setAutoPadding(false);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const piccHex = encrypted.toString('hex').toUpperCase();

  // Session MAC key: AES-CMAC(fileKey, SC_SDMMAC || SCT_1 || SKL_128 || uid || counterLE)
  const sv = Buffer.concat([uid, plaintext.subarray(8, 11)]);
  const sessionVector = Buffer.concat([SC_SDMMAC, SCT_1, SKL_128, sv]);
  const macSessionKey = aesCmac(fileKey, sessionVector);

  // SDMMAC input: host+path?e=<picc>&m= (fixed shape for /t/<urlCode>)
  const macInputStr = `mobile.karta.cards/t/${opts.urlCode}?e=${piccHex}&m=`;
  const fullCmac = aesCmac(macSessionKey, Buffer.from(macInputStr, 'ascii'));
  // Truncate per AN14683: bytes at odd 0-based indices (1,3,5,...,15)
  const truncated = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) truncated[i] = fullCmac[1 + i * 2];
  const macHex = truncated.toString('hex').toUpperCase();

  return {
    metaKeyHex: metaKey.toString('hex'),
    fileKeyHex: fileKey.toString('hex'),
    uid,
    counter,
    piccHex,
    macHex,
    fullUrl: `https://mobile.karta.cards/t/${opts.urlCode}?e=${piccHex}&m=${macHex}`,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('POST /api/tap/verify/:urlCode', () => {
  it('happy path — real PICC + MAC under the matching card → 200 + handoff', async () => {
    const fx = makeChipFixture({ urlCode: 'kp' });
    deriverTable.set(fx.uid.toString('hex'), {
      meta: Buffer.from(fx.metaKeyHex, 'hex'),
      file: Buffer.from(fx.fileKeyHex, 'hex'),
    });
    programFind().mockResolvedValueOnce({ id: 'karta_platinum', urlCode: 'kp' });
    cardFindMany().mockResolvedValueOnce([{
      id: 'card_1',
      status: 'ACTIVATED',
      lastReadCounter: 0,
      keyVersion: 1,
      uidEncrypted: fx.uid.toString('hex'),
    }]);
    cardUpdateMany().mockResolvedValueOnce({ count: 1 });

    const res = await inject(buildApp(), 'POST', '/api/tap/verify/kp', { e: fx.piccHex, m: fx.macHex });

    expect(res.status).toBe(200);
    expect(res.body.cardId).toBe('card_1');
    expect(res.body.cardStatus).toBe('ACTIVATED');
    expect(typeof res.body.handoff).toBe('string');
    expect(res.body.handoff.length).toBeGreaterThan(20);
    expect(res.body.reason).toBe(null);
    // Counter advance was atomic with the right "lt" guard
    expect(cardUpdateMany()).toHaveBeenCalledWith({
      where: { id: 'card_1', lastReadCounter: { lt: fx.counter } },
      data: { lastReadCounter: fx.counter },
    });
  });

  it('finds the right card when multiple candidates exist (trial-decrypt loop)', async () => {
    const fx = makeChipFixture({ urlCode: 'kp', uid: Buffer.from('aabbccddeeff11', 'hex') });
    const decoyUid = Buffer.from('11111111111111', 'hex');
    // Only the "real" UID maps to matching meta/file keys.  The decoy UID
    // gets a bogus all-zero meta key → picc decrypt tag check fails.
    deriverTable.set(fx.uid.toString('hex'), {
      meta: Buffer.from(fx.metaKeyHex, 'hex'),
      file: Buffer.from(fx.fileKeyHex, 'hex'),
    });
    deriverTable.set(decoyUid.toString('hex'), {
      meta: Buffer.alloc(16, 0),
      file: Buffer.alloc(16, 0),
    });
    programFind().mockResolvedValueOnce({ id: 'karta_platinum', urlCode: 'kp' });
    cardFindMany().mockResolvedValueOnce([
      {
        id: 'card_decoy',
        status: 'ACTIVATED',
        lastReadCounter: 0,
        keyVersion: 1,
        uidEncrypted: decoyUid.toString('hex'),
      },
      {
        id: 'card_real',
        status: 'ACTIVATED',
        lastReadCounter: 0,
        keyVersion: 1,
        uidEncrypted: fx.uid.toString('hex'),
      },
    ]);
    cardUpdateMany().mockResolvedValueOnce({ count: 1 });

    const res = await inject(buildApp(), 'POST', '/api/tap/verify/kp', { e: fx.piccHex, m: fx.macHex });
    expect(res.status).toBe(200);
    expect(res.body.cardId).toBe('card_real');
  });

  it('404 program_not_found when urlCode does not match any program', async () => {
    programFind().mockResolvedValueOnce(null);
    const res = await inject(buildApp(), 'POST', '/api/tap/verify/zz', {
      e: 'A'.repeat(32), m: 'B'.repeat(16),
    });
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('program_not_found');
  });

  it('404 card_not_found when no card decrypts the PICC', async () => {
    const uid = Buffer.from('ffffffffffffff', 'hex');
    deriverTable.set(uid.toString('hex'), {
      meta: Buffer.alloc(16, 0),
      file: Buffer.alloc(16, 0),
    });
    programFind().mockResolvedValueOnce({ id: 'karta_platinum', urlCode: 'kp' });
    cardFindMany().mockResolvedValueOnce([{
      id: 'card_x',
      status: 'ACTIVATED',
      lastReadCounter: 0,
      keyVersion: 1,
      uidEncrypted: uid.toString('hex'),
    }]);
    const res = await inject(buildApp(), 'POST', '/api/tap/verify/kp', {
      e: 'A'.repeat(32), m: 'B'.repeat(16),
    });
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('card_not_found');
  });

  it('401 sun_invalid when MAC has been tampered', async () => {
    const fx = makeChipFixture({ urlCode: 'kp' });
    deriverTable.set(fx.uid.toString('hex'), {
      meta: Buffer.from(fx.metaKeyHex, 'hex'),
      file: Buffer.from(fx.fileKeyHex, 'hex'),
    });
    programFind().mockResolvedValueOnce({ id: 'karta_platinum', urlCode: 'kp' });
    cardFindMany().mockResolvedValueOnce([{
      id: 'card_1',
      status: 'ACTIVATED',
      lastReadCounter: 0,
      keyVersion: 1,
      uidEncrypted: fx.uid.toString('hex'),
    }]);
    // PICC is valid, MAC is bogus
    const res = await inject(buildApp(), 'POST', '/api/tap/verify/kp', {
      e: fx.piccHex, m: '0'.repeat(16),
    });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('sun_invalid');
  });

  it('410 sun_counter_replay when the counter is not strictly greater than stored', async () => {
    const fx = makeChipFixture({ urlCode: 'kp', counter: 5 });
    deriverTable.set(fx.uid.toString('hex'), {
      meta: Buffer.from(fx.metaKeyHex, 'hex'),
      file: Buffer.from(fx.fileKeyHex, 'hex'),
    });
    programFind().mockResolvedValueOnce({ id: 'karta_platinum', urlCode: 'kp' });
    cardFindMany().mockResolvedValueOnce([{
      id: 'card_1',
      status: 'ACTIVATED',
      lastReadCounter: 5, // stored counter is already at 5
      keyVersion: 1,
      uidEncrypted: fx.uid.toString('hex'),
    }]);
    cardUpdateMany().mockResolvedValueOnce({ count: 0 }); // race / replay

    const res = await inject(buildApp(), 'POST', '/api/tap/verify/kp', { e: fx.piccHex, m: fx.macHex });
    expect(res.status).toBe(410);
    expect(res.body.error.code).toBe('sun_counter_replay');
  });

  it('400 invalid_url_code on bad urlCode shape', async () => {
    const res = await inject(buildApp(), 'POST', '/api/tap/verify/INVALID-UPPER', {
      e: 'A'.repeat(32), m: 'B'.repeat(16),
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_url_code');
  });

  it('400 on malformed body', async () => {
    const res = await inject(buildApp(), 'POST', '/api/tap/verify/kp', { e: 'short' });
    expect(res.status).toBe(400);
  });
});

