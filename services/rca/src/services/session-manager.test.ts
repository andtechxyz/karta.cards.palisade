import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks
//
// NOTE: vi.mock() runs before imports.  DataPrepService is mocked so we can
// control the decrypted SAD bytes without standing up AWS KMS.  prisma is
// mocked for the same reason as before — no DB in unit tests.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => {
  const p: Record<string, unknown> = {
    provisioningSession: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    sadRecord: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    card: {
      update: vi.fn(),
    },
  };
  // $transaction passes the same `prisma` object back as `tx` so the
  // callback sees the SAME mocked models that top-level tests assert on.
  // Real Prisma gives the caller an isolated tx client; tests don't need
  // that fidelity.
  p.$transaction = vi.fn((cb: (tx: unknown) => unknown) => cb(p));
  return { prisma: p };
});

vi.mock('@palisade/service-auth', () => ({
  signRequest: vi.fn().mockReturnValue('HMAC test-signature'),
}));

vi.mock('undici', () => ({
  request: vi.fn().mockResolvedValue({ statusCode: 200 }),
}));

const { mockDecryptSad } = vi.hoisted(() => ({
  mockDecryptSad: vi.fn(),
}));

vi.mock('@palisade/data-prep/services/data-prep.service', () => ({
  DataPrepService: {
    decryptSad: mockDecryptSad,
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import { SessionManager, _resetSadCacheForTests, type WSMessage } from './session-manager.js';
import { _resetRcaConfig } from '../env.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_SAD_RECORD = {
  id: 'sad_01',
  cardId: 'card_01',
  proxyCardId: 'pxy_abc123',
  sadEncrypted: Buffer.from('DEADBEEF', 'hex'),
  sadKeyVersion: 1,
  status: 'READY',
};

/**
 * Fully-populated IssuerProfile shape — matches the happy path where
 * every field the PA's TRANSFER_SAD parser reads is set.  Tests that
 * want to exercise the fallback/error paths pass a null or a
 * partial object instead.
 */
const FULL_ISSUER_PROFILE = {
  scheme: 'mchip_advance',
  bankId: 0xAABBCCDD,
  progId: 0x11223344,
  postProvisionUrl: 'issuer.example.com',
  chipProfile: {
    iccPrivateKeyDgi: 0x8001,
    iccPrivateKeyTag: 0x9F48,
  },
};

/** Plaintext SAD bytes the decrypt mock returns when called. */
const FAKE_PLAINTEXT_SAD = Buffer.from(
  '0202' + '0A' + '50085041' + '4C495341' + '4445' + // DGI 0x0202 with App Label
  'CAFEBABE',
  'hex',
);



function makeSession(phase: string, overrides: Record<string, unknown> = {}) {
  return {
    id: 'session_01',
    cardId: 'card_01',
    sadRecordId: 'sad_01',
    phase,
    iccPublicKey: null,
    attestation: null,
    ...overrides,
  };
}

function makeSessionWithFullProfile(
  phase: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    ...makeSession(phase, overrides),
    sadRecord: FAKE_SAD_RECORD,
    card: { program: { issuerProfile: FULL_ISSUER_PROFILE } },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SessionManager', () => {
  let mgr: SessionManager;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    _resetRcaConfig();
    // The SAD pre-decrypt cache is module-level; tests that exercise
    // handleMessage without going through startSession expect the cache
    // to be empty so inline decryptSad is still observed by the mock.
    _resetSadCacheForTests();
    delete process.env.RCA_ALLOW_MINIMAL_SAD;
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    mgr = new SessionManager();
    // Decrypt returns our canned plaintext on every call unless a test
    // overrides it.  Matches what DataPrepService.decryptSad would do
    // with a sadKeyVersion=1 ciphertext in dev.
    mockDecryptSad.mockResolvedValue(FAKE_PLAINTEXT_SAD);
  });

  afterEach(() => {
    warnSpy.mockRestore();
    logSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // startSession
  // -------------------------------------------------------------------------

  describe('startSession', () => {
    it('creates ProvisioningSession and returns sessionId on valid proxyCardId', async () => {
      (prisma.sadRecord.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(FAKE_SAD_RECORD);
      (prisma.provisioningSession.create as ReturnType<typeof vi.fn>).mockResolvedValue({
        id: 'session_01',
        cardId: 'card_01',
        sadRecordId: 'sad_01',
        phase: 'INIT',
      });

      const result = await mgr.startSession('pxy_abc123');

      expect(result.sessionId).toBe('session_01');
      expect(result.proxyCardId).toBe('pxy_abc123');
      expect(result.phase).toBe('INIT');
      expect(prisma.provisioningSession.create).toHaveBeenCalledOnce();
    });

    it('throws when no READY SAD record exists', async () => {
      (prisma.sadRecord.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      await expect(mgr.startSession('pxy_missing')).rejects.toThrow(
        'No READY SAD record for proxyCardId: pxy_missing',
      );
    });

    it('throws when SAD record exists but status is not READY', async () => {
      (prisma.sadRecord.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...FAKE_SAD_RECORD,
        status: 'CONSUMED',
      });

      await expect(mgr.startSession('pxy_abc123')).rejects.toThrow(
        'No READY SAD record',
      );
    });
  });

  // -------------------------------------------------------------------------
  // handleMessage — pa_fci
  // -------------------------------------------------------------------------

  describe('handleMessage — pa_fci', () => {
    it('returns GENERATE_KEYS directly (no SCP11 step) and advances phase to KEYGEN', async () => {
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('KEYGEN'),
      );

      const responses = await mgr.handleMessage('session_01', { type: 'pa_fci' });

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('apdu');
      expect(responses[0].phase).toBe('key_generation');
      // 80 E0 00 00 01 01 — exactly the bytes the Palisade SSD e2e test uses.
      expect(responses[0].hex).toBe('80E000000101');
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'session_01' },
          data: { phase: 'KEYGEN' },
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // handleMessage — response in KEYGEN phase
  // -------------------------------------------------------------------------

  describe('handleMessage — response in KEYGEN phase', () => {
    it('returns TRANSFER_SAD APDU, stores iccPublicKey + attestation', async () => {
      // 65 bytes of fake ICC public key + 72 bytes attestation + 42 CPLC
      const fakeIccPub = Buffer.alloc(65, 0x04);
      const fakeAttest = Buffer.alloc(72, 0xAA);
      const fakeCplc = Buffer.alloc(42, 0xBB);
      const responseData = Buffer.concat([fakeIccPub, fakeAttest, fakeCplc]);

      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSessionWithFullProfile('KEYGEN'),
      );
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('SAD_TRANSFER'),
      );

      const msg: WSMessage = { type: 'response', hex: responseData.toString('hex'), sw: '9000' };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('apdu');
      expect(responses[0].phase).toBe('provisioning');
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            phase: 'SAD_TRANSFER',
            iccPublicKey: expect.any(Buffer),
            attestation: expect.any(Buffer),
          }),
        }),
      );
      // Real SAD was decrypted.
      expect(mockDecryptSad).toHaveBeenCalledWith(
        expect.any(Buffer),
        '',
        1,
      );
      // Attestation verify stub warning fired.
      expect(
        warnSpy.mock.calls.some((args) =>
          typeof args[0] === 'string' && args[0].includes('PERMISSIVE MODE'),
        ),
      ).toBe(true);
    });

    it('encodes real issuer profile metadata (not placeholders) in the TRANSFER_SAD APDU', async () => {
      const fakeIccPub = Buffer.alloc(65, 0x04);
      const fakeAttest = Buffer.alloc(72, 0xAA);
      const fakeCplc = Buffer.alloc(42, 0xBB);
      const responseData = Buffer.concat([fakeIccPub, fakeAttest, fakeCplc]);

      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSessionWithFullProfile('KEYGEN'),
      );
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('SAD_TRANSFER'),
      );

      const msg: WSMessage = { type: 'response', hex: responseData.toString('hex'), sw: '9000' };
      const responses = await mgr.handleMessage('session_01', msg);

      const apduHex = (responses[0].hex ?? '').toUpperCase();
      // bankId (0xAABBCCDD) and progId (0x11223344) must appear somewhere
      // in the TRANSFER_SAD payload — exact offset depends on the SAD
      // payload size so we just check for presence.
      expect(apduHex).toContain('AABBCCDD');
      expect(apduHex).toContain('11223344');
      // postProvisionUrl hostname
      const urlHex = Buffer.from('issuer.example.com', 'ascii').toString('hex').toUpperCase();
      expect(apduHex).toContain(urlHex);
      // dgi+emvTag tail is always the last 4 bytes
      expect(apduHex.slice(-8)).toBe('80019F48');
    });
  });

  // -------------------------------------------------------------------------
  // handleMessage — response in SAD_TRANSFER phase
  // -------------------------------------------------------------------------

  describe('handleMessage — response in SAD_TRANSFER phase', () => {
    it('returns FINAL_STATUS APDU and updates phase to AWAITING_FINAL', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('SAD_TRANSFER'),
      );
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('AWAITING_FINAL'),
      );

      const msg: WSMessage = { type: 'response', hex: '', sw: '9000' };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('apdu');
      expect(responses[0].phase).toBe('finalizing');
      expect(responses[0].progress).toBe(0.80);
    });
  });

  // -------------------------------------------------------------------------
  // handleMessage — response in AWAITING_FINAL with success
  // -------------------------------------------------------------------------

  describe('handleMessage — response in AWAITING_FINAL with success byte', () => {
    it('returns CONFIRM + complete, updates card to PROVISIONED', async () => {
      // The implementation pre-fetches the session (with card + sadRecord
      // relations) so the response payload is ready before the DB commit
      // kicks off asynchronously.  AWAITING_FINAL branch on the first
      // findUnique (phase check) + same enriched shape on the second.
      const enriched = {
        ...makeSession('AWAITING_FINAL'),
        cardId: 'card_01',
        sadRecordId: 'sad_01',
        card: { cardRef: 'ref_01', chipSerial: 'CS001' },
        sadRecord: { proxyCardId: 'pxy_abc123' },
      };
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(enriched);
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('COMPLETE'),
        cardId: 'card_01',
        sadRecordId: 'sad_01',
        card: { cardRef: 'ref_01', chipSerial: 'CS001' },
        sadRecord: { proxyCardId: 'pxy_abc123' },
      });
      (prisma.card.update as ReturnType<typeof vi.fn>).mockResolvedValue({});
      (prisma.sadRecord.update as ReturnType<typeof vi.fn>).mockResolvedValue({});

      // 0x01 = success byte, followed by 32 bytes provenance hash
      const statusData = Buffer.concat([
        Buffer.from([0x01]),
        Buffer.alloc(32, 0xCC), // provenance hash
      ]);
      const msg: WSMessage = { type: 'response', hex: statusData.toString('hex'), sw: '9000' };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(2);
      expect(responses[0].type).toBe('apdu');
      expect(responses[0].hex).toBe('80E8000000'); // CONFIRM APDU
      expect(responses[0].phase).toBe('confirming');
      expect(responses[1].type).toBe('complete');
      expect(responses[1].proxyCardId).toBe('pxy_abc123');

      // The atomic commit runs asynchronously now — flush the microtask
      // queue so the $transaction callback (mocked to run inline) has
      // executed by the time we assert on card.update / sadRecord.update.
      await new Promise((r) => setImmediate(r));

      // Card status updated to PROVISIONED
      expect(prisma.card.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'card_01' },
          data: expect.objectContaining({ status: 'PROVISIONED' }),
        }),
      );

      // SAD marked CONSUMED
      expect(prisma.sadRecord.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'sad_01' },
          data: { status: 'CONSUMED' },
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // handleMessage — response in AWAITING_FINAL with failure
  // -------------------------------------------------------------------------

  describe('handleMessage — response in AWAITING_FINAL with failure byte', () => {
    it('returns error and marks session FAILED', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('AWAITING_FINAL'),
      );
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('FAILED'),
      );

      // 0x00 = failure byte
      const statusData = Buffer.from([0x00]);
      const msg: WSMessage = { type: 'response', hex: statusData.toString('hex'), sw: '9000' };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('error');
      expect(responses[0].code).toBe('PA_FAILED');
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            phase: 'FAILED',
            failureReason: 'PA_FAILED',
          }),
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // handleMessage — error
  // -------------------------------------------------------------------------

  describe('handleMessage — error type', () => {
    it('sets session phase=FAILED and records failureReason', async () => {
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('FAILED'),
      );

      const msg: WSMessage = { type: 'error', code: 'NFC_LOST', message: 'Tag was lost' };
      const responses = await mgr.handleMessage('session_01', msg);

      // handleError returns empty array
      expect(responses).toHaveLength(0);
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'session_01' },
          data: expect.objectContaining({
            phase: 'FAILED',
            failureReason: 'NFC_LOST',
          }),
        }),
      );
    });
  });

  // -------------------------------------------------------------------------
  // handleMessage — card error SW
  // -------------------------------------------------------------------------

  describe('handleMessage — card error SW', () => {
    it('returns error when card returns non-9000 SW', async () => {
      const msg: WSMessage = { type: 'response', hex: '', sw: '6A82' };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('error');
      expect(responses[0].code).toBe('CARD_ERROR');
      expect(responses[0].message).toContain('6A82');
    });
  });

  // -------------------------------------------------------------------------
  // Plan mode — buildPlanForSession
  //
  // Happy path + fallback + error path.  Verifies that the session's
  // SadRecord gets decrypted (mocked), the real IssuerProfile fields land
  // in the plan's TRANSFER_SAD APDU, and that the
  // `issuer_profile_incomplete` error throws when metadata is missing
  // unless RCA_ALLOW_MINIMAL_SAD=1.
  // -------------------------------------------------------------------------

  describe('buildPlanForSession — happy path', () => {
    it('decrypts the SAD, plumbs IssuerProfile fields, and emits a 5-step plan', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSessionWithFullProfile('INIT'),
      );

      const plan = await mgr.buildPlanForSession('session_01');

      expect(plan.type).toBe('plan');
      expect(plan.version).toBe(1);
      expect(plan.steps).toHaveLength(5);

      // Decrypt was called with the session's ciphertext + sadKeyVersion=1.
      expect(mockDecryptSad).toHaveBeenCalledOnce();
      expect(mockDecryptSad).toHaveBeenCalledWith(
        FAKE_SAD_RECORD.sadEncrypted,
        '',
        FAKE_SAD_RECORD.sadKeyVersion,
      );

      // Step 2 (TRANSFER_SAD) must contain the real bankId/progId bytes
      // and the postProvisionUrl string — not the old placeholders.
      const transfer = plan.steps[2].apdu.toUpperCase();
      expect(transfer).toContain('AABBCCDD');    // bankId
      expect(transfer).toContain('11223344');    // progId
      const urlHex = Buffer.from('issuer.example.com', 'ascii').toString('hex').toUpperCase();
      expect(transfer).toContain(urlHex);
      // Tail dgi/emvTag
      expect(transfer.slice(-8)).toBe('80019F48');

      // And the plaintext SAD bytes must appear at the start of the
      // TRANSFER_SAD payload body (after the 5-byte APDU header).
      const body = transfer.slice(10);
      expect(body.startsWith(FAKE_PLAINTEXT_SAD.toString('hex').toUpperCase())).toBe(true);
    });

    it('maps IssuerProfile.scheme="vsdc" to 0x02 in the APDU', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        sadRecord: FAKE_SAD_RECORD,
        card: {
          program: {
            issuerProfile: { ...FULL_ISSUER_PROFILE, scheme: 'vsdc' },
          },
        },
      });

      const plan = await mgr.buildPlanForSession('session_01');
      const transfer = plan.steps[2].apdu.toUpperCase();
      // scheme sits between progId(4) and timestamp(4).  Look for the
      // exact metadata sequence: progId || scheme || ts ... ; we know
      // progId = 0x11223344 and scheme should now be 0x02.
      expect(transfer).toContain('1122334402');
    });
  });

  describe('buildPlanForSession — RCA_ALLOW_MINIMAL_SAD=1 dev fallback', () => {
    it('uses placeholders + minimal "PALISADE" SAD when issuer profile is empty', async () => {
      process.env.RCA_ALLOW_MINIMAL_SAD = '1';
      _resetRcaConfig();

      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        sadRecord: FAKE_SAD_RECORD,
        card: { program: { issuerProfile: null } },
      });

      const plan = await mgr.buildPlanForSession('session_01');

      // Plan shape is unchanged.
      expect(plan.steps).toHaveLength(5);

      // Minimal-SAD fallback produces the old placeholder bankId (0x00000001)
      // and progId (0x00000001), with scheme=0x01.  PA parses from the end
      // so we check explicit offsets after the SAD.  Minimal SAD = 13 bytes.
      const transfer = plan.steps[2].apdu.toUpperCase();
      const body = transfer.slice(10); // strip header
      const tail = body.slice(26); // strip 13-byte minimal SAD
      expect(tail.slice(0, 8)).toBe('00000001'); // bankId
      expect(tail.slice(8, 16)).toBe('00000001'); // progId
      expect(tail.slice(16, 18)).toBe('01'); // scheme

      // The decrypt path is NOT hit in fallback mode.
      expect(mockDecryptSad).not.toHaveBeenCalled();

      // Loud warning must have been emitted.
      expect(
        warnSpy.mock.calls.some((args) =>
          typeof args[0] === 'string' && args[0].includes('RCA_ALLOW_MINIMAL_SAD'),
        ),
      ).toBe(true);
    });

    it('still falls back even if only one required IssuerProfile field is missing', async () => {
      process.env.RCA_ALLOW_MINIMAL_SAD = '1';
      _resetRcaConfig();

      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        sadRecord: FAKE_SAD_RECORD,
        card: {
          program: {
            issuerProfile: { ...FULL_ISSUER_PROFILE, bankId: null },
          },
        },
      });

      const plan = await mgr.buildPlanForSession('session_01');
      expect(plan.steps).toHaveLength(5);
      expect(mockDecryptSad).not.toHaveBeenCalled();
    });
  });

  describe('buildPlanForSession — issuer_profile_incomplete error path', () => {
    it('throws badRequest when IssuerProfile is null and fallback flag is off', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        sadRecord: FAKE_SAD_RECORD,
        card: { program: { issuerProfile: null } },
      });

      await expect(mgr.buildPlanForSession('session_01')).rejects.toThrow(
        /issuer_profile_incomplete|IssuerProfile is missing/,
      );
    });

    it('throws badRequest when a required field (progId) is null and flag is off', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        sadRecord: FAKE_SAD_RECORD,
        card: {
          program: {
            issuerProfile: { ...FULL_ISSUER_PROFILE, progId: null },
          },
        },
      });

      await expect(mgr.buildPlanForSession('session_01')).rejects.toThrow(
        /issuer_profile_incomplete|IssuerProfile is missing/,
      );
    });

    it('throws when postProvisionUrl is empty string and flag is off', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        sadRecord: FAKE_SAD_RECORD,
        card: {
          program: {
            issuerProfile: { ...FULL_ISSUER_PROFILE, postProvisionUrl: '' },
          },
        },
      });

      await expect(mgr.buildPlanForSession('session_01')).rejects.toThrow(
        /issuer_profile_incomplete|IssuerProfile is missing/,
      );
    });

    it('throws when the session does not exist', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(null);
      await expect(mgr.buildPlanForSession('missing')).rejects.toThrow('Unknown session');
    });
  });

  // -------------------------------------------------------------------------
  // Plan mode — handleMessage routing via `i` field
  //
  // Responses with `i` go through the plan handlers; responses without
  // `i` go through the classical phase machine.  These tests cover the
  // plan path in isolation.
  // -------------------------------------------------------------------------

  describe('handleMessage — plan-mode response routing', () => {
    it('routes step 1 (keygen) response to iccPublicKey + attestation capture', async () => {
      const fakeIccPub = Buffer.alloc(65, 0x04);
      const fakeAttest = Buffer.alloc(72, 0xAA);
      const fakeCplc = Buffer.alloc(42, 0xBB);
      const responseData = Buffer.concat([fakeIccPub, fakeAttest, fakeCplc]);

      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('PLAN_SENT'),
      );

      const msg: WSMessage = {
        type: 'response',
        i: 1,
        hex: responseData.toString('hex'),
        sw: '9000',
      };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(0); // no outbound on step 1 — phone keeps going
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            iccPublicKey: expect.any(Buffer),
            attestation: expect.any(Buffer),
          }),
        }),
      );

      // Attestation stub banner must have fired exactly once for this
      // keygen response.
      expect(
        warnSpy.mock.calls.some((args) =>
          typeof args[0] === 'string' && args[0].includes('PERMISSIVE MODE'),
        ),
      ).toBe(true);
    });

    it('persists the attestation bytes on the session row', async () => {
      // Distinctive attestation payload so we can verify it was saved
      // verbatim (byte-for-byte) rather than truncated or reshaped.
      const pub = Buffer.alloc(65, 0x04);
      const sig = Buffer.from(
        '3045022100' + '11'.repeat(32) + '022000' + '22'.repeat(30),
        'hex',
      );
      const cplc = Buffer.alloc(42, 0xCC);
      const full = Buffer.concat([pub, sig, cplc]);

      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('PLAN_SENT'),
      );

      await mgr.handleMessage('session_01', {
        type: 'response',
        i: 1,
        hex: full.toString('hex'),
        sw: '9000',
      });

      const updateCall = (prisma.provisioningSession.update as ReturnType<typeof vi.fn>)
        .mock.calls[0][0] as { data: { attestation: Buffer } };
      expect(updateCall.data.attestation.equals(sig)).toBe(true);
    });

    it('step 3 success transitions to AWAITING_CONFIRM and emits no response', async () => {
      const statusData = Buffer.concat([
        Buffer.from([0x01]),       // success byte
        Buffer.alloc(32, 0xCC),    // provenance hash
      ]);

      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('AWAITING_CONFIRM'),
      );

      const msg: WSMessage = {
        type: 'response',
        i: 3,
        hex: statusData.toString('hex'),
        sw: '9000',
      };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(0);
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            phase: 'AWAITING_CONFIRM',
            provenance: expect.any(String),
          }),
        }),
      );
    });

    it('step 3 failure (status byte != 0x01) sends error and marks session FAILED', async () => {
      const statusData = Buffer.from([0x00]); // failure byte

      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('FAILED'),
      );

      const msg: WSMessage = {
        type: 'response',
        i: 3,
        hex: statusData.toString('hex'),
        sw: '9000',
      };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('error');
      expect(responses[0].code).toBe('PA_FAILED');
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            phase: 'FAILED',
            failureReason: 'PA_FAILED',
          }),
        }),
      );
    });

    it('step 4 (confirm) commits: card PROVISIONED + SAD CONSUMED + complete message', async () => {
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('COMPLETE'),
        cardId: 'card_01',
        sadRecordId: 'sad_01',
        card: { cardRef: 'ref_01', chipSerial: 'CS001' },
        sadRecord: { proxyCardId: 'pxy_abc123' },
      });
      (prisma.card.update as ReturnType<typeof vi.fn>).mockResolvedValue({});
      (prisma.sadRecord.update as ReturnType<typeof vi.fn>).mockResolvedValue({});

      const msg: WSMessage = { type: 'response', i: 4, hex: '', sw: '9000' };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('complete');
      expect(responses[0].proxyCardId).toBe('pxy_abc123');
      expect(prisma.card.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ status: 'PROVISIONED' }),
        }),
      );
      expect(prisma.sadRecord.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: { status: 'CONSUMED' },
        }),
      );
    });

    it('non-9000 SW at any step marks session FAILED with step-specific reason', async () => {
      (prisma.provisioningSession.update as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('FAILED'),
      );

      const msg: WSMessage = { type: 'response', i: 2, hex: '', sw: '6A82' };
      const responses = await mgr.handleMessage('session_01', msg);

      expect(responses).toHaveLength(1);
      expect(responses[0].type).toBe('error');
      expect(responses[0].code).toBe('CARD_ERROR');
      expect(responses[0].message).toContain('step 2');
      expect(prisma.provisioningSession.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            phase: 'FAILED',
            failureReason: expect.stringContaining('step_2'),
          }),
        }),
      );
    });

    it('step 0 (SELECT PA) and step 2 (TRANSFER_SAD) responses are logged but emit nothing', async () => {
      const select0: WSMessage = { type: 'response', i: 0, hex: '6F10A00000006250414C', sw: '9000' };
      const responses0 = await mgr.handleMessage('session_01', select0);
      expect(responses0).toHaveLength(0);

      const transfer2: WSMessage = { type: 'response', i: 2, hex: '00020021', sw: '9000' };
      const responses2 = await mgr.handleMessage('session_01', transfer2);
      expect(responses2).toHaveLength(0);
    });
  });
});
