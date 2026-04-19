import { vi, describe, it, expect, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
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
  },
}));

vi.mock('@palisade/service-auth', () => ({
  signRequest: vi.fn().mockReturnValue('HMAC test-signature'),
}));

vi.mock('undici', () => ({
  request: vi.fn().mockResolvedValue({ statusCode: 200 }),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import { SessionManager, type WSMessage } from './session-manager.js';

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



function makeSession(phase: string, overrides: Record<string, unknown> = {}) {
  return {
    id: 'session_01',
    cardId: 'card_01',
    sadRecordId: 'sad_01',
    phase,
    iccPublicKey: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SessionManager', () => {
  let mgr: SessionManager;

  beforeEach(() => {
    vi.clearAllMocks();
    mgr = new SessionManager();
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
    it('returns TRANSFER_SAD APDU and stores iccPublicKey', async () => {
      // 65 bytes of fake ICC public key + 72 bytes attestation + 42 CPLC
      const fakeIccPub = Buffer.alloc(65, 0x04);
      const fakeAttest = Buffer.alloc(72, 0xAA);
      const fakeCplc = Buffer.alloc(42, 0xBB);
      const responseData = Buffer.concat([fakeIccPub, fakeAttest, fakeCplc]);

      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('KEYGEN'),
        sadRecord: FAKE_SAD_RECORD,
        card: {
          program: {
            issuerProfile: {
              chipProfile: {
                iccPrivateKeyDgi: 0x8001,
                iccPrivateKeyTag: 0x9F48,
              },
            },
          },
        },
      });
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
          }),
        }),
      );
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
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeSession('AWAITING_FINAL'),
      );
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
  // Pure delegation to buildProvisioningPlan after a DB lookup.  We verify
  // the shape is right and the chipProfile values flow through.
  // -------------------------------------------------------------------------

  describe('buildPlanForSession', () => {
    it('assembles a 5-step plan using chipProfile DGI/tag from the session', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        card: {
          program: {
            issuerProfile: {
              chipProfile: {
                iccPrivateKeyDgi: 0x8001,
                iccPrivateKeyTag: 0x9F48,
              },
            },
          },
        },
      });

      const plan = await mgr.buildPlanForSession('session_01');

      expect(plan.type).toBe('plan');
      expect(plan.version).toBe(1);
      expect(plan.steps).toHaveLength(5);
      expect(plan.steps[0].apdu).toBe('00A4040008A00000006250414C');
      expect(plan.steps[1].apdu).toBe('80E000000101');
      // TRANSFER_SAD tail should encode dgi+tag
      expect(plan.steps[2].apdu.slice(-8).toUpperCase()).toBe('80019F48');
    });

    it('falls back to M/Chip-CVN18 defaults when chipProfile is missing', async () => {
      (prisma.provisioningSession.findUnique as ReturnType<typeof vi.fn>).mockResolvedValue({
        ...makeSession('INIT'),
        card: { program: { issuerProfile: null } },
      });

      const plan = await mgr.buildPlanForSession('session_01');
      // Defaults are 0x8001 / 0x9F48.
      expect(plan.steps[2].apdu.slice(-8).toUpperCase()).toBe('80019F48');
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
    it('routes step 1 (keygen) response to iccPublicKey capture', async () => {
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
          data: expect.objectContaining({ iccPublicKey: expect.any(Buffer) }),
        }),
      );
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
