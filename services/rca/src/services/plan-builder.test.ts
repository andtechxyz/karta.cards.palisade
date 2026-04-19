import { describe, it, expect } from 'vitest';
import { buildProvisioningPlan } from './plan-builder.js';

describe('buildProvisioningPlan', () => {
  const defaultCtx = { iccPrivateKeyDgi: 0x8001, iccPrivateKeyTag: 0x9F48 };

  it('emits exactly 5 steps in SELECT → KEYGEN → TRANSFER → FINAL → CONFIRM order', () => {
    const plan = buildProvisioningPlan(defaultCtx);

    expect(plan.type).toBe('plan');
    expect(plan.version).toBe(1);
    expect(plan.steps).toHaveLength(5);

    const indexes = plan.steps.map((s) => s.i);
    expect(indexes).toEqual([0, 1, 2, 3, 4]);

    // Phase labels are contractual — mobile UI uses them for the 4-step strip.
    expect(plan.steps.map((s) => s.phase)).toEqual([
      'select_pa',
      'key_generation',
      'provisioning',
      'finalizing',
      'confirming',
    ]);

    // Progress is monotonically increasing.
    for (let i = 1; i < plan.steps.length; i++) {
      expect(plan.steps[i].progress).toBeGreaterThan(plan.steps[i - 1].progress);
    }
  });

  it('SELECT PA step uses the Palisade converter default AID', () => {
    const plan = buildProvisioningPlan(defaultCtx);
    expect(plan.steps[0].apdu).toBe('00A4040008A00000006250414C');
  });

  it('GENERATE_KEYS step is the exact 6-byte Palisade SSD e2e trace APDU', () => {
    const plan = buildProvisioningPlan(defaultCtx);
    // 80 E0 00 00 Lc=01 P1=01 — no session-ID payload, the PA discards it.
    expect(plan.steps[1].apdu).toBe('80E000000101');
  });

  it('FINAL_STATUS + CONFIRM steps are zero-data case-2 APDUs', () => {
    const plan = buildProvisioningPlan(defaultCtx);
    expect(plan.steps[3].apdu).toBe('80E6000000');
    expect(plan.steps[4].apdu).toBe('80E8000000');
  });

  it('every step requests SW=9000', () => {
    const plan = buildProvisioningPlan(defaultCtx);
    for (const step of plan.steps) {
      expect(step.expectSw).toBe('9000');
    }
  });

  it('TRANSFER_SAD encodes the chipProfile DGI/tag bytes in the tail', () => {
    const plan = buildProvisioningPlan({ iccPrivateKeyDgi: 0x8001, iccPrivateKeyTag: 0x9F48 });
    const transfer = plan.steps[2].apdu;

    // Header: CLA=80 INS=E2 P1=00 P2=00 Lc=<1 byte for a small payload>
    expect(transfer.slice(0, 8)).toBe('80E20000');

    // Tail last 4 bytes: dgi(2) || emvTag(2) = 8001 9F48
    expect(transfer.slice(-8).toUpperCase()).toBe('80019F48');
  });

  it('different chipProfile values produce different TRANSFER_SAD bytes', () => {
    const a = buildProvisioningPlan({ iccPrivateKeyDgi: 0x8001, iccPrivateKeyTag: 0x9F48 });
    const b = buildProvisioningPlan({ iccPrivateKeyDgi: 0x9000, iccPrivateKeyTag: 0xDF01 });
    expect(a.steps[2].apdu).not.toBe(b.steps[2].apdu);
    // Confirm the tail bytes differ as expected.
    expect(b.steps[2].apdu.slice(-8).toUpperCase()).toBe('9000DF01');
  });

  it('TRANSFER_SAD carries the minimal DGI 0x0101 SAD and the "PALISADE" app label', () => {
    const plan = buildProvisioningPlan(defaultCtx);
    const transfer = plan.steps[2].apdu;

    // After the 5-byte header (80E20000 Lc) the first 3 bytes are the DGI
    // tag (0101) + its 1-byte length. Then TLV 0x50 ("App Label"), length,
    // then ASCII "PALISADE" (8 bytes = 0x50414C4953414445).
    // So positions 10..32 (hex chars) should contain 0101 <len> 50 08 50414C4953414445.
    const afterHeader = transfer.slice(10);
    expect(afterHeader.slice(0, 24).toUpperCase()).toBe('01010A500850414C49534144');
  });

  it('TRANSFER_SAD places bank/prog/scheme/ts bytes between SAD and url', () => {
    const plan = buildProvisioningPlan(defaultCtx);
    const transfer = plan.steps[2].apdu;
    const body = transfer.slice(10); // strip 80E20000Lc (5 bytes = 10 hex chars)

    // SAD blob is 13 bytes = 26 hex chars: DGI tag(2) + len(1) + TLV(10).
    const tail = body.slice(26);
    expect(tail.slice(0, 8).toUpperCase()).toBe('00000001'); // bank_id
    expect(tail.slice(8, 16).toUpperCase()).toBe('00000001'); // prog_id
    expect(tail.slice(16, 18).toUpperCase()).toBe('01'); // scheme=Mastercard
  });
});
