import { describe, it, expect } from 'vitest';
import {
  buildProvisioningPlan,
  buildTransferSadApdu,
  buildMinimalSadPayload,
  schemeByteForIssuer,
  type PlanContext,
} from './plan-builder.js';

/**
 * A fully-populated default context matching what
 * {@link SessionManager.buildPlanContext} produces when the IssuerProfile is
 * complete.  Tests override individual fields where needed.
 */
function makeCtx(overrides: Partial<PlanContext> = {}): PlanContext {
  return {
    iccPrivateKeyDgi: 0x8001,
    iccPrivateKeyTag: 0x9F48,
    bankId:            0x12345678,
    progId:            0xDEADBEEF,
    scheme:            0x01, // Mastercard
    postProvisionUrl:  'mobile.karta.cards',
    sadPayload:        buildMinimalSadPayload(),
    ...overrides,
  };
}

describe('buildProvisioningPlan', () => {
  it('emits exactly 5 steps in SELECT → KEYGEN → TRANSFER → FINAL → CONFIRM order', () => {
    const plan = buildProvisioningPlan(makeCtx());

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
    const plan = buildProvisioningPlan(makeCtx());
    expect(plan.steps[0].apdu).toBe('00A4040008A00000006250414C');
  });

  it('GENERATE_KEYS step is the exact 6-byte Palisade SSD e2e trace APDU', () => {
    const plan = buildProvisioningPlan(makeCtx());
    // 80 E0 00 00 Lc=01 P1=01 — no session-ID payload, the PA discards it.
    expect(plan.steps[1].apdu).toBe('80E000000101');
  });

  it('FINAL_STATUS + CONFIRM steps are zero-data case-2 APDUs', () => {
    const plan = buildProvisioningPlan(makeCtx());
    expect(plan.steps[3].apdu).toBe('80E6000000');
    expect(plan.steps[4].apdu).toBe('80E8000000');
  });

  it('every step requests SW=9000', () => {
    const plan = buildProvisioningPlan(makeCtx());
    for (const step of plan.steps) {
      expect(step.expectSw).toBe('9000');
    }
  });

  it('TRANSFER_SAD encodes the chipProfile DGI/tag bytes in the tail', () => {
    const plan = buildProvisioningPlan(
      makeCtx({ iccPrivateKeyDgi: 0x8001, iccPrivateKeyTag: 0x9F48 }),
    );
    const transfer = plan.steps[2].apdu;

    // Header: CLA=80 INS=E2 P1=00 P2=00 Lc=<1 byte for a small payload>
    expect(transfer.slice(0, 8)).toBe('80E20000');

    // Tail last 4 bytes: dgi(2) || emvTag(2) = 8001 9F48
    expect(transfer.slice(-8).toUpperCase()).toBe('80019F48');
  });

  it('different chipProfile values produce different TRANSFER_SAD bytes', () => {
    const a = buildProvisioningPlan(makeCtx({ iccPrivateKeyDgi: 0x8001, iccPrivateKeyTag: 0x9F48 }));
    const b = buildProvisioningPlan(makeCtx({ iccPrivateKeyDgi: 0x9000, iccPrivateKeyTag: 0xDF01 }));
    expect(a.steps[2].apdu).not.toBe(b.steps[2].apdu);
    // Confirm the tail bytes differ as expected.
    expect(b.steps[2].apdu.slice(-8).toUpperCase()).toBe('9000DF01');
  });
});

describe('buildTransferSadApdu — real metadata plumbing', () => {
  it('encodes bankId as 4-byte big-endian', () => {
    const apdu = buildTransferSadApdu(makeCtx({ bankId: 0xAABBCCDD })).toString('hex').toUpperCase();
    // bankId lands immediately after the SAD payload.  Minimal SAD is 13
    // bytes = 26 hex chars; header is 5 bytes = 10 hex chars.  So
    // bankId lives at hex offset 10 + 26 = 36.
    expect(apdu.slice(36, 36 + 8)).toBe('AABBCCDD');
  });

  it('encodes progId as 4-byte big-endian immediately after bankId', () => {
    const apdu = buildTransferSadApdu(makeCtx({
      bankId: 0x00000001,
      progId: 0x11223344,
    })).toString('hex').toUpperCase();
    expect(apdu.slice(44, 44 + 8)).toBe('11223344');
  });

  it('encodes scheme as a single byte (0x01 = Mastercard, 0x02 = Visa)', () => {
    const mc = buildTransferSadApdu(makeCtx({ scheme: 0x01 })).toString('hex').toUpperCase();
    const visa = buildTransferSadApdu(makeCtx({ scheme: 0x02 })).toString('hex').toUpperCase();
    expect(mc.slice(52, 54)).toBe('01');
    expect(visa.slice(52, 54)).toBe('02');
  });

  it('places the postProvisionUrl bytes + 1-byte length before the dgi/emv tail', () => {
    const url = 'issuer.example.com';
    const apdu = buildTransferSadApdu(makeCtx({ postProvisionUrl: url }));
    const body = apdu.subarray(5); // strip 5-byte APDU header

    // Tail layout: ... [url:var] [url_len:1] [dgi:2] [emvTag:2]
    // Parse from the end.
    const emvTag = body.readUInt16BE(body.length - 2);
    const dgi = body.readUInt16BE(body.length - 4);
    const urlLen = body[body.length - 5];
    const urlStart = body.length - 5 - urlLen;
    const urlStr = body.subarray(urlStart, urlStart + urlLen).toString('ascii');

    expect(emvTag).toBe(0x9F48);
    expect(dgi).toBe(0x8001);
    expect(urlLen).toBe(url.length);
    expect(urlStr).toBe(url);
  });

  it('embeds the real decrypted SAD bytes at the head of the payload', () => {
    // Minimal SADBuilder-format SAD: count(2)=1 + tag(2) + len(2) + data.
    // The data itself is 11 bytes of distinctive content so we can grep it
    // at the right offset.  Post-conversion the wire format is
    // [tag(2) + BER-len(1) + data(11)] = 14 bytes.
    const dataBytes = Buffer.from('DEADBEEFCAFEBABE' + '424242', 'hex'); // 11 bytes
    const sadPayload = Buffer.concat([
      Buffer.from([0x00, 0x01]),                // count = 1
      Buffer.from([0x02, 0x02]),                // DGI tag 0x0202
      Buffer.from([0x00, dataBytes.length]),    // len = 11 (2-byte BE)
      dataBytes,
    ]);

    const ctx = makeCtx({
      bankId: 0xAABBCCDD,
      progId: 0x11223344,
      scheme: 0x01,
      postProvisionUrl: 'mobile.karta.cards',
      sadPayload,
    });

    const apdu = buildTransferSadApdu(ctx);
    const body = apdu.subarray(5); // strip 5-byte APDU header

    // SAD bytes must appear at the start of the payload body.
    expect(body.subarray(0, sadPayload.length).equals(sadPayload)).toBe(true);

    // Metadata lands immediately after the SAD.
    const metaStart = sadPayload.length;
    expect(body.readUInt32BE(metaStart)).toBe(0xAABBCCDD);
    expect(body.readUInt32BE(metaStart + 4)).toBe(0x11223344);
    expect(body[metaStart + 8]).toBe(0x01);
  });

  it('falls through to extended-length APDU header when payload > 255 bytes', () => {
    const bigSad = Buffer.alloc(300, 0xAB);
    const apdu = buildTransferSadApdu(makeCtx({ sadPayload: bigSad }));

    // Extended header: 80 E2 00 00 00 Lc-hi Lc-lo
    expect(apdu[0]).toBe(0x80);
    expect(apdu[1]).toBe(0xE2);
    expect(apdu[2]).toBe(0x00);
    expect(apdu[3]).toBe(0x00);
    expect(apdu[4]).toBe(0x00); // extended marker
    const lcExt = apdu.readUInt16BE(5);
    expect(lcExt).toBe(apdu.length - 7); // total - (4-byte header + marker + 2-byte Lc)
    expect(lcExt).toBeGreaterThan(255);
  });

  it('rejects a postProvisionUrl longer than 255 bytes', () => {
    const longUrl = 'x'.repeat(300);
    expect(() => buildTransferSadApdu(makeCtx({ postProvisionUrl: longUrl }))).toThrow(
      /too long/,
    );
  });
});

describe('schemeByteForIssuer', () => {
  it('maps mchip_advance → 0x01', () => {
    expect(schemeByteForIssuer('mchip_advance')).toBe(0x01);
  });

  it('maps vsdc → 0x02', () => {
    expect(schemeByteForIssuer('vsdc')).toBe(0x02);
  });

  it('throws for unknown schemes so misconfig fails loudly', () => {
    expect(() => schemeByteForIssuer('amex')).toThrow(/unknown IssuerProfile.scheme/);
    expect(() => schemeByteForIssuer('')).toThrow(/unknown IssuerProfile.scheme/);
  });
});

describe('buildMinimalSadPayload', () => {
  it('produces SADBuilder format: count(2)=1 + DGI 0x0101 carrying TLV 0x50 "PALISADE"', () => {
    const sad = buildMinimalSadPayload();
    // SADBuilder.serialiseDgis format:
    // [count_hi, count_lo, tag_hi, tag_lo, len_hi, len_lo, 0x50, 0x08, "PALISADE"]
    // count=1, tag=0x0101, len=10, tlv(50|08|PALISADE)
    expect(sad[0]).toBe(0x00);
    expect(sad[1]).toBe(0x01); // count = 1
    expect(sad[2]).toBe(0x01);
    expect(sad[3]).toBe(0x01); // DGI tag = 0x0101
    expect(sad[4]).toBe(0x00);
    expect(sad[5]).toBe(0x0a); // DGI len = 10
    expect(sad[6]).toBe(0x50); // TLV tag 0x50
    expect(sad[7]).toBe(0x08); // TLV len = 8
    expect(sad.subarray(8).toString('ascii')).toBe('PALISADE');
  });
});
