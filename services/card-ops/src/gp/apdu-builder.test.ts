import { describe, it, expect } from 'vitest';
import {
  buildSelectByAid,
  buildGetStatus,
  buildDelete,
  buildInstallForLoad,
  buildInstallForInstall,
  chunkLoadBlock,
  parseGetStatusResponse,
} from './apdu-builder.js';

const PA_PACKAGE_AID = Buffer.from('A0000000625041', 'hex');
const PA_INSTANCE_AID = Buffer.from('A00000006250414C', 'hex');

describe('buildSelectByAid', () => {
  it('emits 00 A4 04 00 <len> <aid>', () => {
    const apdu = buildSelectByAid(PA_INSTANCE_AID);
    expect(apdu.toString('hex').toUpperCase()).toBe(
      '00A40400' + '08' + 'A00000006250414C',
    );
  });

  it('rejects out-of-range AIDs', () => {
    expect(() => buildSelectByAid(Buffer.alloc(4))).toThrow();
    expect(() => buildSelectByAid(Buffer.alloc(17))).toThrow();
  });
});

describe('buildGetStatus', () => {
  it('applications (P1=40) first occurrence: 80 F2 40 02 02 4F 00 00', () => {
    const apdu = buildGetStatus(0x40, false);
    expect(apdu.toString('hex').toUpperCase()).toBe('80F24002024F0000');
  });

  it('next occurrence sets P2=0x03', () => {
    const apdu = buildGetStatus(0x40, true);
    expect(apdu[3]).toBe(0x03);
  });
});

describe('buildDelete', () => {
  it('wraps AID in 4F TLV', () => {
    const apdu = buildDelete(PA_PACKAGE_AID);
    // 80 E4 00 00 09 4F 07 A0000000625041
    expect(apdu.toString('hex').toUpperCase()).toBe(
      '80E40000' + '09' + '4F07' + 'A0000000625041',
    );
  });
});

describe('buildInstallForLoad', () => {
  it('encodes empty SD / params / token / hash fields as zero-length', () => {
    const apdu = buildInstallForLoad(PA_PACKAGE_AID);
    // Header: 80 E6 02 00 <Lc>
    // Body  : 07 A0..41 | 00 | 00 | 00 | 00
    //         loadFileAid(7+1) + 4×empty(4) = 12 bytes body
    expect(apdu[0]).toBe(0x80);
    expect(apdu[1]).toBe(0xE6);
    expect(apdu[2]).toBe(0x02);
    expect(apdu[3]).toBe(0x00);
    expect(apdu[4]).toBe(12); // Lc
    // Load file AID bytes
    expect(apdu.subarray(5, 6)).toEqual(Buffer.from([PA_PACKAGE_AID.length]));
    expect(apdu.subarray(6, 6 + PA_PACKAGE_AID.length).equals(PA_PACKAGE_AID)).toBe(true);
  });
});

describe('buildInstallForInstall', () => {
  it('carries load/module/applet AIDs + privileges/params/token lengths', () => {
    const apdu = buildInstallForInstall(PA_PACKAGE_AID, PA_INSTANCE_AID, PA_INSTANCE_AID);
    expect(apdu[0]).toBe(0x80);
    expect(apdu[1]).toBe(0xE6);
    expect(apdu[2]).toBe(0x0C);
    // Body shape (after CLA INS P1 P2 Lc):
    //  07 <pkg> 08 <module> 08 <applet> 01 00 02 C9 00 00
    const bodyStart = 5;
    expect(apdu[bodyStart]).toBe(7);      // loadFileAid len
    expect(apdu[bodyStart + 1 + 7]).toBe(8); // moduleAid len
    expect(apdu[bodyStart + 1 + 7 + 1 + 8]).toBe(8); // appletAid len
  });
});

describe('chunkLoadBlock', () => {
  it('single block gets P1=0x80 immediately', () => {
    const block = Buffer.alloc(100, 0xAA);
    const apdus = chunkLoadBlock(block, 240);
    expect(apdus.length).toBe(1);
    expect(apdus[0][2]).toBe(0x80); // last-block flag
    expect(apdus[0][3]).toBe(0x00); // block index 0
    expect(apdus[0][4]).toBe(100);
  });

  it('splits across blocks with P1=0x00 on all but last', () => {
    const block = Buffer.alloc(500, 0xAA);
    const apdus = chunkLoadBlock(block, 240);
    expect(apdus.length).toBe(3); // 240 + 240 + 20
    expect(apdus[0][2]).toBe(0x00);
    expect(apdus[1][2]).toBe(0x00);
    expect(apdus[2][2]).toBe(0x80);
    expect(apdus[0][3]).toBe(0x00);
    expect(apdus[1][3]).toBe(0x01);
    expect(apdus[2][3]).toBe(0x02);
    expect(apdus[2][4]).toBe(20);
  });

  it('rejects chunk sizes outside 1..255', () => {
    expect(() => chunkLoadBlock(Buffer.alloc(10), 0)).toThrow();
    expect(() => chunkLoadBlock(Buffer.alloc(10), 256)).toThrow();
  });
});

describe('parseGetStatusResponse', () => {
  it('decodes a single application entry', () => {
    // 61 <len> 4F 07 A0..41 9F 70 01 07 C5 01 00
    const entry = Buffer.concat([
      Buffer.from([0x61, 0x10]), // outer
      Buffer.from([0x4F, 0x07]), PA_PACKAGE_AID,
      Buffer.from([0x9F, 0x70, 0x01, 0x07]),
      Buffer.from([0xC5, 0x01, 0x00]),
    ]);
    const apps = parseGetStatusResponse(entry);
    expect(apps).toHaveLength(1);
    expect(apps[0].aid).toBe('A0000000625041');
    expect(apps[0].lifeCycle).toBe(0x07);
    expect(apps[0].privileges).toBe('00');
  });

  it('decodes multiple application entries', () => {
    const entry1 = Buffer.concat([
      Buffer.from([0x61, 0x10]),
      Buffer.from([0x4F, 0x07]), PA_PACKAGE_AID,
      Buffer.from([0x9F, 0x70, 0x01, 0x07]),
      Buffer.from([0xC5, 0x01, 0x00]),
    ]);
    const entry2 = Buffer.concat([
      Buffer.from([0x61, 0x11]),
      Buffer.from([0x4F, 0x08]), PA_INSTANCE_AID,
      Buffer.from([0x9F, 0x70, 0x01, 0x07]),
      Buffer.from([0xC5, 0x01, 0x00]),
    ]);
    const apps = parseGetStatusResponse(Buffer.concat([entry1, entry2]));
    expect(apps).toHaveLength(2);
    expect(apps[1].aid).toBe('A00000006250414C');
  });

  it('throws on malformed outer tag', () => {
    expect(() => parseGetStatusResponse(Buffer.from([0x00, 0x10]))).toThrow();
  });
});
