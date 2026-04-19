/**
 * CAP parser tests — exercised against the real pa.cap shipped with
 * card-ops.  If the Palisade PA rebuild yields a different AID, these
 * tests catch it immediately (rather than at deployment time).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCapFile, parseCapBytes } from './cap-parser.js';

const here = dirname(fileURLToPath(import.meta.url));
// services/card-ops/src/gp/ → cap-files/ lives at services/card-ops/cap-files/
const PA_CAP = join(here, '..', '..', 'cap-files', 'pa.cap');

describe('parseCapFile — pa.cap', () => {
  it('pa.cap ships with card-ops', () => {
    expect(existsSync(PA_CAP)).toBe(true);
  });

  it('extracts package AID A0000000625041 from pa.cap', () => {
    const cap = parseCapFile(PA_CAP);
    // Palisade PA package: A0000000625041 (per the AID used in the
    // rca provisioning SELECT applet code).
    expect(cap.packageAid).toBe('A0000000625041');
  });

  it('extracts at least one applet AID starting with the package AID', () => {
    const cap = parseCapFile(PA_CAP);
    expect(cap.appletAids.length).toBeGreaterThan(0);
    // Every applet AID in the CAP should extend the package AID —
    // JC convention is package.AID || oneByteModuleTag for the applet.
    for (const aid of cap.appletAids) {
      expect(aid.startsWith(cap.packageAid)).toBe(true);
    }
  });

  it('includes the known instance AID A00000006250414C', () => {
    const cap = parseCapFile(PA_CAP);
    // This is the AID the RCA provisioning code SELECTs (rca/ws/relay-handler.ts).
    // The default module AID the JC converter assigns is package || 0x4C.
    expect(cap.appletAids).toContain('A00000006250414C');
  });

  it('produces a non-empty Load File Data Block', () => {
    const cap = parseCapFile(PA_CAP);
    expect(cap.loadFileDataBlock.length).toBeGreaterThan(100);
    // Load block starts with the Header component (tag=1).
    expect(cap.loadFileDataBlock[0]).toBe(0x01);
  });

  it('load block is deterministic across calls', () => {
    const a = parseCapFile(PA_CAP);
    const b = parseCapBytes(readFileSync(PA_CAP));
    expect(a.loadFileDataBlock.equals(b.loadFileDataBlock)).toBe(true);
    expect(a.packageAid).toBe(b.packageAid);
  });
});
