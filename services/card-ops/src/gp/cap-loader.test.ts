import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  loadCap,
  CapFileMissingError,
  CapHashMismatchError,
  CapManifestMissingEntryError,
  _resetCapManifestCache,
} from './cap-loader.js';
import { _resetCardOpsConfig } from '../env.js';

// Test fixtures: a tiny well-formed CAP file (we don't actually parse
// the content here — parseCapFile would reject a synthetic stub.  These
// tests stub the dir + manifest and assert the *hash check* fires
// before parseCapFile runs).
//
// Approach: stand up a temp dir as CAP_FILES_DIR with a real CAP
// (copied from the shipped pa.cap so parseCapFile is happy) plus a
// custom cap-manifest.json we control per-test.

describe('cap-loader hash verification (Stage H.1)', () => {
  let tmpDir: string;
  const REAL_PA_CAP = '/Users/danderson/Palisade/services/card-ops/cap-files/pa.cap';
  const PA_SHA256 =
    '7d9beeb097fadcb627170263106de277ae87e9990013ee9b86c369dc03e2fddc';

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cap-loader-test-'));
    copyFileSync(REAL_PA_CAP, join(tmpDir, 'pa.cap'));
    process.env.CAP_FILES_DIR = tmpDir;
    _resetCardOpsConfig();
    _resetCapManifestCache();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.CAP_FILES_DIR;
    _resetCardOpsConfig();
    _resetCapManifestCache();
  });

  it('loads a CAP whose pinned sha256 matches the file bytes', () => {
    writeFileSync(
      join(tmpDir, 'cap-manifest.json'),
      JSON.stringify({
        entries: { pa: { sha256: PA_SHA256, version: 'v1', builtAt: '', builtBy: '' } },
      }),
    );
    const cap = loadCap('pa');
    expect(cap).toBeDefined();
  });

  it('refuses a CAP whose sha256 does not match the manifest', () => {
    writeFileSync(
      join(tmpDir, 'cap-manifest.json'),
      JSON.stringify({
        entries: {
          pa: {
            sha256: '0000000000000000000000000000000000000000000000000000000000000000',
            version: 'v1', builtAt: '', builtBy: '',
          },
        },
      }),
    );
    expect(() => loadCap('pa')).toThrow(CapHashMismatchError);
  });

  it('refuses a CAP whose key has no manifest entry at all', () => {
    writeFileSync(
      join(tmpDir, 'cap-manifest.json'),
      JSON.stringify({ entries: {} }),
    );
    expect(() => loadCap('pa')).toThrow(CapManifestMissingEntryError);
  });

  it('warns + loads when the manifest entry has empty sha256 (transitional)', () => {
    writeFileSync(
      join(tmpDir, 'cap-manifest.json'),
      JSON.stringify({
        entries: { pa: { sha256: '', version: 'placeholder', builtAt: '', builtBy: '' } },
      }),
    );
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const cap = loadCap('pa');
    expect(cap).toBeDefined();
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('empty pinned sha256'),
    );
    warnSpy.mockRestore();
  });

  it('still throws CapFileMissingError when the CAP file is absent', () => {
    writeFileSync(
      join(tmpDir, 'cap-manifest.json'),
      JSON.stringify({
        entries: {
          'pa-v3': { sha256: PA_SHA256, version: 'v', builtAt: '', builtBy: '' },
        },
      }),
    );
    expect(() => loadCap('pa-v3')).toThrow(CapFileMissingError);
  });
});
