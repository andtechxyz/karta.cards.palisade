/**
 * Locate + load the CAP files shipped with card-ops.
 *
 * Resolution rules:
 *   1. If CAP_FILES_DIR env is set, use that.
 *   2. Otherwise, look in <servicesDir>/card-ops/cap-files/ resolved
 *      relative to the module URL.  This works in dev (ts-node /
 *      tsx running from src/) and in prod (compiled dist/).
 */

import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync } from 'node:fs';
import { parseCapFile, type CapFile } from './cap-parser.js';
import { getCardOpsConfig } from '../env.js';

const CAP_NAMES = {
  /** Legacy PA v1 applet — accepts INS_TRANSFER_SAD (pre-ECDH SAD blob). */
  pa: 'pa.cap',
  /**
   * PA v3 applet — accepts INS_TRANSFER_PARAMS (ECDH-wrapped ParamBundle,
   * chip-computed DGIs).  Dual-mode: if the APDU body starts with 0x04
   * (SEC1 uncompressed EC point) it's a ParamBundle; otherwise it falls
   * through to the legacy SAD path inside the applet so fleet migration
   * can be tracked per-card instead of big-bang.
   */
  'pa-v3': 'pa-v3.cap',
  t4t: 'PalisadeT4T.cap',
  receiver: 'test-receiver.cap',
} as const;

export type CapKey = keyof typeof CAP_NAMES;

function resolveCapDir(): string {
  const env = getCardOpsConfig().CAP_FILES_DIR;
  if (env) return env;

  // src/gp/cap-loader.ts → <card-ops>/cap-files/
  // dist/gp/cap-loader.js → <card-ops>/cap-files/
  const here = dirname(fileURLToPath(import.meta.url));
  // Walk up two dirs: /src/gp/ (or /dist/gp/) → /src/ (or /dist/) → /
  return join(here, '..', '..', 'cap-files');
}

/**
 * Load and parse a CAP file by key.  Throws with a helpful error if
 * the file is missing — operations should surface this as
 * `CAP_FILE_MISSING` over the WS instead of a generic 500.
 *
 * Stage H.1 — also verifies the loaded bytes against the pinned
 * SHA-256 in cap-files/cap-manifest.json BEFORE returning.  Refuses
 * to return a CAP whose digest doesn't match the manifest entry, or
 * whose key has no manifest entry at all.  Closes the supply-chain
 * gap where a tampered or unintended CAP could be silently flashed
 * to a card.
 */
export function loadCap(key: CapKey): CapFile {
  const dir = resolveCapDir();
  const path = join(dir, CAP_NAMES[key]);
  if (!existsSync(path)) {
    throw new CapFileMissingError(key, path);
  }
  verifyCapHash(key, path);
  return parseCapFile(path);
}

/**
 * Load and parse a CAP file by explicit filename (no dictionary lookup).
 *
 * Used for CAPs whose filename is looked up at runtime from a DB
 * column (e.g. ChipProfile.paymentAppletCapFilename) rather than baked
 * into the {@link CAP_NAMES} table.  Resolves against the same
 * CAP_FILES_DIR convention as {@link loadCap}; a filename with a path
 * separator is rejected so callers can't escape the cap-files/
 * directory.  Throws {@link CapFileMissingError} when the file is
 * absent — the operation handler should surface this as
 * `CAP_FILE_MISSING` on the WS.
 */
export function loadCapByFilename(filename: string): CapFile {
  if (!filename || /[\\/]/.test(filename) || filename.startsWith('..')) {
    throw new Error(`invalid cap filename: ${filename}`);
  }
  const dir = resolveCapDir();
  const path = join(dir, filename);
  if (!existsSync(path)) {
    // `capKey` on the error gets the raw filename for observability;
    // the cast is fine — CapFileMissingError already accepts strings
    // since CapKey is just a string-literal union.
    throw new CapFileMissingError(filename as CapKey, path);
  }
  verifyCapHash(filename as CapKey, path);
  return parseCapFile(path);
}

export class CapFileMissingError extends Error {
  constructor(public readonly capKey: CapKey, public readonly path: string) {
    super(`CAP file ${capKey} not found at ${path}`);
    this.name = 'CapFileMissingError';
  }
}

export class CapHashMismatchError extends Error {
  constructor(
    public readonly capKey: CapKey,
    public readonly path: string,
    public readonly expected: string,
    public readonly actual: string,
  ) {
    super(
      `CAP ${capKey} (${path}) sha256 ${actual} does not match pinned ${expected} ` +
        `in cap-manifest.json — refusing to install.  If the CAP was intentionally ` +
        `updated, regenerate the manifest entry (sha256 + version + builtAt).`,
    );
    this.name = 'CapHashMismatchError';
  }
}

export class CapManifestMissingEntryError extends Error {
  constructor(public readonly capKey: CapKey, public readonly path: string) {
    super(
      `CAP ${capKey} (${path}) has no entry in cap-manifest.json — refusing to ` +
        `install an unpinned CAP.  Add the entry first (Stage H.1 supply-chain ` +
        `enforcement: silent unpinned CAPs are exactly what this gate exists to prevent).`,
    );
    this.name = 'CapManifestMissingEntryError';
  }
}

// -----------------------------------------------------------------------------
// Stage H.1 — manifest-based hash verification
// -----------------------------------------------------------------------------

interface CapManifestEntry {
  sha256: string;       // empty string disables the check (transitional new entries)
  version: string;
  builtAt: string;
  builtBy: string;
}
interface CapManifest {
  entries: Record<string, CapManifestEntry>;
}

let manifestCache: CapManifest | null = null;

function loadManifest(): CapManifest {
  if (manifestCache) return manifestCache;
  const path = join(resolveCapDir(), 'cap-manifest.json');
  if (!existsSync(path)) {
    throw new Error(
      `cap-manifest.json missing at ${path} — Stage H.1 requires the manifest ` +
        `to be present even if entries are empty.  Create with all currently-shipped ` +
        `CAP keys + their sha256s.`,
    );
  }
  const raw = readFileSync(path, 'utf8');
  const parsed = JSON.parse(raw) as CapManifest;
  if (!parsed || typeof parsed !== 'object' || !parsed.entries) {
    throw new Error('cap-manifest.json: missing top-level "entries" object');
  }
  manifestCache = parsed;
  return parsed;
}

/** Test-only: drop the manifest cache so a tweaked manifest reloads. */
export function _resetCapManifestCache(): void {
  manifestCache = null;
}

function verifyCapHash(capKey: CapKey, path: string): void {
  const manifest = loadManifest();
  const entry = manifest.entries[capKey as string];
  if (!entry) {
    throw new CapManifestMissingEntryError(capKey, path);
  }
  // Empty sha256 string = transitional disable.  Logged but not enforced.
  if (!entry.sha256) {
    // eslint-disable-next-line no-console
    console.warn(
      `[cap-loader] ⚠️  CAP ${capKey} has empty pinned sha256 in manifest — skipping hash check (transitional).  Pin it as soon as the CAP is finalised.`,
    );
    return;
  }
  const bytes = readFileSync(path);
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual.toLowerCase() !== entry.sha256.toLowerCase()) {
    throw new CapHashMismatchError(capKey, path, entry.sha256, actual);
  }
}
