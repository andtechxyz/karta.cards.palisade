/**
 * Locate + load the CAP files shipped with card-ops.
 *
 * Resolution rules:
 *   1. If CAP_FILES_DIR env is set, use that.
 *   2. Otherwise, look in <servicesDir>/card-ops/cap-files/ resolved
 *      relative to the module URL.  This works in dev (ts-node /
 *      tsx running from src/) and in prod (compiled dist/).
 */

import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { parseCapFile, type CapFile } from './cap-parser.js';
import { getCardOpsConfig } from '../env.js';

const CAP_NAMES = {
  pa: 'pa.cap',
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
 */
export function loadCap(key: CapKey): CapFile {
  const dir = resolveCapDir();
  const path = join(dir, CAP_NAMES[key]);
  if (!existsSync(path)) {
    throw new CapFileMissingError(key, path);
  }
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
  return parseCapFile(path);
}

export class CapFileMissingError extends Error {
  constructor(public readonly capKey: CapKey, public readonly path: string) {
    super(`CAP file ${capKey} not found at ${path}`);
    this.name = 'CapFileMissingError';
  }
}
