/**
 * Parser registry — lookup by formatType string.
 *
 * To add a new format: implement EmbossingParser in its own file, import
 * here, and add to the `parsers` record.  No other changes needed — the
 * batch processor picks up new formats automatically.
 */

import type { EmbossingParser } from '../embossing-parser.js';
import { csvParser } from './csv-parser.js';
import { fixedWidthParser } from './fixed-width-parser.js';

export const parsers: Record<string, EmbossingParser> = {
  csv: csvParser,
  fixed_width: fixedWidthParser,
  // Future: episode_six, vpa (Visa), xml, etc.
};

export function getParser(formatType: string): EmbossingParser | null {
  return parsers[formatType] ?? null;
}

export { csvParser, fixedWidthParser };
