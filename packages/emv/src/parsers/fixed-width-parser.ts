/**
 * Fixed-width embossing file parser.
 *
 * Template format: JSON describing each field's offset + length + target
 *   {
 *     "recordLength": 256,
 *     "fields": [
 *       { "name": "pan",             "offset": 0,   "length": 19, "trim": "right" },
 *       { "name": "expiry_month",    "offset": 19,  "length": 2 },
 *       { "name": "expiry_year",     "offset": 21,  "length": 4 },
 *       { "name": "cardholder_name", "offset": 25,  "length": 26, "trim": "right" },
 *       { "name": "cvc",             "offset": 51,  "length": 3,  "optional": true }
 *     ]
 *   }
 *
 * Batch: flat file with fixed-length records, no delimiters.  Record
 * length validated against template.
 *
 * Field name → EmbossingRecord mapping same as CSV parser.
 */

import type { EmbossingParser, EmbossingRecord, ParseResult, ParseError } from '../embossing-parser.js';

interface FixedWidthField {
  name: string;
  offset: number;
  length: number;
  trim?: 'left' | 'right' | 'both';
  optional?: boolean;
}

interface FixedWidthTemplate {
  recordLength: number;
  fields: FixedWidthField[];
  /** Optional encoding — default UTF-8 */
  encoding?: BufferEncoding;
}

const REQUIRED_FIELDS = ['pan', 'expiry_month', 'expiry_year', 'cardholder_name'];

export const fixedWidthParser: EmbossingParser = {
  formatType: 'fixed_width',

  async parse(template: Buffer, batch: Buffer): Promise<ParseResult> {
    const records: EmbossingRecord[] = [];
    const errors: ParseError[] = [];

    let tpl: FixedWidthTemplate;
    try {
      tpl = JSON.parse(template.toString('utf-8')) as FixedWidthTemplate;
    } catch {
      errors.push({ lineNumber: 0, error: 'Template is not valid JSON' });
      return { records, errors };
    }

    if (!tpl.recordLength || !Array.isArray(tpl.fields)) {
      errors.push({ lineNumber: 0, error: 'Template must have recordLength and fields' });
      return { records, errors };
    }

    // Validate required fields present in template
    const fieldNames = new Set(tpl.fields.map((f) => f.name));
    for (const req of REQUIRED_FIELDS) {
      if (!fieldNames.has(req)) {
        errors.push({ lineNumber: 0, error: `Template missing required field: ${req}` });
      }
    }
    if (errors.length > 0) return { records, errors };

    const encoding: BufferEncoding = tpl.encoding ?? 'utf-8';

    // Batch must be a multiple of recordLength (tolerate trailing newline-only bytes)
    let batchText = batch.toString(encoding);
    // Strip trailing whitespace/newlines
    batchText = batchText.replace(/[\r\n\s]+$/, '');

    if (batchText.length % tpl.recordLength !== 0) {
      errors.push({
        lineNumber: 0,
        error: `Batch length ${batchText.length} is not a multiple of recordLength ${tpl.recordLength}`,
      });
      return { records, errors };
    }

    const recordCount = batchText.length / tpl.recordLength;
    for (let i = 0; i < recordCount; i++) {
      const recordText = batchText.slice(i * tpl.recordLength, (i + 1) * tpl.recordLength);
      try {
        const row: Record<string, string> = {};
        for (const field of tpl.fields) {
          let value = recordText.slice(field.offset, field.offset + field.length);
          if (field.trim === 'left' || field.trim === 'both') value = value.trimStart();
          if (field.trim === 'right' || field.trim === 'both') value = value.trimEnd();
          row[field.name] = value;
        }
        records.push(buildRecord(row));
      } catch (err) {
        errors.push({
          lineNumber: i + 1,
          error: err instanceof Error ? err.message : 'Parse error',
        });
      }
    }

    return { records, errors };
  },
};

function buildRecord(row: Record<string, string>): EmbossingRecord {
  const pan = (row['pan'] ?? '').trim();
  const expiryMonth = (row['expiry_month'] ?? '').trim();
  const expiryYear = (row['expiry_year'] ?? '').trim();
  const cardholderName = (row['cardholder_name'] ?? '').trim();

  if (!pan || !/^\d{13,19}$/.test(pan)) throw new Error('Invalid PAN');
  if (!/^(0[1-9]|1[0-2])$/.test(expiryMonth)) throw new Error('Invalid expiryMonth');
  if (!/^\d{2,4}$/.test(expiryYear)) throw new Error('Invalid expiryYear');
  if (!cardholderName) throw new Error('Missing cardholderName');

  const record: EmbossingRecord = { pan, expiryMonth, expiryYear, cardholderName };

  const cvc = (row['cvc'] ?? '').trim();
  if (cvc) record.cvc = cvc;
  const uid = (row['uid'] ?? '').trim();
  if (uid) record.uid = uid;
  const sdmMeta = (row['sdm_meta_read_key'] ?? '').trim();
  if (sdmMeta) record.sdmMetaReadKey = sdmMeta;
  const sdmFile = (row['sdm_file_read_key'] ?? '').trim();
  if (sdmFile) record.sdmFileReadKey = sdmFile;
  const chipSerial = (row['chip_serial'] ?? '').trim();
  if (chipSerial) record.chipSerial = chipSerial;
  const cardRef = (row['card_ref'] ?? '').trim();
  if (cardRef) record.cardRef = cardRef;

  return record;
}
