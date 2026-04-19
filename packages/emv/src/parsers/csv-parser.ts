/**
 * CSV embossing file parser.
 *
 * Template format: first line = header row (comma-separated field names).
 * Batch format: each line = one card record following the header order.
 *
 * Required fields: pan, expiry_month, expiry_year, cardholder_name
 * Optional:  cvc, uid, sdm_meta_read_key, sdm_file_read_key, chip_serial,
 *            card_ref
 *
 * Quoting: standard CSV — values containing commas or double-quotes must
 * be wrapped in double quotes, with internal quotes escaped by doubling.
 */

import type { EmbossingParser, EmbossingRecord, ParseResult, ParseError } from '../embossing-parser.js';

const REQUIRED = ['pan', 'expiry_month', 'expiry_year', 'cardholder_name'] as const;

export const csvParser: EmbossingParser = {
  formatType: 'csv',

  async parse(template: Buffer, batch: Buffer): Promise<ParseResult> {
    const records: EmbossingRecord[] = [];
    const errors: ParseError[] = [];

    // Template: header row defines column order
    const templateLines = template.toString('utf-8').split(/\r?\n/);
    const header = templateLines[0]?.trim();
    if (!header) {
      errors.push({ lineNumber: 0, error: 'Template is empty or missing header row' });
      return { records, errors };
    }
    const columns = splitCsvRow(header).map((c) => c.trim().toLowerCase());

    // Verify required fields
    for (const req of REQUIRED) {
      if (!columns.includes(req)) {
        errors.push({ lineNumber: 0, error: `Template missing required column: ${req}` });
      }
    }
    if (errors.length > 0) return { records, errors };

    // Batch: each line is a data row.  Skip header if present (detected by
    // matching the template header exactly).
    const batchText = batch.toString('utf-8');
    const batchLines = batchText.split(/\r?\n/);
    let startIdx = 0;
    if (batchLines[0]?.trim() === header) startIdx = 1;

    for (let i = startIdx; i < batchLines.length; i++) {
      const raw = batchLines[i];
      if (!raw || !raw.trim()) continue; // skip empty lines

      try {
        const values = splitCsvRow(raw);
        if (values.length !== columns.length) {
          errors.push({
            lineNumber: i + 1,
            error: `Expected ${columns.length} columns, got ${values.length}`,
          });
          continue;
        }

        const row: Record<string, string> = {};
        for (let c = 0; c < columns.length; c++) {
          row[columns[c]] = values[c]?.trim() ?? '';
        }

        const record = buildRecord(row);
        records.push(record);
      } catch (err) {
        errors.push({
          lineNumber: i + 1,
          error: err instanceof Error ? err.message : 'Parse error',
          // Redact PAN from raw before recording — keep only first 6 + last 4
          rawRecord: redactRaw(raw),
        });
      }
    }

    return { records, errors };
  },
};

function buildRecord(row: Record<string, string>): EmbossingRecord {
  const pan = row['pan'];
  const expiryMonth = row['expiry_month'];
  const expiryYear = row['expiry_year'];
  const cardholderName = row['cardholder_name'];

  if (!pan || !/^\d{13,19}$/.test(pan)) throw new Error('Invalid PAN');
  if (!expiryMonth || !/^(0[1-9]|1[0-2])$/.test(expiryMonth)) throw new Error('Invalid expiryMonth');
  if (!expiryYear || !/^\d{2,4}$/.test(expiryYear)) throw new Error('Invalid expiryYear');
  if (!cardholderName) throw new Error('Missing cardholderName');

  const record: EmbossingRecord = {
    pan,
    expiryMonth,
    expiryYear,
    cardholderName,
  };

  if (row['cvc']) record.cvc = row['cvc'];
  if (row['uid']) record.uid = row['uid'];
  if (row['sdm_meta_read_key']) record.sdmMetaReadKey = row['sdm_meta_read_key'];
  if (row['sdm_file_read_key']) record.sdmFileReadKey = row['sdm_file_read_key'];
  if (row['chip_serial']) record.chipSerial = row['chip_serial'];
  if (row['card_ref']) record.cardRef = row['card_ref'];

  return record;
}

/**
 * Split a single CSV row respecting standard quoting rules.
 */
function splitCsvRow(row: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < row.length; i++) {
    const ch = row[i];
    if (inQuotes) {
      if (ch === '"' && row[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        cur += ch;
      }
    } else {
      if (ch === ',') {
        out.push(cur);
        cur = '';
      } else if (ch === '"') {
        inQuotes = true;
      } else {
        cur += ch;
      }
    }
  }
  out.push(cur);
  return out;
}

function redactRaw(raw: string): string {
  // Replace any 13–19 digit run with BIN+last4 mask
  return raw.replace(/\b(\d{6})\d{3,9}(\d{4})\b/g, '$1******$2');
}
