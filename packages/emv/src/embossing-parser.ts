/**
 * Embossing file parser interface.
 *
 * Batch files follow a template that defines the record layout (field
 * positions, types, delimiters).  Each parser plugin handles one format
 * type (e.g. "csv", "episode_six", "fixed_width").  The template file
 * itself is opaque to this layer — the parser knows how to interpret it.
 */

export interface EmbossingRecord {
  /** Primary Account Number (13–19 digits) */
  pan: string;
  /** Card verification code (3–4 digits) */
  cvc?: string;
  /** Expiry month, 2-digit string "01"–"12" */
  expiryMonth: string;
  /** Expiry year, 2 or 4 digits */
  expiryYear: string;
  /** Cardholder name as embossed */
  cardholderName: string;
  /** PICC UID hex (optional — often provided out-of-band by pers bureau) */
  uid?: string;
  /** SDM meta-read key hex (optional) */
  sdmMetaReadKey?: string;
  /** SDM file-read key hex (optional) */
  sdmFileReadKey?: string;
  /** Chip serial (optional) */
  chipSerial?: string;
  /** Card reference slug (optional — generated server-side if absent) */
  cardRef?: string;
}

export interface ParseError {
  lineNumber: number;
  error: string;
  /** Raw record content that failed.  Redact sensitive fields before logging. */
  rawRecord?: string;
}

export interface ParseResult {
  records: EmbossingRecord[];
  errors: ParseError[];
}

export interface EmbossingParser {
  /** The formatType string this parser handles — must match EmbossingTemplate.formatType */
  readonly formatType: string;
  /**
   * Parse a batch file using the given template.
   *
   * @param template Plaintext template file (already decrypted by caller).
   * @param batch    Plaintext batch file (already decrypted by caller).
   * @param parserMeta Optional format-specific metadata stored on the template row.
   */
  parse(template: Buffer, batch: Buffer, parserMeta?: unknown): Promise<ParseResult>;
}
