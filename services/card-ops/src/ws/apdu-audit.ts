/**
 * In-memory APDU audit log for a single CardOpSession.
 *
 * PCI audit requires a durable trail of every APDU command/response
 * pair exchanged with an issued card under admin operation.  This
 * module owns the session-scoped append + flush-to-DB cycle.
 *
 * Shape (matches the schema comment on CardOpSession.apduLog):
 *   Array<{
 *     ts: string;                    // ISO timestamp
 *     direction: 'cmd' | 'rsp';      // command-from-us or response-from-card
 *     hex: string;                   // uppercase hex
 *     sw?: string;                   // for 'rsp', the 4-char hex SW
 *     phase?: string;                // op-emitted phase milestone, e.g. 'INSTALL_LOAD'
 *   }>
 *
 * Flush strategy:
 *   - In-memory array accumulates every entry during the operation.
 *   - `flush()` writes the full accumulated array to CardOpSession.apduLog
 *     via a Prisma update().  Called at phase transitions (PLAN_SENT →
 *     RUNNING, RUNNING → COMPLETE/FAILED) so a partial transcript is
 *     durable even if the WS dies mid-operation.
 *   - The entire array is rewritten on each flush (simpler than
 *     JSON-patch append semantics in Postgres).  Entries are small
 *     (~100 bytes each) and sessions are short — the bandwidth cost is
 *     negligible.
 *
 * Thread-safety: a CardOpSession handles exactly one admin at a time,
 * driven by a single WebSocket, so the runner is the only writer.  No
 * locking needed.
 */

import { prisma } from '@palisade/db';

export interface ApduAuditEntry {
  ts: string;
  direction: 'cmd' | 'rsp';
  hex: string;
  sw?: string;
  phase?: string;
  /**
   * Flag set when this entry's hex has been redacted (CHD / key material
   * suspected).  `hex` then holds only the 4-byte APDU header (CLA INS P1 P2)
   * or "REDACTED" for the data body.  PCI 3.2 / 3.5 — ingestible fields
   * cannot be shown in plaintext in audit logs.
   */
  redacted?: boolean;
}

// -----------------------------------------------------------------------------
// Sensitive-APDU redaction policy
// -----------------------------------------------------------------------------
//
// GP management APDUs that carry key material OR cardholder data must not
// be logged in full.  The redaction keeps the APDU header (CLA/INS/P1/P2)
// for audit correlation but strips the data body and any plaintext SW
// payload that could carry keys.
//
// PCI-relevant sensitive APDUs on a card-ops session:
//   - STORE DATA    (CLA=8x / INS=E2)         — DGI-wrapped data incl.
//                                                EMV MK / ICC priv key
//   - PUT KEY       (CLA=8x / INS=D8)         — loads a new SCP03 or
//                                                ISD key
//   - INSTALL [for load/install]  (CLA=8x / INS=E6)  — can carry key
//                                                      material in C9
//                                                      install data
//   - Anything post-EXTERNAL_AUTHENTICATE on the same session is SCP03-
//     enciphered, but the WRAPPER bytes still leak structure — redact
//     bodies to be conservative.

const SENSITIVE_INS = new Set<number>([
  0xE2, // STORE DATA
  0xD8, // PUT KEY
  0xE6, // INSTALL (in GP context — lengths can carry key bytes)
]);

/**
 * Decide whether an APDU's data body should be redacted.  Returns true
 * for any APDU whose INS byte is in SENSITIVE_INS.  Strictly by INS; we
 * don't try to sniff the CLA bits because (a) the SCP03 proprietary CLA
 * varies with session level, (b) INS is enough — STORE DATA with CLA=00
 * is equally sensitive as CLA=84.
 */
function isSensitiveCommand(hex: string): boolean {
  if (hex.length < 4) return false;
  const ins = parseInt(hex.slice(2, 4), 16);
  return SENSITIVE_INS.has(ins);
}

/**
 * Redact an APDU command to header-only.  Keep CLA INS P1 P2 (first 8
 * hex chars) so phase correlation still works in post-mortem; drop Lc +
 * data + Le.  The replacement string is a deterministic "REDACTED"
 * marker so the audit row is obviously redacted vs just empty.
 */
function redactCommand(hex: string): string {
  const header = hex.slice(0, 8).toUpperCase(); // CLA INS P1 P2
  return `${header}-REDACTED`;
}

/**
 * Redact a response that MAY carry key material.  When the immediately
 * preceding command was sensitive, the response body can contain (a)
 * SCP03-enciphered key blobs, (b) STORE DATA error diagnostics that
 * echo loaded bytes, (c) enumerations of key identifiers.  Redact the
 * data portion, keep the trailing 4-char SW for pass/fail audit.
 */
function redactResponse(hex: string): string {
  if (hex.length < 4) return hex.toUpperCase();
  const sw = hex.slice(-4).toUpperCase();
  return `REDACTED-${sw}`;
}

export class ApduAuditLogger {
  private entries: ApduAuditEntry[] = [];
  private readonly sessionId: string;
  /**
   * Redaction context — set true by the most recent recordCommand when
   * that command was sensitive (STORE DATA / PUT KEY / INSTALL).  The
   * NEXT recordResponse checks this flag to decide whether to also
   * redact the response body.  Reset after the response is recorded so
   * subsequent non-sensitive APDUs aren't accidentally redacted.
   */
  private lastCommandSensitive = false;

  constructor(sessionId: string) {
    this.sessionId = sessionId;
  }

  /**
   * Append a command APDU (on the wire, uppercase hex).  Sensitive INS
   * values (STORE DATA, PUT KEY, INSTALL) have their data body redacted
   * before the entry is stored — header bytes are preserved so audit
   * correlation still works.
   */
  recordCommand(hex: string, phase?: string): void {
    const upper = hex.toUpperCase();
    const sensitive = isSensitiveCommand(upper);
    this.lastCommandSensitive = sensitive;
    this.entries.push({
      ts: new Date().toISOString(),
      direction: 'cmd',
      hex: sensitive ? redactCommand(upper) : upper,
      ...(sensitive ? { redacted: true } : {}),
      ...(phase ? { phase } : {}),
    });
  }

  /**
   * Append a response APDU including SW (uppercase hex).  If the
   * immediately-preceding command was sensitive, the response body is
   * redacted too — SCP03-enciphered key blobs and STORE DATA
   * diagnostics can echo loaded bytes back.  SW is always preserved.
   */
  recordResponse(hex: string, sw?: string, phase?: string): void {
    const upper = hex.toUpperCase();
    const redact = this.lastCommandSensitive;
    this.lastCommandSensitive = false;
    this.entries.push({
      ts: new Date().toISOString(),
      direction: 'rsp',
      hex: redact ? redactResponse(upper) : upper,
      ...(redact ? { redacted: true } : {}),
      ...(sw ? { sw: sw.toUpperCase() } : {}),
      ...(phase ? { phase } : {}),
    });
  }

  /** For tests / debug — read-only snapshot of the current buffer. */
  snapshot(): readonly ApduAuditEntry[] {
    return this.entries;
  }

  /**
   * Flush the in-memory buffer to CardOpSession.apduLog.
   *
   * Writes the full array every time (idempotent rewrite).  Swallows
   * DB errors — an audit flush failure is loggable but must not block
   * the operation from completing.
   */
  async flush(): Promise<void> {
    // Clone so a concurrent append after flush starts doesn't mutate
    // the JSON the DB is about to receive.  Cheap — entries are tiny.
    const payload = this.entries.map((e) => ({ ...e }));
    try {
      await prisma.cardOpSession.update({
        where: { id: this.sessionId },
        data: {
          // Prisma 5's Json field accepts a plain JS value; no need for
          // JsonValue wrapping.  An empty array is valid JSON and
          // distinct from Prisma.DbNull (which we reserve for scpState
          // clearing on COMPLETE/FAILED).
          apduLog: payload,
        },
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[card-ops][audit] flush failed for session ${this.sessionId}: ${msg}`);
    }
  }
}
