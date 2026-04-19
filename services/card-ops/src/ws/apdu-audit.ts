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
}

export class ApduAuditLogger {
  private entries: ApduAuditEntry[] = [];
  private readonly sessionId: string;

  constructor(sessionId: string) {
    this.sessionId = sessionId;
  }

  /** Append a command APDU (on the wire, uppercase hex). */
  recordCommand(hex: string, phase?: string): void {
    this.entries.push({
      ts: new Date().toISOString(),
      direction: 'cmd',
      hex: hex.toUpperCase(),
      ...(phase ? { phase } : {}),
    });
  }

  /** Append a response APDU including SW (uppercase hex). */
  recordResponse(hex: string, sw?: string, phase?: string): void {
    this.entries.push({
      ts: new Date().toISOString(),
      direction: 'rsp',
      hex: hex.toUpperCase(),
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
