#!/usr/bin/env tsx
/**
 * Reaper for expired SAD records and abandoned provisioning / card-op
 * sessions.  Runs as a scheduled task (ECS) against the production DB;
 * idempotent so re-runs are safe.
 *
 * This is NOT a service endpoint — it's a one-shot script invoked from
 * a scheduled runner.  Keeps the services themselves stateless with
 * regard to retention; all retention policy lives here.
 *
 * ----------------------------------------------------------------------------
 * What it does
 * ----------------------------------------------------------------------------
 *
 *   1. SadRecord — hard-delete:
 *      - status = READY   AND expiresAt < now()
 *      - status IN (CONSUMED, REVOKED) AND updatedAt < now() - 30 days
 *      The READY-but-expired case is a real leak: the TTL already fired,
 *      the blob is unusable, and it carries encrypted card data nobody
 *      can use.
 *
 *   2. ProvisioningSession — soft-archive abandoned, hard-delete old:
 *      - phase NOT IN (COMPLETE, FAILED) AND createdAt < now() - 1h
 *        → update phase='EXPIRED', set failedAt=now().  Sessions are
 *          ~30 seconds by design; anything past an hour is abandoned
 *          and should not block a re-provision attempt.
 *      - phase IN (COMPLETE, FAILED) AND updatedAt < now() - 90 days
 *        → hard-delete.  Matches docs/security/data-classification.md.
 *
 *   3. CardOpSession — same 1-hour abandonment + 90-day retention.
 *      Added by the card-ops track; this reaper discovers the Prisma
 *      delegate at runtime so it no-ops cleanly if the migration hasn't
 *      landed yet in the target environment.
 *
 * Running twice in quick succession is a no-op — every delete/update is
 * gated by a strict time predicate.
 *
 * ----------------------------------------------------------------------------
 * CLI
 * ----------------------------------------------------------------------------
 *
 *   tsx scripts/reaper-sad-sessions.ts            # live run
 *   tsx scripts/reaper-sad-sessions.ts --dry-run  # print counts only
 *
 * Exit codes:
 *   0 — success (including dry-run)
 *   1 — DB error
 *   2 — CLI usage error
 *
 * ----------------------------------------------------------------------------
 * Env
 * ----------------------------------------------------------------------------
 *
 *   DATABASE_URL — Postgres connection string for the target env.
 *
 * ----------------------------------------------------------------------------
 * Deployment
 * ----------------------------------------------------------------------------
 *
 * The Dockerfile already bakes scripts/ into every runtime image and
 * tsx is resolvable from root node_modules/.  No Dockerfile change is
 * needed; the ENTRYPOINT `tini -- <command>` accepts any command
 * override.
 *
 * Local sanity-check (dry-run against a real DB, touches nothing):
 *
 *   DATABASE_URL=postgresql://... tsx scripts/reaper-sad-sessions.ts --dry-run
 *
 * Docker invocation (override the service CMD):
 *
 *   docker run --env-file .env vera-rca tsx scripts/reaper-sad-sessions.ts
 *
 * ECS scheduled task (EventBridge → RunTask):
 *
 *   Schedule:        cron(0 * * * ? *)     — every hour, on the hour
 *   Target:          ECS cluster, task definition for any service image
 *                    that already holds the DATABASE_URL secret (rca or
 *                    activation are natural picks).
 *   Command override (RunTask `containerOverrides[].command`):
 *                    ["tsx", "scripts/reaper-sad-sessions.ts"]
 *
 * Output is a single line of counters — the task's log group picks it
 * up.  Alarm on non-zero exit, not on output content.
 */

import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';

// ---------------------------------------------------------------------------
// Retention policy constants
// ---------------------------------------------------------------------------
//
// Expressed in milliseconds so we can feed them straight into `new Date()`
// arithmetic.  If any of these change, update
// docs/security/data-classification.md to match.

export const ONE_HOUR_MS = 60 * 60 * 1000;
export const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
export const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Counters shape — exported so tests can assert on it directly
// ---------------------------------------------------------------------------

export interface ReaperCounters {
  sadRecordsExpiredDeleted: number;
  sadRecordsTerminalDeleted: number;
  provisioningSessionsAbandonedArchived: number;
  provisioningSessionsTerminalDeleted: number;
  cardOpSessionsAbandonedArchived: number;
  cardOpSessionsTerminalDeleted: number;
}

export function emptyCounters(): ReaperCounters {
  return {
    sadRecordsExpiredDeleted: 0,
    sadRecordsTerminalDeleted: 0,
    provisioningSessionsAbandonedArchived: 0,
    provisioningSessionsTerminalDeleted: 0,
    cardOpSessionsAbandonedArchived: 0,
    cardOpSessionsTerminalDeleted: 0,
  };
}

// ---------------------------------------------------------------------------
// Structural type for the Prisma delegates we use — lets the reaper be
// called with either a real PrismaClient or a mock in tests.  Only the
// exact methods we touch are listed; do not widen without reason.
// ---------------------------------------------------------------------------

export interface ReaperPrisma {
  sadRecord: {
    deleteMany: (args: { where: unknown }) => Promise<{ count: number }>;
    count: (args: { where: unknown }) => Promise<number>;
  };
  provisioningSession: {
    updateMany: (args: { where: unknown; data: unknown }) => Promise<{ count: number }>;
    deleteMany: (args: { where: unknown }) => Promise<{ count: number }>;
    count: (args: { where: unknown }) => Promise<number>;
  };
  // CardOpSession is added by a separate track.  Its delegate may or may
  // not exist at the time this script runs against a given environment's
  // DB.  When absent, the caller passes a client without the key and we
  // skip those two steps quietly.
  cardOpSession?: {
    updateMany: (args: { where: unknown; data: unknown }) => Promise<{ count: number }>;
    deleteMany: (args: { where: unknown }) => Promise<{ count: number }>;
    count: (args: { where: unknown }) => Promise<number>;
  };
}

// ---------------------------------------------------------------------------
// Core reaper — pure function of (prisma, options, now).
// `now` is injected so tests can pin time without monkey-patching Date.
// ---------------------------------------------------------------------------

export interface ReaperOptions {
  dryRun: boolean;
}

export async function runReaper(
  prisma: ReaperPrisma,
  opts: ReaperOptions,
  now: Date = new Date(),
): Promise<ReaperCounters> {
  const counters = emptyCounters();

  const oneHourAgo = new Date(now.getTime() - ONE_HOUR_MS);
  const thirtyDaysAgo = new Date(now.getTime() - THIRTY_DAYS_MS);
  const ninetyDaysAgo = new Date(now.getTime() - NINETY_DAYS_MS);

  // ---- SadRecord: READY + past expiresAt -------------------------------
  const sadExpiredWhere = {
    status: 'READY',
    expiresAt: { lt: now },
  };
  if (opts.dryRun) {
    counters.sadRecordsExpiredDeleted = await prisma.sadRecord.count({
      where: sadExpiredWhere,
    });
  } else {
    const res = await prisma.sadRecord.deleteMany({ where: sadExpiredWhere });
    counters.sadRecordsExpiredDeleted = res.count;
  }

  // ---- SadRecord: CONSUMED/REVOKED older than 30 days ------------------
  //
  // SadRecord has a `createdAt` column but not `updatedAt` in the current
  // schema.  The status flip is an UPDATE though, and `createdAt` can be
  // up to 30 days before that UPDATE (the record's TTL is 30 days and it
  // typically gets CONSUMED shortly before expiry).  We key off
  // `createdAt < now - 30d` so we only delete records whose entire TTL
  // window has already closed, independent of when the status flip
  // happened — that's safer than referencing a column that might not
  // exist and avoids a migration.
  const sadTerminalWhere = {
    status: { in: ['CONSUMED', 'REVOKED'] },
    createdAt: { lt: thirtyDaysAgo },
  };
  if (opts.dryRun) {
    counters.sadRecordsTerminalDeleted = await prisma.sadRecord.count({
      where: sadTerminalWhere,
    });
  } else {
    const res = await prisma.sadRecord.deleteMany({ where: sadTerminalWhere });
    counters.sadRecordsTerminalDeleted = res.count;
  }

  // ---- ProvisioningSession: abandoned (> 1h, not terminal) → archive ---
  const psAbandonedWhere = {
    phase: { notIn: ['COMPLETE', 'FAILED'] },
    createdAt: { lt: oneHourAgo },
  };
  if (opts.dryRun) {
    counters.provisioningSessionsAbandonedArchived =
      await prisma.provisioningSession.count({ where: psAbandonedWhere });
  } else {
    const res = await prisma.provisioningSession.updateMany({
      where: psAbandonedWhere,
      data: {
        phase: 'EXPIRED',
        failedAt: now,
        failureReason: 'reaper: session abandoned (>1h without completion)',
      },
    });
    counters.provisioningSessionsAbandonedArchived = res.count;
  }

  // ---- ProvisioningSession: terminal + > 90 days → hard-delete ---------
  //
  // `updatedAt` is the right column here because the terminal state is
  // reached via UPDATE (phase=COMPLETE/FAILED, completedAt/failedAt set).
  const psTerminalWhere = {
    phase: { in: ['COMPLETE', 'FAILED'] },
    updatedAt: { lt: ninetyDaysAgo },
  };
  if (opts.dryRun) {
    counters.provisioningSessionsTerminalDeleted =
      await prisma.provisioningSession.count({ where: psTerminalWhere });
  } else {
    const res = await prisma.provisioningSession.deleteMany({
      where: psTerminalWhere,
    });
    counters.provisioningSessionsTerminalDeleted = res.count;
  }

  // ---- CardOpSession (optional — added by card-ops track) --------------
  if (prisma.cardOpSession) {
    const copAbandonedWhere = {
      phase: { notIn: ['COMPLETE', 'FAILED'] },
      createdAt: { lt: oneHourAgo },
    };
    if (opts.dryRun) {
      counters.cardOpSessionsAbandonedArchived =
        await prisma.cardOpSession.count({ where: copAbandonedWhere });
    } else {
      const res = await prisma.cardOpSession.updateMany({
        where: copAbandonedWhere,
        data: {
          phase: 'EXPIRED',
          failedAt: now,
          failureReason: 'reaper: session abandoned (>1h without completion)',
        },
      });
      counters.cardOpSessionsAbandonedArchived = res.count;
    }

    const copTerminalWhere = {
      phase: { in: ['COMPLETE', 'FAILED'] },
      updatedAt: { lt: ninetyDaysAgo },
    };
    if (opts.dryRun) {
      counters.cardOpSessionsTerminalDeleted =
        await prisma.cardOpSession.count({ where: copTerminalWhere });
    } else {
      const res = await prisma.cardOpSession.deleteMany({
        where: copTerminalWhere,
      });
      counters.cardOpSessionsTerminalDeleted = res.count;
    }
  }

  return counters;
}

// ---------------------------------------------------------------------------
// Log formatting — kept as its own function so tests can lock the wire
// format.  Each tool that parses reaper output (CloudWatch metric filter,
// ad-hoc ops greps) should key off the `[reaper]` prefix.
// ---------------------------------------------------------------------------

export function formatCountersLine(
  counters: ReaperCounters,
  dryRun: boolean,
): string {
  const mode = dryRun ? 'DRY-RUN' : 'LIVE';
  return (
    `[reaper] ${mode} ` +
    `sad.expired=${counters.sadRecordsExpiredDeleted} ` +
    `sad.terminal=${counters.sadRecordsTerminalDeleted} ` +
    `prov.abandoned=${counters.provisioningSessionsAbandonedArchived} ` +
    `prov.terminal=${counters.provisioningSessionsTerminalDeleted} ` +
    `cardop.abandoned=${counters.cardOpSessionsAbandonedArchived} ` +
    `cardop.terminal=${counters.cardOpSessionsTerminalDeleted}`
  );
}

// ---------------------------------------------------------------------------
// CLI entrypoint
// ---------------------------------------------------------------------------

function parseCli(): { dryRun: boolean } {
  const { values } = parseArgs({
    options: {
      'dry-run': { type: 'boolean' },
      help: { type: 'boolean' },
    },
  });

  if (values.help) {
    // eslint-disable-next-line no-console
    console.log(
      'Usage: tsx scripts/reaper-sad-sessions.ts [--dry-run]\n\n' +
      '  --dry-run   Report what would happen without touching any rows.\n' +
      '  --help      Show this message.\n',
    );
    process.exit(0);
  }

  return { dryRun: values['dry-run'] ?? false };
}

async function main(): Promise<void> {
  const { dryRun } = parseCli();
  const prisma = new PrismaClient();

  try {
    const counters = await runReaper(prisma as unknown as ReaperPrisma, {
      dryRun,
    });
    // eslint-disable-next-line no-console
    console.log(formatCountersLine(counters, dryRun));
  } finally {
    await prisma.$disconnect();
  }
}

// Only auto-run when invoked via `tsx scripts/reaper-sad-sessions.ts`.
// Tests import this module and call runReaper() directly; they must not
// trigger a real PrismaClient construction.
const isMain =
  typeof process !== 'undefined' &&
  process.argv[1] !== undefined &&
  /reaper-sad-sessions\.(ts|js|mjs)$/.test(process.argv[1]);

if (isMain) {
  main().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[reaper] FAILED:', err);
    process.exit(1);
  });
}
