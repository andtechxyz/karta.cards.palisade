// setInterval-based retention sweeper.
//
//   - `.unref()` the timer so retention never blocks graceful shutdown.
//   - `busy` guard skips ticks when a sweep is still in flight — no queueing.
//   - Errors are caught and logged: retention is non-critical; a DB blip must
//     not crash the service it's attached to.
//   - Silent when no rows were affected, so an idle service is log-quiet.

export interface SweepTask {
  name: string;
  intervalMs: number;
  /** Returns the count of rows affected.  `now` is injected for tests. */
  run: (now: Date) => Promise<number>;
}

export interface Sweeper {
  /** Stop the interval.  Idempotent. */
  stop: () => void;
}

export type SweeperLogger = (msg: string, meta?: Record<string, unknown>) => void;

export function startSweeper(task: SweepTask, log: SweeperLogger = defaultLog): Sweeper {
  let busy = false;
  let stopped = false;

  const tick = async () => {
    if (busy || stopped) return;
    busy = true;
    try {
      const count = await task.run(new Date());
      if (count > 0) log(`[retention] ${task.name} swept ${count} rows`);
    } catch (err) {
      log(`[retention] ${task.name} failed`, { err });
    } finally {
      busy = false;
    }
  };

  const handle = setInterval(tick, task.intervalMs);
  handle.unref?.();

  return {
    stop: () => {
      if (stopped) return;
      stopped = true;
      clearInterval(handle);
    },
  };
}

function defaultLog(msg: string, meta?: Record<string, unknown>): void {
  // eslint-disable-next-line no-console
  meta ? console.log(msg, meta) : console.log(msg);
}
