import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { startSweeper } from './sweeper.js';

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('startSweeper', () => {
  it('invokes run() on each tick and logs when rows are affected', async () => {
    const run = vi.fn().mockResolvedValue(3);
    const log = vi.fn();
    const sweeper = startSweeper({ name: 'test-task', intervalMs: 1000, run }, log);

    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith('[retention] test-task swept 3 rows');

    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(2);

    sweeper.stop();
  });

  it('is silent when no rows are affected', async () => {
    const run = vi.fn().mockResolvedValue(0);
    const log = vi.fn();
    const sweeper = startSweeper({ name: 'idle', intervalMs: 1000, run }, log);

    await vi.advanceTimersByTimeAsync(3000);
    expect(run).toHaveBeenCalledTimes(3);
    expect(log).not.toHaveBeenCalled();

    sweeper.stop();
  });

  it('swallows errors so a DB blip does not crash the service', async () => {
    const boom = new Error('connection refused');
    const run = vi.fn().mockRejectedValue(boom);
    const log = vi.fn();
    const sweeper = startSweeper({ name: 'flaky', intervalMs: 1000, run }, log);

    await vi.advanceTimersByTimeAsync(1000);
    // Whole error is forwarded to the logger so stack traces survive.
    expect(log).toHaveBeenCalledWith('[retention] flaky failed', { err: boom });

    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(2);

    sweeper.stop();
  });

  it('skips overlapping ticks so a slow sweep does not pile up', async () => {
    let resolveSlow: (v: number) => void = () => {};
    const run = vi.fn(
      () =>
        new Promise<number>((resolve) => {
          resolveSlow = resolve;
        }),
    );
    const sweeper = startSweeper({ name: 'slow', intervalMs: 1000, run });

    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(1);

    // A second tick fires while the first is still pending — must be skipped.
    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(1);

    resolveSlow(0);
    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(2);

    sweeper.stop();
  });

  it('stop() halts further ticks and is idempotent', async () => {
    const run = vi.fn().mockResolvedValue(0);
    const sweeper = startSweeper({ name: 'stoppable', intervalMs: 1000, run });

    await vi.advanceTimersByTimeAsync(1000);
    expect(run).toHaveBeenCalledTimes(1);

    sweeper.stop();
    sweeper.stop();

    await vi.advanceTimersByTimeAsync(5000);
    expect(run).toHaveBeenCalledTimes(1);
  });
});
