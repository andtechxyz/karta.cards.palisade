/**
 * Module-level MetricsClient singleton for the tap service.
 *
 * Mirrors services/rca/src/metrics.ts and services/card-ops/src/metrics.ts
 * — same lazy-init + test-hook pattern.  Production flips
 * `METRICS_BACKEND=cloudwatch` in the ECS task def; dev + tests get
 * the silent noop backend.
 *
 * Metric naming convention (CloudWatch namespace `tap`):
 *   tap.verify.ok        — SUN URL verified + counter advanced
 *   tap.verify.fail      — SUN URL rejected
 *                          dims: reason={sun_invalid, sun_counter_replay,
 *                                        card_not_found, card_disabled,
 *                                        decrypt_failed}
 *   tap.counter.advance  — TIMING (ms); useful to spot DB contention
 *                          during the monotonic updateMany
 *
 * The verify hot path is the highest-throughput endpoint in the whole
 * stack (every tap hits it before anything else), so keep dimension
 * cardinality tight — only the reason enum gets tagged, never cardId
 * / cardRef / IP.
 */

import { createMetricsClient, type MetricsClient } from '@palisade/metrics';

let _metrics: MetricsClient | null = null;

export function metrics(): MetricsClient {
  if (_metrics === null) {
    _metrics = createMetricsClient('tap');
  }
  return _metrics;
}

/**
 * Test hook: reset the singleton so tests can stub with a spy.  Called
 * from test setup; production code should never touch this.
 */
export function _setMetricsForTests(client: MetricsClient | null): void {
  _metrics = client;
}
