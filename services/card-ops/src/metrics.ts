/**
 * Module-level MetricsClient singleton for the card-ops service.
 *
 * Mirrors services/rca/src/metrics.ts — same lazy-init + test-hook
 * pattern.  Production flips `METRICS_BACKEND=cloudwatch` in the ECS
 * task def; dev + tests get the silent noop backend.
 *
 * Metric naming convention (CloudWatch namespace `card-ops`):
 *   card-ops.operation.started      — every runOperation() entry
 *                                      dims: op={install_pa,…}
 *   card-ops.operation.completed    — terminal {type:'complete'}
 *                                      dims: op
 *   card-ops.operation.failed       — terminal {type:'error'} or throw
 *                                      dims: op, code
 *   card-ops.operation.duration_ms  — timing from start to terminal
 *                                      dims: op
 *
 * Tag discipline: only op name + low-cardinality error codes.  Never
 * tag on sessionId / cardId — unbounded dimensions blow CloudWatch
 * cost without analytical value.
 */

import { createMetricsClient, type MetricsClient } from '@palisade/metrics';

let _metrics: MetricsClient | null = null;

export function metrics(): MetricsClient {
  if (_metrics === null) {
    _metrics = createMetricsClient('card-ops');
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
