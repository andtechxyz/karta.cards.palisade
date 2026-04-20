/**
 * Module-level MetricsClient singleton for the rca service.
 *
 * Created lazily on first access so tests that don't import this file
 * don't pay the EMF backend's setInterval cost.  Production flips
 * `METRICS_BACKEND=cloudwatch` in the ECS task definition and every
 * metric emission becomes an EMF-formatted stdout line that CloudWatch
 * Logs Insights parses into dashboards.  Everywhere else (dev, tests,
 * unset env) gets the noop backend.
 *
 * Metric naming convention:
 *   rca.<subject>.<verb>      — e.g. `rca.plan_step.rejected`
 *   rca.<subject>              — for gauges (e.g. `rca.sessions.active`)
 *
 * Tag naming convention:
 *   Use low-cardinality values only (reason codes, mode strings,
 *   attestation verdicts).  Never tag on sessionId / cardId — those
 *   blow out CloudWatch dimensions and cost money for no analytical
 *   value.
 */

import { createMetricsClient, type MetricsClient } from '@palisade/metrics';

let _metrics: MetricsClient | null = null;

export function metrics(): MetricsClient {
  if (_metrics === null) {
    _metrics = createMetricsClient('rca');
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
