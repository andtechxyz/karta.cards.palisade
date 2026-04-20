/**
 * Module-level MetricsClient singleton for the data-prep service.
 *
 * Mirrors the pattern in services/rca/, services/card-ops/,
 * services/tap/, services/activation/.  Production flips
 * `METRICS_BACKEND=cloudwatch` in the ECS task def; dev + tests get
 * the silent noop backend.
 *
 * Metric naming convention (CloudWatch namespace `data-prep`):
 *   data-prep.prepare.ok            — SAD prep + KMS encrypt succeeded
 *   data-prep.prepare.fail          — prep threw
 *                                      dims: reason ∈ {validation,
 *                                            issuer_profile_missing,
 *                                            kms_error, apc_error, other}
 *   data-prep.prepare.duration_ms   — TIMING (ms); useful to spot AWS
 *                                      PC / KMS slowdowns
 *   data-prep.sad_decrypt.ok        — server-side decryptSad (called from
 *                                      rca / card-ops via the exported API)
 *   data-prep.sad_decrypt.fail      — decryptSad threw
 *                                      dims: reason
 *   data-prep.sad_decrypt.duration_ms — TIMING (ms); this is a major
 *                                      contributor to provisioning
 *                                      latency; p95 spike = KMS slow
 *
 * Tag discipline: only low-cardinality enums.  No cardId/PAN/programId
 * in tags — those blow out CloudWatch cost.
 */

import { createMetricsClient, type MetricsClient } from '@palisade/metrics';

let _metrics: MetricsClient | null = null;

export function metrics(): MetricsClient {
  if (_metrics === null) {
    _metrics = createMetricsClient('data-prep');
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
