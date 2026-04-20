/**
 * Module-level MetricsClient singleton for the batch-processor service.
 *
 * Mirrors the pattern in the five other instrumented services.
 * Production flips `METRICS_BACKEND=cloudwatch` in the ECS task def;
 * dev + tests get the silent noop backend.
 *
 * Metric naming convention (CloudWatch namespace `batch-processor`):
 *   batch-processor.batch.processed   — full batch run terminal
 *                                        dims: result ∈ {ok, partial, failed}
 *   batch-processor.card.registered   — per-card register call ok
 *   batch-processor.card.failed       — per-card register threw
 *                                        dims: reason ∈ {register_error,
 *                                          data_prep_error, duplicate, other}
 *   batch-processor.batch.duration_ms — TIMING end-to-end batch wall clock
 *   batch-processor.cards.in_batch    — GAUGE (last batch card count)
 *
 * Batch-level metrics are typically low volume (N batches/day); card-
 * level metrics can be per-card-in-batch which could be thousands.
 * Keep dimensions low-cardinality (result/reason enums only).
 */

import { createMetricsClient, type MetricsClient } from '@palisade/metrics';

let _metrics: MetricsClient | null = null;

export function metrics(): MetricsClient {
  if (_metrics === null) {
    _metrics = createMetricsClient('batch-processor');
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
