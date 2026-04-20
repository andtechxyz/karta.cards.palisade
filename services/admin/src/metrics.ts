/**
 * Module-level MetricsClient singleton for the admin service.
 *
 * Mirrors the pattern in services/rca/, services/card-ops/,
 * services/tap/, services/activation/, services/data-prep/.
 * Production flips `METRICS_BACKEND=cloudwatch` in the ECS task def;
 * dev + tests get the silent noop backend.
 *
 * Focus: partner ingestion + batch upload paths — these are the
 * external-facing surfaces where failures matter most operationally.
 *
 * Metric naming convention (CloudWatch namespace `admin`):
 *   admin.partner_auth.ok           — HMAC verified, request accepted
 *   admin.partner_auth.fail         — HMAC rejected (unknown key,
 *                                      bad sig, clock skew, etc.)
 *                                      dims: reason ∈ {missing_signature,
 *                                        bad_signature, clock_skew,
 *                                        bad_timestamp}
 *   admin.batch.received            — `/embossing-batches` accepted
 *                                      dims: result ∈ {ok, too_large,
 *                                        fi_mismatch, program_mismatch}
 *   admin.batch.size_bytes          — GAUGE (last batch's size)
 *
 * Tag discipline: partner keyId IS low-cardinality (~10 partners in
 * steady state, not cardholders) so it's safe to tag on.  keyId's
 * enough to distinguish the active partner without broadcasting
 * cardholder PII.
 */

import { createMetricsClient, type MetricsClient } from '@palisade/metrics';

let _metrics: MetricsClient | null = null;

export function metrics(): MetricsClient {
  if (_metrics === null) {
    _metrics = createMetricsClient('admin');
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
