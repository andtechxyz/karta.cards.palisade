/**
 * Module-level MetricsClient singleton for the activation service.
 *
 * Mirrors the pattern in services/rca/, services/card-ops/, and
 * services/tap/.  Production flips `METRICS_BACKEND=cloudwatch` in
 * the ECS task def; dev + tests get the silent noop backend.
 *
 * Metric naming convention (CloudWatch namespace `activation`):
 *   activation.register.ok              — card registration succeeded
 *   activation.register.fail            — register rejected
 *                                          dims: reason ∈ {duplicate,
 *                                                 vault_rejected, validation}
 *   activation.provision_start.ok       — mobile /provisioning/start served
 *   activation.provision_start.fail     — start rejected
 *                                          dims: reason ∈ {card_not_activated,
 *                                                 handoff_invalid, rca_failed}
 *   activation.provision_complete.ok    — RCA callback wired card→PROVISIONED
 *   activation.provision_complete.fail  — callback rejected
 *                                          dims: reason (e.g. invalid_status)
 *   activation.admin_card_op.started    — POST /api/admin/card-op/start
 *                                          dims: op ∈ {install_pa,…}
 *
 * Tag discipline: only enumerable reason strings + operation names.
 * No cardRef/cardId/cognitoSub — those blow out CloudWatch dimensions.
 */

import { createMetricsClient, type MetricsClient } from '@palisade/metrics';

let _metrics: MetricsClient | null = null;

export function metrics(): MetricsClient {
  if (_metrics === null) {
    _metrics = createMetricsClient('activation');
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
