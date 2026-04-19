// @palisade/metrics — service-side metrics primitives.
//
// Two backends:
//   EmfMetricsClient    CloudWatch Embedded Metric Format (stdout JSON)
//   NoopMetricsClient   silent, for tests + local dev
//
// Selection is env-driven (METRICS_BACKEND=cloudwatch → EMF, else noop).
// See factory.ts.
//
// See docs/runbooks/ for operational notes once services wire this in.

export type { MetricsClient, MetricsClientOptions, MetricTags } from './types.js';

export { createMetricsClient, resolveBackend } from './factory.js';
export type { MetricsBackend } from './factory.js';

export { EmfMetricsClient } from './emf-backend.js';
export type { EmfBackendOptions, EmfDocument } from './emf-backend.js';

export { NoopMetricsClient } from './noop-backend.js';

export { wrapExpressMetrics } from './express-middleware.js';
export type { WrapExpressMetricsOptions } from './express-middleware.js';
