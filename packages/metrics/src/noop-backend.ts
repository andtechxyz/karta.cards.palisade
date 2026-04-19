// No-op metrics backend — used in unit tests and local dev to keep the
// MetricsClient API available without polluting stdout.  Every method
// is a typed-through shim that discards its arguments.

import type { MetricsClient, MetricTags } from './types.js';

export class NoopMetricsClient implements MetricsClient {
  // Argument names use the underscore-prefix convention so noUnusedParameters
  // stays quiet.  Signatures mirror MetricsClient so call sites type-check.
  counter(_name: string, _value?: number, _tags?: MetricTags): void {
    // intentionally silent
  }
  gauge(_name: string, _value: number, _tags?: MetricTags): void {
    // intentionally silent
  }
  timing(_name: string, _durationMs: number, _tags?: MetricTags): void {
    // intentionally silent
  }
  async flush(): Promise<void> {
    // intentionally silent
  }
}
