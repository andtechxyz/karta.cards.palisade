// Public types for @palisade/metrics.
//
// Kept intentionally narrow: we model counters, gauges, and timings —
// the three primitives CloudWatch can express directly without fancy
// client-side aggregation.  Histograms are implemented on top of timing
// by letting CloudWatch bucket server-side (each emitted timing value
// becomes a sample in a "Metrics with statistics" metric).

export type MetricTags = Readonly<Record<string, string | number>>;

/**
 * Minimal metrics surface.  Every backend implements this, so services
 * can swap EMF for OTEL or a local Prometheus shim without code changes
 * at the callsite.
 */
export interface MetricsClient {
  /**
   * Increment `name` by `value` (default 1).  Tags become CloudWatch
   * dimensions for the EMF backend; they're also free-form attributes
   * for any alternate backend.
   *
   * Multiple counter() calls with the same (name, tags) pair within the
   * same flush window aggregate client-side into a single emission so
   * we don't spam CloudWatch with per-request JSON lines.
   */
  counter(name: string, value?: number, tags?: MetricTags): void;

  /**
   * Record an instantaneous value for `name`.  Unlike counter, gauges
   * overwrite within the flush window — the last value wins.
   */
  gauge(name: string, value: number, tags?: MetricTags): void;

  /**
   * Record a duration (ms).  Each call is kept as a distinct sample
   * within the flush window so CloudWatch can compute p50/p90/p99
   * server-side.  Collapsing client-side would destroy those statistics.
   */
  timing(name: string, durationMs: number, tags?: MetricTags): void;

  /**
   * Drain the in-memory buffer.  Safe to call repeatedly; a no-op when
   * there's nothing buffered.
   */
  flush(): Promise<void>;
}

/**
 * Common options accepted by every backend.  Backends may add their own
 * on top.
 */
export interface MetricsClientOptions {
  /**
   * Logical service identifier baked into every metric namespace.  In
   * EMF, this surfaces as the CloudWatch `Namespace` field.
   */
  serviceName: string;

  /**
   * How often to auto-flush, in ms.  Defaults to 10 seconds.  Set to 0
   * to disable auto-flush and rely on explicit `flush()` calls.
   */
  flushIntervalMs?: number;
}
