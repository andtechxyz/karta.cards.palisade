// CloudWatch Embedded Metric Format (EMF) backend.
//
// EMF works by printing a specific JSON envelope to stdout that the
// CloudWatch agent (or, in ECS, the awslogs driver) parses into real
// metrics.  No SDK call is made — this is pure structured logging,
// which means:
//
//   * Zero cost to emit beyond the log bytes.
//   * No IAM permissions needed beyond whatever already publishes
//     CloudWatch logs.
//   * Metric cardinality bounded by dimensions (max 30 per emission,
//     CloudWatch docs).
//
// EMF reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/
//                monitoring/CloudWatch_Embedded_Metric_Format.html

import type {
  MetricsClient,
  MetricsClientOptions,
  MetricTags,
} from './types.js';

// EMF uses the minute resolution unless Unit says otherwise; we keep
// everything at millisecond resolution for timings and Count for
// counters/gauges.  These are the exact CloudWatch Unit strings.
type EmfUnit = 'Count' | 'None' | 'Milliseconds';

interface BufferedMetric {
  kind: 'counter' | 'gauge' | 'timing';
  name: string;
  values: number[]; // aggregated samples — one for gauges, many for timings, sum for counters
  tags: MetricTags;
}

// Buffer key: `${kind}|${name}|${stable-tag-string}`.  Tag order is
// normalised so two callers with the same tags but different key order
// hash to the same bucket.
function bufferKey(kind: string, name: string, tags: MetricTags): string {
  const keys = Object.keys(tags).sort();
  const tagStr = keys.map((k) => `${k}=${tags[k]}`).join(',');
  return `${kind}|${name}|${tagStr}`;
}

function unitFor(kind: BufferedMetric['kind']): EmfUnit {
  switch (kind) {
    case 'counter':
      return 'Count';
    case 'gauge':
      return 'None';
    case 'timing':
      return 'Milliseconds';
  }
}

/**
 * Shape of a single EMF JSON document.  We intentionally type-narrow this
 * here rather than expose it publicly — callers should never need to
 * construct one by hand.
 */
export interface EmfDocument {
  _aws: {
    Timestamp: number;
    CloudWatchMetrics: Array<{
      Namespace: string;
      Dimensions: string[][];
      Metrics: Array<{ Name: string; Unit: EmfUnit }>;
    }>;
  };
  [key: string]: unknown;
}

export interface EmfBackendOptions extends MetricsClientOptions {
  /**
   * Where to send the EMF JSON lines.  Defaults to console.log so
   * stdout-attached log drivers pick them up.  Override in tests to
   * collect the emitted documents.
   */
  sink?: (line: string) => void;

  /**
   * Override "now" for deterministic tests.
   */
  now?: () => number;
}

export class EmfMetricsClient implements MetricsClient {
  private readonly namespace: string;
  private readonly sink: (line: string) => void;
  private readonly now: () => number;
  private readonly flushIntervalMs: number;

  // Buffered metrics, keyed by (kind, name, tags).  Holds an array of
  // raw values so timings preserve distribution for server-side stats.
  private buffer: Map<string, BufferedMetric> = new Map();

  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(opts: EmfBackendOptions) {
    this.namespace = opts.serviceName;
    this.sink = opts.sink ?? ((line) => {
      // eslint-disable-next-line no-console
      console.log(line);
    });
    this.now = opts.now ?? (() => Date.now());
    this.flushIntervalMs = opts.flushIntervalMs ?? 10_000;

    if (this.flushIntervalMs > 0) {
      // unref() so an idle timer doesn't keep the process alive.  Node
      // typings for setInterval vary; guard the unref call.
      this.flushTimer = setInterval(() => {
        this.flush().catch(() => {
          // Flush errors are best-effort for a log-driven backend —
          // there's no upstream to retry against.
        });
      }, this.flushIntervalMs);
      if (typeof (this.flushTimer as unknown as { unref?: () => void }).unref === 'function') {
        (this.flushTimer as unknown as { unref: () => void }).unref();
      }
    }
  }

  counter(name: string, value: number = 1, tags: MetricTags = {}): void {
    const key = bufferKey('counter', name, tags);
    const existing = this.buffer.get(key);
    if (existing) {
      // Counters sum — squash the running total into slot 0 so we emit
      // one number, not N.
      existing.values[0] = (existing.values[0] ?? 0) + value;
    } else {
      this.buffer.set(key, {
        kind: 'counter',
        name,
        values: [value],
        tags,
      });
    }
  }

  gauge(name: string, value: number, tags: MetricTags = {}): void {
    const key = bufferKey('gauge', name, tags);
    // Last-write-wins: replace, don't accumulate.
    this.buffer.set(key, {
      kind: 'gauge',
      name,
      values: [value],
      tags,
    });
  }

  timing(name: string, durationMs: number, tags: MetricTags = {}): void {
    const key = bufferKey('timing', name, tags);
    const existing = this.buffer.get(key);
    if (existing) {
      existing.values.push(durationMs);
    } else {
      this.buffer.set(key, {
        kind: 'timing',
        name,
        values: [durationMs],
        tags,
      });
    }
  }

  async flush(): Promise<void> {
    if (this.buffer.size === 0) return;

    // Snapshot + clear so new writes during flush aren't lost.
    const snapshot = this.buffer;
    this.buffer = new Map();

    for (const metric of snapshot.values()) {
      const doc = this.buildDocument(metric);
      this.sink(JSON.stringify(doc));
    }
  }

  /**
   * Stop the auto-flush timer.  Safe to call even if timer isn't set.
   * Services should call this on graceful shutdown.
   */
  close(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  private buildDocument(metric: BufferedMetric): EmfDocument {
    const dimensionKeys = Object.keys(metric.tags);
    const unit = unitFor(metric.kind);

    // Values: counters emit a single scalar (the accumulated sum);
    // timings emit the full array so CloudWatch can compute stats;
    // gauges emit their single latest value.
    const emittedValue: number | number[] =
      metric.kind === 'timing' && metric.values.length > 1
        ? metric.values
        : metric.values[0] ?? 0;

    const doc: EmfDocument = {
      _aws: {
        Timestamp: this.now(),
        CloudWatchMetrics: [
          {
            Namespace: this.namespace,
            // CloudWatch expects Dimensions as an array of arrays —
            // each inner array is a dimension combination to emit.
            // We emit one combination (all tags together).
            Dimensions: dimensionKeys.length > 0 ? [dimensionKeys] : [[]],
            Metrics: [{ Name: metric.name, Unit: unit }],
          },
        ],
      },
      [metric.name]: emittedValue,
    };

    // Copy tag values onto the top-level doc — CloudWatch reads them
    // by name from here when rendering the metric's dimensions.
    for (const k of dimensionKeys) {
      doc[k] = metric.tags[k];
    }

    return doc;
  }
}
