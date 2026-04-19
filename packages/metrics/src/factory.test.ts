import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolveBackend, createMetricsClient } from './factory.js';
import { EmfMetricsClient } from './emf-backend.js';
import { NoopMetricsClient } from './noop-backend.js';

describe('resolveBackend', () => {
  it('returns noop for undefined', () => {
    expect(resolveBackend(undefined)).toBe('noop');
  });
  it('returns noop for empty string', () => {
    expect(resolveBackend('')).toBe('noop');
  });
  it('returns noop for any non-cloudwatch value', () => {
    expect(resolveBackend('noop')).toBe('noop');
    expect(resolveBackend('prometheus')).toBe('noop');
  });
  it('returns cloudwatch for "cloudwatch" (any case)', () => {
    expect(resolveBackend('cloudwatch')).toBe('cloudwatch');
    expect(resolveBackend('CloudWatch')).toBe('cloudwatch');
    expect(resolveBackend('CLOUDWATCH')).toBe('cloudwatch');
  });
});

describe('createMetricsClient', () => {
  const originalBackend = process.env.METRICS_BACKEND;

  beforeEach(() => {
    delete process.env.METRICS_BACKEND;
  });
  afterEach(() => {
    // Restore original env to avoid leaking across tests.
    if (originalBackend === undefined) {
      delete process.env.METRICS_BACKEND;
    } else {
      process.env.METRICS_BACKEND = originalBackend;
    }
  });

  it('returns Noop when METRICS_BACKEND is unset', () => {
    const client = createMetricsClient('svc');
    expect(client).toBeInstanceOf(NoopMetricsClient);
  });

  it('returns EMF client when METRICS_BACKEND=cloudwatch', () => {
    process.env.METRICS_BACKEND = 'cloudwatch';
    const client = createMetricsClient('svc', { flushIntervalMs: 0 });
    expect(client).toBeInstanceOf(EmfMetricsClient);
    // Stop the auto-flush timer cleanly
    (client as EmfMetricsClient).close();
  });

  it('silently returns Noop for unknown backend values', () => {
    process.env.METRICS_BACKEND = 'datadog';
    const client = createMetricsClient('svc');
    expect(client).toBeInstanceOf(NoopMetricsClient);
  });
});
