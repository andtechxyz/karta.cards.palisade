import { describe, it, expect } from 'vitest';
import { EmfMetricsClient, type EmfDocument } from './emf-backend.js';

// Small helper — spin up an EMF client that captures emitted JSON lines
// in-memory, with a pinned clock so timestamps are deterministic.
function makeClient(now = 1_700_000_000_000): {
  client: EmfMetricsClient;
  lines: string[];
  parsed: () => EmfDocument[];
} {
  const lines: string[] = [];
  const client = new EmfMetricsClient({
    serviceName: 'test-svc',
    flushIntervalMs: 0, // disable auto-flush; drive manually
    sink: (l) => lines.push(l),
    now: () => now,
  });
  return {
    client,
    lines,
    parsed: () => lines.map((l) => JSON.parse(l) as EmfDocument),
  };
}

describe('EmfMetricsClient — document shape', () => {
  it('emits the CloudWatch-expected envelope for a counter', async () => {
    const { client, parsed } = makeClient();
    client.counter('auth.success', 1, { route: '/login' });
    await client.flush();

    const docs = parsed();
    expect(docs).toHaveLength(1);
    const doc = docs[0]!;

    // _aws envelope shape — exactly what CloudWatch's metric extractor
    // looks for in log lines.
    expect(doc._aws).toBeDefined();
    expect(doc._aws.CloudWatchMetrics).toHaveLength(1);
    const cw = doc._aws.CloudWatchMetrics[0]!;
    expect(cw.Namespace).toBe('test-svc');
    expect(cw.Metrics).toEqual([{ Name: 'auth.success', Unit: 'Count' }]);
    expect(cw.Dimensions).toEqual([['route']]);

    // Top-level fields: metric value keyed by name, tags keyed by
    // dimension name.
    expect(doc['auth.success']).toBe(1);
    expect(doc.route).toBe('/login');
  });

  it('uses None unit for gauges', async () => {
    const { client, parsed } = makeClient();
    client.gauge('queue.depth', 42);
    await client.flush();

    const cw = parsed()[0]!._aws.CloudWatchMetrics[0]!;
    expect(cw.Metrics).toEqual([{ Name: 'queue.depth', Unit: 'None' }]);
  });

  it('uses Milliseconds unit for timings', async () => {
    const { client, parsed } = makeClient();
    client.timing('db.query', 15);
    await client.flush();

    const cw = parsed()[0]!._aws.CloudWatchMetrics[0]!;
    expect(cw.Metrics).toEqual([{ Name: 'db.query', Unit: 'Milliseconds' }]);
  });

  it('emits Timestamp from the injected clock', async () => {
    const { client, parsed } = makeClient(1_234_567_890_123);
    client.counter('x');
    await client.flush();
    expect(parsed()[0]!._aws.Timestamp).toBe(1_234_567_890_123);
  });

  it('emits empty dimensions array when no tags supplied', async () => {
    const { client, parsed } = makeClient();
    client.counter('noop');
    await client.flush();
    expect(parsed()[0]!._aws.CloudWatchMetrics[0]!.Dimensions).toEqual([[]]);
  });
});

describe('EmfMetricsClient — aggregation within flush window', () => {
  it('counter sums multiple calls with identical (name, tags) into one emission', async () => {
    const { client, parsed } = makeClient();
    client.counter('hits', 1, { route: '/a' });
    client.counter('hits', 1, { route: '/a' });
    client.counter('hits', 5, { route: '/a' });
    await client.flush();

    const docs = parsed();
    expect(docs).toHaveLength(1);
    expect(docs[0]!.hits).toBe(7);
  });

  it('counter keeps separate buckets for different tag values', async () => {
    const { client, parsed } = makeClient();
    client.counter('hits', 1, { route: '/a' });
    client.counter('hits', 1, { route: '/b' });
    await client.flush();

    const docs = parsed();
    expect(docs).toHaveLength(2);
    const byRoute = Object.fromEntries(docs.map((d) => [d.route as string, d.hits]));
    expect(byRoute).toEqual({ '/a': 1, '/b': 1 });
  });

  it('tag order does not create separate buckets', async () => {
    const { client, parsed } = makeClient();
    client.counter('hits', 1, { a: 'x', b: 'y' });
    client.counter('hits', 1, { b: 'y', a: 'x' });
    await client.flush();

    expect(parsed()).toHaveLength(1);
    expect(parsed()[0]!.hits).toBe(2);
  });

  it('gauge uses last-write-wins semantics', async () => {
    const { client, parsed } = makeClient();
    client.gauge('depth', 10);
    client.gauge('depth', 20);
    client.gauge('depth', 5);
    await client.flush();

    const docs = parsed();
    expect(docs).toHaveLength(1);
    expect(docs[0]!.depth).toBe(5);
  });

  it('timing keeps per-call samples for server-side distribution', async () => {
    const { client, parsed } = makeClient();
    client.timing('lat', 10);
    client.timing('lat', 20);
    client.timing('lat', 30);
    await client.flush();

    const docs = parsed();
    expect(docs).toHaveLength(1);
    expect(docs[0]!.lat).toEqual([10, 20, 30]);
  });

  it('timing with a single sample emits a scalar, not a one-element array', async () => {
    const { client, parsed } = makeClient();
    client.timing('lat', 42);
    await client.flush();
    expect(parsed()[0]!.lat).toBe(42);
  });
});

describe('EmfMetricsClient — flush semantics', () => {
  it('flush on an empty buffer emits nothing', async () => {
    const { client, lines } = makeClient();
    await client.flush();
    expect(lines).toEqual([]);
  });

  it('flush clears the buffer — second flush is a no-op', async () => {
    const { client, lines } = makeClient();
    client.counter('a');
    await client.flush();
    expect(lines).toHaveLength(1);
    await client.flush();
    expect(lines).toHaveLength(1);
  });

  it('writes during flush are retained for the next flush', async () => {
    const { client, lines } = makeClient();
    // Simulate an interleaving: we can't actually get in-between since
    // flush is synchronous in the happy path, but we can check that the
    // buffer starts fresh for the next cycle.
    client.counter('a');
    await client.flush();
    client.counter('b');
    await client.flush();
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!).a).toBe(1);
    expect(JSON.parse(lines[1]!).b).toBe(1);
  });
});
