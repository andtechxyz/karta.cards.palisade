import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { wrapExpressMetrics } from './express-middleware.js';
import type { MetricsClient, MetricTags } from './types.js';

// In-memory recording client — lets us assert on every emission.
class RecordingClient implements MetricsClient {
  counters: Array<{ name: string; value: number; tags: MetricTags }> = [];
  gauges: Array<{ name: string; value: number; tags: MetricTags }> = [];
  timings: Array<{ name: string; value: number; tags: MetricTags }> = [];

  counter(name: string, value: number = 1, tags: MetricTags = {}): void {
    this.counters.push({ name, value, tags });
  }
  gauge(name: string, value: number, tags: MetricTags = {}): void {
    this.gauges.push({ name, value, tags });
  }
  timing(name: string, value: number, tags: MetricTags = {}): void {
    this.timings.push({ name, value, tags });
  }
  async flush(): Promise<void> {}

  reset(): void {
    this.counters = [];
    this.gauges = [];
    this.timings = [];
  }
}

function buildApp(
  client: MetricsClient,
  routes: Array<(app: express.Express) => void>,
): express.Express {
  const app = express();
  wrapExpressMetrics(app, client);
  for (const r of routes) r(app);
  return app;
}

describe('wrapExpressMetrics', () => {
  let client: RecordingClient;

  beforeEach(() => {
    client = new RecordingClient();
  });

  it('records http.requests.total for a successful 200', async () => {
    const app = buildApp(client, [
      (a) => a.get('/ping', (_req, res) => res.json({ ok: true })),
    ]);

    await request(app).get('/ping').expect(200);

    const totals = client.counters.filter((c) => c.name === 'http.requests.total');
    expect(totals).toHaveLength(1);
    expect(totals[0]!.tags).toMatchObject({
      route: '/ping',
      method: 'GET',
      status_code: 200,
      status_class: '2xx',
    });
  });

  it('does NOT emit http.requests.errors on 2xx', async () => {
    const app = buildApp(client, [
      (a) => a.get('/ok', (_req, res) => res.json({ ok: true })),
    ]);
    await request(app).get('/ok').expect(200);
    const errors = client.counters.filter((c) => c.name === 'http.requests.errors');
    expect(errors).toHaveLength(0);
  });

  it('emits http.requests.errors for 4xx responses', async () => {
    const app = buildApp(client, [
      (a) => a.get('/bad', (_req, res) => res.status(400).json({ err: 'nope' })),
    ]);
    await request(app).get('/bad').expect(400);

    const errors = client.counters.filter((c) => c.name === 'http.requests.errors');
    expect(errors).toHaveLength(1);
    expect(errors[0]!.tags).toMatchObject({
      route: '/bad',
      method: 'GET',
      status_code: 400,
      status_class: '4xx',
    });
  });

  it('emits http.requests.errors for 5xx responses', async () => {
    const app = buildApp(client, [
      (a) =>
        a.get('/boom', (_req, res) => res.status(500).json({ err: 'broken' })),
    ]);
    await request(app).get('/boom').expect(500);

    const errors = client.counters.filter((c) => c.name === 'http.requests.errors');
    expect(errors).toHaveLength(1);
    expect(errors[0]!.tags).toMatchObject({
      status_code: 500,
      status_class: '5xx',
    });
  });

  it('records timing with route + method + status_class (lower cardinality)', async () => {
    const app = buildApp(client, [
      (a) => a.get('/api/ping', (_req, res) => res.json({ ok: true })),
    ]);
    await request(app).get('/api/ping').expect(200);

    const timings = client.timings.filter((t) => t.name === 'http.request.duration');
    expect(timings).toHaveLength(1);
    expect(timings[0]!.tags).toMatchObject({
      route: '/api/ping',
      method: 'GET',
      status_class: '2xx',
    });
    // No raw status_code in timing tags.
    expect(timings[0]!.tags).not.toHaveProperty('status_code');
    // Duration is a non-negative number of milliseconds.
    expect(timings[0]!.value).toBeGreaterThanOrEqual(0);
  });

  it('uses the matched route pattern so :id variants collapse', async () => {
    const app = buildApp(client, [
      (a) =>
        a.get('/cards/:id', (req, res) => {
          res.json({ id: req.params.id });
        }),
    ]);

    await request(app).get('/cards/abc').expect(200);
    await request(app).get('/cards/def').expect(200);
    await request(app).get('/cards/ghi').expect(200);

    const totals = client.counters.filter((c) => c.name === 'http.requests.total');
    expect(totals).toHaveLength(3);
    for (const t of totals) {
      expect(t.tags.route).toBe('/cards/:id');
    }
  });

  it('labels unmatched routes as "unknown" instead of raw req.path', async () => {
    const app = buildApp(client, [
      (a) =>
        a.get('/known', (_req, res) => res.json({ ok: true })),
    ]);

    // An unmatched path — Express returns 404.  The route label must
    // not be the raw URL (cardinality explosion); it must be "unknown".
    await request(app).get('/attacker-probe-a').expect(404);
    await request(app).get('/attacker-probe-b').expect(404);

    const totals = client.counters.filter((c) => c.name === 'http.requests.total');
    expect(totals).toHaveLength(2);
    expect(totals.every((t) => t.tags.route === 'unknown')).toBe(true);
  });

  it('records POST method correctly', async () => {
    const app = express();
    wrapExpressMetrics(app, client);
    app.use(express.json());
    app.post('/data', (_req, res) => res.status(201).json({ id: 'x' }));

    await request(app).post('/data').send({ foo: 'bar' }).expect(201);

    const totals = client.counters.filter((c) => c.name === 'http.requests.total');
    expect(totals).toHaveLength(1);
    expect(totals[0]!.tags).toMatchObject({
      method: 'POST',
      status_code: 201,
      status_class: '2xx',
    });
  });

  it('supports extraTags to attach tenant-style context', async () => {
    const client2 = new RecordingClient();
    const app = express();
    wrapExpressMetrics(app, client2, {
      extraTags: () => ({ tenant: 'acme' }),
    });
    app.get('/x', (_req, res) => res.json({ ok: true }));

    await request(app).get('/x').expect(200);

    const totals = client2.counters.filter((c) => c.name === 'http.requests.total');
    expect(totals[0]!.tags).toMatchObject({
      tenant: 'acme',
      route: '/x',
      status_code: 200,
    });
  });

  it('swallows errors from extraTags so a broken extractor does not fail the request', async () => {
    const client2 = new RecordingClient();
    const app = express();
    wrapExpressMetrics(app, client2, {
      extraTags: () => {
        throw new Error('boom');
      },
    });
    app.get('/x', (_req, res) => res.json({ ok: true }));

    await request(app).get('/x').expect(200);

    // Request completed, and the counter still fired with base tags.
    const totals = client2.counters.filter((c) => c.name === 'http.requests.total');
    expect(totals).toHaveLength(1);
    expect(totals[0]!.tags).not.toHaveProperty('tenant');
  });

  it('supports a custom prefix', async () => {
    const client2 = new RecordingClient();
    const app = express();
    wrapExpressMetrics(app, client2, { prefix: 'vera' });
    app.get('/x', (_req, res) => res.json({ ok: true }));

    await request(app).get('/x').expect(200);

    expect(client2.counters.some((c) => c.name === 'vera.requests.total')).toBe(true);
    expect(client2.timings.some((t) => t.name === 'vera.request.duration')).toBe(true);
  });
});
