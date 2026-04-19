// HTTP-request metrics middleware for Express.
//
// Records three metrics per response:
//
//   http.requests.total      counter, tagged route + method + status_code
//   http.requests.errors     counter, only emitted for status >= 400
//   http.request.duration    timing (ms), tagged route + method + status_class
//
// Routing tag: we use `req.route?.path` when set (matched Express route),
// otherwise fall back to `req.path`.  This prevents cardinality explosion
// from /users/:id path-variants: all :id values collapse onto the same
// matched-route label.

import type { Express, Request, Response, NextFunction } from 'express';
import type { MetricsClient, MetricTags } from './types.js';

export interface WrapExpressMetricsOptions {
  /**
   * Metric name prefix.  Defaults to `http` — emits
   * `http.requests.total`, etc.
   */
  prefix?: string;

  /**
   * Optional tag extractor — lets callers attach per-request context
   * (e.g. tenant id) to every metric.  Errors thrown here are swallowed
   * so a broken extractor can't break the request.
   */
  extraTags?: (req: Request, res: Response) => MetricTags;
}

/**
 * Attach HTTP metrics middleware to `app`.  Call once at startup, after
 * CORS / body parsing / auth are configured but before route handlers.
 */
export function wrapExpressMetrics(
  app: Express,
  client: MetricsClient,
  opts: WrapExpressMetricsOptions = {},
): void {
  const prefix = opts.prefix ?? 'http';
  const extraTags = opts.extraTags;

  app.use((req: Request, res: Response, next: NextFunction) => {
    const start = hrNowMs();

    // `res.on('finish')` fires after headers + body have been written
    // AND Express has populated req.route, so we get the matched path.
    res.on('finish', () => {
      const duration = hrNowMs() - start;
      const statusCode = res.statusCode;
      const route = routeLabel(req);

      // status_class: "2xx" / "4xx" / "5xx" — lower cardinality than
      // the raw status code, useful for SLO alarms.
      const statusClass = `${Math.floor(statusCode / 100)}xx`;

      const base: Record<string, string | number> = {
        route,
        method: req.method,
        status_code: statusCode,
        status_class: statusClass,
      };

      let tags: MetricTags = base;
      if (extraTags) {
        try {
          tags = { ...base, ...extraTags(req, res) };
        } catch {
          // Fall through with `base` — don't let a bad extractor ever
          // affect a real request.
        }
      }

      client.counter(`${prefix}.requests.total`, 1, tags);
      if (statusCode >= 400) {
        client.counter(`${prefix}.requests.errors`, 1, tags);
      }
      client.timing(`${prefix}.request.duration`, duration, {
        route,
        method: req.method,
        status_class: statusClass,
      });
    });

    next();
  });
}

function routeLabel(req: Request): string {
  // When Express has matched a route, req.route.path holds the pattern
  // (e.g. "/cards/:id").  For unmatched requests (e.g. 404s before any
  // router), fall back to "unknown" — NOT req.path, which would blow up
  // cardinality with scanner / fuzzer traffic.
  const matched = (req as Request & { route?: { path?: string } }).route?.path;
  if (typeof matched === 'string' && matched.length > 0) {
    // baseUrl is the mount point of the router that matched; combine it
    // so "/api/cards" + ":id" → "/api/cards/:id".
    const base = req.baseUrl ?? '';
    return base + matched;
  }
  return 'unknown';
}

// Prefer process.hrtime-driven time so tests with fake timers can still
// measure wall-clock delta; falls back to Date.now if hrtime is absent.
function hrNowMs(): number {
  if (typeof process !== 'undefined' && typeof process.hrtime?.bigint === 'function') {
    return Number(process.hrtime.bigint() / 1_000_000n);
  }
  return Date.now();
}
