// Backend selection.  Services call createMetricsClient() once at
// startup; the env decides whether they get a real EMF emitter or a
// silent no-op.
//
// Selection rule:
//   METRICS_BACKEND=cloudwatch → EmfMetricsClient
//   anything else (unset, "noop", etc.) → NoopMetricsClient
//
// The string comparison is lowercased so callers don't have to be
// careful about case in ECS task definitions.

import { EmfMetricsClient } from './emf-backend.js';
import { NoopMetricsClient } from './noop-backend.js';
import type { MetricsClient, MetricsClientOptions } from './types.js';

export type MetricsBackend = 'cloudwatch' | 'noop';

export function resolveBackend(raw: string | undefined): MetricsBackend {
  if (!raw) return 'noop';
  return raw.toLowerCase() === 'cloudwatch' ? 'cloudwatch' : 'noop';
}

/**
 * Build a MetricsClient for `serviceName`.  The returned client is
 * stable for the lifetime of the process; callers should construct one
 * at startup and inject it into routes / middleware.
 *
 * Optional `opts` overrides select behaviour (flush interval, custom
 * sink for tests); it does NOT override the backend choice — that's
 * always driven by METRICS_BACKEND so an ops toggle flips every service
 * consistently.
 */
export function createMetricsClient(
  serviceName: string,
  opts: Partial<Omit<MetricsClientOptions, 'serviceName'>> = {},
): MetricsClient {
  const backend = resolveBackend(process.env.METRICS_BACKEND);
  if (backend === 'cloudwatch') {
    return new EmfMetricsClient({ serviceName, ...opts });
  }
  return new NoopMetricsClient();
}
