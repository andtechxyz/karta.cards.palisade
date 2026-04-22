/**
 * X-Request-ID correlation middleware (PCI DSS Req 10 / CPL LSR 8).
 *
 * Every inbound HTTP request gets a stable identifier that threads
 * through every log line + outbound service-to-service call + WS
 * session log, making cross-service tracing tractable without a
 * full SIEM ingest.  Format:
 *
 *   X-Request-ID: <32 lowercase hex chars>   (16 random bytes)
 *
 * Inbound handling:
 *   - Honour an incoming `X-Request-ID` if it's already well-formed
 *     (32 lowercase hex chars).  This lets tap → activation → rca
 *     share the same ID when they call each other via signRequest.
 *   - Otherwise generate a fresh one.
 *   - Echo back in the response `X-Request-ID` header so the caller
 *     can log what the downstream saw.
 *   - Stash on `req.requestId` for downstream handlers + loggers.
 *
 * AWS ALB also injects an `X-Amzn-Trace-Id` header; we keep ours
 * separate because:
 *   (a) Amzn-Trace-Id uses `Root=1-...` format, not a plain UUID-
 *       like token — logs would be harder to grep.
 *   (b) WS upgrade requests don't carry the Amzn-Trace-Id past the
 *       upgrade, and we need the same ID threading into the rca WS
 *       relay context.
 *   (c) Ours is client-overridable (for the service-to-service
 *       chain), the AWS one isn't.
 */

import type { RequestHandler } from 'express';
import { randomBytes } from 'node:crypto';

const REQUEST_ID_HEX_LEN = 32;
const REQUEST_ID_RE = /^[0-9a-f]{32}$/;

/** Generate a fresh request ID.  16 random bytes as lowercase hex. */
export function newRequestId(): string {
  return randomBytes(16).toString('hex');
}

/** Sniff an incoming header and return it iff well-formed. */
export function parseInboundRequestId(hdr: unknown): string | null {
  if (typeof hdr !== 'string') return null;
  const trimmed = hdr.trim().toLowerCase();
  if (trimmed.length !== REQUEST_ID_HEX_LEN) return null;
  if (!REQUEST_ID_RE.test(trimmed)) return null;
  return trimmed;
}

/**
 * Express middleware.  Mount BEFORE any other handler so every log
 * line emitted during the request lifecycle sees the ID via
 * `req.requestId` + the echoed response header.
 */
export const requestIdMiddleware: RequestHandler = (req, res, next) => {
  const inbound = parseInboundRequestId(req.headers['x-request-id']);
  const id = inbound ?? newRequestId();
  // Express typing doesn't include a custom field natively; stash via
  // property assignment.  Downstream handlers read via `req.requestId`.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (req as any).requestId = id;
  res.setHeader('X-Request-ID', id);
  next();
};

/**
 * Helper for log lines — falls back to a sentinel when no ID is
 * available (e.g. outside an HTTP context).  Callers: `log(\`[svc]
 * [rid=${getRequestId(req)}] msg\`)` or similar structured logger.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getRequestId(req: any): string {
  return (req && typeof req.requestId === 'string' && req.requestId) || '-';
}

/** Header name constant for code that builds outbound requests. */
export const REQUEST_ID_HEADER = 'X-Request-ID' as const;
