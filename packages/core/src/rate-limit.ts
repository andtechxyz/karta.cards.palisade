import rateLimit from 'express-rate-limit';
import type { Request } from 'express';

// Behind Cloudflare + ALB, req.ip is the immediate upstream hop (a changing
// edge IP), which defeats per-client rate limiting.  Cloudflare forwards the
// real client IP in CF-Connecting-IP; fall back to req.ip for direct hits.
function clientIp(req: Request): string {
  const cfIp = req.headers['cf-connecting-ip'];
  if (typeof cfIp === 'string' && cfIp.length > 0) return cfIp;
  return req.ip ?? 'unknown';
}

/** Strict rate limiter for auth endpoints: 10 requests per minute per IP */
export const authRateLimit = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: clientIp,
  message: { error: { code: 'rate_limited', message: 'Too many requests, try again later' } },
});

/** Standard rate limiter for API endpoints: 100 requests per minute per IP */
export const apiRateLimit = rateLimit({
  windowMs: 60_000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: clientIp,
  message: { error: { code: 'rate_limited', message: 'Too many requests' } },
});
