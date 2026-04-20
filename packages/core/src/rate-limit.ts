import rateLimit from 'express-rate-limit';
import type { Request } from 'express';

// Behind Cloudflare + ALB, req.ip is the immediate upstream hop (a changing
// edge IP), which defeats per-client rate limiting.  Cloudflare forwards the
// real client IP in CF-Connecting-IP; fall back to req.ip for direct hits.
//
// PCI 8.3.6 defence: only trust CF-Connecting-IP when the request
// genuinely came from Cloudflare's edge.  A request landing directly on
// the ALB (misrouted, staging IP, attacker bypassing CF) with a
// spoofed CF-Connecting-IP would otherwise get per-IP rate-limit bypass
// by rotating the header per request.  We validate via CIDR match of
// req.ip against Cloudflare's published IPv4 + IPv6 ranges.
//
// The range list is pinned at deploy time rather than fetched at runtime
// — if CF adds a new /12 and we don't know about it, a rare CF-upgraded
// client fails closed to req.ip (still gets rate-limited, just by CF
// edge IP rather than true client IP).  Refresh the list from
// https://www.cloudflare.com/ips-v4 / ips-v6 during normal maintenance.

const CLOUDFLARE_IPV4_CIDRS: string[] = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
];

const CLOUDFLARE_IPV6_CIDRS: string[] = [
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

// -----------------------------------------------------------------------------
// CIDR match — pre-parsed for performance
// -----------------------------------------------------------------------------

interface Cidr4 { base: number; mask: number; }
interface Cidr6 { base: bigint; mask: bigint; }

const cidr4List: Cidr4[] = CLOUDFLARE_IPV4_CIDRS.map(parseCidr4);
const cidr6List: Cidr6[] = CLOUDFLARE_IPV6_CIDRS.map(parseCidr6);

function parseCidr4(cidr: string): Cidr4 {
  const [ipStr, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const octets = ipStr.split('.').map((o) => parseInt(o, 10));
  const ip = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: ip & mask, mask };
}

function parseCidr6(cidr: string): Cidr6 {
  const [ipStr, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const ip = ipv6ToBigInt(ipStr);
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
  return { base: ip & mask, mask };
}

function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const b = parseInt(part, 10);
    if (Number.isNaN(b) || b < 0 || b > 255) return null;
    n = (n << 8) | b;
  }
  return n >>> 0;
}

function ipv6ToBigInt(ip: string): bigint {
  // Handle :: expansion and embedded IPv4.
  let parts = ip.split('::');
  let left: string[] = parts[0] ? parts[0].split(':') : [];
  let right: string[] = parts[1] ? parts[1].split(':') : [];
  // Embedded IPv4 suffix: last segment can be a.b.c.d — expand to two groups.
  const expandV4 = (arr: string[]): string[] => {
    if (arr.length === 0) return arr;
    const last = arr[arr.length - 1];
    if (last.includes('.')) {
      const n = ipv4ToNumber(last);
      if (n === null) return arr;
      const hi = ((n >>> 16) & 0xffff).toString(16);
      const lo = (n & 0xffff).toString(16);
      return [...arr.slice(0, -1), hi, lo];
    }
    return arr;
  };
  left = expandV4(left);
  right = expandV4(right);
  const missing = 8 - (left.length + right.length);
  const full = [...left, ...Array(missing).fill('0'), ...right];
  let n = 0n;
  for (const group of full) {
    n = (n << 16n) | BigInt(parseInt(group || '0', 16));
  }
  return n;
}

function isCloudflareIp(ip: string | null | undefined): boolean {
  if (!ip) return false;
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — extract the IPv4 portion.
  const v4Match = ip.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (v4Match) ip = v4Match[1];
  if (ip.includes('.') && !ip.includes(':')) {
    const n = ipv4ToNumber(ip);
    if (n === null) return false;
    return cidr4List.some((c) => (n & c.mask) === c.base);
  }
  if (ip.includes(':')) {
    try {
      const n = ipv6ToBigInt(ip);
      return cidr6List.some((c) => (n & c.mask) === c.base);
    } catch {
      return false;
    }
  }
  return false;
}

export function _testIsCloudflareIp(ip: string): boolean {
  return isCloudflareIp(ip);
}

/**
 * Resolve the true client IP.  When the request's immediate upstream
 * (req.ip — after `trust proxy` strips the ALB layer) is a Cloudflare
 * edge IP, trust the CF-Connecting-IP header.  Otherwise, treat
 * CF-Connecting-IP as untrusted and fall back to req.ip.
 */
function clientIp(req: Request): string {
  const upstream = req.ip ?? '';
  if (isCloudflareIp(upstream)) {
    const cfIp = req.headers['cf-connecting-ip'];
    if (typeof cfIp === 'string' && cfIp.length > 0) return cfIp;
  }
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
