import { describe, it, expect } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

import {
  newRequestId,
  parseInboundRequestId,
  requestIdMiddleware,
  getRequestId,
  REQUEST_ID_HEADER,
} from './request-id.js';

// Minimal test doubles — we don't need an Express instance.
function mkReq(headers: Record<string, string | undefined> = {}): Request {
  return { headers } as unknown as Request;
}
function mkRes(): { res: Response; headers: Record<string, string> } {
  const headers: Record<string, string> = {};
  const res = {
    setHeader(name: string, value: string) {
      headers[name] = value;
    },
  } as unknown as Response;
  return { res, headers };
}

describe('newRequestId', () => {
  it('returns 32 lowercase hex chars', () => {
    const id = newRequestId();
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(id.length).toBe(32);
  });

  it('is unique across calls (birthday-bound)', () => {
    const a = newRequestId();
    const b = newRequestId();
    expect(a).not.toBe(b);
  });
});

describe('parseInboundRequestId', () => {
  it('accepts a well-formed lowercase hex 32-char header', () => {
    const id = 'a'.repeat(32);
    expect(parseInboundRequestId(id)).toBe(id);
  });

  it('lowercases an uppercase-hex inbound value', () => {
    const id = 'DEADBEEF'.repeat(4);
    expect(parseInboundRequestId(id)).toBe(id.toLowerCase());
  });

  it('trims surrounding whitespace', () => {
    const id = 'a'.repeat(32);
    expect(parseInboundRequestId(`  ${id}  `)).toBe(id);
  });

  it('returns null on wrong length', () => {
    expect(parseInboundRequestId('abc123')).toBeNull();
    expect(parseInboundRequestId('a'.repeat(31))).toBeNull();
    expect(parseInboundRequestId('a'.repeat(33))).toBeNull();
  });

  it('returns null on non-hex characters', () => {
    expect(parseInboundRequestId('g'.repeat(32))).toBeNull();
    expect(parseInboundRequestId('z'.repeat(32))).toBeNull();
    expect(parseInboundRequestId('!'.repeat(32))).toBeNull();
  });

  it('returns null on non-string inputs', () => {
    expect(parseInboundRequestId(undefined)).toBeNull();
    expect(parseInboundRequestId(null)).toBeNull();
    expect(parseInboundRequestId(42)).toBeNull();
    expect(parseInboundRequestId(['abcd'])).toBeNull();
  });
});

describe('requestIdMiddleware', () => {
  it('generates a fresh ID when no inbound header', () => {
    const req = mkReq({});
    const { res, headers } = mkRes();
    const next: NextFunction = () => {};
    requestIdMiddleware(req, res, next);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const id = (req as any).requestId;
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(headers[REQUEST_ID_HEADER]).toBe(id);
  });

  it('honours a well-formed inbound X-Request-ID', () => {
    const inbound = 'b'.repeat(32);
    const req = mkReq({ 'x-request-id': inbound });
    const { res, headers } = mkRes();
    const next: NextFunction = () => {};
    requestIdMiddleware(req, res, next);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((req as any).requestId).toBe(inbound);
    expect(headers[REQUEST_ID_HEADER]).toBe(inbound);
  });

  it('regenerates when inbound is malformed', () => {
    const req = mkReq({ 'x-request-id': 'not-valid' });
    const { res, headers } = mkRes();
    const next: NextFunction = () => {};
    requestIdMiddleware(req, res, next);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const id = (req as any).requestId;
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(id).not.toBe('not-valid');
    expect(headers[REQUEST_ID_HEADER]).toBe(id);
  });
});

describe('getRequestId', () => {
  it('returns the stashed ID when present', () => {
    const req = { requestId: 'a'.repeat(32) };
    expect(getRequestId(req)).toBe('a'.repeat(32));
  });

  it("returns '-' sentinel when absent or non-string", () => {
    expect(getRequestId({})).toBe('-');
    expect(getRequestId(null)).toBe('-');
    expect(getRequestId(undefined)).toBe('-');
    expect(getRequestId({ requestId: 42 })).toBe('-');
  });
});
