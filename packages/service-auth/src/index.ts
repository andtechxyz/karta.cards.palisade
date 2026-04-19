import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { internal } from '@palisade/core';

// -----------------------------------------------------------------------------
// @palisade/service-auth — HMAC-signed service-to-service requests.
//
// Every call from pay→vault and activation→vault carries an Authorization
// header binding the HTTP method, path+query, a timestamp, and the SHA-256 of
// the raw request body.  The vault's edge middleware verifies the signature
// against a per-caller shared secret before the route handler runs.
//
// PCI-DSS 7.1/7.2/8.2 — restrict CHD access by need-to-know and identify the
// caller before access.  Same wire protocol works unchanged behind a private
// ALB on AWS; the shared secrets would move to Secrets Manager.
//
// Envelope:
//   Authorization: VeraHmac keyId=<id>,ts=<unix>,sig=<hex>
//
// Canonical string signed:
//   `${METHOD}\n${PATH_AND_QUERY}\n${TS}\n${BODY_SHA256_HEX}`
//
// Replay resistance: ±windowSeconds around the server clock (default 60s).
// The body hash ensures a replay is byte-identical to the original; it cannot
// be mutated to e.g. charge a different amount within the window.
// -----------------------------------------------------------------------------

const SCHEME = 'VeraHmac';
const DEFAULT_WINDOW_SECONDS = 60;

export class ServiceAuthError extends Error {
  constructor(
    public readonly code:
      | 'missing_auth'
      | 'malformed_auth'
      | 'unknown_key'
      | 'bad_signature'
      | 'clock_skew'
      | 'body_mismatch',
    message?: string,
  ) {
    super(message ?? code);
    this.name = 'ServiceAuthError';
  }
}

// --- Signer -----------------------------------------------------------------

export interface SignRequestInput {
  method: string;
  /** Path including the querystring (e.g. `/api/vault/store?x=1`). */
  pathAndQuery: string;
  /** Raw body bytes as sent on the wire.  Pass empty buffer for GET / no body. */
  body: Buffer;
  keyId: string;
  /** 32-byte secret, hex-encoded. */
  secret: string;
  /** Unix seconds.  Defaults to now; override for tests. */
  now?: number;
}

/** Build the `Authorization` header value for an outbound request. */
export function signRequest(input: SignRequestInput): string {
  const ts = input.now ?? Math.floor(Date.now() / 1000);
  const message = canonical(input.method, input.pathAndQuery, ts, input.body);
  const sig = hmac(input.secret, message).toString('hex');
  return `${SCHEME} keyId=${input.keyId},ts=${ts},sig=${sig}`;
}

// --- Verifier ---------------------------------------------------------------

export interface VerifyRequestInput {
  /** Raw value of the `Authorization` header. */
  authorization: string | undefined;
  method: string;
  pathAndQuery: string;
  /** Raw body bytes as received.  Pass empty buffer for GET / no body. */
  body: Buffer;
  /** Map of keyId → 32-byte hex secret.  Supply multiple for rotation. */
  keys: Record<string, string>;
  /** Unix seconds.  Defaults to now; override for tests. */
  now?: number;
  /** Accept timestamps within ±window seconds of `now`.  Default 60. */
  windowSeconds?: number;
}

export interface VerifiedRequest {
  keyId: string;
}

/** Verify the header on an inbound request.  Throws ServiceAuthError on failure. */
export function verifyRequest(input: VerifyRequestInput): VerifiedRequest {
  if (!input.authorization) throw new ServiceAuthError('missing_auth');
  const parsed = parseAuthorization(input.authorization);

  const secret = input.keys[parsed.keyId];
  if (!secret) throw new ServiceAuthError('unknown_key');

  const now = input.now ?? Math.floor(Date.now() / 1000);
  const window = input.windowSeconds ?? DEFAULT_WINDOW_SECONDS;
  if (Math.abs(now - parsed.ts) > window) throw new ServiceAuthError('clock_skew');

  const expected = hmac(secret, canonical(input.method, input.pathAndQuery, parsed.ts, input.body));
  const got = Buffer.from(parsed.sig, 'hex');
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
    throw new ServiceAuthError('bad_signature');
  }

  return { keyId: parsed.keyId };
}

function parseAuthorization(header: string): { keyId: string; ts: number; sig: string } {
  const [scheme, rest] = header.split(/\s+/, 2);
  if (scheme !== SCHEME || !rest) throw new ServiceAuthError('malformed_auth');

  const parts: Record<string, string> = {};
  for (const piece of rest.split(',')) {
    const eq = piece.indexOf('=');
    if (eq <= 0) throw new ServiceAuthError('malformed_auth');
    parts[piece.slice(0, eq).trim()] = piece.slice(eq + 1).trim();
  }

  const { keyId, ts, sig } = parts;
  if (!keyId || !ts || !sig) throw new ServiceAuthError('malformed_auth');
  const tsNum = Number.parseInt(ts, 10);
  if (!Number.isFinite(tsNum)) throw new ServiceAuthError('malformed_auth');
  if (!/^[0-9a-f]+$/i.test(sig)) throw new ServiceAuthError('malformed_auth');

  return { keyId, ts: tsNum, sig };
}

// --- Express middleware -----------------------------------------------------

// The JSON body is parsed by express.json before our middleware sees it, so we
// have to capture the raw bytes separately.  This `verify` callback attaches
// them to the request for the signature-check step.
export function captureRawBody(req: Request, _res: Response, buf: Buffer): void {
  // Express calls verify with a Buffer; store a defensive copy so downstream
  // body parsers can't mutate the bytes we'll hash.
  (req as RequestWithRawBody).rawBody = Buffer.from(buf);
}

interface RequestWithRawBody extends Request {
  rawBody?: Buffer;
  callerKeyId?: string;
}

export interface RequireSignedRequestOptions {
  /** keyId → 32-byte hex secret. */
  keys: Record<string, string>;
  windowSeconds?: number;
  /** For tests — inject a clock instead of Date.now(). */
  now?: () => number;
}

/**
 * Express middleware that rejects any request whose Authorization header is
 * missing, malformed, or doesn't verify.  On success the resolved keyId is
 * stored on `req.callerKeyId` for downstream audit logging.
 *
 * MUST be mounted after `express.json({ verify: captureRawBody })` so that
 * `req.rawBody` is populated; without it the body-hash check is impossible.
 */
export function requireSignedRequest(opts: RequireSignedRequestOptions): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = (req as RequestWithRawBody).rawBody ?? Buffer.alloc(0);
      const { keyId } = verifyRequest({
        authorization: req.get('authorization') ?? undefined,
        method: req.method,
        pathAndQuery: req.originalUrl,
        body,
        keys: opts.keys,
        now: opts.now?.(),
        windowSeconds: opts.windowSeconds,
      });
      (req as RequestWithRawBody).callerKeyId = keyId;
      next();
    } catch (err) {
      if (err instanceof ServiceAuthError) {
        res.status(401).json({ error: { code: err.code, message: err.message } });
        return;
      }
      next(err);
    }
  };
}

/** Read the verified caller id from a request that passed requireSignedRequest. */
export function getCallerKeyId(req: Request): string | undefined {
  return (req as RequestWithRawBody).callerKeyId;
}

/**
 * Throws a 500 ApiError if `req.callerKeyId` is missing.  That's an "impossible
 * state" assert — `requireSignedRequest` sets it on every accepted request, so
 * a missing value means middleware order is wrong, not that the caller is
 * unauthenticated.  Handlers call this to collapse the null-check to one line
 * and keep the error code consistent across routes.
 */
export function requireCallerKeyId(req: Request): string {
  const id = getCallerKeyId(req);
  if (!id) throw internal('caller_unidentified', 'callerKeyId missing on signed request');
  return id;
}

// --- Internals --------------------------------------------------------------

function canonical(method: string, pathAndQuery: string, ts: number, body: Buffer): string {
  const bodyHash = createHash('sha256').update(body).digest('hex');
  return `${method.toUpperCase()}\n${pathAndQuery}\n${ts}\n${bodyHash}`;
}

function hmac(secretHex: string, message: string): Buffer {
  return createHmac('sha256', Buffer.from(secretHex, 'hex')).update(message).digest();
}
