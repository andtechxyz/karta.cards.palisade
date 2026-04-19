import { createHmac, timingSafeEqual } from 'node:crypto';

// -----------------------------------------------------------------------------
// Cross-service handoff token.
//
// When tap.karta.cards verifies a SUN URL, it mints a short-lived bearer
// that the next service (activation / pay) accepts without re-running the
// SUN crypto.  Stateless, HMAC-signed, no shared session store.
//
// Format: base64url(JSON(payload)).base64url(hmacSha256(secret, firstPart))
//
// Each service has its own HANDOFF_JWT_KEY in env.  Keys rotate by adding a
// second one to verify against, then retiring the old.  For the prototype we
// keep a single key per process.
// -----------------------------------------------------------------------------

export interface HandoffPayload {
  /** Subject — typically the Card.id.  Opaque to the verifying service. */
  sub: string;
  /** Purpose — e.g. 'activation', 'payment'.  Narrows acceptable next-step. */
  purpose: 'activation' | 'payment' | 'provisioning';
  /** Issued-at, seconds since epoch. */
  iat: number;
  /** Expires-at, seconds since epoch.  Verifier rejects past this. */
  exp: number;
  /** Issuer — which service signed (for audit). */
  iss: string;
  /** Optional extras — opaque to the signer/verifier. */
  ctx?: Record<string, string | number | boolean>;
}

const b64url = (buf: Buffer | Uint8Array): string =>
  Buffer.from(buf).toString('base64url');

const fromB64url = (s: string): Buffer => Buffer.from(s, 'base64url');

export interface SignInput {
  sub: string;
  purpose: HandoffPayload['purpose'];
  iss: string;
  ttlSeconds?: number; // default 30
  ctx?: HandoffPayload['ctx'];
}

export function signHandoff(input: SignInput, secretHex: string): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: HandoffPayload = {
    sub: input.sub,
    purpose: input.purpose,
    iat: now,
    exp: now + (input.ttlSeconds ?? 30),
    iss: input.iss,
    ...(input.ctx ? { ctx: input.ctx } : {}),
  };
  const payloadStr = b64url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const sig = b64url(mac(secretHex, payloadStr));
  return `${payloadStr}.${sig}`;
}

export interface VerifyInput {
  token: string;
  secretHex: string;
  /** Accept only tokens with this purpose.  Refuses otherwise. */
  expectedPurpose: HandoffPayload['purpose'];
  /** Accept only tokens from these issuers, if supplied. */
  allowedIssuers?: string[];
}

export function verifyHandoff(input: VerifyInput): HandoffPayload {
  const parts = input.token.split('.');
  if (parts.length !== 2) throw new HandoffError('malformed_token');
  const [payloadStr, sigStr] = parts as [string, string];

  const expected = mac(input.secretHex, payloadStr);
  const got = fromB64url(sigStr);
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
    throw new HandoffError('bad_signature');
  }

  let payload: HandoffPayload;
  try {
    payload = JSON.parse(fromB64url(payloadStr).toString('utf8')) as HandoffPayload;
  } catch {
    throw new HandoffError('malformed_payload');
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) {
    throw new HandoffError('expired');
  }
  if (payload.purpose !== input.expectedPurpose) {
    throw new HandoffError('wrong_purpose');
  }
  if (input.allowedIssuers && !input.allowedIssuers.includes(payload.iss)) {
    throw new HandoffError('unknown_issuer');
  }
  return payload;
}

export class HandoffError extends Error {
  constructor(
    public readonly code:
      | 'malformed_token'
      | 'malformed_payload'
      | 'bad_signature'
      | 'expired'
      | 'wrong_purpose'
      | 'unknown_issuer',
  ) {
    super(code);
    this.name = 'HandoffError';
  }
}

function mac(secretHex: string, message: string): Buffer {
  return createHmac('sha256', Buffer.from(secretHex, 'hex')).update(message).digest();
}
