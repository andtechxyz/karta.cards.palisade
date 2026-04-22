import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import { ApiError } from '@palisade/core';
import { ServiceAuthError, signRequest, verifyRequest, requireCallerKeyId } from './index.js';

// -----------------------------------------------------------------------------
// Service-to-service HMAC: every failure mode that should keep the vault
// secure.  Each test mutates exactly one input from the happy path so a
// regression pinpoints which binding broke.
// -----------------------------------------------------------------------------

const KEY_A = 'a'.repeat(64);
const KEY_B = 'b'.repeat(64);
const PATH = '/api/vault/store';
const METHOD = 'POST';
const BODY = Buffer.from('{"pan":"4242424242424242"}', 'utf8');
const NOW = 1_700_000_000;

function signed(overrides: { body?: Buffer; method?: string; path?: string; now?: number } = {}): string {
  return signRequest({
    method: overrides.method ?? METHOD,
    pathAndQuery: overrides.path ?? PATH,
    body: overrides.body ?? BODY,
    keyId: 'pay',
    secret: KEY_A,
    now: overrides.now ?? NOW,
  });
}

describe('signRequest / verifyRequest', () => {
  it('round-trips a signed request with matching inputs', () => {
    const auth = signed();
    const result = verifyRequest({
      authorization: auth,
      method: METHOD,
      pathAndQuery: PATH,
      body: BODY,
      keys: { pay: KEY_A },
      now: NOW,
    });
    expect(result.keyId).toBe('pay');
    // Legacy single-secret path → usedSecretIndex is always 0.
    expect(result.usedSecretIndex).toBe(0);
  });

  describe('rotation (array-form keys)', () => {
    // PCI DSS 8.3.6 / CPL LSR 2 — HMAC key rotation with a grace
    // window where both the new and old secrets verify.  The verifier
    // surfaces usedSecretIndex so operators can observe when all
    // in-flight traffic has migrated to the new secret.

    it('accepts a new-secret signature against a [new, old] array', () => {
      // Caller already signed with the new secret.
      const authNew = signRequest({
        method: METHOD, pathAndQuery: PATH, body: BODY,
        keyId: 'pay', secret: KEY_A, now: NOW,
      });
      const result = verifyRequest({
        authorization: authNew,
        method: METHOD, pathAndQuery: PATH, body: BODY,
        keys: { pay: [KEY_A, KEY_B] },
        now: NOW,
      });
      expect(result.keyId).toBe('pay');
      expect(result.usedSecretIndex).toBe(0);
    });

    it('accepts a stragglers-signed-by-old signature during the grace window', () => {
      // Caller not yet rotated — still signing with the old secret.
      const authOld = signRequest({
        method: METHOD, pathAndQuery: PATH, body: BODY,
        keyId: 'pay', secret: KEY_B, now: NOW,
      });
      const result = verifyRequest({
        authorization: authOld,
        method: METHOD, pathAndQuery: PATH, body: BODY,
        keys: { pay: [KEY_A, KEY_B] },
        now: NOW,
      });
      expect(result.keyId).toBe('pay');
      // usedSecretIndex=1 tells operators "there's still traffic
      // signed by the old secret — don't retire it yet".
      expect(result.usedSecretIndex).toBe(1);
    });

    it('rejects a signature signed by a retired secret no longer in the array', () => {
      const KEY_C = 'c'.repeat(64);
      const authRetired = signRequest({
        method: METHOD, pathAndQuery: PATH, body: BODY,
        keyId: 'pay', secret: KEY_C, now: NOW,
      });
      expect(() =>
        verifyRequest({
          authorization: authRetired,
          method: METHOD, pathAndQuery: PATH, body: BODY,
          keys: { pay: [KEY_A, KEY_B] },
          now: NOW,
        }),
      ).toThrowError(expect.objectContaining({ code: 'bad_signature' }));
    });

    it('rejects when the array is empty', () => {
      const auth = signed();
      expect(() =>
        verifyRequest({
          authorization: auth,
          method: METHOD, pathAndQuery: PATH, body: BODY,
          keys: { pay: [] },
          now: NOW,
        }),
      ).toThrowError(expect.objectContaining({ code: 'unknown_key' }));
    });

    it('rejects an unknown keyId even when the map has rotation arrays', () => {
      const auth = signRequest({
        method: METHOD, pathAndQuery: PATH, body: BODY,
        keyId: 'someone-else', secret: KEY_A, now: NOW,
      });
      expect(() =>
        verifyRequest({
          authorization: auth,
          method: METHOD, pathAndQuery: PATH, body: BODY,
          keys: { pay: [KEY_A, KEY_B] },
          now: NOW,
        }),
      ).toThrowError(expect.objectContaining({ code: 'unknown_key' }));
    });
  });

  it('rejects a missing Authorization header', () => {
    expect(() =>
      verifyRequest({
        authorization: undefined,
        method: METHOD,
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
      }),
    ).toThrowError(expect.objectContaining({ code: 'missing_auth' }));
  });

  it.each([
    ['wrong scheme', 'Bearer keyId=pay,ts=1,sig=aa'],
    ['no rest', 'VeraHmac'],
    ['no keyId', 'VeraHmac ts=1,sig=aa'],
    ['no ts', 'VeraHmac keyId=pay,sig=aa'],
    ['no sig', 'VeraHmac keyId=pay,ts=1'],
    ['non-numeric ts', 'VeraHmac keyId=pay,ts=abc,sig=aa'],
    ['non-hex sig', 'VeraHmac keyId=pay,ts=1,sig=zz'],
  ])('rejects malformed header: %s', (_label, header) => {
    expect(() =>
      verifyRequest({
        authorization: header,
        method: METHOD,
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
      }),
    ).toThrowError(expect.objectContaining({ code: 'malformed_auth' }));
  });

  it('rejects when keyId is unknown to the server', () => {
    const auth = signRequest({
      method: METHOD,
      pathAndQuery: PATH,
      body: BODY,
      keyId: 'someone-else',
      secret: KEY_A,
      now: NOW,
    });
    expect(() =>
      verifyRequest({
        authorization: auth,
        method: METHOD,
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
      }),
    ).toThrowError(expect.objectContaining({ code: 'unknown_key' }));
  });

  it('rejects a tampered method (GET signature replayed as POST)', () => {
    const auth = signed({ method: 'GET' });
    expect(() =>
      verifyRequest({
        authorization: auth,
        method: 'POST',
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
      }),
    ).toThrowError(expect.objectContaining({ code: 'bad_signature' }));
  });

  it('rejects a tampered path (signed against /store, sent to /retrieve)', () => {
    const auth = signed({ path: '/api/vault/store' });
    expect(() =>
      verifyRequest({
        authorization: auth,
        method: METHOD,
        pathAndQuery: '/api/vault/retrieve',
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
      }),
    ).toThrowError(expect.objectContaining({ code: 'bad_signature' }));
  });

  it('rejects a tampered body (amount swap after signing)', () => {
    const auth = signed({ body: Buffer.from('{"amount":100}') });
    expect(() =>
      verifyRequest({
        authorization: auth,
        method: METHOD,
        pathAndQuery: PATH,
        body: Buffer.from('{"amount":1000000}'),
        keys: { pay: KEY_A },
        now: NOW,
      }),
    ).toThrowError(expect.objectContaining({ code: 'bad_signature' }));
  });

  it('rejects a timestamp older than the replay window', () => {
    const auth = signed({ now: NOW - 3600 });
    expect(() =>
      verifyRequest({
        authorization: auth,
        method: METHOD,
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
        windowSeconds: 60,
      }),
    ).toThrowError(expect.objectContaining({ code: 'clock_skew' }));
  });

  it('rejects a timestamp too far in the future (skewed signer clock)', () => {
    const auth = signed({ now: NOW + 3600 });
    expect(() =>
      verifyRequest({
        authorization: auth,
        method: METHOD,
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
        windowSeconds: 60,
      }),
    ).toThrowError(expect.objectContaining({ code: 'clock_skew' }));
  });

  it('rejects a signature made with the wrong secret for the right keyId', () => {
    // Signer thinks "pay" maps to KEY_A; server maps "pay" to KEY_B.
    const auth = signRequest({
      method: METHOD,
      pathAndQuery: PATH,
      body: BODY,
      keyId: 'pay',
      secret: KEY_A,
      now: NOW,
    });
    expect(() =>
      verifyRequest({
        authorization: auth,
        method: METHOD,
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_B },
        now: NOW,
      }),
    ).toThrowError(expect.objectContaining({ code: 'bad_signature' }));
  });

  it('supports multiple active keys for rotation (both keyIds verify)', () => {
    const authPay = signRequest({
      method: METHOD,
      pathAndQuery: PATH,
      body: BODY,
      keyId: 'pay',
      secret: KEY_A,
      now: NOW,
    });
    const authAct = signRequest({
      method: METHOD,
      pathAndQuery: PATH,
      body: BODY,
      keyId: 'activation',
      secret: KEY_B,
      now: NOW,
    });
    const keys = { pay: KEY_A, activation: KEY_B };
    expect(
      verifyRequest({ authorization: authPay, method: METHOD, pathAndQuery: PATH, body: BODY, keys, now: NOW }).keyId,
    ).toBe('pay');
    expect(
      verifyRequest({ authorization: authAct, method: METHOD, pathAndQuery: PATH, body: BODY, keys, now: NOW }).keyId,
    ).toBe('activation');
  });

  it('accepts an empty body (GET) when signer and verifier both see empty', () => {
    const auth = signRequest({
      method: 'GET',
      pathAndQuery: '/api/health',
      body: Buffer.alloc(0),
      keyId: 'pay',
      secret: KEY_A,
      now: NOW,
    });
    expect(
      verifyRequest({
        authorization: auth,
        method: 'GET',
        pathAndQuery: '/api/health',
        body: Buffer.alloc(0),
        keys: { pay: KEY_A },
        now: NOW,
      }).keyId,
    ).toBe('pay');
  });

  it('is case-insensitive on HTTP method (GET vs get both sign the same)', () => {
    const auth = signRequest({
      method: 'get',
      pathAndQuery: PATH,
      body: BODY,
      keyId: 'pay',
      secret: KEY_A,
      now: NOW,
    });
    expect(
      verifyRequest({
        authorization: auth,
        method: 'GET',
        pathAndQuery: PATH,
        body: BODY,
        keys: { pay: KEY_A },
        now: NOW,
      }).keyId,
    ).toBe('pay');
  });

  it('exposes typed error codes on ServiceAuthError', () => {
    try {
      verifyRequest({
        authorization: undefined,
        method: METHOD,
        pathAndQuery: PATH,
        body: BODY,
        keys: {},
        now: NOW,
      });
      throw new Error('should not reach');
    } catch (err) {
      expect(err).toBeInstanceOf(ServiceAuthError);
      expect((err as ServiceAuthError).code).toBe('missing_auth');
    }
  });
});

describe('requireCallerKeyId', () => {
  it('returns the callerKeyId when set by the middleware', () => {
    const req = { callerKeyId: 'pay' } as unknown as Request;
    expect(requireCallerKeyId(req)).toBe('pay');
  });

  it('throws a 500 ApiError with code caller_unidentified when missing', () => {
    const req = {} as Request;
    expect(() => requireCallerKeyId(req)).toThrowError(ApiError);
    try {
      requireCallerKeyId(req);
    } catch (err) {
      // Has to be ApiError so @palisade/core's errorMiddleware serialises it as
      // {error:{code,message}} rather than collapsing to "internal_error".
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(500);
      expect((err as ApiError).code).toBe('caller_unidentified');
    }
  });
});
