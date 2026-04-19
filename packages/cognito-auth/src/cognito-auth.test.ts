import { vi, describe, it, expect, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

// ---------------------------------------------------------------------------
// Mock jose — intercept JWKS fetching and JWT verification so we never hit
// the network and can control every success/failure path.
// ---------------------------------------------------------------------------

vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn().mockReturnValue(vi.fn()),
  jwtVerify: vi.fn(),
}));

import { jwtVerify } from 'jose';
import { createCognitoAuthMiddleware } from './index.js';

// ---------------------------------------------------------------------------
// Helpers — lightweight Express req/res/next stubs, same shape as
// require-admin-key.test.ts.
// ---------------------------------------------------------------------------

const mockReq = (headers: Record<string, string> = {}) => ({
  get: (h: string) => headers[h.toLowerCase()],
  headers,
  cognitoUser: undefined,
} as unknown as Request);

const mockRes = () => {
  const res = { status: vi.fn().mockReturnThis(), json: vi.fn() } as unknown as Response;
  return res;
};

const mockNext = () => vi.fn() as NextFunction;

// ---------------------------------------------------------------------------
// Factory config — region is derived from the pool ID prefix.
// ---------------------------------------------------------------------------

const CONFIG = {
  userPoolId: 'ap-southeast-2_Db4d1vpIV',
  clientId: '7pj9230obhsa6h6vrvk9tru7do',
};

const middleware = createCognitoAuthMiddleware(CONFIG);

beforeEach(() => {
  vi.mocked(jwtVerify).mockReset();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createCognitoAuthMiddleware', () => {
  it('401 missing_token when Authorization header is absent', async () => {
    const req = mockReq({});
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'missing_token' }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('401 missing_token when Authorization header uses wrong scheme', async () => {
    const req = mockReq({ authorization: 'Basic dXNlcjpwYXNz' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'missing_token' }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('sets req.cognitoUser and calls next() on valid JWT', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: { sub: 'user-uuid-123', email: 'test@example.com', token_use: 'id', aud: '7pj9230obhsa6h6vrvk9tru7do' },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer valid.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.cognitoUser).toEqual({
      sub: 'user-uuid-123',
      email: 'test@example.com',
      groups: [],
    });
    expect(res.status).not.toHaveBeenCalled();
  });

  it('sets sub to empty string when payload.sub is missing', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: { email: 'test@example.com', token_use: 'id', aud: '7pj9230obhsa6h6vrvk9tru7do' },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer valid.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.cognitoUser).toEqual({
      sub: '',
      email: 'test@example.com',
      groups: [],
    });
  });

  it('omits email when payload has no email claim', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: { sub: 'user-uuid-456', token_use: 'id', aud: '7pj9230obhsa6h6vrvk9tru7do' },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer valid.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.cognitoUser).toEqual({
      sub: 'user-uuid-456',
      email: undefined,
      groups: [],
    });
  });

  it('extracts cognito:groups claim when present', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: {
        sub: 'user-uuid',
        'cognito:groups': ['admin', 'developers'],
        token_use: 'id',
        aud: '7pj9230obhsa6h6vrvk9tru7do',
      },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer valid.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.cognitoUser?.groups).toEqual(['admin', 'developers']);
  });

  it('403 forbidden when requiredGroup not in user groups', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: {
        sub: 'user-uuid',
        'cognito:groups': ['developers'],
        token_use: 'id',
        aud: 'test-client-id',
      },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const gatedMiddleware = createCognitoAuthMiddleware({
      userPoolId: 'ap-southeast-2_TestPool',
      clientId: 'test-client-id',
      requiredGroup: 'admin',
    });

    const req = mockReq({ authorization: 'Bearer valid.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await gatedMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'forbidden' }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('allows when user is in requiredGroup', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: {
        sub: 'user-uuid',
        'cognito:groups': ['admin'],
        token_use: 'id',
        aud: 'test-client-id',
      },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const gatedMiddleware = createCognitoAuthMiddleware({
      userPoolId: 'ap-southeast-2_TestPool',
      clientId: 'test-client-id',
      requiredGroup: 'admin',
    });

    const req = mockReq({ authorization: 'Bearer valid.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await gatedMiddleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('401 invalid_token when JWT is expired', async () => {
    vi.mocked(jwtVerify).mockRejectedValue(
      new Error('"exp" claim timestamp check failed'),
    );

    const req = mockReq({ authorization: 'Bearer expired.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_token',
        message: expect.stringContaining('exp'),
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('401 invalid_token when issuer does not match', async () => {
    vi.mocked(jwtVerify).mockRejectedValue(
      new Error('"iss" claim mismatch'),
    );

    const req = mockReq({ authorization: 'Bearer wrong-issuer.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_token',
        message: expect.stringContaining('iss'),
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('401 invalid_token when audience does not match', async () => {
    vi.mocked(jwtVerify).mockRejectedValue(
      new Error('"aud" claim mismatch'),
    );

    const req = mockReq({ authorization: 'Bearer wrong-aud.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_token',
        message: expect.stringContaining('aud'),
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('401 invalid_token when jwtVerify throws a non-Error', async () => {
    vi.mocked(jwtVerify).mockRejectedValue('unexpected string error');

    const req = mockReq({ authorization: 'Bearer bad.jwt.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_token',
        message: 'Token verification failed',
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('passes correct issuer and audience to jwtVerify', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: { sub: 'user-1', token_use: 'id', aud: '7pj9230obhsa6h6vrvk9tru7do' },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer check.options.token' });
    const res = mockRes();
    const next = mockNext();

    await middleware(req, res, next);

    // We verify signature + issuer with `jose` and check audience/client_id
    // ourselves (depending on token_use), so the only option passed in is
    // the issuer.
    expect(jwtVerify).toHaveBeenCalledWith(
      'check.options.token',
      expect.any(Function), // JWKS function
      {
        issuer: `https://cognito-idp.ap-southeast-2.amazonaws.com/${CONFIG.userPoolId}`,
      },
    );
  });

  it('accepts an access token (no aud, has client_id + token_use=access)', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: {
        sub: 'user-uuid-access',
        token_use: 'access',
        client_id: CONFIG.clientId,
        scope: 'aws.cognito.signin.user.admin',
      },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer access.token' });
    const res = mockRes();
    const next = mockNext();
    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.cognitoUser?.sub).toBe('user-uuid-access');
    expect(res.status).not.toHaveBeenCalled();
  });

  it('rejects an access token whose client_id does not match', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: {
        sub: 'user-uuid',
        token_use: 'access',
        client_id: 'wrong-client-id',
      },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer access.token' });
    const res = mockRes();
    const next = mockNext();
    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_token',
        message: expect.stringContaining('client_id'),
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects an ID token whose aud does not match', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: { sub: 'user-uuid', token_use: 'id', aud: 'wrong-aud' },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer id.token' });
    const res = mockRes();
    const next = mockNext();
    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_token',
        message: expect.stringContaining('aud'),
      }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects a token without a token_use claim', async () => {
    vi.mocked(jwtVerify).mockResolvedValue({
      payload: { sub: 'user-uuid' },
      protectedHeader: { alg: 'RS256' },
      key: {} as any,
    } as any);

    const req = mockReq({ authorization: 'Bearer no-token-use.token' });
    const res = mockRes();
    const next = mockNext();
    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'invalid_token',
        message: expect.stringContaining('token_use'),
      }),
    );
  });
});
