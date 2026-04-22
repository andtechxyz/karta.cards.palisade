import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { RequestHandler, Request, Response, NextFunction } from 'express';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CognitoUser {
  /** Cognito user pool subject (UUID). */
  sub: string;
  /** Email claim — present if the user pool includes it. */
  email?: string;
  /** Cognito groups the user belongs to (from `cognito:groups` claim). */
  groups: string[];
}

export interface CognitoAuthConfig {
  /** Cognito User Pool ID, e.g. "ap-southeast-2_Db4d1vpIV". */
  userPoolId: string;
  /** App client ID used as the JWT audience. */
  clientId: string;
  /** AWS region — defaults to the region prefix of userPoolId. */
  region?: string;
  /**
   * If set, the user must be a member of this Cognito group.  Rejects with
   * 403 if the group claim is missing or does not include this value.
   */
  requiredGroup?: string;
  /**
   * If set, the user's `email` claim must appear in this list (case-insensitive).
   * An empty array is treated as "allow nobody" — the caller MUST NOT pass `[]`
   * if they intend to allow everyone; omit the field entirely in that case.
   * Rejects with 403 when the email is missing or not on the list.
   *
   * Used for admin-operated endpoints where group membership alone is too
   * coarse (e.g. card-ops needs a tighter breakglass set than the general
   * `admin` group).  Pair with `requiredGroup` for defence in depth.
   */
  emailAllowlist?: readonly string[];
}

// ---------------------------------------------------------------------------
// Augment Express Request so downstream handlers see `req.cognitoUser`.
// ---------------------------------------------------------------------------

declare global {
  namespace Express {
    interface Request {
      cognitoUser?: CognitoUser;
    }
  }
}

// ---------------------------------------------------------------------------
// Pure verifier (transport-agnostic) — used by Express middleware below
// AND by the card-ops WS upgrade handler (no req/res context there).
// ---------------------------------------------------------------------------

/**
 * Outcome of `verifyCognitoToken`.  `ok=false` carries an error code +
 * message that the caller can map to whatever response shape it needs
 * (HTTP 401/403, WS close code, etc.).
 */
export type VerifyResult =
  | { ok: true; user: CognitoUser }
  | { ok: false; status: 401 | 403; code: string; message: string };

/**
 * Build a reusable verifier from a CognitoAuthConfig.  The returned
 * function takes a raw JWT string and returns a VerifyResult — no HTTP
 * coupling.  JWKS is fetched + cached lazily on first call (via the
 * `jose` `createRemoteJWKSet` cache).
 *
 * Validates: signature (RS256), expiry, issuer, token_use → audience/
 * client_id, optional group membership, optional email allowlist.
 *
 * Accepts both Cognito ID tokens (`aud=clientId`) and access tokens
 * (`client_id=clientId`).  See createCognitoAuthMiddleware below for
 * the rationale.
 */
export function createCognitoTokenVerifier(
  config: CognitoAuthConfig,
): (token: string) => Promise<VerifyResult> {
  const region = config.region ?? config.userPoolId.split('_')[0];
  const issuer = `https://cognito-idp.${region}.amazonaws.com/${config.userPoolId}`;
  const jwksUrl = new URL(`${issuer}/.well-known/jwks.json`);
  const jwks = createRemoteJWKSet(jwksUrl);

  return async (token: string): Promise<VerifyResult> => {
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        algorithms: ['RS256'],
      });

      const tokenUse = payload['token_use'];
      if (tokenUse === 'access') {
        if (payload['client_id'] !== config.clientId) {
          return {
            ok: false,
            status: 401,
            code: 'invalid_token',
            message: `"client_id" claim mismatch: got ${String(payload['client_id'])}, expected ${config.clientId}`,
          };
        }
      } else if (tokenUse === 'id') {
        if (payload.aud !== config.clientId) {
          return {
            ok: false,
            status: 401,
            code: 'invalid_token',
            message: `"aud" claim mismatch: got ${String(payload.aud)}, expected ${config.clientId}`,
          };
        }
      } else {
        return {
          ok: false,
          status: 401,
          code: 'invalid_token',
          message: `unsupported "token_use": ${String(tokenUse)} (expected "access" or "id")`,
        };
      }

      const user = extractUser(payload);

      if (config.requiredGroup && !user.groups.includes(config.requiredGroup)) {
        return {
          ok: false,
          status: 403,
          code: 'forbidden',
          message: `Requires membership in '${config.requiredGroup}' group`,
        };
      }

      if (config.emailAllowlist) {
        const email = user.email?.toLowerCase();
        const list = config.emailAllowlist.map((e) => e.toLowerCase());
        if (!email || !list.includes(email)) {
          return {
            ok: false,
            status: 403,
            code: 'forbidden',
            message: 'Email not on admin allowlist',
          };
        }
      }

      return { ok: true, user };
    } catch (err) {
      return {
        ok: false,
        status: 401,
        code: 'invalid_token',
        message: err instanceof Error ? err.message : 'Token verification failed',
      };
    }
  };
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Creates Express middleware that verifies AWS Cognito JWTs.
 *
 * - Reads `Authorization: Bearer <token>` from the request.
 * - Fetches the JWKS from the Cognito well-known endpoint (cached by `jose`).
 * - Validates signature, expiry, issuer, and audience/client_id.
 * - On success: populates `req.cognitoUser` and calls `next()`.
 * - On failure: responds with a 401 JSON error.
 *
 * Implementation now thin-wraps the pure `createCognitoTokenVerifier`.
 */
export function createCognitoAuthMiddleware(config: CognitoAuthConfig): RequestHandler {
  const verify = createCognitoTokenVerifier(config);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      res.status(401).json({ error: 'missing_token', message: 'Authorization Bearer token required' });
      return;
    }

    const result = await verify(auth.slice(7));
    if (!result.ok) {
      res.status(result.status).json({ error: result.code, message: result.message });
      return;
    }

    req.cognitoUser = result.user;
    next();
  };
}

// ---------------------------------------------------------------------------
// Convenience — use env defaults
// ---------------------------------------------------------------------------

/**
 * Convenience wrapper that pulls config from env vars.  Primary entry point
 * for services that only need the default Karta Cognito pool:
 *
 *   app.use('/api/mine', requireCognitoAuth(), handler);
 *
 * Env vars:
 *   COGNITO_USER_POOL_ID   (default 'ap-southeast-2_Db4d1vpIV')
 *   COGNITO_CLIENT_ID      (default '7pj9230obhsa6h6vrvk9tru7do')
 *   COGNITO_REGION         (default derived from pool ID prefix)
 */
export function requireCognitoAuth(
  overrides?: Partial<CognitoAuthConfig>,
): RequestHandler {
  const userPoolId =
    overrides?.userPoolId ??
    process.env.COGNITO_USER_POOL_ID ??
    'ap-southeast-2_Db4d1vpIV';
  const clientId =
    overrides?.clientId ??
    process.env.COGNITO_CLIENT_ID ??
    '7pj9230obhsa6h6vrvk9tru7do';
  const region =
    overrides?.region ??
    process.env.COGNITO_REGION ??
    userPoolId.split('_')[0] ??
    'ap-southeast-2';

  return createCognitoAuthMiddleware({
    userPoolId,
    clientId,
    region,
    ...(overrides?.requiredGroup ? { requiredGroup: overrides.requiredGroup } : {}),
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractUser(payload: JWTPayload): CognitoUser {
  const rawGroups = payload['cognito:groups'];
  const groups = Array.isArray(rawGroups)
    ? rawGroups.filter((g): g is string => typeof g === 'string')
    : [];

  return {
    sub: payload.sub ?? '',
    email: typeof payload.email === 'string' ? payload.email : undefined,
    groups,
  };
}
