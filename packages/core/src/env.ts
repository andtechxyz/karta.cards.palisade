import { config as loadDotenv } from 'dotenv';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { z, type ZodRawShape, type ZodObject } from 'zod';

// -----------------------------------------------------------------------------
// .env loading.
//
// Each service runs from its own workspace dir (cwd = services/<name>), but
// the `.env` lives at the monorepo root.  Walk up from cwd until we find the
// nearest `.env` and load it.  If none is found, fall through silently — zod
// validation below will raise a clear error listing the missing keys.
// -----------------------------------------------------------------------------
function findEnvFile(startDir: string): string | undefined {
  let dir = startDir;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const candidate = join(dir, '.env');
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

const envPath = findEnvFile(process.cwd());
if (envPath) loadDotenv({ path: envPath });

// -----------------------------------------------------------------------------
// Shared env schema fragments.
//
// Each service extends `baseEnv` with its own fields via `defineEnv(extraShape)`.
// RP-ID is `karta.cards` (the apex) so credentials minted on any subdomain are
// usable across the whole ecosystem.  `WEBAUTHN_ORIGINS` is a comma-separated
// list of full origins allowed in clientDataJSON verification.
// -----------------------------------------------------------------------------

/** Zod schema for a fixed-length hex string (`bytes` bytes = `bytes*2` chars). */
export const hexKey = (bytes: number) =>
  z
    .string()
    .length(bytes * 2, `expected ${bytes} bytes (${bytes * 2} hex chars)`)
    .regex(/^[0-9a-fA-F]+$/);

/** Comma-separated list of URLs → string[] after trim + filter. */
export const originList = z
  .string()
  .min(1)
  .transform((s) =>
    s
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean),
  )
  .pipe(z.array(z.string().url()).min(1));

export const baseEnvShape = {
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  DATABASE_URL: z.string().url(),
} as const;

// -----------------------------------------------------------------------------
// Cryptographic key env shapes — split by purpose.
//
// PCI-DSS 3.5/3.6 require keys to be scoped to their protected data.  The
// vault PAN keyspace (Vera-side) and the card-field (UID + SDM) keyspace
// cover different fields protected by different services; they MUST NOT
// share a root.  Each shape below is spread into only the services that
// legitimately need it:
//
//   vaultPanCryptoEnvShape     → vault service only
//   cardFieldCryptoEnvShape    → activation (write) + tap (read)
//
// The UID dedup fingerprint (activation-only) is declared inline in
// activation's env shape — no shared fragment, because nothing else uses it.
// -----------------------------------------------------------------------------

/** DEK + fingerprint for PAN encryption (vault service only). */
export const vaultPanCryptoEnvShape = {
  VAULT_PAN_DEK_V1: hexKey(32),
  VAULT_PAN_DEK_ACTIVE_VERSION: z.coerce.number().int().positive().default(1),
  VAULT_PAN_FINGERPRINT_KEY: hexKey(32),
} as const;

/** DEK for Card.uid + SDM read keys (activation writes, tap reads). */
export const cardFieldCryptoEnvShape = {
  CARD_FIELD_DEK_V1: hexKey(32),
  CARD_FIELD_DEK_ACTIVE_VERSION: z.coerce.number().int().positive().default(1),
} as const;

// -----------------------------------------------------------------------------
// Service-to-service auth env shapes.
//
// Any service that accepts inbound HMAC-signed requests holds a JSON-encoded
// map of caller keyId → 32-byte hex secret.  The vault uses SERVICE_AUTH_KEYS,
// activation uses PROVISION_AUTH_KEYS for its provisioning endpoint.  Each
// caller holds its own single client secret under a service-specific variable
// name declared in its own env.ts.
// -----------------------------------------------------------------------------

/**
 * Zod schema for a JSON-encoded `{ keyId: hexSecret }` map.  Reused by every
 * service that verifies inbound HMAC-signed requests — each service binds it
 * to its own env-var name.
 */
export const authKeysJson = z
  .string()
  .min(1)
  .transform((raw, ctx): Record<string, string> => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'value must be a JSON object mapping keyId to hex secret',
      });
      return z.NEVER;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'value must be a JSON object',
      });
      return z.NEVER;
    }
    const out: Record<string, string> = {};
    for (const [id, val] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof val !== 'string' || !/^[0-9a-fA-F]{64}$/.test(val)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `key "${id}" must be 32-byte hex (64 chars)`,
        });
        return z.NEVER;
      }
      out[id] = val;
    }
    if (Object.keys(out).length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'must declare at least one caller',
      });
      return z.NEVER;
    }
    return out;
  });

/** Vault's inbound auth shape — binds `authKeysJson` to `SERVICE_AUTH_KEYS`. */
export const serviceAuthServerEnvShape = {
  SERVICE_AUTH_KEYS: authKeysJson,
} as const;

/**
 * Build a process-wide config loader from a zod shape.  Caches the parsed
 * result; exposes `_reset()` for tests.
 */
export function defineEnv<Shape extends ZodRawShape>(shape: Shape) {
  const schema: ZodObject<Shape> = z.object(shape);
  type Env = z.infer<typeof schema>;
  let cached: Env | null = null;

  function get(): Env {
    if (cached) return cached;
    const parsed = schema.safeParse(process.env);
    if (!parsed.success) {
      const msg = parsed.error.issues
        .map((i) => `  ${i.path.join('.')}: ${i.message}`)
        .join('\n');
      throw new Error(`Invalid environment configuration:\n${msg}`);
    }
    cached = parsed.data;
    return cached;
  }

  function reset(): void {
    cached = null;
  }

  return { get, reset, schema };
}

