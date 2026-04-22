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
// vault PAN keyspace (Vera-side) and the card-field (UID) keyspace cover
// different fields protected by different services; they MUST NOT share a
// root.  Each shape below is spread into only the services that legitimately
// need it:
//
//   vaultPanCryptoEnvShape     → vault service only
//   cardFieldCryptoEnvShape    → activation (write) + tap (read)
//   sdmKeyDerivationEnvShape   → tap (primary) + activation (karta-url CMAC)
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

/** DEK for Card.uid (activation writes, tap reads). */
export const cardFieldCryptoEnvShape = {
  CARD_FIELD_DEK_V1: hexKey(32),
  CARD_FIELD_DEK_ACTIVE_VERSION: z.coerce.number().int().positive().default(1),
} as const;

/**
 * SDM key-derivation backend selection.  The two AES-128 SDM keys (metaRead,
 * fileRead) are NEVER stored at rest; they are derived on every tap from the
 * card UID via AES-CMAC(MASTER_<role>, UID) (NXP AN12196 / AN14683).
 *
 * Used by tap (primary — derives on every SUN verify) and activation (for the
 * karta-url CMAC baked into the begin-activation assertion payload).
 *
 *   hsm    — AWS Payment Cryptography GenerateMac(CMAC).  Prod.
 *   local  — Node crypto AES-CMAC, masters HKDF'd from DEV_SDM_ROOT_SEED.  Dev.
 *   mock   — sha256 stand-ins.  Unit tests only.
 */
export const sdmKeyDerivationEnvShape = {
  SDM_KEY_BACKEND: z.enum(['hsm', 'local', 'mock']).default('hsm'),
  SDM_META_MASTER_KEY_ARN: z.string().default(''),
  SDM_FILE_MASTER_KEY_ARN: z.string().default(''),
  DEV_SDM_ROOT_SEED: z.string().default(''),
  AWS_REGION: z.string().default('ap-southeast-2'),
} as const;

/**
 * Validate a resolved env against `sdmKeyDerivationEnvShape`.  Call once per
 * process from the deriver factory — throws with a clear message if the
 * selected backend's required inputs are missing.
 */
export function assertSdmEnv(cfg: {
  SDM_KEY_BACKEND: 'hsm' | 'local' | 'mock';
  SDM_META_MASTER_KEY_ARN: string;
  SDM_FILE_MASTER_KEY_ARN: string;
  DEV_SDM_ROOT_SEED: string;
}): void {
  if (cfg.SDM_KEY_BACKEND === 'hsm') {
    if (!cfg.SDM_META_MASTER_KEY_ARN || !cfg.SDM_FILE_MASTER_KEY_ARN) {
      throw new Error(
        "SDM_KEY_BACKEND='hsm' requires SDM_META_MASTER_KEY_ARN and " +
          'SDM_FILE_MASTER_KEY_ARN to be set to the ARNs of the two AES-128 ' +
          'CMAC keys in AWS Payment Cryptography.',
      );
    }
  } else if (cfg.SDM_KEY_BACKEND === 'local') {
    if (!/^[0-9a-fA-F]{64}$/.test(cfg.DEV_SDM_ROOT_SEED)) {
      throw new Error(
        "SDM_KEY_BACKEND='local' requires DEV_SDM_ROOT_SEED to be a 32-byte " +
          'hex string (64 hex chars).',
      );
    }
  }
}

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

// -----------------------------------------------------------------------------
// Production env hardening.
//
// Some env vars have dev-friendly fallbacks baked into their zod schema — HSM
// ARNs default to '', localhost service URLs keep `pnpm dev` unblocked, HMAC
// secrets fall back to 64 zero chars, etc.  Those defaults are fine for local
// and tests but dangerous in production: SAD decryption falling back to an
// AES-128-ECB stub, WS URLs handed to the phone pointing at the inbound host
// (which breaks behind CloudFront), callbacks signed with an all-zero key a
// determined attacker could guess without the secret ever leaking.
//
// `assertProdRequiredEnv` is the single gate every service uses to promote
// those dev fallbacks into hard-required values in production.  Operator
// intent: the only way to stand up prod without these values set is to rip
// the assertion out of the code — no "just set NODE_ENV=development" escape.
//
// In dev/test it emits a one-line warning per fallback-active field so the
// operator can see which knobs are unsafe without blocking startup.
// -----------------------------------------------------------------------------

/**
 * One field the caller wants prod-checked.  Keep the shape minimal so
 * services can build the list inline at the getConfig boundary.
 */
export interface ProdRequiredField {
  /** Env var name as shown to the operator in error/warning output. */
  name: string;
  /**
   * Resolved value from the parsed env config (already passed through zod).
   * `undefined` or empty string means the field is effectively unset.
   */
  value: string | undefined;
  /**
   * The dev fallback the zod schema filled in when the env var wasn't
   * provided.  Used to detect "is this the default value?" — if it is,
   * the field is implicitly unsafe in prod.  Pass `undefined` for fields
   * declared `.optional()` (i.e. no default at all).
   */
  devFallback?: string;
  /**
   * Additional concrete string values that should be treated as "using
   * the dev fallback" even though they aren't the zod default.  Some
   * env vars have in-band sentinels meaning "no real value" that arose
   * because Secrets Manager refuses zero-length strings — e.g.
   * KMS_SAD_KEY_ARN accepts '', 'none', 'dev' as "no KMS, use AES stub"
   * (see commit cde5f8d).  Naming all three here makes the prod gate
   * catch a literal "none" secret in production, not just empty string.
   */
  fallbackSentinels?: readonly string[];
  /**
   * Human-readable one-line explanation of what this var is for and where
   * it should come from in prod (Secrets Manager path, task-def override,
   * etc.).  Included in the startup error so the fix is obvious.
   */
  description: string;
  /**
   * When true, also treat hostnames 'localhost', '127.0.0.1', and '0.0.0.0'
   * as invalid in production even if the value isn't equal to the declared
   * devFallback.  Prevents the "operator pasted the local URL into a secret"
   * foot-gun.  Only meaningful for URL-shaped fields.
   */
  rejectLocalhostInProd?: boolean;
}

const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0']);

function isUsingFallback(f: ProdRequiredField): boolean {
  if (f.value === undefined || f.value === '') return true;
  if (f.devFallback !== undefined && f.value === f.devFallback) return true;
  if (f.fallbackSentinels?.includes(f.value)) return true;
  return false;
}

function isLocalhostUrl(value: string): boolean {
  try {
    const host = new URL(value).hostname;
    return LOCALHOST_HOSTS.has(host);
  } catch {
    // Not a URL — leave to the zod schema, which already validated shape
    // for any field declared as z.string().url().  Non-URL values never
    // trigger the localhost check.
    return false;
  }
}

/**
 * Validate a subset of env fields against production-only requirements.
 * Must be called after the zod config parse succeeds — `value` is the
 * already-resolved config.<field> string, not raw process.env.
 *
 * Behaviour:
 *   - `nodeEnv === 'production'` and any field is using its fallback or a
 *     localhost URL → throws, listing every offending field at once so
 *     operators don't have to redeploy four times to chase them down.
 *   - anything else → prints a warning to stderr per offending field,
 *     tagged `[env]`, and returns normally.  Warnings fire only once per
 *     process (caller is expected to call this from a cached getConfig).
 */
export function assertProdRequiredEnv(
  nodeEnv: string,
  fields: ProdRequiredField[],
): void {
  const prodFailures: string[] = [];
  const devWarnings: string[] = [];

  for (const f of fields) {
    const usingFallback = isUsingFallback(f);
    const localhostInProd =
      nodeEnv === 'production' &&
      f.rejectLocalhostInProd === true &&
      typeof f.value === 'string' &&
      isLocalhostUrl(f.value);

    if (!usingFallback && !localhostInProd) continue;

    if (nodeEnv === 'production') {
      const reason = usingFallback
        ? 'using dev fallback / unset'
        : 'hostname is localhost/loopback';
      prodFailures.push(`  ${f.name} (${reason}) — ${f.description}`);
    } else {
      const shown = f.value === undefined || f.value === ''
        ? '<unset>'
        : f.value;
      devWarnings.push(
        `[env] ${f.name} = ${shown} (dev fallback active) — ${f.description}`,
      );
    }
  }

  if (prodFailures.length > 0) {
    throw new Error(
      'Production environment is missing required configuration.\n' +
        'These values MUST be set via ECS task definition / Secrets ' +
        'Manager before startup:\n' +
        prodFailures.join('\n'),
    );
  }

  for (const w of devWarnings) {
    // eslint-disable-next-line no-console
    console.warn(w);
  }
}

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

