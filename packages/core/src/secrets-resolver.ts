/**
 * Boot-time Secrets Manager resolver.
 *
 * Scans process.env for values that look like Secrets Manager references
 * and resolves each to its plaintext.  Supports two formats:
 *
 *   - Full ARN:   `arn:aws:secretsmanager:ap-southeast-2:123:secret:name-suffix`
 *   - Shortcut:   `secretsmanager:<name-or-arn>` (resolves in AWS_REGION)
 *
 * Values that don't match either prefix are left alone, so plain literal
 * env values keep working.  Mixed modes are supported — production task
 * defs can reference Secrets Manager for sensitive DEKs while dev `.env`
 * files keep plaintext for local runs.
 *
 * Fetches happen in parallel.  A single failed fetch aborts the whole
 * resolution — a service must NOT start with a half-resolved secret map.
 *
 * Usage: call once at service boot BEFORE the first `getConfig()` call.
 * Because `defineEnv()` doesn't read process.env until `.get()`, simply
 * awaiting the resolver at top-of-index is sufficient:
 *
 *   // services/foo/src/index.ts
 *   import { resolveSecretRefs } from '@palisade/core';
 *   await resolveSecretRefs();
 *   import { getFooConfig } from './env.js';  // reads process.env on .get()
 *   const cfg = getFooConfig();
 *
 * Rationale (PCI 3.5.1 / 3.6.1): DEKs, HMAC keys and fingerprint keys
 * should never sit as plaintext in `.env` files at rest.  The task def
 * `secrets:` block already fetches some at container-start; this
 * resolver closes the gap for env values that reference ARNs directly
 * (useful in `.env.local` for dev, and as a forward-compat hook for any
 * env shape that isn't threaded through `secrets:`).
 */

import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';

const ARN_PREFIX = 'arn:aws:secretsmanager:';
const SHORTCUT_PREFIX = 'secretsmanager:';

export interface ResolveOptions {
  /** AWS region override.  Defaults to AWS_REGION / ap-southeast-2. */
  region?: string;
  /**
   * Override the list of env keys to consider.  Defaults to ALL env
   * keys.  Useful for tests.
   */
  envKeysToScan?: string[];
  /**
   * Accept the resolver being called in a no-AWS context (e.g. unit
   * tests).  When true, logs a warning and silently returns on the
   * first AWS error rather than throwing.  Default false — production
   * must fail closed.
   */
  allowFailure?: boolean;
}

export async function resolveSecretRefs(opts: ResolveOptions = {}): Promise<void> {
  const envKeys = opts.envKeysToScan ?? Object.keys(process.env);

  // Collect all env keys whose values LOOK like Secrets Manager refs.
  const toResolve: Array<{ envKey: string; secretId: string }> = [];
  for (const k of envKeys) {
    const v = process.env[k];
    if (typeof v !== 'string' || v.length === 0) continue;
    if (v.startsWith(ARN_PREFIX)) {
      toResolve.push({ envKey: k, secretId: v });
    } else if (v.startsWith(SHORTCUT_PREFIX)) {
      toResolve.push({ envKey: k, secretId: v.slice(SHORTCUT_PREFIX.length) });
    }
  }

  if (toResolve.length === 0) return;

  const region = opts.region ?? process.env.AWS_REGION ?? 'ap-southeast-2';
  const sm = new SecretsManagerClient({ region });

  // Parallel fetches.  Promise.allSettled so the first failure doesn't
  // leave other in-flight requests dangling; we aggregate the error list
  // after and throw once.
  const results = await Promise.allSettled(
    toResolve.map(({ secretId }) =>
      sm.send(new GetSecretValueCommand({ SecretId: secretId })),
    ),
  );

  const errors: string[] = [];
  for (let i = 0; i < toResolve.length; i++) {
    const { envKey, secretId } = toResolve[i];
    const r = results[i];
    if (r.status === 'rejected') {
      errors.push(`${envKey} (${secretId}): ${String(r.reason).slice(0, 200)}`);
      continue;
    }
    const { SecretString, SecretBinary } = r.value;
    if (typeof SecretString === 'string') {
      process.env[envKey] = SecretString;
    } else if (SecretBinary instanceof Uint8Array) {
      // Fallback: base64-encode binary into the env slot.  Callers that
      // expect hex should decode; this is a narrow path — most secrets
      // are stored as SecretString.
      process.env[envKey] = Buffer.from(SecretBinary).toString('base64');
    } else {
      errors.push(`${envKey} (${secretId}): secret has neither SecretString nor SecretBinary`);
    }
  }

  if (errors.length > 0) {
    const msg = `[secrets-resolver] Failed to resolve ${errors.length} secret(s):\n  ${errors.join('\n  ')}`;
    if (opts.allowFailure) {
      // eslint-disable-next-line no-console
      console.warn(msg);
      return;
    }
    throw new Error(msg);
  }
}
