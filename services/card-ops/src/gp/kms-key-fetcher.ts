/**
 * Per-card GlobalPlatform SCP03 key fetcher.
 *
 * Cards issued under different FIs (IssuerProfiles) hold different
 * AES-128 SCP03 static keys.  The ARNs for those keys live on
 * IssuerProfile.{gpEncKeyArn, gpMacKeyArn, gpDekKeyArn}.  This module
 * resolves an ARN to the raw 16-byte key material.
 *
 * ## Storage approach (documented choice)
 *
 * The ARN refers to a **Secrets Manager secret**.  The secret value IS
 * the 16-byte AES-128 key, stored as:
 *   - `SecretBinary` — raw bytes (preferred; Secrets Manager writes the
 *     protection at rest via KMS transparently), OR
 *   - `SecretString` — 32-hex-char representation, which we decode.
 *
 * We chose Secrets Manager over a KMS-CiphertextBlob-plus-sidecar model
 * because:
 *   1. Secrets Manager secrets are the canonical "opaque secret" shape
 *      in AWS — versioned, rotation-aware, resource-policy-gated.
 *   2. No plaintext lives outside the fetcher; Secrets Manager already
 *      encrypts at rest with a KMS key under the hood.
 *   3. Operations (rotation, cross-account sharing) are first-class in
 *      Secrets Manager.  Rolling your own KMS-CiphertextBlob store would
 *      reinvent those without improving the threat model.
 *
 * A future KMS-envelope mode (ARN + CiphertextBlob fetched from
 * elsewhere) could be layered on by inspecting the ARN prefix; the
 * current code exports the single fetchGpKey() entry point so that's
 * a one-call-site swap if we add it.
 *
 * ## Caching
 *
 * Keys are cached per-ARN for the lifetime of the process.  SCP03
 * keys rotate on the order of months; refetching on every APDU would
 * turn every GP op into an AWS call.  Tests use _resetGpKeyCache() to
 * reset between runs.
 *
 * ## Dev fallback
 *
 * When the ARN is `null`/empty OR `CARD_OPS_USE_TEST_KEYS=1` is set,
 * the caller (static-keys.ts) supplies the GP test key (0x40..0x4F)
 * instead of calling this module.  This module always fetches real
 * material — it's the caller's job to decide whether to call it.
 */

import { Buffer } from 'node:buffer';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';

const KEY_BYTE_LENGTH = 16;

// Per-ARN cache.  Module-scoped — lifetime == process lifetime.  Tests
// reset via _resetGpKeyCache() in the vitest beforeEach.
const cache = new Map<string, Buffer>();

// Lazy-constructed AWS client so unit tests that never reach the real
// path don't need to mock module-level construction.  The factory is
// overridable for tests that DO want to exercise the fetch path.
type ClientFactory = () => SecretsManagerClient;

let clientFactory: ClientFactory = () => new SecretsManagerClient({});

/** Test-only: inject a mocked Secrets Manager client. */
export function _setSecretsManagerClientFactory(factory: ClientFactory): void {
  clientFactory = factory;
  client = null; // force re-construction via the new factory on next call
}

/** Test-only: reset the cache so a second test sees a cold fetch. */
export function _resetGpKeyCache(): void {
  cache.clear();
  clientFactory = () => new SecretsManagerClient({});
  client = null;
}

let client: SecretsManagerClient | null = null;
function getClient(): SecretsManagerClient {
  if (!client) client = clientFactory();
  return client;
}

/**
 * Fetch the raw 16-byte AES-128 key material for the given Secrets
 * Manager ARN.  Result is cached for the process lifetime.
 *
 * Throws if the secret is missing, the ARN is invalid, the value is
 * not 16 bytes after decode, or the SDK call fails.  Callers catch +
 * fall back to test keys when appropriate.
 */
export async function fetchGpKey(arn: string): Promise<Buffer> {
  if (!arn) {
    throw new Error('fetchGpKey: ARN is empty');
  }
  const cached = cache.get(arn);
  if (cached) return cached;

  const resp = await getClient().send(
    new GetSecretValueCommand({ SecretId: arn }),
  );

  const raw = decodeSecret(resp);
  if (raw.length !== KEY_BYTE_LENGTH) {
    throw new Error(
      `fetchGpKey: secret at ${arn} is ${raw.length} bytes, expected ${KEY_BYTE_LENGTH}`,
    );
  }

  cache.set(arn, raw);
  return raw;
}

/**
 * Decode a GetSecretValueCommand result into a Buffer.
 *
 *   - SecretBinary is preferred (raw bytes, no encoding drift).
 *   - SecretString is accepted as 32 hex chars for operator ergonomics
 *     — it's common to paste a hex string into the Secrets Manager
 *     console when rotating by hand.
 */
function decodeSecret(resp: {
  SecretBinary?: Uint8Array;
  SecretString?: string;
}): Buffer {
  if (resp.SecretBinary) {
    return Buffer.from(resp.SecretBinary);
  }
  if (resp.SecretString) {
    const str = resp.SecretString.trim();
    if (!/^[0-9a-fA-F]+$/.test(str)) {
      throw new Error('fetchGpKey: SecretString is not hex');
    }
    if (str.length % 2 !== 0) {
      throw new Error('fetchGpKey: SecretString has odd length');
    }
    return Buffer.from(str, 'hex');
  }
  throw new Error('fetchGpKey: Secrets Manager returned no SecretBinary or SecretString');
}
