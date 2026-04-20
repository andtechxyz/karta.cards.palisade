/**
 * Load the GP static keys for SCP03, resolved per card.
 *
 * Lookup order for a given cardId:
 *   1. If CARD_OPS_USE_TEST_KEYS is set, short-circuit to the env-wide
 *      GP_MASTER_KEY triplet (GP test key 0x40..0x4F by default).
 *   2. Otherwise load the Card → Program → IssuerProfile chain, read
 *      the three gp{Enc,Mac,Dek}KeyArn columns, fetch each via the
 *      Secrets Manager helper.
 *   3. If cardId is undefined OR the IssuerProfile is missing OR any
 *      of the three ARNs is empty, warn and fall back to the test keys.
 *
 * The pre-Phase 3 behaviour was a single env-wide triplet applied to
 * every card.  That is a Tier-1 blast-radius risk: compromising one
 * card's keys compromises every card in the env.  This version binds
 * the key set to the Card → Program → IssuerProfile chain so each FI's
 * cards are isolated from the rest.
 *
 * GP_MASTER_KEY env shape (JSON):
 *   { "enc": "<32 hex chars>", "mac": "<32 hex chars>", "dek": "<32 hex chars>" }
 *
 * Note the API is now async — the DB lookup + Secrets Manager fetch
 * are awaited.  Callers (operation handlers) already run inside async
 * bodies so this isn't disruptive.
 */

import { Buffer } from 'node:buffer';
import { prisma } from '@palisade/db';
import type { StaticKeys } from './scp03.js';
import { getCardOpsConfig } from '../env.js';
import { fetchGpKey } from './kms-key-fetcher.js';

// Memoised parse of GP_MASTER_KEY — the fallback test-key triplet.
let testKeysCached: StaticKeys | null = null;

function getTestKeys(): StaticKeys {
  if (testKeysCached) return testKeysCached;

  const raw = getCardOpsConfig().GP_MASTER_KEY;
  let parsed: { enc?: string; mac?: string; dek?: string };
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('GP_MASTER_KEY is not valid JSON');
  }
  if (!parsed.enc || !parsed.mac || !parsed.dek) {
    throw new Error('GP_MASTER_KEY must have enc, mac, dek fields');
  }

  const toBuf = (hex: string, label: string): Buffer => {
    if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
      throw new Error(`GP_MASTER_KEY.${label} must be 32 hex chars (16 bytes)`);
    }
    return Buffer.from(hex, 'hex');
  };

  testKeysCached = {
    enc: toBuf(parsed.enc, 'enc'),
    mac: toBuf(parsed.mac, 'mac'),
    dek: toBuf(parsed.dek, 'dek'),
  };
  return testKeysCached;
}

/**
 * Return the SCP03 static keys for the given card.
 *
 * Resolves against the card's IssuerProfile when a cardId is supplied
 * and CARD_OPS_USE_TEST_KEYS is NOT set.  Falls back to the env-wide
 * GP test key triplet otherwise (with a console warning in prod so the
 * operator notices the unsafe shortcut).
 */
export async function getGpStaticKeys(cardId?: string): Promise<StaticKeys> {
  const cfg = getCardOpsConfig();

  // Explicit opt-in for dev / early staging — skip the DB hop entirely.
  if (cfg.CARD_OPS_USE_TEST_KEYS) {
    return getTestKeys();
  }

  if (!cardId) {
    // In production, missing cardId is a hard failure — authenticating a
    // real card with test keys (known-plaintext 404142…4F) means any admin
    // op after could be signed by anyone who can reach the card.  PCI 3.5.
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        '[card-ops][static-keys] cardId is required in production; refusing to fall back to GP test keys',
      );
    }
    console.warn('[card-ops][static-keys] no cardId supplied; falling back to GP test keys');
    return getTestKeys();
  }

  // Resolve Card → Program → IssuerProfile → {gpEncKeyArn, ...}.
  //
  // All three fields may be null if the program predates the GP-key
  // migration OR belongs to a tenant that hasn't rotated keys yet.  We
  // refuse to silently proceed with the env key in that case; instead
  // we warn + use test keys (dev-only path).  Production should set
  // CARD_OPS_USE_TEST_KEYS='' and populate ARNs; the warning is the
  // canary that something needs attention.
  const card = await prisma.card.findUnique({
    where: { id: cardId },
    select: {
      program: {
        select: {
          issuerProfile: {
            select: {
              gpEncKeyArn: true,
              gpMacKeyArn: true,
              gpDekKeyArn: true,
            },
          },
        },
      },
    },
  });

  const issuer = card?.program?.issuerProfile;
  const isProd = process.env.NODE_ENV === 'production';
  if (!issuer || !issuer.gpEncKeyArn || !issuer.gpMacKeyArn || !issuer.gpDekKeyArn) {
    // Same PCI concern as the no-cardId branch: refusing test-key fallback
    // is the only safe answer in prod for a card that IS configured but
    // whose ARNs are missing.
    if (isProd) {
      throw new Error(
        `[card-ops][static-keys] cardId=${cardId} has no GP key ARNs configured; refusing to fall back to GP test keys in production`,
      );
    }
    console.warn(
      `[card-ops][static-keys] cardId=${cardId} has no GP key ARNs configured; falling back to GP test keys (dev only)`,
    );
    return getTestKeys();
  }

  try {
    const [enc, mac, dek] = await Promise.all([
      fetchGpKey(issuer.gpEncKeyArn),
      fetchGpKey(issuer.gpMacKeyArn),
      fetchGpKey(issuer.gpDekKeyArn),
    ]);
    return { enc, mac, dek };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // A transient Secrets Manager error must NEVER cause us to authenticate
    // a real card with the GP test keys.  Propagate the error — the caller
    // will fail the operation and the UI will surface it; operator can
    // retry.  This closes the "momentary SM outage downgrades security"
    // attack.
    if (isProd) {
      throw new Error(
        `[card-ops][static-keys] cardId=${cardId} key fetch failed (${msg}); refusing to fall back to GP test keys in production`,
      );
    }
    console.warn(
      `[card-ops][static-keys] cardId=${cardId} key fetch failed (${msg}); falling back to GP test keys (dev only)`,
    );
    return getTestKeys();
  }
}

/** Test-only: flush caches between runs. */
export function _resetGpStaticKeysCache(): void {
  testKeysCached = null;
}
