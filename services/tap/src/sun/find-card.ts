import { prisma } from '@palisade/db';
import { decrypt, type KeyProvider } from '@palisade/core';
import type { SdmDeriver } from '@palisade/sdm-keys';
import { decryptPiccData } from './picc.js';

// Resolve a cardRef-less SUN URL (e.g. the mobile app's `/api/tap/verify/:urlCode`
// path) to a specific Card by trial-deriving its meta-read key from each
// candidate's stored UID and attempting PICC decrypt.  The "match" signal is
// the SDM tag byte (0xC7) at plaintext offset 0 — every other key produces
// effectively-random bytes there with probability 1/256.
//
// This code path is live in production: Karta Platinum cards' NDEF URL
// template is `https://mobile.karta.cards/t/{urlCode}?e={PICCData}&m={CMAC}`
// (no cardRef), and the mobile app POSTs the `{e, m}` pair back here at
// every tap.  See apps/mobile/src/screens/tap/TapVerifyScreen.tsx.
//
// Performance model:
//   - Per-tap cost is dominated by the HSM round-trip for key derivation
//     (~20-50ms per AWS PC GenerateMac in-region).
//   - Two mitigations are applied here:
//       (1) UID-keyed LRU: once a card taps, subsequent taps within the
//           TTL window hit an in-process cache and avoid the HSM entirely.
//           Repeat-tap hot path drops to <1ms.  The PICC is the cache key
//           because it deterministically identifies the card (only the
//           right meta-key decrypts it; only the right card produced it).
//       (2) Bounded parallel trial-decrypt: for the first tap (cache
//           miss), candidate cards are checked with a concurrency of
//           CONCURRENCY.  10K cards at 20ms serial = 200s; at 32-way
//           parallel = ~6s.  AWS PC handles concurrent GenerateMac
//           well; we bound to stay under the PC rate limit.
//
// Neither lowers the worst case for first-time-ever taps; that's the
// expected PCI tradeoff for keeping UIDs out of the URL and per-card keys
// in the HSM.  The cheap first-tap lever (future work) is eager derivation
// at card register time, caching (cardId, metaKey, fileKey) in Redis.
//
// Filters to ACTIVATED + PROVISIONED only — SHIPPED cards have no business
// hitting this endpoint (their NDEF URL points at the activation flow, not at
// /t/<urlCode>), and SUSPENDED/REVOKED cards must be rejected upstream of any
// signed-handoff mint.

export interface FindCardByPiccInput {
  /**
   * Program scope.  Iteration is over Cards in this program only, derived
   * from the `urlCode` in the chip's URL.
   */
  programId: string;
  piccHex: string;
  /** Decrypts the stored UID on each candidate. */
  keyProvider: KeyProvider;
  /** Derives meta/file read keys from a UID. */
  sdmDeriver: SdmDeriver;
}

export interface FindCardByPiccMatch {
  cardId: string;
  cardStatus: string;
  lastReadCounter: number;
  /** AES-128 key, plaintext.  Caller MUST scrub when done. */
  sdmMetaReadKey: Buffer;
  /** AES-128 key, plaintext.  Caller MUST scrub when done. */
  sdmFileReadKey: Buffer;
  /** PICC plaintext fields (UID, counter, etc) — already decrypted, save redoing. */
  uid: Buffer;
  counter: number;
}

// -----------------------------------------------------------------------------
// UID → derived-keys LRU cache.  Hot path: same card tapping again.
// -----------------------------------------------------------------------------
//
// Keyed by UID-hex (not piccHex, because the PICC ciphertext contains a
// nonce that changes on every tap; UID is stable per card).  We derive the
// UID from the DB row's decrypted uidEncrypted column — that's what we
// already do per candidate — and use it to hit the cache before calling
// the HSM.
//
// Cache value holds BOTH meta + file keys so a hit saves two HSM calls.
// Entries are sensitive (plaintext SDM keys); TTL + eviction keep the
// window small.  Note keys in the cache are copied — callers get a fresh
// Buffer each time so their .fill(0) scrubs don't break the cache entry.

const CACHE_TTL_MS = 60_000;
const CACHE_MAX_ENTRIES = 1024;

interface CacheEntry {
  cardId: string;
  cardStatus: string;
  metaKey: Buffer;
  fileKey: Buffer;
  expiresAt: number;
}

const uidKeyCache = new Map<string, CacheEntry>();

/** Drop expired entries; cap map size via insertion-order eviction. */
function pruneCache(): void {
  const now = Date.now();
  for (const [uid, e] of uidKeyCache) {
    if (e.expiresAt < now) {
      e.metaKey.fill(0);
      e.fileKey.fill(0);
      uidKeyCache.delete(uid);
    }
  }
  while (uidKeyCache.size > CACHE_MAX_ENTRIES) {
    const firstKey = uidKeyCache.keys().next().value;
    if (!firstKey) break;
    const e = uidKeyCache.get(firstKey)!;
    e.metaKey.fill(0);
    e.fileKey.fill(0);
    uidKeyCache.delete(firstKey);
  }
}

function cacheGet(uidHex: string): CacheEntry | null {
  pruneCache();
  return uidKeyCache.get(uidHex) ?? null;
}

function cachePut(uidHex: string, entry: CacheEntry): void {
  // Remove any existing entry first so re-insertion bumps it to "fresh"
  // in insertion-order eviction.
  const prev = uidKeyCache.get(uidHex);
  if (prev) {
    prev.metaKey.fill(0);
    prev.fileKey.fill(0);
    uidKeyCache.delete(uidHex);
  }
  uidKeyCache.set(uidHex, entry);
  pruneCache();
}

/** Test hook: clear the cache between runs. */
export function _resetFindCardCache(): void {
  for (const e of uidKeyCache.values()) {
    e.metaKey.fill(0);
    e.fileKey.fill(0);
  }
  uidKeyCache.clear();
}

// -----------------------------------------------------------------------------
// Trial-decrypt concurrency for cache-miss path.
// -----------------------------------------------------------------------------

/**
 * Max in-flight HSM derivations during trial decrypt.  AWS Payment
 * Cryptography documented rate limits are well above 32; this bound is
 * mainly about not flooding the service on a misconfigured huge program.
 * Override in tests via _setTrialDecryptConcurrency.
 */
let CONCURRENCY = 32;

/** Test hook. */
export function _setTrialDecryptConcurrency(n: number): void {
  CONCURRENCY = Math.max(1, n);
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

/**
 * Returns the matching Card + already-decrypted PICC, or null if no card
 * in the program decrypted the PICC bytes to a valid (tag=0xC7) plaintext.
 */
export async function findCardByPicc(
  input: FindCardByPiccInput,
): Promise<FindCardByPiccMatch | null> {
  const candidates = await prisma.card.findMany({
    where: {
      programId: input.programId,
      status: { in: ['ACTIVATED', 'PROVISIONED'] },
    },
    select: {
      id: true,
      status: true,
      lastReadCounter: true,
      keyVersion: true,
      uidEncrypted: true,
    },
  });

  // Phase 1: try the cache first.  A hit means we already know this
  // card's keys and can skip the HSM entirely.  On every candidate whose
  // uid is in the cache we attempt decrypt; the first valid one wins.
  for (const c of candidates) {
    let uidHex: string;
    let uid: Buffer | null = null;
    try {
      uidHex = decrypt(
        { ciphertext: c.uidEncrypted, keyVersion: c.keyVersion },
        input.keyProvider,
      );
    } catch {
      continue; // UID decrypt fail — skip
    }
    const cached = cacheGet(uidHex);
    if (!cached) continue;

    try {
      // Copy so caller's .fill(0) doesn't zero the cache entry.
      const metaCopy = Buffer.from(cached.metaKey);
      const picc = decryptPiccData(metaCopy, input.piccHex);
      if (!picc.valid) {
        metaCopy.fill(0);
        continue;
      }
      uid = Buffer.from(uidHex, 'hex');
      // Refresh TTL on a hit.  IMPORTANT: do NOT route through cachePut(),
      // which zeros the previous entry's keys before swapping in the new
      // one — here the new entry holds the SAME Buffer refs as the
      // previous entry (spread preserves references), so cachePut would
      // zero its own keys.  Post-audit fix (N-1) — directly mutate the
      // existing entry's expiresAt; Map retains insertion order.
      cached.expiresAt = Date.now() + CACHE_TTL_MS;
      return {
        cardId: cached.cardId,
        cardStatus: cached.cardStatus,
        lastReadCounter: c.lastReadCounter,
        sdmMetaReadKey: metaCopy,
        sdmFileReadKey: Buffer.from(cached.fileKey),
        uid: picc.uid,
        counter: picc.counter,
      };
    } catch {
      // Swallow and fall through to cache-miss path.
      uid?.fill(0);
    }
  }

  // Phase 2: cache miss.  Bounded-parallel trial decrypt across
  // candidates.  Each worker: derive metaKey from UID, try PICC decrypt,
  // report match.  First match wins; remaining workers are cancelled via
  // the shared `found` flag to stop HSM calls that can't matter.
  let found = false;

  // Partition candidates into batches of CONCURRENCY.  Simple chunking is
  // fine — we don't need dynamic work stealing given HSM latency is uniform.
  for (let i = 0; i < candidates.length && !found; i += CONCURRENCY) {
    const batch = candidates.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async (c) => {
        if (found) return null;
        let uid: Buffer | null = null;
        let metaKey: Buffer | null = null;
        let uidHex: string;
        try {
          uidHex = decrypt(
            { ciphertext: c.uidEncrypted, keyVersion: c.keyVersion },
            input.keyProvider,
          );
        } catch {
          return null;
        }
        try {
          uid = Buffer.from(uidHex, 'hex');
          metaKey = await input.sdmDeriver.deriveMetaReadKey(uid);
          if (found) {
            metaKey.fill(0);
            uid.fill(0);
            return null;
          }
          const picc = decryptPiccData(metaKey, input.piccHex);
          if (!picc.valid) {
            metaKey.fill(0);
            uid.fill(0);
            return null;
          }
          // Match.  Also derive fileKey and warm the cache so the NEXT
          // tap is an O(1) hit.
          const fileKey = await input.sdmDeriver.deriveFileReadKey(uid);
          cachePut(uidHex, {
            cardId: c.id,
            cardStatus: c.status,
            metaKey: Buffer.from(metaKey),
            fileKey: Buffer.from(fileKey),
            expiresAt: Date.now() + CACHE_TTL_MS,
          });
          found = true;
          return {
            cardId: c.id,
            cardStatus: c.status,
            lastReadCounter: c.lastReadCounter,
            sdmMetaReadKey: metaKey,
            sdmFileReadKey: fileKey,
            uid: picc.uid,
            counter: picc.counter,
          };
        } catch {
          metaKey?.fill(0);
          uid?.fill(0);
          return null;
        }
      }),
    );

    for (const r of batchResults) {
      if (r) return r;
    }
  }

  return null;
}
