/**
 * Provisioning session lifecycle management.
 *
 * Coordinates the complete provisioning flow through 6 phases:
 *   Phase 0: PA SELECT + FCI validation
 *   Phase 1: SCP11c session establishment
 *   Phase 2: Key generation + attestation
 *   Phase 3: SAD transfer
 *   Phase 4: Awaiting final status
 *   Phase 5: CONFIRM + callback
 *
 * Ported from palisade-rca/app/services/session_manager.py.
 */

import { prisma } from '@palisade/db';
import { APDUBuilder, ParamTag, spliceSensitiveFields } from '@palisade/emv';
import { badRequest, redactSid } from '@palisade/core';
import { DataPrepService } from '@palisade/data-prep/services/data-prep.service';

import { getRcaConfig } from '../env.js';
import { metrics } from '../metrics.js';
import {
  buildProvisioningPlan,
  buildMinimalSadPayload,
  buildTransferSadApdu,
  buildParamBundleApduChunks,
  schemeByteForIssuer,
  type Plan,
  type PlanContext,
  type PlanStep,
} from './plan-builder.js';
import {
  AttestationVerifier,
  ICC_PUBKEY_LEN,
  type AttestationMode,
  type AttestationVerifierConfig,
} from './attestation-verifier.js';

/**
 * Build the AttestationVerifier strict-mode config from the rca env.
 * Returns undefined in permissive mode (verify() accepts undefined
 * there).  Hex-decode happens on every call — inexpensive for the
 * handful of attestation verifies per tap and avoids a module-scope
 * cache that would need test invalidation.
 */
function attestationConfigFor(mode: AttestationMode): AttestationVerifierConfig | undefined {
  if (mode !== 'strict') return undefined;
  const cfg = getRcaConfig();
  return {
    rootPubkey: Buffer.from(cfg.KARTA_ATTESTATION_ROOT_PUBKEY, 'hex'),
    issuerCert: Buffer.from(cfg.KARTA_ATTESTATION_ISSUER_CERT, 'hex'),
  };
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WSMessage {
  type: 'apdu' | 'response' | 'complete' | 'error' | 'pa_fci' | 'plan';
  hex?: string;
  sw?: string;
  phase?: string;
  progress?: number;
  code?: string;
  message?: string;
  proxyCardId?: string;

  // Plan-mode fields -------------------------------------------------------
  /**
   * Step index.
   *   - Outbound (server→app) on a 'plan' message: unused (steps carry their
   *     own `i` on each PlanStep).
   *   - Inbound (app→server) on a 'response' message: which plan step this
   *     response belongs to.  Presence of `i` is how handleMessage
   *     distinguishes plan-mode responses from classical-mode phase-driven
   *     responses.
   */
  i?: number;
  /** On a 'plan' message: the ordered list of APDU steps to execute. */
  steps?: PlanStep[];
  /** On a 'plan' message: plan schema version (1 today). */
  version?: number;
}

interface SessionState {
  sessionId: string;
  proxyCardId: string;
  cardId: string;
  sadRecordId: string;
  phase: string;
}

// ---------------------------------------------------------------------------
// Minimal shapes for building the PlanContext + TRANSFER_SAD APDU.
//
// These are intentionally narrower than Prisma's generated types so the
// assembly code can be unit-tested with plain objects without importing
// @prisma/client.
// ---------------------------------------------------------------------------

interface ChipProfileShape {
  iccPrivateKeyDgi: number;
  iccPrivateKeyTag: number;
}

interface IssuerProfileShape {
  scheme: string;
  bankId: number | null;
  progId: number | null;
  postProvisionUrl: string | null;
  chipProfile: ChipProfileShape | null;
}

interface SadRecordShape {
  sadEncrypted: Buffer | Uint8Array;
  sadKeyVersion: number;
}

// ---------------------------------------------------------------------------
// SAD pre-decrypt cache (latency optimization)
// ---------------------------------------------------------------------------
//
// `POST /api/provision/start` fires a KMS decrypt in the background and
// stores the plaintext SAD keyed by sessionId.  By the time the mobile
// app finishes its TLS handshake + WS upgrade + attestation round-trip,
// the plaintext is almost always already cached — `buildPlanContext`
// pulls from the cache instead of paying the 150-400ms KMS round-trip
// inline during the SAD_TRANSFER window.
//
// Cache entry lifecycle:
//   - Populated by `startSession()` (fire-and-forget background task).
//   - Read by `buildPlanContext()` on cache hit; falls back to inline
//     `DataPrepService.decryptSad` on miss or expiry.
//   - Zeroed + removed by `consumeSadFromCache()` once the plaintext has
//     been serialized into the TRANSFER_SAD APDU (match to S-2 scrub).
//   - Sweep-expired after WS_TIMEOUT_SECONDS via `pruneSadCache()`;
//     in-memory only, so an RCA restart starts clean.
//
// The cache is a module-level Map, not per-instance, because the WS
// relay handler and the HTTP router create separate SessionManager
// instances in the current design.  A singleton cache lets the /start
// writer and the WS-driven reader be different SM instances.
interface SadCacheEntry {
  payload: Buffer;
  /** Epoch-ms — when this entry becomes unusable. */
  expiresAt: number;
}
const sadCache = new Map<string, SadCacheEntry>();
// 60 seconds aligns with WS_TIMEOUT_SECONDS default; startSession reads
// config.WS_TIMEOUT_SECONDS and passes it to the prime path, but we
// also cap with this constant so a pathological config can't leak
// plaintext SAD for hours.
const SAD_CACHE_MAX_TTL_MS = 120_000;

/**
 * Fetch a cached plaintext SAD, deleting + scrubbing the entry on hit.
 * Returns `null` if the cache entry is missing or expired (in which
 * case the caller decrypts inline as a fallback).
 *
 * Emits `rca.sad_cache.{hit,miss,expired}` so operators can validate
 * the hit rate of the pre-decrypt optimization on the real traffic
 * mix.  Target is >95% hit on steady-state; a dropping hit rate
 * suggests mobiles are taking longer between /start and WS open than
 * the prime path's KMS latency budget.
 */
function consumeSadFromCache(sessionId: string): Buffer | null {
  const entry = sadCache.get(sessionId);
  if (!entry) {
    metrics().counter('rca.sad_cache.miss', 1);
    return null;
  }
  sadCache.delete(sessionId);
  if (entry.expiresAt < Date.now()) {
    // Expired — still zero it before returning null so a later core
    // dump doesn't leak the plaintext.
    entry.payload.fill(0);
    metrics().counter('rca.sad_cache.expired', 1);
    return null;
  }
  metrics().counter('rca.sad_cache.hit', 1);
  return entry.payload;
}

/**
 * Store a pre-decrypted SAD in the cache.  TTL is clamped to
 * `SAD_CACHE_MAX_TTL_MS` to prevent config-driven long-lived plaintext.
 *
 * Emits a `rca.sad_cache.size` gauge post-insert so operators can alert
 * on unbounded growth (indicates mobiles abandoning sessions faster
 * than the sweep TTL reclaims them).
 */
function storeSadInCache(
  sessionId: string,
  payload: Buffer,
  ttlMs: number,
): void {
  const clamped = Math.min(Math.max(ttlMs, 10_000), SAD_CACHE_MAX_TTL_MS);
  sadCache.set(sessionId, {
    payload,
    expiresAt: Date.now() + clamped,
  });
  metrics().gauge('rca.sad_cache.size', sadCache.size);
}

/**
 * Best-effort sweep of expired SAD cache entries.  Run opportunistically
 * at every startSession call so the map doesn't accumulate expired
 * entries when the mobile never connects.  Scrubs plaintext on eviction.
 */
function pruneSadCache(): void {
  const now = Date.now();
  for (const [sid, entry] of sadCache) {
    if (entry.expiresAt < now) {
      entry.payload.fill(0);
      sadCache.delete(sid);
    }
  }
}

// ---------------------------------------------------------------------------
// TRANSFER_PARAMS chunk queue — for chained short APDUs
// ---------------------------------------------------------------------------
//
// When pa-v3's TRANSFER_PARAMS body exceeds 255 B (the real case for any
// ParamBundle), rca splits the wire into ≤240-byte chunks with the ISO
// 7816-4 chaining bit (CLA bit 0x10) set on everything but the last.
// iOS CoreNFC / JCOP 5 JC 3.0.4 reject extended APDUs on this silicon
// — tested SW=6700 across four consecutive taps despite correct case-4
// framing — and short APDUs are the only path that got pa-v1's
// TRANSFER_SAD over the wire too.  The applet-side accumulator (see
// pa-v3 ProvisioningAgentV3 processTransferParams chainOff) reads
// chunks into wireBuf and only runs unwrap on the final (non-chained)
// chunk.
//
// Cache entry: ordered array of pre-built APDU buffers ready to emit,
// plus an index of the next one.  Both produced at handleKeygenResponse
// time; consumed chunk-by-chunk in handleSadResponse as the chip acks
// each one with 9000.

interface ParamChunkQueue {
  /** Ordered APDU bytes, chain-bit-on on all but the last. */
  chunks: Buffer[];
  /** Index of the chunk that was just sent (awaiting its ack). */
  sentIdx: number;
  expiresAt: number;
}
const paramChunkCache = new Map<string, ParamChunkQueue>();

function putParamChunks(sessionId: string, chunks: Buffer[], ttlMs: number): void {
  paramChunkCache.set(sessionId, {
    chunks,
    sentIdx: 0,
    expiresAt: Date.now() + Math.min(Math.max(ttlMs, 10_000), SAD_CACHE_MAX_TTL_MS),
  });
}

/**
 * Mark the currently-in-flight chunk as acked and return info about
 * what's next.  Returns `{ done: true }` when the chip just acked the
 * last chunk — caller should proceed to FINAL_STATUS.
 */
function advanceParamChunk(sessionId: string): { done: boolean; next: Buffer | null } {
  const q = paramChunkCache.get(sessionId);
  if (!q) return { done: true, next: null };
  q.sentIdx += 1;
  if (q.sentIdx >= q.chunks.length) {
    paramChunkCache.delete(sessionId);
    // Drain paired nonce material — chip has accepted the bundle, the
    // nonce has now served its C4 replay-binding purpose and must not
    // be reused if the session somehow cycles.
    clearChipNonce(sessionId);
    return { done: true, next: null };
  }
  return { done: false, next: q.chunks[q.sentIdx] };
}

/** Test hook: clear the module-level SAD cache between runs. */
export function _resetSadCacheForTests(): void {
  for (const [, entry] of sadCache) entry.payload.fill(0);
  sadCache.clear();
}

// ---------------------------------------------------------------------------
// Chip-nonce cache — patent C4 (chip-side replay binding)
// ---------------------------------------------------------------------------
//
// The applet emits a fresh 16-byte nonce in the trailing bytes of its
// GENERATE_KEYS response and appends the same nonce to its own
// sessionId[] buffer before the HKDF-expand that derives the
// TRANSFER_PARAMS AES/IV/HMAC triple.  For the wrap side to produce
// bytes the chip will accept, we need to remember the nonce between
// handleKeygenResponse (when we first see it) and the moment we call
// buildParamBundleApduChunks (minutes later at most — typically <2 s
// of wall-clock).  Short-lived Map keyed by sessionId matches the
// existing paramChunkCache pattern; no DB column needed.
//
// Entries expire on: successful chunk queue drain (paired delete in
// handleSadResponse), session FAILED transition, WS disconnect TTL,
// or the reaper-sad-sessions sweep.  Missing entry at wrap time is
// treated as "card is running an older applet that doesn't emit a
// nonce" — we fall back to the legacy HKDF info (sessionId only) so
// permissive deploys during rollout don't break mid-tap.

interface ChipNonceEntry {
  nonce: Buffer;
  expiresAt: number;
}
const chipNonceCache = new Map<string, ChipNonceEntry>();

function putChipNonce(sessionId: string, nonce: Buffer, ttlMs: number): void {
  chipNonceCache.set(sessionId, {
    nonce,
    expiresAt:
      Date.now() + Math.min(Math.max(ttlMs, 10_000), SAD_CACHE_MAX_TTL_MS),
  });
}

function getChipNonce(sessionId: string): Buffer | undefined {
  const e = chipNonceCache.get(sessionId);
  if (!e) return undefined;
  if (Date.now() > e.expiresAt) {
    chipNonceCache.delete(sessionId);
    return undefined;
  }
  return e.nonce;
}

function clearChipNonce(sessionId: string): void {
  const e = chipNonceCache.get(sessionId);
  if (e) e.nonce.fill(0);
  chipNonceCache.delete(sessionId);
}

/** Test hook: clear the chip-nonce cache between runs. */
export function _resetChipNonceCacheForTests(): void {
  for (const [, e] of chipNonceCache) e.nonce.fill(0);
  chipNonceCache.clear();
}

// ---------------------------------------------------------------------------
// Card cert cache — patent C16/C23 cross-plan-step carry
//
// When includeAttestationChain is on, the GET_ATTESTATION_CHAIN step
// runs BEFORE GENERATE_KEYS and returns the per-card cert blob (65 B
// card pubkey + 42 B CPLC + ~72 B DER sig).  The verifier runs at
// keygen-response time and needs that cardCert plus the attestSig
// trailer off GEN_KEYS together.  We stash cardCert here between
// steps — in-memory only, never persisted, cleared on terminal /
// sweep just like the chip nonce cache.
//
// TTL is bounded the same way as chipNonceCache: [10 s, SAD_CACHE_
// MAX_TTL_MS].  A plan that stalls between steps beyond that window
// is going to hit the session WS timeout anyway; missing cardCert at
// verify time surfaces as a normal strict-mode attestation failure
// with warning 'cardCert not supplied'.
// ---------------------------------------------------------------------------

interface CardCertEntry {
  cardCert: Buffer;
  expiresAt: number;
}
const cardCertCache = new Map<string, CardCertEntry>();

function putCardCert(sessionId: string, cardCert: Buffer, ttlMs: number): void {
  cardCertCache.set(sessionId, {
    cardCert,
    expiresAt:
      Date.now() + Math.min(Math.max(ttlMs, 10_000), SAD_CACHE_MAX_TTL_MS),
  });
}

function getCardCert(sessionId: string): Buffer | undefined {
  const e = cardCertCache.get(sessionId);
  if (!e) return undefined;
  if (Date.now() > e.expiresAt) {
    cardCertCache.delete(sessionId);
    return undefined;
  }
  return e.cardCert;
}

function clearCardCert(sessionId: string): void {
  cardCertCache.delete(sessionId);
}

/** Test hook: clear the card-cert cache between runs. */
export function _resetCardCertCacheForTests(): void {
  cardCertCache.clear();
}

// ---------------------------------------------------------------------------
// Plan-mode step sequencing (patent C5 state-machine enforcement)
// ---------------------------------------------------------------------------
//
// Plan-mode trusts the mobile app to execute steps in order.  A rogue or
// buggy client could:
//   1. Skip step 1 (GENERATE_KEYS) so attestation never runs, then jump
//      to step 3 (FINAL_STATUS) and trick the server into committing a
//      provisioning flow we never verified the chip for.
//   2. Replay step 3 or step 4 to fire the activation callback twice or
//      double-advance the state machine.
//   3. Jump past the chip-challenge step when includeChipChallenge is
//      opted in — defeating the C4 nonce binding entirely.
//
// The server-side defence is a per-session step cursor: we require the
// first inbound `i` to be 0 and each subsequent `i` to be exactly
// `lastProcessed + 1`.  Anything else returns an error and FAILs the
// session.  The cursor is initialized when buildPlanForSession() runs
// and cleared on terminal state or sweep.
//
// Module-level Map (not per-instance) for the same reason the SAD cache
// is — the HTTP router and the WS relay handler may instantiate
// separate SessionManagers.
interface PlanStepState {
  /** Total steps in the plan (from PlanContext at build time). */
  expectedSteps: number;
  /** Index of the most recently accepted step.  -1 before step 0 runs. */
  lastProcessed: number;
  /** Epoch-ms expiry for sweep — aligns with the session WS timeout. */
  expiresAt: number;
  /**
   * Ordered phase names — `phases[i]` is the `phase` field of
   * `plan.steps[i]`.  Populated at initPlanStepState time so the
   * inbound-response dispatcher in handlePlanResponse can switch on
   * semantic phase (`key_generation`, `get_attestation_chain`, …)
   * instead of a hardcoded index.  Fixes the latent bug where
   * `includeAttestationChain` or `includeChipChallenge` shift the
   * keygen step from index 1 to index 2 / 3 respectively and the
   * original `case 1:` dispatch would mis-route.
   */
  phases: string[];
}
const planStepState = new Map<string, PlanStepState>();
const PLAN_STEP_STATE_TTL_MS = 120_000;

/**
 * Initialize the step-sequence cursor for a plan-mode session.  Called
 * by buildPlanForSession() once the plan is built but before it's sent
 * on the wire.
 */
function initPlanStepState(
  sessionId: string,
  phases: string[],
): void {
  planStepState.set(sessionId, {
    expectedSteps: phases.length,
    lastProcessed: -1,
    expiresAt: Date.now() + PLAN_STEP_STATE_TTL_MS,
    phases: [...phases],
  });
}

/**
 * Resolve the phase name for a given step index on a session.  Returns
 * `null` if the session's plan state is gone (sweep / restart / never
 * armed) — callers treat that as "unknown phase" and reject the
 * response before dispatching.
 */
function phaseForPlanStep(sessionId: string, i: number): string | null {
  const state = planStepState.get(sessionId);
  if (!state) return null;
  if (i < 0 || i >= state.phases.length) return null;
  return state.phases[i] ?? null;
}

/**
 * Attempt to advance the step cursor to `i`.  Returns the previous
 * `lastProcessed` on success so callers can tell if this is a first-time
 * step completion; returns an error string on rejection (bad index,
 * replay, skipped step, unknown session).
 */
function advancePlanStep(
  sessionId: string,
  i: number,
): { ok: true; prior: number } | { ok: false; reason: string } {
  const state = planStepState.get(sessionId);
  if (!state) {
    // Either a stale session (server restart lost the in-memory cursor)
    // or a malicious response with no prior plan message.  Either way,
    // reject — plan mode requires the server-side cursor.
    return { ok: false, reason: 'plan_step_state_missing' };
  }
  if (state.expiresAt < Date.now()) {
    planStepState.delete(sessionId);
    return { ok: false, reason: 'plan_step_state_expired' };
  }
  if (i < 0 || i >= state.expectedSteps) {
    return { ok: false, reason: `plan_step_out_of_range(got=${i},max=${state.expectedSteps - 1})` };
  }
  if (i <= state.lastProcessed) {
    return { ok: false, reason: `plan_step_replay(got=${i},last=${state.lastProcessed})` };
  }
  if (i > state.lastProcessed + 1) {
    return { ok: false, reason: `plan_step_skip(got=${i},last=${state.lastProcessed})` };
  }
  const prior = state.lastProcessed;
  state.lastProcessed = i;
  return { ok: true, prior };
}

/** Release the step cursor on terminal / sweep. */
function clearPlanStepState(sessionId: string): void {
  planStepState.delete(sessionId);
  // Keep the three session-scoped caches in lockstep.  Anywhere we
  // terminate / fail a session also scrubs the in-memory attestation
  // cardCert + chip nonce + SAD pre-decrypt.  Easier to change one
  // helper than audit four callsites every time.
  clearCardCert(sessionId);
}

/** Best-effort sweep of expired plan-step cursors (called from startSession). */
function prunePlanStepState(): void {
  const now = Date.now();
  for (const [sid, state] of planStepState) {
    if (state.expiresAt < now) planStepState.delete(sid);
  }
}

/** Test hook: clear the module-level plan-step cursor map between runs. */
export function _resetPlanStepStateForTests(): void {
  planStepState.clear();
}

/**
 * Test hook: seed the cursor for a given sessionId.  Lets tests that
 * exercise handlePlanResponse directly (without going through
 * buildPlanForSession) skip the init dance.  Production code does NOT
 * call this — the cursor is set only via initPlanStepState inside
 * buildPlanForSession.
 */
export function _seedPlanStepStateForTests(
  sessionId: string,
  expectedSteps: number,
  lastProcessed: number = -1,
  /**
   * Optional phase names — when omitted the seeder synthesizes the
   * canonical 5-step classical sequence so existing tests (which
   * predate phase-based dispatch) keep working unchanged.  New tests
   * exercising `includeAttestationChain` / `includeChipChallenge`
   * pass their expected phase order explicitly.
   */
  phases?: string[],
): void {
  // Canonical 6-step sequence with WIPE inserted between select_pa and
  // key_generation (see plan-builder.ts).  Tests that want the older
  // pre-WIPE shape for regression coverage pass an explicit `phases`
  // array.
  const defaultPhases = [
    'select_pa',
    'wipe_applet',
    'key_generation',
    'provisioning',
    'finalizing',
    'confirming',
  ];
  const resolvedPhases =
    phases ??
    defaultPhases.slice(0, expectedSteps).concat(
      // Pad if the caller requested more steps than the canonical 6.
      Array(Math.max(0, expectedSteps - defaultPhases.length)).fill('unknown'),
    );
  planStepState.set(sessionId, {
    expectedSteps,
    lastProcessed,
    expiresAt: Date.now() + PLAN_STEP_STATE_TTL_MS,
    phases: resolvedPhases,
  });
}

// ---------------------------------------------------------------------------
// Session Manager
// ---------------------------------------------------------------------------

export class SessionManager {
  /**
   * Start a provisioning session.
   * Validates the card has a READY SAD record, creates a ProvisioningSession.
   */
  async startSession(proxyCardId: string): Promise<SessionState> {
    // Opportunistic sweep of expired cache entries so the maps don't
    // accumulate stale plaintext / step-cursors when mobiles abandon
    // sessions.  Both are in-memory Maps, cheap to iterate.
    pruneSadCache();
    prunePlanStepState();

    // The proxyCardId on the wire can be either namespace:
    //   - pxy_xxx  : ParamRecord.proxyCardId (prototype, PARAM_BUNDLE)
    //   - proxy_xxx: SadRecord.proxyCardId   (legacy, TRANSFER_SAD)
    // Try ParamRecord first so hybrid cards (both rows linked to the
    // same card) get the prototype path.  Both tables have @unique
    // constraints on proxyCardId, so at most one hit in each.
    const paramRecord = await prisma.paramRecord.findUnique({
      where: { proxyCardId },
      select: { id: true, cardId: true, status: true },
    });

    let cardId: string;
    let sadRecordId: string;

    if (paramRecord) {
      if (paramRecord.status !== 'READY') {
        throw new Error(
          `ParamRecord for proxyCardId ${proxyCardId} is ${paramRecord.status}, expected READY`,
        );
      }
      cardId = paramRecord.cardId;
      // ProvisioningSession.sadRecordId is still NOT NULL in the
      // schema; use any historic SadRecord for this card as the FK
      // placeholder.  Prototype flow doesn't consume the SAD bytes —
      // wrap happens from ParamRecord.bundleEncrypted (+ the per-
      // column envelopes once PARAMS_PER_COLUMN=1) via
      // buildTransferParamsApduChunks.  See schema.prisma TODO for
      // the proper sadRecordId-nullable migration.
      const placeholder = await prisma.sadRecord.findFirst({
        where: { cardId: paramRecord.cardId },
        orderBy: { createdAt: 'desc' },
        select: { id: true },
      });
      if (!placeholder) {
        throw new Error(
          `[rca] prototype session for ${proxyCardId} has no SadRecord for FK placeholder — card was never SAD-registered`,
        );
      }
      sadRecordId = placeholder.id;
    } else {
      const sadRecord = await prisma.sadRecord.findUnique({
        where: { proxyCardId },
      });
      if (!sadRecord || sadRecord.status !== 'READY') {
        throw new Error(`No READY SAD record for proxyCardId: ${proxyCardId}`);
      }
      cardId = sadRecord.cardId;
      sadRecordId = sadRecord.id;

      // Legacy-only: prefetch + decrypt the SAD blob so the plaintext
      // is ready by the time the mobile hits SAD_TRANSFER.  Prototype
      // flow skips this — decryption there happens later inside
      // buildTransferParamsApduChunks against ParamRecord data.
      const config = getRcaConfig();
      const encryptedBuf = Buffer.isBuffer(sadRecord.sadEncrypted)
        ? sadRecord.sadEncrypted
        : Buffer.from(sadRecord.sadEncrypted);
      const ttlMs = (config.WS_TIMEOUT_SECONDS ?? 60) * 1000;
      const sessionIdForCache = ''; // set below after session.create
      void sessionIdForCache; // appease no-unused-vars; captured via closure on `session.id`
      const prefetch = DataPrepService.decryptSad(
        encryptedBuf,
        config.KMS_SAD_KEY_ARN ?? '',
        sadRecord.sadKeyVersion,
      );
      // Chain the cache-store to session creation below so we can key
      // the cache by the real session id rather than a stub.
      (this as unknown as { __prefetchSad?: { p: Promise<Buffer>; ttlMs: number } }).__prefetchSad = {
        p: prefetch,
        ttlMs,
      };
    }

    const session = await prisma.provisioningSession.create({
      data: {
        cardId,
        sadRecordId,
        phase: 'INIT',
      },
    });

    console.log(
      `[rca] session created: ${session.id} for card ${cardId} (path=${paramRecord ? 'param' : 'sad'})`,
    );
    metrics().counter('rca.session.started', 1, {
      path: paramRecord ? 'param' : 'sad',
    });

    // Wire up the legacy prefetch-into-cache once we have the real
    // session id.  Errors are swallowed here but replayed inline on
    // cache miss inside buildPlanContext.
    const stash = (this as unknown as {
      __prefetchSad?: { p: Promise<Buffer>; ttlMs: number };
    }).__prefetchSad;
    if (stash) {
      delete (this as unknown as { __prefetchSad?: unknown }).__prefetchSad;
      stash.p
        .then((payload) => storeSadInCache(session.id, payload, stash.ttlMs))
        .catch((err) => {
          console.warn(
            `[rca] SAD pre-decrypt failed for ${redactSid(session.id)}: ${err instanceof Error ? err.message : err} — will retry inline`,
          );
        });
    }

    return {
      sessionId: session.id,
      proxyCardId,
      cardId,
      sadRecordId,
      phase: 'INIT',
    };
  }

  /**
   * Process an incoming WebSocket message and return response messages.
   *
   * Two protocols coexist:
   *
   *   - **Classical** (phase-driven): server sends one APDU per round-trip,
   *     tracked via `ProvisioningSession.phase`.  Entered when the mobile
   *     app connects without `?mode=plan` and emits a `pa_fci` message
   *     after running SELECT PA locally.
   *   - **Plan** (pre-computed): server ships all 5 APDUs up front on WS
   *     open and the phone streams responses back indexed by step number.
   *     Entered when `?mode=plan` is on the WS URL; the initial message
   *     sent to the phone is `{type:'plan', steps: [...]}`.  Inbound
   *     responses carry the step `i` — handleMessage routes those through
   *     {@link handlePlanResponse} instead of the classical phase machine.
   *
   * Plan mode trims 2 s off the tap on 500 ms-RTT connections by removing
   * the 4 server-waits embedded in classical mode.  See plan-builder.ts
   * for the protocol rationale.
   */
  async handleMessage(sessionId: string, message: WSMessage): Promise<WSMessage[]> {
    if (message.type === 'pa_fci') {
      return this.handlePaFci(sessionId);
    }

    if (message.type === 'response') {
      // Plan-mode responses carry `i` (the step index).  Classical-mode
      // responses don't — they're phase-driven and read only hex/sw.
      if (typeof message.i === 'number') {
        return this.handlePlanResponse(sessionId, message);
      }
      return this.handleCardResponse(sessionId, message);
    }

    if (message.type === 'error') {
      await this.handleError(sessionId, message);
      return [];
    }

    return [];
  }

  /**
   * Plan-mode entry point: load the session's chip-profile + issuer-profile
   * + SAD-record inputs, decrypt the SAD blob, and assemble the full APDU
   * plan.
   *
   * Called from the WebSocket relay handler on connection open when the
   * client requested `?mode=plan`.  The relay sends the returned plan
   * over the wire and transitions the session's phase to PLAN_SENT.
   *
   * Failure modes:
   *   - Session missing: throws a plain Error (caller maps to
   *     PLAN_BUILD_FAILED on the wire).
   *   - IssuerProfile missing any of bankId/progId/scheme/postProvisionUrl:
   *     throws badRequest('issuer_profile_incomplete', ...) UNLESS
   *     RCA_ALLOW_MINIMAL_SAD=1 — then falls back to the minimal
   *     "PALISADE" payload + placeholder metadata, with a loud warning.
   *   - SadRecord decrypt fails: propagates the underlying error.
   *
   * No chipProfile defaults here anymore — the IssuerProfile must point
   * at a real ChipProfile.  The old 0x8001/0x9F48 fallback is retained
   * ONLY in the minimal-SAD dev path where the entire IssuerProfile is
   * allowed to be missing.
   */
  async buildPlanForSession(sessionId: string): Promise<Plan> {
    const session = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
      include: {
        sadRecord: true,
        card: {
          include: {
            program: {
              include: { issuerProfile: { include: { chipProfile: true } } },
            },
          },
        },
      },
    });
    if (!session) {
      throw new Error(`Unknown session: ${sessionId}`);
    }

    const issuerProfile = session.card?.program?.issuerProfile ?? null;
    const ctx = await this.buildPlanContext(
      issuerProfile,
      session.sadRecord,
      sessionId,
    );
    // Patent C16/C23 gate: strict mode MUST include GET_ATTESTATION_CHAIN
    // because the verifier needs the cardCert to chain-walk the
    // attestSig trailer.  Permissive mode leaves it off — legacy cards
    // (pre-Drop-3 applet bytecode) return 6D00 on INS=0xEE and would
    // fail-fast the whole plan.  Once every card in the fleet has been
    // re-personalised with STORE_ATTESTATION material AND bumped to
    // Drop 3 bytecode, permissive mode goes away and the gate collapses
    // to "always on".
    const attestationMode = getRcaConfig().PALISADE_ATTESTATION_MODE;
    const plan = buildProvisioningPlan(ctx, {
      includeAttestationChain: attestationMode === 'strict',
    });
    // Patent C5: arm the per-session step cursor BEFORE the plan goes on
    // the wire.  Any inbound plan-mode response must then match the
    // cursor (step index must strictly increment by 1 starting at 0) —
    // the server rejects anything else at handlePlanResponse.  Pass
    // the phase list so the inbound dispatcher can switch on
    // semantic phase rather than a hardcoded index (which would
    // mis-route when optional steps shift the key_generation index).
    initPlanStepState(sessionId, plan.steps.map((s) => s.phase));
    return plan;
  }

  /**
   * Resolve a PlanContext from a session's IssuerProfile + SadRecord.
   *
   * Path A (happy): IssuerProfile has bankId/progId/postProvisionUrl/scheme
   * and chipProfile.  Real SAD bytes are pulled from the pre-decrypt
   * cache when available (populated in `startSession`); otherwise
   * decrypted inline from SadRecord.sadEncrypted.
   *
   * Path B (RCA_ALLOW_MINIMAL_SAD=1 fallback): any of the required
   * IssuerProfile fields are missing.  We log a prominent warning and
   * synthesize a context using the minimal "PALISADE" SAD plus the old
   * placeholder metadata.  Dev only.
   *
   * Path C (neither): throw badRequest('issuer_profile_incomplete', ...).
   */
  private async buildPlanContext(
    issuerProfile: IssuerProfileShape | null,
    sadRecord: SadRecordShape | null,
    sessionId?: string,
  ): Promise<PlanContext> {
    const complete =
      issuerProfile !== null &&
      issuerProfile.bankId !== null &&
      issuerProfile.progId !== null &&
      issuerProfile.postProvisionUrl !== null &&
      issuerProfile.postProvisionUrl.length > 0 &&
      issuerProfile.chipProfile !== null;

    if (complete) {
      // Path A — all IssuerProfile fields populated; decrypt real SAD.
      if (!sadRecord) {
        throw badRequest(
          'sad_record_missing',
          'Session has no SAD record to decrypt',
        );
      }

      // Prefer the pre-decrypted plaintext from startSession's background
      // task when available.  Cache miss (pre-decrypt failed, or a
      // restart between /start and WS open) → decrypt inline.  Both
      // paths return the same Buffer shape downstream.
      let sadPayload = sessionId ? consumeSadFromCache(sessionId) : null;
      if (!sadPayload) {
        const config = getRcaConfig();
        const encryptedBuf = Buffer.isBuffer(sadRecord.sadEncrypted)
          ? sadRecord.sadEncrypted
          : Buffer.from(sadRecord.sadEncrypted);
        sadPayload = await DataPrepService.decryptSad(
          encryptedBuf,
          config.KMS_SAD_KEY_ARN ?? '',
          sadRecord.sadKeyVersion,
        );
      }

      const ip = issuerProfile as IssuerProfileShape & {
        bankId: number;
        progId: number;
        postProvisionUrl: string;
        chipProfile: ChipProfileShape;
      };

      return {
        iccPrivateKeyDgi: ip.chipProfile.iccPrivateKeyDgi,
        iccPrivateKeyTag: ip.chipProfile.iccPrivateKeyTag,
        bankId:            ip.bankId,
        progId:            ip.progId,
        scheme:            schemeByteForIssuer(ip.scheme),
        postProvisionUrl:  ip.postProvisionUrl,
        sadPayload,
      };
    }

    // Path B/C: IssuerProfile incomplete.  Check the dev flag.
    const config = getRcaConfig();
    if (config.RCA_ALLOW_MINIMAL_SAD !== '1') {
      throw badRequest(
        'issuer_profile_incomplete',
        'IssuerProfile is missing one or more required fields ' +
        '(bankId, progId, postProvisionUrl, chipProfile).  Set ' +
        'RCA_ALLOW_MINIMAL_SAD=1 for dev fallback.',
      );
    }
    // Hard guard: this flag ships cards with placeholder bank/program IDs
    // which CORRUPTS per-FI chip identity.  Must never be active in prod.
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'RCA_ALLOW_MINIMAL_SAD=1 is forbidden in production.  Populate ' +
        'IssuerProfile (bankId/progId/postProvisionUrl/scheme/chipProfile) ' +
        'on the Program instead.  The dev flag corrupts per-FI identity on ' +
        'the chip and leaks placeholder values into the provenance log.',
      );
    }

    console.warn(
      '[rca] RCA_ALLOW_MINIMAL_SAD=1: falling back to minimal "PALISADE" ' +
      'SAD with placeholder metadata — this corrupts per-FI identity on ' +
      'the chip and must NOT be enabled in prod.  Populate IssuerProfile ' +
      '(bankId/progId/postProvisionUrl/scheme/chipProfile) to use real SAD.',
    );

    return {
      iccPrivateKeyDgi: issuerProfile?.chipProfile?.iccPrivateKeyDgi ?? 0x8001,
      iccPrivateKeyTag: issuerProfile?.chipProfile?.iccPrivateKeyTag ?? 0x9F48,
      bankId:           0x00000001,
      progId:           0x00000001,
      scheme:           0x01,
      postProvisionUrl: 'mobile.karta.cards',
      sadPayload:       buildMinimalSadPayload(),
    };
  }

  // -----------------------------------------------------------------------
  // Phase handlers
  // -----------------------------------------------------------------------

  /**
   * Phase 0: PA FCI received → send GENERATE_KEYS directly (no SCP11).
   *
   * Palisade dropped SCP11c entirely (it never worked end-to-end with the
   * real PA applet — see palisade/tools/test_ssd_e2e.py which is the
   * working reference flow).  The sequence is:
   *   SELECT PA → FCI → GENERATE_KEYS → TRANSFER_SAD (direct delivery)
   *               → re-SELECT PA → FINAL_STATUS → CONFIRM
   *
   * No PSO, no ECDH, no script wrapping.  The SAD is transferred as
   * cleartext over the WebSocket relay because the relay is already
   * inside our trust boundary (HMAC-signed APDU stream from the mobile
   * app the cardholder is logged into).
   */
  private async handlePaFci(sessionId: string): Promise<WSMessage[]> {
    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: { phase: 'KEYGEN' },
    });

    // GENERATE_KEYS for pa-v3.  Body layout:
    //
    //   byte 0          0x01 = "ECC P-256 keypair please"
    //   bytes 1..N      sessionId (UTF-8), up to 63 B
    //
    // The session ID MUST match the HKDF `info` string that
    // wrapParamBundle uses at TRANSFER_PARAMS wrap time — pa-v3's
    // EcdhUnwrapper re-derives the AES/HMAC session keys using the
    // sessionId bytes stored here; mismatch → HMAC verify fail →
    // SW=6A80 (SW_PARAM_BUNDLE_GCM_FAILED).  Legacy pa-v1 ignored this
    // field entirely, which is why the original GENERATE_KEYS APDU
    // shipped no body beyond the keyType marker.
    //
    // Trailing Le = 0x41 (65 — exact pubkey response size) rather than
    // 0x00 (max 256).  Debug variant hunting iOS ISO-DEP quirks; chip
    // accepts both equally.  Revert to 0x00 once pa-v3 e2e lands.
    const sessionIdBytes = Buffer.from(sessionId, 'utf8');
    if (sessionIdBytes.length > 63) {
      throw new Error(
        `[rca] sessionId too long for GENERATE_KEYS body: ${sessionIdBytes.length} B > 63 B max`,
      );
    }
    const keygenBody = Buffer.concat([
      Buffer.from([0x01]),
      sessionIdBytes,
    ]);
    const keygenApduBuf = Buffer.concat([
      Buffer.from([0x80, 0xE0, 0x00, 0x00, keygenBody.length]),
      keygenBody,
      Buffer.from([0x41]),
    ]);
    const keygenHex = keygenApduBuf.toString('hex').toUpperCase();

    // Temporary prototype-debug log so we can confirm on the wire what
    // bytes rca is handing to the mobile.  Remove once pa-v3 e2e lands.
    console.log(`[rca][debug] classical keygen APDU → session=${sessionId} hex=${keygenHex} (len=${keygenApduBuf.length}B)`);

    return [{
      type: 'apdu',
      hex: keygenHex,
      phase: 'key_generation',
      progress: 0.1,
    }];
  }

  /**
   * Route card responses based on the current phase.
   *
   * The mobile app's WS message shape for a card response is:
   *   { type:'response', hex:'<full response including SW>', sw:'<last 4 hex chars>' }
   *
   * `hex` already contains the full response bytes *including* the trailing
   * SW, so `sw` is a duplicate of the last 2 bytes of `hex`.  We read SW
   * from `sw` directly (authoritative, always 4 hex chars when well-formed)
   * and slice the data portion off `hex`.  An older version of this handler
   * concatenated `hex + sw` and parsed last-2-bytes-of-that as SW, which
   * worked but left phase-handler callers with a buffer that still had SW
   * bytes glued on the end.
   *
   * Empty/missing fields: the app sometimes emits `{hex:'', sw:''}` after a
   * native NFC transceive failure.  Distinguish that from a real chip error
   * so the logs point at the right layer.
   */
  private async handleCardResponse(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const rawHex = msg.hex ?? '';
    const rawSw = msg.sw ?? '';
    const appErrored = rawSw.length !== 4 && rawHex.length < 4;

    let sw: number;
    if (rawSw.length === 4) {
      sw = parseInt(rawSw, 16);
    } else if (rawHex.length >= 4) {
      // Fallback — sw field wasn't populated but full response landed in hex.
      sw = parseInt(rawHex.slice(-4), 16);
    } else {
      sw = 0x6f00;
    }

    // Strip trailing SW from data so phase handlers get clean bytes.
    // If hex already ended in the SW (expected shape), drop those 4 chars.
    const dataHex =
      rawHex.length >= 4 && rawHex.slice(-4).toLowerCase() === rawSw.toLowerCase()
        ? rawHex.slice(0, -4)
        : rawHex;
    const normalizedMsg: WSMessage = { ...msg, hex: dataHex, sw: rawSw };

    // Check for card error
    if (sw !== 0x9000) {
      const swStr = sw.toString(16).padStart(4, '0').toUpperCase();
      if (appErrored) {
        console.warn(
          `[rca] mobile-side NFC failure (empty response) in session ${sessionId}: ` +
          `msg={type:"${msg.type}", hex.len=${rawHex.length}, sw="${rawSw}", phase:"${msg.phase ?? ''}"}.`
          + ` RCA is synthesizing SW=6F00 but the chip never responded.`,
        );
      } else {
        console.warn(
          `[rca] chip card error SW=${swStr} in session ${sessionId} ` +
          `(response was data.len=${dataHex.length / 2}B, sw="${rawSw}")`,
        );
      }
      return [{
        type: 'error',
        code: appErrored ? 'NFC_ERROR' : 'CARD_ERROR',
        message: appErrored
          ? `Mobile NFC transceive failed — no chip response received`
          : `Card returned error SW=${swStr}`,
      }];
    }

    const session = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
    });
    if (!session) return [];

    switch (session.phase) {
      case 'KEYGEN':
        return this.handleKeygenResponse(sessionId, normalizedMsg);
      case 'SAD_TRANSFER':
        return this.handleSadResponse(sessionId);
      case 'AWAITING_FINAL':
        return this.handleFinalStatus(sessionId, normalizedMsg);
      case 'CONFIRMING':
        // Chip's CONFIRM 9000 just landed — commit the session + flip
        // Card.status=PROVISIONED + emit `complete` to the mobile.
        // SW != 9000 already rejected upstream (line ~910), so
        // arriving here means the applet latched to STATE_COMMITTED.
        return this.handleConfirmResponse(sessionId);
      default:
        return [];
    }
  }

  /**
   * Phase 2: Process keygen response, store ICC public key + attestation,
   * run the stub attestation verify, then send TRANSFER_SAD.
   *
   * Response layout: ICC_PubKey(65) || Attest_Sig(var, ~70-72) || CPLC(42)
   *
   * The pubkey capture + TRANSFER_SAD assembly used to live inline here
   * as 40 lines of hand-sliced Buffer math and placeholder metadata.
   * Both responsibilities now route through dedicated helpers so the
   * classical path matches plan mode byte-for-byte.
   */
  private async handleKeygenResponse(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const respData = Buffer.from(msg.hex ?? '', 'hex');

    // Load session with SAD record and card's program/issuer/chip profile
    const session = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
      include: {
        sadRecord: true,
        card: {
          include: {
            program: {
              include: { issuerProfile: { include: { chipProfile: true } } },
            },
          },
        },
      },
    });

    if (!session) return [];

    // Extract pubkey + attestation + CPLC + optional cert chain from the
    // GENERATE_KEYS response.  Patent claim C23: verify attestation before
    // encrypting SAD for this chip.  Strict mode refuses to continue if
    // cert-chain validation fails; permissive mode (legacy) logs a warning
    // and accepts.  See services/rca/src/services/attestation-verifier.ts.
    const extracted = AttestationVerifier.extract(respData);
    const { iccPubkey, attestation } = extracted;

    // Patent C4 chip-side nonce binding: pa-v3 writes the 16-byte nonce
    // immediately after the 65-byte iccPubkey in the GEN_KEYS response.
    // Cache it by sessionId for the TRANSFER_PARAMS wrap (minutes later
    // at most).  Older applets that don't emit a nonce produce a shorter
    // response, in which case this subarray is empty and we fall back
    // to the legacy HKDF info shape (sessionId alone) at wrap time.
    const CHIP_NONCE_LEN = 16;
    if (
      respData.length >= ICC_PUBKEY_LEN + CHIP_NONCE_LEN &&
      respData.length !== ICC_PUBKEY_LEN  // legacy pubkey-only response shape
    ) {
      const nonce = Buffer.from(
        respData.subarray(ICC_PUBKEY_LEN, ICC_PUBKEY_LEN + CHIP_NONCE_LEN),
      );
      putChipNonce(sessionId, nonce, getRcaConfig().WS_TIMEOUT_SECONDS * 1000);
    }
    const mode = getRcaConfig().PALISADE_ATTESTATION_MODE;
    const verifyResult = AttestationVerifier.verify(extracted, mode, attestationConfigFor(mode));
    metrics().counter('rca.attestation.verify', 1, {
      mode,
      result: verifyResult.ok ? 'ok' : 'fail',
      path: 'classical',
    });
    if (!verifyResult.ok) {
      // eslint-disable-next-line no-console
      console.error(
        `[rca] attestation verification FAILED (mode=${mode}): ${verifyResult.warning}`,
      );
      // Mark the session failed so the mobile app sees a clean error.
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'FAILED', iccPublicKey: iccPubkey, attestation },
      });
      return [{
        type: 'error',
        code: 'attestation_failed',
        message: verifyResult.warning ?? 'attestation verification failed',
      }];
    }

    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'SAD_TRANSFER',
        iccPublicKey: iccPubkey,
        attestation,
      },
    });

    // Dispatch: ParamBundle prototype path vs legacy SAD path.
    //
    // Null-check FIRST — legacy cards have Card.paramRecordId = null
    // and always fall through to buildTransferSadApdu (unchanged).
    //
    // Env flag gates the prototype route.  Even if a card has a
    // ParamRecord, RCA_ENABLE_PARAM_BUNDLE = '0' (default) forces the
    // legacy path.  Belt-and-suspenders: two guards must both flip to
    // '1' / non-null before a single byte of prototype code executes
    // on a provisioning session.
    const paramRecordId = session.card?.paramRecordId ?? null;
    const paramBundleEnabled = getRcaConfig().RCA_ENABLE_PARAM_BUNDLE === '1';
    const useParamBundle = paramRecordId !== null && paramBundleEnabled;

    let transferApdu: Buffer;
    let wirePhase: string;
    if (useParamBundle) {
      // PARAM_BUNDLE path — can span multiple chained short APDUs.
      // Build all chunks up front, queue the rest for handleSadResponse
      // to drain, and emit the first chunk now.
      const chunks = await this.buildTransferParamsApduChunks(
        paramRecordId!,
        iccPubkey,
        sessionId,
      );
      if (chunks.length === 0) {
        throw new Error(`[rca] TRANSFER_PARAMS produced 0 chunks for session ${sessionId}`);
      }
      const ttlMs = (getRcaConfig().WS_TIMEOUT_SECONDS ?? 60) * 1000;
      putParamChunks(sessionId, chunks, ttlMs);
      transferApdu = chunks[0];
      wirePhase = chunks.length > 1
        ? 'provisioning_param_bundle_chain_1_of_' + chunks.length
        : 'provisioning_param_bundle';
    } else {
      const ctx = await this.buildPlanContext(
        session.card?.program?.issuerProfile ?? null,
        session.sadRecord,
        sessionId,
      );
      try {
        transferApdu = buildTransferSadApdu(ctx);
      } finally {
        // PCI 3.5 — S-2 from the post-fix audit: plaintext SAD contains
        // per-card EMV master keys, PAN, expiry, etc.  After the wire APDU
        // is built, the plaintext bytes serve no purpose — scrub the Buffer
        // so a later core dump / memory scrape doesn't leak it.  The
        // Buffer is the only reference the caller holds; scrub in place.
        ctx.sadPayload.fill(0);
      }
      wirePhase = 'provisioning';
    }

    return [{
      type: 'apdu',
      hex: transferApdu.toString('hex').toUpperCase(),
      phase: wirePhase,
      progress: 0.55,
    }];
  }

  /**
   * Build the TRANSFER_PARAMS APDU for a card on the ParamBundle
   * prototype flow.  Loads the ParamRecord, decrypts the at-rest
   * bundle (envelope-encrypted via KMS or dev-AES, same pattern as
   * SadRecord), ECDH-wraps against the chip's pubkey, returns the
   * wire-ready APDU.
   *
   * Scrubs the plaintext ParamBundle after wrap — the wrapped bytes
   * are the only thing that persists on the wire.  Also marks the
   * ParamRecord CONSUMED on the way out so a second provisioning
   * attempt against the same record is rejected upfront.
   */
  private async buildTransferParamsApduChunks(
    paramRecordId: string,
    chipPubUncompressed: Buffer,
    sessionId: string,
  ): Promise<Buffer[]> {
    const pr = await prisma.paramRecord.findUnique({
      where: { id: paramRecordId },
    });
    if (!pr || pr.status !== 'READY') {
      throw badRequest(
        'param_record_not_ready',
        `ParamRecord ${paramRecordId} is ${pr?.status ?? 'missing'}, expected READY`,
      );
    }

    const config = getRcaConfig();
    const kmsArn = config.KMS_SAD_KEY_ARN ?? '';

    // Decrypt the at-rest bundle first.  Under legacy mode this is
    // the full ParamBundle; under C17/C22 per-column mode it's the
    // "reduced" bundle with the four crypto-sensitive TLVs zeroed
    // out (see data-prep.prepareParamBundle::reduceSensitiveFields).
    const restedBundle = await DataPrepService.decryptSad(
      Buffer.isBuffer(pr.bundleEncrypted)
        ? pr.bundleEncrypted
        : Buffer.from(pr.bundleEncrypted),
      kmsArn,
      pr.bundleKeyVersion,
    );

    // Patent C17/C22 per-column dispatch.  Auto-detect by presence of
    // the envelope columns — this row was written by a data-prep with
    // PARAMS_PER_COLUMN=1.  The legacy path (all four columns NULL)
    // uses `restedBundle` verbatim as plaintextBundle.
    let plaintextBundle: Buffer;
    const perColumn = pr.mkAcEncrypted != null;
    if (perColumn) {
      // Decrypt the four per-field envelopes in parallel.  Each is a
      // small KMS round-trip (tens of bytes of ciphertext each); all
      // four are independent so parallel cuts the critical path.
      const [mkAc, mkSmi, mkSmc, rsaPriv] = await Promise.all([
        DataPrepService.decryptSad(
          Buffer.from(pr.mkAcEncrypted!),
          kmsArn,
          pr.mkAcKeyVersion ?? 0,
        ),
        DataPrepService.decryptSad(
          Buffer.from(pr.mkSmiEncrypted!),
          kmsArn,
          pr.mkSmiKeyVersion ?? 0,
        ),
        DataPrepService.decryptSad(
          Buffer.from(pr.mkSmcEncrypted!),
          kmsArn,
          pr.mkSmcKeyVersion ?? 0,
        ),
        DataPrepService.decryptSad(
          Buffer.from(pr.iccRsaPrivEncrypted!),
          kmsArn,
          pr.iccRsaPrivKeyVersion ?? 0,
        ),
      ]);
      try {
        const tagMap = new Map<number, Buffer>([
          [ParamTag.MK_AC, mkAc],
          [ParamTag.MK_SMI, mkSmi],
          [ParamTag.MK_SMC, mkSmc],
          [ParamTag.ICC_RSA_PRIV, rsaPriv],
        ]);
        plaintextBundle = spliceSensitiveFields(restedBundle, tagMap);
      } finally {
        // Scrub each per-field buffer the moment the splice is done.
        // Total plaintext-in-RAM window per field now bounded by the
        // ~microsecond splice copy, not the ~50 ms whole-bundle wrap.
        mkAc.fill(0);
        mkSmi.fill(0);
        mkSmc.fill(0);
        rsaPriv.fill(0);
        restedBundle.fill(0);
      }
    } else {
      plaintextBundle = restedBundle;
    }

    // Patent C4: feed the chip-side nonce (captured in
    // handleKeygenResponse) into the wrap's HKDF info so the AES/IV/HMAC
    // triple binds to the specific GEN_KEYS session.  getChipNonce
    // returns undefined for older applets; wrapParamBundle then falls
    // back to legacy info shape (sessionId alone).
    const chipNonce = getChipNonce(sessionId);

    let chunks: Buffer[];
    try {
      chunks = buildParamBundleApduChunks({
        plaintextBundle,
        chipPubUncompressed,
        sessionId,
        chipNonce,
      });
    } finally {
      plaintextBundle.fill(0);
    }
    return chunks;
  }

  /**
   * Phase 3: SAD / ParamBundle transfer complete → send FINAL_STATUS.
   *
   * For the PARAM_BUNDLE path with a multi-chunk TRANSFER_PARAMS, each
   * chip ack lands here.  We peek the chunk queue: if there are more
   * chunks to send, emit the next one and stay in the SAD_TRANSFER
   * phase; only the last chunk's ack triggers the real transition to
   * AWAITING_FINAL and the FINAL_STATUS APDU.  Single-APDU flows
   * (legacy SAD, or PARAM_BUNDLE bodies that fit in 255 B) skip this
   * entirely and go straight to FINAL_STATUS.
   */
  private async handleSadResponse(sessionId: string): Promise<WSMessage[]> {
    const advance = advanceParamChunk(sessionId);
    if (!advance.done && advance.next) {
      // Still more chained chunks to ship; stay in SAD_TRANSFER.
      return [{
        type: 'apdu',
        hex: advance.next.toString('hex').toUpperCase(),
        phase: 'provisioning_param_bundle_chain',
        progress: 0.55,
      }];
    }

    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: { phase: 'AWAITING_FINAL' },
    });

    return [{
      type: 'apdu',
      hex: APDUBuilder.finalStatus(),
      phase: 'finalizing',
      progress: 0.80,
    }];
  }

  /**
   * Phase 4-5: Process final status, send CONFIRM, fire callback.
   */
  private async handleFinalStatus(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const respData = Buffer.from(msg.hex ?? '', 'hex');
    const statusByte = respData.length > 0 ? respData[0] : 0;
    const success = statusByte === 0x01;

    if (!success) {
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'FAILED', failedAt: new Date(), failureReason: 'PA_FAILED' },
      });
      return [{
        type: 'error',
        code: 'PA_FAILED',
        message: 'Provisioning failed on card',
      }];
    }

    // Extract provenance hash (32 bytes) + FIDO data
    const provHash = respData.length > 33 ? respData.subarray(1, 33).toString('hex') : '';
    let fidoCredData = '';
    if (respData.length > 66) {
      const credIdLen = respData[65];
      const credId = respData.subarray(66, 66 + credIdLen);
      fidoCredData = credId.toString('base64url');
    }

    // Two-phase finalize — split the previous single-$transaction into
    // (a) AWAITING_FINAL → CONFIRMING (captures provenance + FIDO data)
    // (b) CONFIRMING → COMPLETE (flips Card.status=PROVISIONED +
    //     SadRecord.status=CONSUMED, fires callback, emits `complete`
    //     to the mobile client)
    //
    // Phase (b) only runs from handleConfirmResponse AFTER the chip's
    // CONFIRM 9000 lands — previously we kicked an async $transaction
    // + emitted `complete` in the same message as the CONFIRM APDU,
    // which raced the mobile client's UI flip against the CONFIRM
    // actually reaching the card.  The failure mode: user lifts card
    // as soon as the UI says "provisioned" → CONFIRM APDU dies with
    // "Tag not connected" → applet stuck in STATE_AWAITING_CONFIRM →
    // server row already says PROVISIONED.
    //
    // Split-phase cost: ~one extra WS round-trip on the success path
    // (mobile already does the SEND-CONFIRM / RECV-9000 dance, we just
    // hold `complete` until the 9000 arrives).  No extra chip or DB
    // work.  Correct ordering is worth the ~20 ms.
    const preFetched = await prisma.provisioningSession.findUnique({
      where: { id: sessionId },
      include: { card: true, sadRecord: true },
    });
    if (!preFetched) {
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'FAILED', failedAt: new Date(), failureReason: 'session_missing' },
      });
      return [{ type: 'error', code: 'session_missing', message: 'Session vanished between FINAL_STATUS and commit' }];
    }

    // Phase (a): capture what we got from FINAL_STATUS + advance the
    // state machine to CONFIRMING.  No Card / SadRecord writes yet —
    // those are phase (b), conditional on the chip's CONFIRM ack.
    // Synchronous so a DB outage surfaces as an immediate error to
    // the mobile (rather than a silent race that leaves the session
    // in an inconsistent phase).
    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'CONFIRMING',
        provenance: provHash,
        fidoCredData,
      },
    });

    return [
      { type: 'apdu', hex: APDUBuilder.confirm(), phase: 'confirming', progress: 0.95 },
      // NOTE: no `{type:'complete'}` here.  It fires from
      // handleConfirmResponse once the chip acks 9000.  Mobile UI
      // should stay in a "finalizing" state between these two
      // messages (~20-30 ms typical).
    ];
  }

  /**
   * CONFIRMING phase handler — runs when the chip's 9000 response to
   * the CONFIRM APDU lands.  SW != 9000 is caught by handleCardResponse
   * before this runs, so by the time we're here the chip is latched
   * to STATE_COMMITTED.  Commits the Card.status=PROVISIONED flip +
   * SadRecord/ParamRecord CONSUMED + session.COMPLETE in a single
   * atomic transaction, fires the activation callback, then emits
   * `complete` to the mobile client.
   */
  private async handleConfirmResponse(sessionId: string): Promise<WSMessage[]> {
    const committed = await prisma.$transaction(async (tx) => {
      const s = await tx.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'COMPLETE', completedAt: new Date() },
        include: { card: true, sadRecord: true },
      });
      await tx.card.update({
        where: { id: s.cardId },
        data: { status: 'PROVISIONED', provisionedAt: new Date() },
      });
      await tx.sadRecord.update({
        where: { id: s.sadRecordId },
        data: { status: 'CONSUMED' },
      });
      // Mirror the SadRecord CONSUMED transition onto ParamRecord
      // when the card rode the prototype path.  Belt-and-suspenders:
      // the retention reaper would sweep READY-and-expired ParamRecords
      // eventually, but an explicit CONSUMED matches the state-
      // machine semantics callers expect.
      if (s.card.paramRecordId) {
        await tx.paramRecord.update({
          where: { id: s.card.paramRecordId },
          data: { status: 'CONSUMED' },
        });
      }
      return s;
    });

    console.log(
      `[rca] provisioning complete: session=${redactSid(sessionId)}, card=${redactSid(committed.cardId)}`,
    );
    metrics().counter('rca.provisioning.complete', 1, { mode: 'classical' });

    // Fire callback to activation — best-effort, idempotent on the
    // activation side so a retry from here (or the retention reaper)
    // is safe.
    this.fireCallback(committed.card.cardRef, committed.card.chipSerial ?? '').catch((err) =>
      console.error('[rca] callback failed:', err),
    );

    return [
      { type: 'complete', proxyCardId: committed.sadRecord.proxyCardId },
    ];
  }

  // -----------------------------------------------------------------------
  // Plan-mode response handlers
  //
  // The 5 plan steps correspond to the classical phases 1:1 (SELECT PA,
  // GENERATE_KEYS, TRANSFER_SAD, FINAL_STATUS, CONFIRM) but execute
  // without a server round-trip between them.  We still run the same
  // artefact-capture and DB-commit logic, just keyed off the response
  // `i` index rather than the session `phase`.
  // -----------------------------------------------------------------------

  /**
   * Route an indexed plan-mode response to the per-step handler.
   *
   * SW decoding matches the classical {@link handleCardResponse} exactly:
   * prefer `sw` when well-formed (4 hex chars), fall back to
   * last-4-hex-chars of `hex`, and synthesize 6F00 only if both are empty
   * (mobile-side NFC failure, not a chip error).  The critical difference
   * from classical mode: any non-9000 SW at ANY step is fatal, because
   * the phone has already committed to executing the subsequent steps.
   * We mark the session FAILED with a step-specific reason and rely on
   * the phone to abort remaining steps when it receives the {type:'error'}
   * reply.
   */
  private async handlePlanResponse(sessionId: string, msg: WSMessage): Promise<WSMessage[]> {
    const rawHex = msg.hex ?? '';
    const rawSw = msg.sw ?? '';
    const i = msg.i ?? -1;
    const appErrored = rawSw.length !== 4 && rawHex.length < 4;

    // Patent C5 step-cursor enforcement.  `advancePlanStep` rejects:
    //   - first message arriving with i != 0
    //   - any replay (i <= lastProcessed)
    //   - any skip (i > lastProcessed + 1) — prevents bypassing step 1
    //     (attestation verify) or step 3 (FINAL_STATUS decode) by
    //     jumping forward
    //   - out-of-range indices (< 0 or >= expectedSteps)
    //   - unknown session (server restart lost cursor, or no prior plan)
    //   - expired session
    // On reject we FAIL the session so any subsequent in-flight
    // responses from the same WS are also rejected on the phase guard.
    const advance = advancePlanStep(sessionId, i);
    if (!advance.ok) {
      // Emit a CloudWatch counter so dashboards can alarm on rejected
      // step bursts — either a buggy mobile build or an attack probing
      // the cursor.  Reason is a low-cardinality enum
      // (missing/expired/out_of_range/replay/skip) so it's safe as a
      // CloudWatch dimension.  Extract just the code, not the
      // parenthesised numbers.
      const reasonCode = advance.reason.split('(')[0];
      metrics().counter('rca.plan_step.rejected', 1, { reason: reasonCode });
      console.warn(
        `[rca] plan-mode step rejected for session ${redactSid(sessionId)}: i=${i} reason=${advance.reason}`,
      );
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: {
          phase: 'FAILED',
          failedAt: new Date(),
          failureReason: advance.reason,
        },
      }).catch(() => { /* best-effort; session may already be gone */ });
      clearPlanStepState(sessionId);
      return [{
        type: 'error',
        code: 'plan_step_invalid',
        message: `plan step rejected: ${advance.reason}`,
      }];
    }

    let sw: number;
    if (rawSw.length === 4) {
      sw = parseInt(rawSw, 16);
    } else if (rawHex.length >= 4) {
      sw = parseInt(rawHex.slice(-4), 16);
    } else {
      sw = 0x6f00;
    }

    const dataHex =
      rawHex.length >= 4 && rawHex.slice(-4).toLowerCase() === rawSw.toLowerCase()
        ? rawHex.slice(0, -4)
        : rawHex;
    const data = Buffer.from(dataHex, 'hex');

    if (sw !== 0x9000) {
      const swStr = sw.toString(16).padStart(4, '0').toUpperCase();
      if (appErrored) {
        console.warn(
          `[rca] plan-mode mobile NFC failure at step ${i} in session ${sessionId}: ` +
          `empty hex + empty sw.  Synthesizing 6F00.`,
        );
      } else {
        console.warn(
          `[rca] plan-mode chip error SW=${swStr} at step ${i} in session ${sessionId}`,
        );
      }
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: {
          phase: 'FAILED',
          failedAt: new Date(),
          failureReason: appErrored ? `NFC_ERROR_step_${i}` : `CARD_ERROR_${swStr}_step_${i}`,
        },
      });
      return [{
        type: 'error',
        code: appErrored ? 'NFC_ERROR' : 'CARD_ERROR',
        message: appErrored
          ? `Mobile NFC transceive failed at plan step ${i}`
          : `Card returned error SW=${swStr} at plan step ${i}`,
      }];
    }

    // Phase-based dispatch.  Optional plan steps (GET_ATTESTATION_CHAIN,
    // chip-challenge pair) shift the canonical key_generation /
    // provisioning / finalizing / confirming indices around — switching
    // on the phase name resolves that without a per-option index table.
    const phase = phaseForPlanStep(sessionId, i);
    if (phase === null) {
      console.warn(
        `[rca] plan step ${i} has no phase mapping in session ${sessionId} ` +
          `(advancePlanStep accepted it, so this is a state desync)`,
      );
      return [];
    }
    switch (phase) {
      case 'select_pa':
        return []; // Phone parsed FCI locally; nothing server-side.
      case 'wipe_applet':
        // Idempotency guard — see plan-builder.ts:WIPE_APDU.  Chip
        // returns SW=9000 with no data.  We just accept the step-cursor
        // advance and continue.  Logging the wipe is useful for audit:
        // every successful plan includes a reset of chip state before
        // fresh key generation.
        console.log(
          `[rca][plan] wipe applied: session=${redactSid(sessionId)} — ` +
            `applet now STATE_IDLE (attestation material preserved)`,
        );
        return [];
      case 'chip_challenge_select':
      case 'chip_challenge_fetch':
        // Audit-trail only today; PA applet doesn't consume the nonce
        // yet.  The step-cursor advance was enough — no server action.
        return [];
      case 'get_attestation_chain':
        return this.handlePlanAttestationChain(sessionId, data);
      case 'key_generation':
        return this.handlePlanKeygen(sessionId, data);
      case 'provisioning':
        return []; // PA returns STATUS bytes; no server action.
      case 'finalizing':
        return this.handlePlanFinalStatus(sessionId, data);
      case 'confirming':
        return this.handlePlanConfirm(sessionId);
      default:
        console.warn(
          `[rca] unknown plan phase '${phase}' at step ${i} in session ${sessionId}`,
        );
        return [];
    }
  }

  /**
   * Step 1: GENERATE_KEYS response — capture the chip's ECC P-256 public
   * key AND the vendor-signed attestation bytes.  In the classical path
   * this is handleKeygenResponse; plan mode skips the state-machine
   * transitions (no phase updates) because the phone is already executing
   * subsequent steps.
   *
   * Response body: ICC_PubKey(65) || Attest_Sig(~72) || CPLC(42).  We
   * store the pubkey and the raw attestation bytes for audit + offline
   * analysis.  AttestationVerifier.verify() is currently STUB MODE —
   * always returns ok=true while logging a prominent warning banner so
   * we can't accidentally ship this path as production.  We'll gate plan
   * execution on the real verdict once the mobile client supports the
   * protocol checkpoint mechanism (plan field {checkpointAfter: 1}).
   */
  /**
   * Step: GET_ATTESTATION_CHAIN response — stash the card cert blob
   * for the subsequent keygen-step verify.
   *
   * Wire body (from IssuerAttestation.getCardCert on the applet):
   *   card_pubkey(65) || cplc(42) || sig(DER ECDSA-SHA256)  — signed
   *   by the Issuer CA over (card_pubkey || cplc).
   *
   * Parsing is lenient here: we accept anything the applet sent and
   * pass it verbatim to AttestationVerifier.verify (which will
   * parseCardCert + chain-walk).  A card running pre-Drop-3 bytecode
   * would have returned 6D00 and the pre-switch fail-fast would
   * have aborted the plan before we got here — so reaching this
   * handler implies the chip's IssuerAttestation.getCardCert path
   * returned 9000.
   */
  private async handlePlanAttestationChain(
    sessionId: string,
    data: Buffer,
  ): Promise<WSMessage[]> {
    if (data.length === 0) {
      // Shouldn't happen on SW=9000, but treat as "no material loaded"
      // — strict mode will catch it at verify time with a clearer
      // 'cardCert missing' warning than anything we could emit here.
      console.warn(
        `[rca][plan] GET_ATTESTATION_CHAIN returned 9000 but zero bytes ` +
          `for session ${redactSid(sessionId)}; verify will fail strict`,
      );
      return [];
    }
    putCardCert(sessionId, data, PLAN_STEP_STATE_TTL_MS);
    // Echo a compact log line so operators can audit "did we actually
    // receive a cert" without chasing per-phase logs across services.
    console.log(
      `[rca][plan] attestation chain received: session=${redactSid(sessionId)} ` +
        `cardCertLen=${data.length}`,
    );
    return [];
  }

  private async handlePlanKeygen(sessionId: string, data: Buffer): Promise<WSMessage[]> {
    const extracted = AttestationVerifier.extract(data);
    const { iccPubkey, attestation } = extracted;
    // Patent C23 checkpoint: verify attestation before phone executes the
    // next step of the plan.  In strict mode, a failing verdict aborts the
    // session so TRANSFER_PARAMS / TRANSFER_SAD never runs.  In permissive
    // mode, we log a warning and continue — rollout path until the live
    // fleet has been re-personalised with issuer-signed attestation certs.
    const mode = getRcaConfig().PALISADE_ATTESTATION_MODE;
    // Pull the stashed cardCert off the per-session cache — written by
    // handlePlanAttestationChain when includeAttestationChain is on.
    // In permissive mode it's undefined (the step wasn't in the plan);
    // verify() then falls back to extract.cardCert which is the legacy
    // pre-split wire shape.
    const cardCertOverride = getCardCert(sessionId);
    const verifyResult = AttestationVerifier.verify(
      extracted,
      mode,
      attestationConfigFor(mode),
      cardCertOverride,
    );
    metrics().counter('rca.attestation.verify', 1, {
      mode,
      result: verifyResult.ok ? 'ok' : 'fail',
      path: 'plan',
    });
    if (!verifyResult.ok) {
      // eslint-disable-next-line no-console
      console.error(
        `[rca][plan] attestation verification FAILED (mode=${mode}): ${verifyResult.warning}`,
      );
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'FAILED', iccPublicKey: iccPubkey, attestation },
      });
      return [{
        type: 'error',
        code: 'attestation_failed',
        message: verifyResult.warning ?? 'attestation verification failed',
      }];
    }

    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        iccPublicKey: iccPubkey,
        attestation,
      },
    });
    return [];
  }

  /**
   * Step 3: FINAL_STATUS response — the PA's success/fail verdict.
   *
   * Response byte layout:
   *   [0]           status — 0x01 = success, anything else = failure
   *   [1..33]       provenance hash (32 bytes)
   *   [65]          FIDO credId length
   *   [66..66+len]  FIDO credId
   *
   * SW=9000 only tells us the APDU was well-formed; the semantic success
   * signal is data[0] == 0x01.  On failure we mark the session FAILED
   * and emit {type:'error'} so the phone aborts before step 4 (CONFIRM).
   * On success we extract provenance + FIDO data and transition to
   * AWAITING_CONFIRM — the actual card/SAD commit happens in step 4
   * once CONFIRM lands 9000 (matches classical semantics: step 4 is
   * what latches the chip to COMMITTED state).
   */
  private async handlePlanFinalStatus(sessionId: string, data: Buffer): Promise<WSMessage[]> {
    const statusByte = data.length > 0 ? data[0] : 0;

    if (statusByte !== 0x01) {
      await prisma.provisioningSession.update({
        where: { id: sessionId },
        data: { phase: 'FAILED', failedAt: new Date(), failureReason: 'PA_FAILED' },
      });
      return [{
        type: 'error',
        code: 'PA_FAILED',
        message: 'Provisioning failed on card',
      }];
    }

    const provHash = data.length > 33 ? data.subarray(1, 33).toString('hex') : '';
    let fidoCredData = '';
    if (data.length > 66) {
      const credIdLen = data[65];
      const credId = data.subarray(66, 66 + credIdLen);
      fidoCredData = credId.toString('base64url');
    }

    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'AWAITING_CONFIRM',
        provenance: provHash,
        fidoCredData,
      },
    });

    // No outbound message — phone is already executing step 4 locally.
    return [];
  }

  /**
   * Step 4: CONFIRM response — the chip has latched to COMMITTED.
   *
   * This is where we actually finalize the session: mark it COMPLETE,
   * flip Card.status to PROVISIONED, consume the SAD record, and fire
   * the async callback to the activation service.  The `complete`
   * response tells the phone the session ended successfully.
   *
   * Matches handleFinalStatus in the classical path, minus the CONFIRM
   * APDU send (phone already executed it before we got here).
   */
  private async handlePlanConfirm(sessionId: string): Promise<WSMessage[]> {
    // Same atomicity argument as handleFinalStatus in the classical path:
    // a crash between writes would leave an orphaned COMPLETE session with
    // an ACTIVATED (not PROVISIONED) card and a READY (not CONSUMED) SAD.
    // $transaction groups them so either all commit or none do.  PCI 10.5 /
    // patent C5.
    const session = await prisma.$transaction(async (tx) => {
      const s = await tx.provisioningSession.update({
        where: { id: sessionId },
        data: {
          phase: 'COMPLETE',
          completedAt: new Date(),
        },
        include: { card: true, sadRecord: true },
      });
      await tx.card.update({
        where: { id: s.cardId },
        data: { status: 'PROVISIONED', provisionedAt: new Date() },
      });
      await tx.sadRecord.update({
        where: { id: s.sadRecordId },
        data: { status: 'CONSUMED' },
      });
      return s;
    });

    console.log(
      `[rca] plan-mode provisioning complete: session=${redactSid(sessionId)}, card=${redactSid(session.cardId)}`,
    );
    metrics().counter('rca.provisioning.complete', 1, { mode: 'plan' });

    // Release the step cursor — session is terminal, any further plan
    // responses for this sessionId must fail at advancePlanStep.
    clearPlanStepState(sessionId);

    // Fire callback to activation service (async, non-blocking).
    this.fireCallback(session.card.cardRef, session.card.chipSerial ?? '').catch((err) =>
      console.error('[rca] callback failed:', err),
    );

    return [{
      type: 'complete',
      proxyCardId: session.sadRecord.proxyCardId,
    }];
  }

  /**
   * Handle app-reported error (NFC lost, etc.)
   */
  private async handleError(sessionId: string, msg: WSMessage): Promise<void> {
    await prisma.provisioningSession.update({
      where: { id: sessionId },
      data: {
        phase: 'FAILED',
        failedAt: new Date(),
        failureReason: msg.code ?? 'APP_ERROR',
      },
    });
    // Terminal transition — release plan-step cursor if this was a
    // plan-mode session.  Safe to call on classical sessions too (Map
    // delete of a non-existent key is a no-op).
    clearPlanStepState(sessionId);
    console.warn(
      `[rca] session error: ${sessionId} — ${msg.code}` +
      (msg.message ? `: ${msg.message}` : ''),
    );
  }

  /**
   * Fire HMAC-signed callback to the activation service.
   */
  private async fireCallback(cardRef: string, chipSerial: string): Promise<void> {
    const config = getRcaConfig();
    const { signRequest } = await import('@palisade/service-auth');
    const { request } = await import('undici');

    const path = `/api/cards/${encodeURIComponent(cardRef)}/provision-complete`;
    const body = JSON.stringify({ chipSerial });
    const bodyBuf = Buffer.from(body, 'utf8');

    const authorization = signRequest({
      method: 'POST',
      pathAndQuery: path,
      body: bodyBuf,
      keyId: 'rca',
      secret: config.CALLBACK_HMAC_SECRET,
    });

    await request(`${config.ACTIVATION_CALLBACK_URL}${path}`, {
      method: 'POST',
      headers: {
        authorization,
        'content-type': 'application/json',
      },
      body: bodyBuf,
    });
  }
}
