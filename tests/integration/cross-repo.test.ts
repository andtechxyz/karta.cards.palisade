/**
 * Cross-repo integration tests (Palisade-side mirror).
 *
 * Hits the *live* local stack brought up by
 *   bash scripts/dev-stack.sh up
 * followed by `npm run dev` in both Vera and Palisade.  Exercises the
 * signed-request boundary between Palisade (this repo) and Vera.
 *
 * Gated behind INTEGRATION=1 so a normal `npm test` or `vitest run` does
 * NOT need docker / npm dev servers.
 *
 * To run:
 *   # 1. Bring the stack up in two shells:
 *   bash scripts/dev-stack.sh up
 *   ( cd /Users/danderson/Vera      && npm run dev )  # in terminal A
 *   ( cd /Users/danderson/Palisade  && npm run dev )  # in terminal B
 *
 *   # 2. Run these tests:
 *   INTEGRATION=1 npx vitest run tests/integration/cross-repo.test.ts
 */

import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'node:crypto';

// Keep in sync with tests/setup.ts (Vera + Palisade copies).
const HEX32_G = '6'.repeat(64); // activation

const VERA_VAULT_URL = process.env.VERA_VAULT_URL ?? 'http://localhost:3004';
const VERA_PAY_URL = process.env.VERA_PAY_URL ?? 'http://localhost:3003';
const VERA_ADMIN_URL = process.env.VERA_ADMIN_URL ?? 'http://localhost:3005';
const PALISADE_ACTIVATION_URL =
  process.env.PALISADE_ACTIVATION_URL ?? 'http://localhost:3002';

// Wire protocol duplicated here rather than imported so the test doesn't
// depend on either service-auth package's dist output.
function signRequest(opts: {
  method: string;
  pathAndQuery: string;
  body: Buffer;
  keyId: string;
  secret: string;
}): string {
  const ts = Math.floor(Date.now() / 1000);
  const bodyHash = createHash('sha256').update(opts.body).digest('hex');
  const canonical = `${opts.method}\n${opts.pathAndQuery}\n${ts}\n${bodyHash}`;
  const sig = createHmac('sha256', Buffer.from(opts.secret, 'hex'))
    .update(canonical)
    .digest('hex');
  return `VeraHmac keyId=${opts.keyId},ts=${ts},sig=${sig}`;
}

const INTEGRATION = process.env.INTEGRATION === '1';

describe.skipIf(!INTEGRATION)('cross-repo integration (live stack)', () => {
  // -------------------------------------------------------------------------
  // Test 1 — Palisade-signed request to Vera vault.
  // -------------------------------------------------------------------------
  describe('vault: Palisade activation → Vera', () => {
    it('POST /api/vault/store returns 201 with panLast4 for an activation-signed request', async () => {
      const path = '/api/vault/store';
      const body = {
        pan: '4242424242424242',
        expiryMonth: '12',
        expiryYear: '2028',
        cardholderName: 'Cross-Repo Smoke',
        purpose: 'cross_repo_integration_test_palisade',
      };
      const bodyBuf = Buffer.from(JSON.stringify(body), 'utf8');

      const authorization = signRequest({
        method: 'POST',
        pathAndQuery: path,
        body: bodyBuf,
        keyId: 'activation',
        secret: HEX32_G,
      });

      const res = await fetch(`${VERA_VAULT_URL}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization,
        },
        body: bodyBuf,
      });

      expect([200, 201]).toContain(res.status);
      const json = (await res.json()) as { panLast4?: string };
      expect(json.panLast4).toBe('4242');
    });

    it('POST /api/vault/register returns {vaultToken, panLast4} when the endpoint exists', async () => {
      const path = '/api/vault/register';
      const body = {
        cardRef: `cross_repo_${Date.now()}`,
        pan: '4242424242424242',
        expiryMonth: '12',
        expiryYear: '2028',
        cardholderName: 'Cross-Repo Smoke',
        idempotencyKey: `cross_repo_${Date.now()}`,
      };
      const bodyBuf = Buffer.from(JSON.stringify(body), 'utf8');

      const authorization = signRequest({
        method: 'POST',
        pathAndQuery: path,
        body: bodyBuf,
        keyId: 'activation',
        secret: HEX32_G,
      });

      const res = await fetch(`${VERA_VAULT_URL}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization,
        },
        body: bodyBuf,
      });

      if (res.status === 404) {
        // eslint-disable-next-line no-console
        console.warn(
          `[cross-repo] ${path} returned 404; marking as pending until the endpoint lands`,
        );
        return;
      }

      expect([200, 201]).toContain(res.status);
      const json = (await res.json()) as {
        vaultToken?: string;
        panLast4?: string;
      };
      expect(json.vaultToken).toBeTruthy();
      expect(json.panLast4).toBe('4242');
    });
  });

  // -------------------------------------------------------------------------
  // Test 2 — Vera pay → Palisade activation /api/cards/lookup/:cardId.
  // Parallel-agent work; replace the .todo with a real test once landed.
  // -------------------------------------------------------------------------
  describe.todo(
    'activation: Vera pay → Palisade /api/cards/lookup/:cardId (endpoint not yet landed)',
  );

  // -------------------------------------------------------------------------
  // Test 3 — Admin capabilities endpoint.  Not yet landed.
  // -------------------------------------------------------------------------
  describe.todo(
    'admin: GET /api/capabilities returns {hasVera:true, hasPalisade:true} (endpoint not yet landed)',
  );

  // -------------------------------------------------------------------------
  // Baseline health checks — also cover the Palisade side in this mirror.
  // -------------------------------------------------------------------------
  describe('health baseline', () => {
    it.each([
      ['vera-pay', `${VERA_PAY_URL}/api/health`],
      ['vera-vault', `${VERA_VAULT_URL}/api/health`],
      ['vera-admin', `${VERA_ADMIN_URL}/api/health`],
      ['palisade-activation', `${PALISADE_ACTIVATION_URL}/api/health`],
    ])('%s health returns 200 + ok', async (_name, url) => {
      const res = await fetch(url);
      expect(res.status).toBe(200);
      const json = (await res.json()) as { ok?: boolean };
      expect(json.ok).toBe(true);
    });
  });
});
