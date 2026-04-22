/**
 * Tests for the production guard on `getCardOpsConfig`.
 *
 * PCI DSS 3.6.1 / 6.4.3 mandate that test keys never authenticate
 * production cards.  `services/card-ops/src/env.ts` implements this
 * gate by throwing at config-resolve time when NODE_ENV=production
 * AND either:
 *   - CARD_OPS_USE_TEST_KEYS is truthy, OR
 *   - GP_MASTER_KEY decodes to the well-known GP test key
 *     (40 41 ... 4F) in any of the enc / mac / dek slots.
 *
 * These tests exercise both branches plus the happy paths (dev +
 * prod-with-real-keys).  Added 2026-04-21 to back the PCI audit
 * finding that the guard exists in code but isn't regression-
 * tested.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { getCardOpsConfig, _resetCardOpsConfig } from './env.js';

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;
const ORIGINAL_USE_TEST_KEYS = process.env.CARD_OPS_USE_TEST_KEYS;
const ORIGINAL_GP_MASTER_KEY = process.env.GP_MASTER_KEY;
const ORIGINAL_WS_TOKEN_SECRET = process.env.WS_TOKEN_SECRET;
const ORIGINAL_AUTH_KEYS = process.env.CARD_OPS_AUTH_KEYS;

// WS_TOKEN_SECRET is zod-validated as 64 hex chars (32 bytes).  Provide
// a dummy value so config resolution doesn't explode on that check
// before reaching the prod-guard branches.
const DUMMY_WS_SECRET = 'a'.repeat(64);
// CARD_OPS_AUTH_KEYS is a zod-validated JSON object of {keyId: secret}.
// Minimal valid value.
const DUMMY_AUTH_KEYS = JSON.stringify({ tap: 'b'.repeat(64) });

const REAL_GP_KEY_JSON = JSON.stringify({
  enc: 'AB'.repeat(16),
  mac: 'CD'.repeat(16),
  dek: 'EF'.repeat(16),
});

const TEST_GP_KEY_JSON = JSON.stringify({
  enc: '404142434445464748494A4B4C4D4E4F',
  mac: 'AB'.repeat(16),
  dek: 'CD'.repeat(16),
});

describe('env.ts prod guard (PCI 3.6.1 / 6.4.3)', () => {
  beforeEach(() => {
    _resetCardOpsConfig();
    process.env.WS_TOKEN_SECRET = DUMMY_WS_SECRET;
    process.env.CARD_OPS_AUTH_KEYS = DUMMY_AUTH_KEYS;
  });

  afterEach(() => {
    // Restore process.env so unrelated suites run unperturbed.
    _resetCardOpsConfig();
    if (ORIGINAL_NODE_ENV === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = ORIGINAL_NODE_ENV;

    if (ORIGINAL_USE_TEST_KEYS === undefined) delete process.env.CARD_OPS_USE_TEST_KEYS;
    else process.env.CARD_OPS_USE_TEST_KEYS = ORIGINAL_USE_TEST_KEYS;

    if (ORIGINAL_GP_MASTER_KEY === undefined) delete process.env.GP_MASTER_KEY;
    else process.env.GP_MASTER_KEY = ORIGINAL_GP_MASTER_KEY;

    if (ORIGINAL_WS_TOKEN_SECRET === undefined) delete process.env.WS_TOKEN_SECRET;
    else process.env.WS_TOKEN_SECRET = ORIGINAL_WS_TOKEN_SECRET;

    if (ORIGINAL_AUTH_KEYS === undefined) delete process.env.CARD_OPS_AUTH_KEYS;
    else process.env.CARD_OPS_AUTH_KEYS = ORIGINAL_AUTH_KEYS;
  });

  it('resolves cleanly in dev with default GP test keys', () => {
    process.env.NODE_ENV = 'development';
    delete process.env.CARD_OPS_USE_TEST_KEYS;
    delete process.env.GP_MASTER_KEY; // fall through to the schema default (GP test keys)
    expect(() => getCardOpsConfig()).not.toThrow();
  });

  it('resolves cleanly in prod with real per-FI keys and CARD_OPS_USE_TEST_KEYS unset', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.CARD_OPS_USE_TEST_KEYS;
    process.env.GP_MASTER_KEY = REAL_GP_KEY_JSON;
    expect(() => getCardOpsConfig()).not.toThrow();
  });

  it('throws in prod when CARD_OPS_USE_TEST_KEYS=1 (guard branch 1)', () => {
    process.env.NODE_ENV = 'production';
    process.env.CARD_OPS_USE_TEST_KEYS = '1';
    process.env.GP_MASTER_KEY = REAL_GP_KEY_JSON;
    expect(() => getCardOpsConfig()).toThrow(
      /CARD_OPS_USE_TEST_KEYS=1 is forbidden in production/,
    );
  });

  it('throws in prod when GP_MASTER_KEY contains the well-known test key (guard branch 2)', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.CARD_OPS_USE_TEST_KEYS;
    process.env.GP_MASTER_KEY = TEST_GP_KEY_JSON;
    expect(() => getCardOpsConfig()).toThrow(
      /well-known GlobalPlatform test key/,
    );
  });

  it('throws in prod when GP_MASTER_KEY is not valid JSON', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.CARD_OPS_USE_TEST_KEYS;
    process.env.GP_MASTER_KEY = '{this-is-not-json';
    expect(() => getCardOpsConfig()).toThrow(/not valid JSON/);
  });

  it('permits test key in GP_MASTER_KEY in dev (no guard runs)', () => {
    process.env.NODE_ENV = 'development';
    process.env.GP_MASTER_KEY = TEST_GP_KEY_JSON;
    expect(() => getCardOpsConfig()).not.toThrow();
  });
});
