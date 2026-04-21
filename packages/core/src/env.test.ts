/**
 * Tests for the production env-hardening gate.  The knobs we're protecting
 * (KMS ARNs, internal ALB DNS, HMAC secrets, public WS URLs) all have
 * dev-friendly fallbacks baked into the zod schema so local dev and tests
 * don't need to plumb them — but those same fallbacks are dangerous in
 * production.  assertProdRequiredEnv is the single gate that flips the
 * severity based on NODE_ENV.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { assertProdRequiredEnv } from './env.js';

describe('assertProdRequiredEnv', () => {
  const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

  afterEach(() => {
    warnSpy.mockClear();
  });

  it('is a no-op when every field has an explicit non-default value', () => {
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'KMS_SAD_KEY_ARN',
          value: 'arn:aws:kms:ap-southeast-2:123:key/abc',
          devFallback: '',
          description: 'prod KMS ARN',
        },
      ]),
    ).not.toThrow();
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('throws in production when a field is still on its dev fallback', () => {
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'CALLBACK_HMAC_SECRET',
          value: '0'.repeat(64),
          devFallback: '0'.repeat(64),
          description: 'HMAC key for activation callbacks',
        },
      ]),
    ).toThrow(/CALLBACK_HMAC_SECRET.*using dev fallback/s);
  });

  it('throws in production when a required field is unset (empty string)', () => {
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'KMS_SAD_KEY_ARN',
          value: '',
          devFallback: '',
          description: 'prod KMS ARN',
        },
      ]),
    ).toThrow(/KMS_SAD_KEY_ARN/);
  });

  it('throws in production when a required field is undefined (no schema default)', () => {
    // Mirrors RCA_PUBLIC_WS_BASE, declared z.string().url().optional().
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'RCA_PUBLIC_WS_BASE',
          value: undefined,
          devFallback: undefined,
          description: 'public WS origin',
        },
      ]),
    ).toThrow(/RCA_PUBLIC_WS_BASE/);
  });

  it('throws in production when the value matches an in-band fallback sentinel', () => {
    // AWS Secrets Manager refuses zero-length strings, so some env vars
    // have sentinels like 'none'/'dev' meaning "no real value, use the
    // stub path".  The prod gate must treat those as fallback too.
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'KMS_SAD_KEY_ARN',
          value: 'none',
          devFallback: '',
          fallbackSentinels: ['none', 'dev'],
          description: 'KMS key ARN',
        },
      ]),
    ).toThrow(/KMS_SAD_KEY_ARN.*using dev fallback/s);

    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'KMS_SAD_KEY_ARN',
          value: 'dev',
          devFallback: '',
          fallbackSentinels: ['none', 'dev'],
          description: 'KMS key ARN',
        },
      ]),
    ).toThrow(/KMS_SAD_KEY_ARN/);

    // A real ARN passes even though we listed sentinels.
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'KMS_SAD_KEY_ARN',
          value: 'arn:aws:kms:ap-southeast-2:600743178530:key/abc-123',
          devFallback: '',
          fallbackSentinels: ['none', 'dev'],
          description: 'KMS key ARN',
        },
      ]),
    ).not.toThrow();
  });

  it('throws in production when a URL field points at localhost', () => {
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'DATA_PREP_SERVICE_URL',
          value: 'http://localhost:3006',
          devFallback: 'http://localhost:3006',
          description: 'internal ALB DNS',
          rejectLocalhostInProd: true,
        },
      ]),
    ).toThrow(/DATA_PREP_SERVICE_URL/);
  });

  it('rejects 127.0.0.1 and 0.0.0.0 in production too', () => {
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'DATA_PREP_SERVICE_URL',
          value: 'http://127.0.0.1:3006',
          devFallback: 'http://localhost:3006', // different from value
          description: 'internal ALB DNS',
          rejectLocalhostInProd: true,
        },
      ]),
    ).toThrow(/DATA_PREP_SERVICE_URL.*localhost/s);

    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'ACTIVATION_CALLBACK_URL',
          value: 'http://0.0.0.0:3002',
          devFallback: 'http://localhost:3002',
          description: 'internal ALB DNS',
          rejectLocalhostInProd: true,
        },
      ]),
    ).toThrow(/ACTIVATION_CALLBACK_URL.*localhost/s);
  });

  it('does not reject localhost in production when rejectLocalhostInProd is unset', () => {
    // A field might legitimately be localhost-looking in prod (e.g. a debug
    // URL that's only used when PALISADE_ATTESTATION_MODE=permissive).
    // Opt-in flag means default-off.
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'SOME_OTHER_URL',
          value: 'http://localhost:3006',
          devFallback: '',
          description: 'some other url',
          // rejectLocalhostInProd absent → only fallback check applies.
        },
      ]),
    ).not.toThrow();
  });

  it('batches all offending fields into a single error message', () => {
    // Operators shouldn't have to redeploy four times to chase four
    // missing env vars.
    expect(() =>
      assertProdRequiredEnv('production', [
        {
          name: 'KMS_SAD_KEY_ARN',
          value: '',
          devFallback: '',
          description: 'A',
        },
        {
          name: 'CALLBACK_HMAC_SECRET',
          value: '0'.repeat(64),
          devFallback: '0'.repeat(64),
          description: 'B',
        },
        {
          name: 'DATA_PREP_SERVICE_URL',
          value: 'http://localhost:3006',
          devFallback: 'http://localhost:3006',
          description: 'C',
          rejectLocalhostInProd: true,
        },
      ]),
    ).toThrow(/KMS_SAD_KEY_ARN[\s\S]+CALLBACK_HMAC_SECRET[\s\S]+DATA_PREP_SERVICE_URL/);
  });

  it('warns but does not throw in development', () => {
    expect(() =>
      assertProdRequiredEnv('development', [
        {
          name: 'KMS_SAD_KEY_ARN',
          value: '',
          devFallback: '',
          description: 'prod KMS ARN',
        },
      ]),
    ).not.toThrow();
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0][0]).toMatch(/\[env\] KMS_SAD_KEY_ARN/);
    expect(warnSpy.mock.calls[0][0]).toMatch(/dev fallback active/);
  });

  it('warns but does not throw in test', () => {
    // Same behaviour as development — running tests shouldn't require
    // every operator to plumb KMS ARNs through their dev shell.
    expect(() =>
      assertProdRequiredEnv('test', [
        {
          name: 'CALLBACK_HMAC_SECRET',
          value: '0'.repeat(64),
          devFallback: '0'.repeat(64),
          description: 'HMAC key',
        },
      ]),
    ).not.toThrow();
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  it('emits one warning line per offending field in dev, not a single batched line', () => {
    assertProdRequiredEnv('development', [
      {
        name: 'A',
        value: '',
        devFallback: '',
        description: 'a',
      },
      {
        name: 'B',
        value: '',
        devFallback: '',
        description: 'b',
      },
      {
        name: 'C',
        value: 'https://good.example.com',
        devFallback: '',
        description: 'c',
      },
    ]);
    expect(warnSpy).toHaveBeenCalledTimes(2);
    expect(warnSpy.mock.calls[0][0]).toMatch(/\[env\] A/);
    expect(warnSpy.mock.calls[1][0]).toMatch(/\[env\] B/);
  });
});
