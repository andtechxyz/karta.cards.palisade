import { describe, it, expect } from 'vitest';
import { renderNdefUrls, validateNdefUrlTemplate } from './ndef.js';

// Tests run with WEBAUTHN_ORIGIN=https://pay.karta.cards (see tests/setup.ts).
const ORIGIN = 'https://pay.karta.cards';

describe('renderNdefUrls', () => {
  it('falls back to origin-derived defaults when templates are null', () => {
    const out = renderNdefUrls({
      cardRef: 'abc-123',
      preActivationTemplate: null,
      postActivationTemplate: null,
    });
    expect(out.preActivation).toBe(`${ORIGIN}/activate/abc-123?e={PICCData}&m={CMAC}`);
    expect(out.postActivation).toBe(`${ORIGIN}/tap/abc-123?e={PICCData}&m={CMAC}`);
  });

  it('substitutes {cardRef} in a custom template', () => {
    const out = renderNdefUrls({
      cardRef: 'xyz',
      preActivationTemplate: 'https://issuer.example/go/{cardRef}?e={PICCData}&m={CMAC}',
      postActivationTemplate: 'https://pay.issuer.example/tap/{cardRef}?e={PICCData}&m={CMAC}',
    });
    expect(out.preActivation).toBe(
      'https://issuer.example/go/xyz?e={PICCData}&m={CMAC}',
    );
    expect(out.postActivation).toBe(
      'https://pay.issuer.example/tap/xyz?e={PICCData}&m={CMAC}',
    );
  });

  it('leaves SDM markers ({PICCData}/{CMAC}) intact for the card to fill in', () => {
    const out = renderNdefUrls({
      cardRef: 'card-1',
      preActivationTemplate: 'https://x.example/{cardRef}?e={PICCData}&m={CMAC}',
      postActivationTemplate: null,
    });
    expect(out.preActivation).toContain('{PICCData}');
    expect(out.preActivation).toContain('{CMAC}');
  });

  it('substitutes multiple {cardRef} occurrences in the same template', () => {
    const out = renderNdefUrls({
      cardRef: 'c',
      preActivationTemplate: 'https://x.example/{cardRef}/{cardRef}?e={PICCData}&m={CMAC}',
      postActivationTemplate: null,
    });
    expect(out.preActivation).toBe('https://x.example/c/c?e={PICCData}&m={CMAC}');
  });

  it('defaults for either side independently when only one template is provided', () => {
    const out = renderNdefUrls({
      cardRef: 'ref',
      preActivationTemplate: 'https://custom.example/{cardRef}?e={PICCData}&m={CMAC}',
      postActivationTemplate: null,
    });
    expect(out.preActivation).toBe('https://custom.example/ref?e={PICCData}&m={CMAC}');
    expect(out.postActivation).toBe(`${ORIGIN}/tap/ref?e={PICCData}&m={CMAC}`);
  });
});

describe('validateNdefUrlTemplate', () => {
  it('accepts a well-formed https template with all three placeholders', () => {
    expect(() =>
      validateNdefUrlTemplate('https://x.example/{cardRef}?e={PICCData}&m={CMAC}'),
    ).not.toThrow();
  });

  it('accepts http as well as https (dev environments)', () => {
    expect(() => validateNdefUrlTemplate('http://localhost/{cardRef}')).not.toThrow();
  });

  it('rejects a non-http(s) scheme', () => {
    expect(() => validateNdefUrlTemplate('ftp://x.example/{cardRef}')).toThrow(/http\(s\)/);
  });

  it('rejects a template missing {cardRef}', () => {
    expect(() =>
      validateNdefUrlTemplate('https://x.example/fixed?e={PICCData}&m={CMAC}'),
    ).toThrow(/\{cardRef\}/);
  });

  it('rejects an unknown placeholder alongside the required {cardRef}', () => {
    // {cardref} (lowercase) is a distinct token from {cardRef}; the template
    // still has {cardRef}, so this lands on the allowlist check rather than
    // the "must contain" check.
    expect(() =>
      validateNdefUrlTemplate('https://x.example/{cardRef}/{cardref}?e={PICCData}&m={CMAC}'),
    ).toThrow(/unknown placeholder/);
  });

  it('rejects placeholders outside the allowlist (typos, rogue tokens)', () => {
    expect(() =>
      validateNdefUrlTemplate('https://x.example/{cardRef}?x={UID}'),
    ).toThrow(/unknown placeholder/);
  });
});
