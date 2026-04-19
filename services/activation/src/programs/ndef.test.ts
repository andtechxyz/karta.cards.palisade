import { describe, it, expect, vi, beforeEach } from 'vitest';

// Minimal env mock — renderNdefUrls only reads PAY_URL.
vi.mock('../env.js', () => ({
  getActivationConfig: vi.fn(() => ({ PAY_URL: 'https://pay.karta.cards' })),
}));

import { renderNdefUrls, validateNdefUrlTemplate } from './ndef.js';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('renderNdefUrls — {urlCode} substitution', () => {
  it('substitutes {urlCode} alongside {cardRef}', () => {
    const r = renderNdefUrls({
      cardRef: 'e2e_fi_2590',
      urlCode: 'kp',
      preActivationTemplate: 'https://tap.karta.cards/activate/{cardRef}?e={PICCData}&m={CMAC}',
      postActivationTemplate: 'https://mobile.karta.cards/t/{urlCode}?e={PICCData}&m={CMAC}',
    });
    expect(r.preActivation).toBe('https://tap.karta.cards/activate/e2e_fi_2590?e={PICCData}&m={CMAC}');
    expect(r.postActivation).toBe('https://mobile.karta.cards/t/kp?e={PICCData}&m={CMAC}');
  });

  it('throws when template references {urlCode} but none was supplied', () => {
    expect(() =>
      renderNdefUrls({
        cardRef: 'card_1',
        urlCode: null,
        postActivationTemplate: 'https://mobile.karta.cards/t/{urlCode}?e={PICCData}&m={CMAC}',
      }),
    ).toThrow(expect.objectContaining({ code: 'missing_url_code' }));
  });

  it('passes through templates that do not reference {urlCode} even when urlCode is unset', () => {
    const r = renderNdefUrls({
      cardRef: 'card_1',
      urlCode: null,
      postActivationTemplate: 'https://tap.karta.cards/pay/{cardRef}?e={PICCData}&m={CMAC}',
    });
    expect(r.postActivation).toBe('https://tap.karta.cards/pay/card_1?e={PICCData}&m={CMAC}');
  });
});

describe('validateNdefUrlTemplate', () => {
  it('accepts a template with {cardRef}', () => {
    expect(() =>
      validateNdefUrlTemplate('https://tap.karta.cards/activate/{cardRef}?e={PICCData}&m={CMAC}'),
    ).not.toThrow();
  });

  it('accepts a template with {urlCode} (cardRef-less post-activation)', () => {
    expect(() =>
      validateNdefUrlTemplate('https://mobile.karta.cards/t/{urlCode}?e={PICCData}&m={CMAC}'),
    ).not.toThrow();
  });

  it('rejects a template with neither {cardRef} nor {urlCode}', () => {
    expect(() =>
      validateNdefUrlTemplate('https://tap.karta.cards/?e={PICCData}&m={CMAC}'),
    ).toThrow(/cardRef.*urlCode/);
  });

  it('rejects unknown placeholders', () => {
    expect(() =>
      validateNdefUrlTemplate('https://tap.karta.cards/{cardRef}/{ohno}?e={PICCData}&m={CMAC}'),
    ).toThrow(/Unknown placeholder/);
  });

  it('rejects non-http(s) schemes', () => {
    expect(() =>
      validateNdefUrlTemplate('ftp://tap.karta.cards/{cardRef}?e={PICCData}&m={CMAC}'),
    ).toThrow(/http/i);
  });
});
