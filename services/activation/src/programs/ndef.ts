import { badRequest } from '@palisade/core';
import { getActivationConfig } from '../env.js';

// NDEF URL template renderer for activation service.
//
// Post-activation NDEF URL is per-program.  For Karta-style FI programs
// it points at mobile.karta.cards (universal-link host that wakes the
// mobile wallet app); for retail it points at tap.karta.cards/pay
// (server-side SUN-verify + redirect).  The chip stores the host+path
// portion only; the SDM applet appends `?e=<picc>&m=<cmac>` on every tap.

const SDM_MARKERS = ['{PICCData}', '{CMAC}'] as const;

export interface NdefUrlPair {
  preActivation: string;
  postActivation: string;
}

export interface RenderNdefInput {
  cardRef: string;
  /**
   * Program-scoped opaque code (e.g. `kp` for Karta Platinum).  Substitutes
   * `{urlCode}` in templates.  When omitted, templates that reference it
   * throw at render time — by design, so we fail loudly rather than emit a
   * literal `{urlCode}` onto the chip.
   */
  urlCode?: string | null;
  preActivationTemplate?: string | null;
  postActivationTemplate?: string | null;
}

export function renderNdefUrls(input: RenderNdefInput): NdefUrlPair {
  const config = getActivationConfig();
  const tapOrigin = `https://tap.karta.cards`;
  const payOrigin = config.PAY_URL;

  const pre =
    input.preActivationTemplate ??
    `${tapOrigin}/activate/{cardRef}?e={PICCData}&m={CMAC}`;
  const post =
    input.postActivationTemplate ??
    `${payOrigin}/tap/{cardRef}?e={PICCData}&m={CMAC}`;

  return {
    preActivation: substitute(pre, input),
    postActivation: substitute(post, input),
  };
}

function substitute(template: string, input: RenderNdefInput): string {
  let out = template.replaceAll('{cardRef}', input.cardRef);
  if (out.includes('{urlCode}')) {
    if (!input.urlCode) {
      throw badRequest(
        'missing_url_code',
        'Template references {urlCode} but the program has no urlCode set',
      );
    }
    out = out.replaceAll('{urlCode}', input.urlCode);
  }
  return out;
}

export function validateNdefUrlTemplate(template: string): void {
  if (!/^https?:\/\//i.test(template)) {
    throw badRequest('invalid_ndef_template', `NDEF URL template must be http(s): got "${template}"`);
  }
  // {cardRef} is required EXCEPT when {urlCode} is present — the latter is
  // the cardRef-less post-activation shape and intentionally doesn't carry
  // the cardRef in plaintext.
  const hasCardRef = template.includes('{cardRef}');
  const hasUrlCode = template.includes('{urlCode}');
  if (!hasCardRef && !hasUrlCode) {
    throw badRequest(
      'invalid_ndef_template',
      `NDEF URL template must contain {cardRef} or {urlCode}: "${template}"`,
    );
  }
  const tokens = template.match(/\{[^}]+\}/g) ?? [];
  const allowed = new Set<string>(['{cardRef}', '{urlCode}', ...SDM_MARKERS]);
  for (const tok of tokens) {
    if (!allowed.has(tok)) {
      throw badRequest('invalid_ndef_template', `Unknown placeholder ${tok}`);
    }
  }
}
