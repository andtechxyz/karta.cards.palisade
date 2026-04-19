import { badRequest } from '@palisade/core';
import { getAdminConfig } from '../env.js';

// -----------------------------------------------------------------------------
// NDEF URL templates — admin service copy.
// Renders NDEF URLs for programs, substituting {cardRef} and preserving SDM
// markers ({PICCData}, {CMAC}) for on-card NXP SDM substitution.
// -----------------------------------------------------------------------------

const SDM_MARKERS = ['{PICCData}', '{CMAC}'] as const;

export interface NdefUrlPair {
  preActivation: string;
  postActivation: string;
}

export interface RenderNdefInput {
  cardRef: string;
  preActivationTemplate?: string | null;
  postActivationTemplate?: string | null;
}

export function renderNdefUrls(input: RenderNdefInput): NdefUrlPair {
  const origin = getAdminConfig().WEBAUTHN_ORIGIN;
  const pre =
    input.preActivationTemplate ??
    `${origin}/activate/{cardRef}?e={PICCData}&m={CMAC}`;
  const post =
    input.postActivationTemplate ??
    `${origin}/tap/{cardRef}?e={PICCData}&m={CMAC}`;
  return {
    preActivation: substituteCardRef(pre, input.cardRef),
    postActivation: substituteCardRef(post, input.cardRef),
  };
}

function substituteCardRef(template: string, cardRef: string): string {
  return template.replaceAll('{cardRef}', cardRef);
}

export function validateNdefUrlTemplate(template: string): void {
  if (!/^https?:\/\//i.test(template)) {
    throw badRequest(
      'invalid_ndef_template',
      `NDEF URL template must be http(s): got "${template}"`,
    );
  }
  if (!template.includes('{cardRef}')) {
    throw badRequest(
      'invalid_ndef_template',
      `NDEF URL template must contain {cardRef}: "${template}"`,
    );
  }
  const tokens = template.match(/\{[^}]+\}/g) ?? [];
  const allowed = new Set<string>(['{cardRef}', ...SDM_MARKERS]);
  for (const tok of tokens) {
    if (!allowed.has(tok)) {
      throw badRequest(
        'invalid_ndef_template',
        `NDEF URL template contains unknown placeholder ${tok}; allowed: {cardRef}, {PICCData}, {CMAC}`,
      );
    }
  }
}
