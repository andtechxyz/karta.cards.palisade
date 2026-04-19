import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { api } from './api';

// -----------------------------------------------------------------------------
// Browser-side WebAuthn.
//
// Everything goes through @simplewebauthn/browser v10's startRegistration /
// startAuthentication helpers.  We never hand-roll base64url conversion —
// that's what fixes the Android Chrome double-encoding bug New T4T debugged.
//
// The caller supplies the card and kind (PLATFORM vs CROSS_PLATFORM / NFC).
// The server's canonical option builders (src/webauthn/config.ts) apply the
// CTAP1-compatible NFC settings where required — the browser does not need
// to know which ceremony is happening, it just hands the options to the
// library.
// -----------------------------------------------------------------------------

export type CredentialKind = 'PLATFORM' | 'CROSS_PLATFORM';

/** Runtime array of every CredentialKind — for UI loops that need one row per kind. */
export const CREDENTIAL_KINDS: readonly CredentialKind[] = ['PLATFORM', 'CROSS_PLATFORM'] as const;

export async function registerCredential(input: {
  cardId: string;
  kind: CredentialKind;
  deviceName?: string;
}): Promise<{ id: string; credentialId: string }> {
  // userHandle / userLabel are derived server-side from the Card's opaque
  // cuid — the browser must not influence them (would leak PII otherwise).
  const options = await api.post<Parameters<typeof startRegistration>[0]>(
    '/auth/register/options',
    { cardId: input.cardId, kind: input.kind },
  );

  // The library handles ArrayBuffer ↔ base64url conversions internally,
  // matching the shape the server emits via @simplewebauthn/server v10.
  const attResp = await startRegistration(options);

  return api.post('/auth/register/verify', {
    cardId: input.cardId,
    response: attResp,
    deviceName: input.deviceName,
  });
}

export async function authenticate(input: {
  rlid: string;
  kinds?: CredentialKind[];
}): Promise<unknown> {
  const options = await api.post<Parameters<typeof startAuthentication>[0]>(
    '/auth/authenticate/options',
    { rlid: input.rlid, kinds: input.kinds },
  );

  const assertion = await startAuthentication(options);

  return api.post('/auth/authenticate/verify', {
    rlid: input.rlid,
    response: assertion,
  });
}

/**
 * Activation ceremony — runs on the cardholder's phone after the SUN-tap
 * landed them on /activate?session=<token>.  The session token is the only
 * handle the page sees; the server resolves it to the underlying card.
 *
 * Two paths, decided by the /begin response:
 *
 *   1. mode=register (no preregistered cred):
 *      a. /begin returns WebAuthn registration options
 *      b. browser runs startRegistration() — user taps card on phone
 *      c. /finish verifies the attestation + activates
 *
 *   2. mode=assert (perso-time preregistered cred exists):
 *      a. /begin returns WebAuthn assertion options carrying the chip-
 *         update payload on TWO channels (the browser picks whichever it
 *         doesn't strip): allowCredentials[0].id is the base64url blob
 *         <realCredId>||<url>||<cmac(16)> — the applet's CTAP1 path and
 *         CTAP2 allowList tail-stripper consume it.  options.extensions
 *         carries `karta-url` = <url>||<cmac> — the applet's CTAP2
 *         extension parser consumes it.  Either channel triggers the
 *         applet's setUrlWithMac() via SIO.
 *      b. browser runs startAuthentication() — user taps card on phone
 *      c. chip signs the challenge + self-updates (baseUrl + state)
 *      d. /finish verifies the assertion + flips Card.status to ACTIVATED
 *
 * Works on iOS Safari 16+ (CTAP2 over NFC) and Android Chrome (CTAP1 or
 * CTAP2 over NFC).  No more browser/platform gating at this layer.
 */
type BeginResponse =
  | { mode: 'register'; options: Parameters<typeof startRegistration>[0] }
  | { mode: 'assert'; options: Parameters<typeof startAuthentication>[0] };

export async function activateWithSession(input: {
  sessionToken: string;
  deviceLabel?: string;
}): Promise<{
  credentialId: string;
  cardActivated: true;
  mode: 'register' | 'assert';
  micrositeUrl: string | null;
}> {
  const path = `/activation/sessions/${encodeURIComponent(input.sessionToken)}`;
  const begin = await api.post<BeginResponse>(`${path}/begin`);

  if (begin.mode === 'assert') {
    // Real WebAuthn assertion — the extended credential ID carries the
    // chip-update payload.  User will see a platform NFC prompt.
    const assResp = await startAuthentication(begin.options);
    return api.post(`${path}/finish`, {
      response: assResp,
      deviceLabel: input.deviceLabel,
    });
  }

  // Fresh registration — user taps the card to let the FIDO applet mint a
  // credential, then we store the public key.
  const attResp = await startRegistration(begin.options);
  return api.post(`${path}/finish`, {
    response: attResp,
    deviceLabel: input.deviceLabel,
  });
}
