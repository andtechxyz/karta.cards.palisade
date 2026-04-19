import { defineEnv, originList } from '@palisade/core';
import { z } from 'zod';

// -----------------------------------------------------------------------------
// WebAuthn environment.
//
// `WEBAUTHN_RP_ID` is the *apex* domain (`karta.cards`) so credentials minted
// on any subdomain (tap / activation / pay / admin) are usable across the
// whole ecosystem.  The WebAuthn spec allows the RP ID to be a registrable
// suffix of the page's origin.
//
// `WEBAUTHN_ORIGINS` is a comma-separated list of full origins that
// verifyRegistrationResponse / verifyAuthenticationResponse will accept in
// clientDataJSON.origin — one entry per subdomain that actually serves pages.
// -----------------------------------------------------------------------------

const { get, reset } = defineEnv({
  WEBAUTHN_RP_ID: z.string().min(1),
  WEBAUTHN_ORIGINS: originList,
  WEBAUTHN_RP_NAME: z.string().default('Palisade Pay'),
});

export { get as getWebAuthnConfig, reset as _resetWebAuthnConfig };
