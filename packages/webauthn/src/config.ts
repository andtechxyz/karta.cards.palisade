import type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
} from '@simplewebauthn/server';
import { CredentialKind } from '@palisade/db';
import { getWebAuthnConfig } from './env.js';

// -----------------------------------------------------------------------------
// Canonical WebAuthn option builders — SHARED across every service that
// needs to mint or consume WebAuthn options.
//
// Defaults are transcribed verbatim from New T4T (see
// /Users/danderson/.claude/plans/tingly-imagining-sketch.md, "WebAuthn/NFC
// requirements").  Deviating from any of these silently breaks Android
// Chrome's NFC path.
//
// RP-ID is read from env — `karta.cards` (the apex) in production so a
// credential minted on any subdomain (tap / activation / pay / admin) is
// usable across the whole ecosystem.
// -----------------------------------------------------------------------------

type RegOpts = GenerateRegistrationOptionsOpts;
type AuthOpts = GenerateAuthenticationOptionsOpts;

export interface RegInputCommon {
  /**
   * Opaque per-card handle that becomes WebAuthn's user.id / userHandle.
   * MUST be the Card's internal cuid — never the PICC UID.
   */
  userHandle: string;
  /** Display label shown in the authenticator's account picker. */
  userLabel: string;
  /** Credentials already registered; excluded so the same device can't re-bind. */
  excludeCredentialIds?: string[];
}

function rp() {
  const c = getWebAuthnConfig();
  return { name: c.WEBAUTHN_RP_NAME, id: c.WEBAUTHN_RP_ID };
}

// --- Registration -----------------------------------------------------------

export function buildNfcCardRegistrationOptions(input: RegInputCommon): RegOpts {
  const { id: rpID, name: rpName } = rp();
  return {
    rpName,
    rpID,
    userID: Buffer.from(input.userHandle, 'utf8'),
    userName: input.userLabel,
    userDisplayName: input.userLabel,
    timeout: 120_000,
    // ES256 only.  CTAP1/U2F path only signs ES256 (COSE alg = -7).
    supportedAlgorithmIDs: [-7],
    // Attestation MUST be 'none' — CTAP1 attestation is unparseable as packed.
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      residentKey: 'discouraged',
      userVerification: 'discouraged',
      requireResidentKey: false,
    },
    excludeCredentials: (input.excludeCredentialIds ?? []).map((id) => ({
      id,
      transports: ['nfc'],
    })),
  };
}

export function buildPlatformRegistrationOptions(input: RegInputCommon): RegOpts {
  const { id: rpID, name: rpName } = rp();
  return {
    rpName,
    rpID,
    userID: Buffer.from(input.userHandle, 'utf8'),
    userName: input.userLabel,
    userDisplayName: input.userLabel,
    timeout: 120_000,
    // ES256 first, then RS256 fallback for Windows Hello legacy.
    supportedAlgorithmIDs: [-7, -257],
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      userVerification: 'preferred',
      requireResidentKey: false,
    },
    excludeCredentials: (input.excludeCredentialIds ?? []).map((id) => ({
      id,
      transports: ['internal', 'hybrid'],
    })),
  };
}

// --- Authentication ---------------------------------------------------------

export interface AuthInput {
  credentials: Array<{ id: string; kind: CredentialKind; transports: string[] }>;
}

export function buildAuthenticationOptions(input: AuthInput): AuthOpts {
  const { id: rpID } = rp();
  return {
    rpID,
    timeout: 120_000,
    // Discouraged — 'required' on the NFC path immediately fails because the
    // card has no PIN/UV.
    userVerification: 'discouraged',
    allowCredentials: input.credentials.map((c) => {
      // NFC path MUST carry transports: ['nfc'] or Chrome refuses to even try.
      const transports =
        c.kind === CredentialKind.CROSS_PLATFORM
          ? (['nfc'] as const)
          : (c.transports as AuthenticatorTransportFuture[]).length > 0
            ? (c.transports as AuthenticatorTransportFuture[])
            : (['internal', 'hybrid'] as const);
      return {
        id: c.id,
        transports: transports as unknown as AuthenticatorTransportFuture[],
      };
    }),
  };
}

export type AuthenticatorTransportFuture =
  | 'ble'
  | 'cable'
  | 'hybrid'
  | 'internal'
  | 'nfc'
  | 'smart-card'
  | 'usb';
