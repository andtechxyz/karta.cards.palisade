import {
  verifyAuthenticationResponse as simpleVerifyAuth,
  verifyRegistrationResponse as simpleVerifyReg,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import { getWebAuthnConfig } from './env.js';

// Thin wrappers over @simplewebauthn/server that inject RP config from env.
// Services own the DB I/O around these; this package stays stateless.

export interface VerifyRegistrationInput {
  response: RegistrationResponseJSON;
  expectedChallenge: string;
  requireUserVerification?: boolean;
}

export async function verifyRegistration(input: VerifyRegistrationInput) {
  const c = getWebAuthnConfig();
  return simpleVerifyReg({
    response: input.response,
    expectedChallenge: input.expectedChallenge,
    expectedOrigin: c.WEBAUTHN_ORIGINS,
    expectedRPID: c.WEBAUTHN_RP_ID,
    requireUserVerification: input.requireUserVerification ?? false,
  });
}

export interface VerifyAuthenticationInput {
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
  credential: {
    credentialId: string;
    publicKey: string; // base64url
    counter: bigint | number;
    transports: string[];
  };
  requireUserVerification?: boolean;
}

export async function verifyAuthentication(input: VerifyAuthenticationInput) {
  const c = getWebAuthnConfig();
  return simpleVerifyAuth({
    response: input.response,
    expectedChallenge: input.expectedChallenge,
    expectedOrigin: c.WEBAUTHN_ORIGINS,
    expectedRPID: c.WEBAUTHN_RP_ID,
    authenticator: {
      credentialID: input.credential.credentialId,
      credentialPublicKey: Buffer.from(input.credential.publicKey, 'base64url'),
      counter: Number(input.credential.counter),
      transports: input.credential.transports as AuthenticatorTransportFuture[],
    },
    requireUserVerification: input.requireUserVerification ?? false,
  });
}
