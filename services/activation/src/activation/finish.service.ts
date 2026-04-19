import { CardStatus, CredentialKind } from '@prisma/client';
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import { prisma } from '@palisade/db';
import { badRequest, unauthorized } from '@palisade/core';
import { verifyAuthentication, verifyRegistration } from '@palisade/webauthn';
import { renderNdefUrls } from '../programs/ndef.js';
import { getActivationConfig } from '../env.js';
import { loadActiveSession } from './session.js';

// Second leg of the activation ceremony.  The frontend POSTs either:
//
//   - { response: RegistrationResponseJSON }      — register mode (legacy)
//   - { response: AuthenticationResponseJSON }    — assert mode (chip had a
//                                                   preregistered FIDO cred)
//
// We sniff the shape (attestation vs assertion) to pick the path; no
// explicit `mode` flag on the wire keeps the contract small.  Both paths
// end with Card.status = ACTIVATED.

export interface FinishInput {
  sessionToken: string;
  response: RegistrationResponseJSON | AuthenticationResponseJSON;
  deviceLabel?: string;
}

export interface FinishResult {
  cardActivated: true;
  credentialId: string;
  postActivationNdefUrl: string;
  /** 'register' = brand-new cred; 'assert' = existing preregistered cred used. */
  mode: 'register' | 'assert';
  micrositeUrl: string | null;
}

export async function finishActivationRegistration(input: FinishInput): Promise<FinishResult> {
  const session = await loadActiveSession(input.sessionToken);
  if (!session.challenge) {
    throw badRequest('no_pending_challenge', 'Call /begin first');
  }
  if (!input.response) {
    throw badRequest('missing_response', 'Response body is required');
  }

  // Shape-sniff: attestation has `attestationObject`, assertion has
  // `signature` + `authenticatorData`.
  const r = input.response as unknown as Record<string, unknown>;
  const resp = (r.response ?? {}) as Record<string, unknown>;
  const isAssertion = typeof resp.signature === 'string';

  if (isAssertion) {
    return finishAssert(session, input.response as AuthenticationResponseJSON, input.deviceLabel);
  }
  return finishRegister(session, input.response as RegistrationResponseJSON, input.deviceLabel);
}

// ---------------------------------------------------------------------------
// Register path — fresh WebAuthn registration (legacy flow)
// ---------------------------------------------------------------------------

async function finishRegister(
  session: { id: string; cardId: string; challenge: string | null },
  response: RegistrationResponseJSON,
  deviceLabel: string | undefined,
): Promise<FinishResult> {
  if (!session.challenge) {
    throw badRequest('no_pending_challenge', 'Call /begin first');
  }

  const verification = await verifyRegistration({
    response,
    expectedChallenge: session.challenge,
    requireUserVerification: false,
  });
  if (!verification.verified || !verification.registrationInfo) {
    throw unauthorized('registration_verify_failed', 'WebAuthn registration failed');
  }

  const info = verification.registrationInfo;
  const credentialId = info.credentialID;
  const publicKey = Buffer.from(info.credentialPublicKey).toString('base64url');
  const transports = response.response?.transports ?? ['nfc'];

  const [, updatedCard] = await prisma.$transaction([
    prisma.webAuthnCredential.create({
      data: {
        credentialId,
        publicKey,
        counter: BigInt(info.counter),
        kind: CredentialKind.CROSS_PLATFORM,
        transports,
        deviceName: deviceLabel,
        cardId: session.cardId,
      },
    }),
    prisma.card.update({
      where: { id: session.cardId },
      data: { status: CardStatus.ACTIVATED },
      select: micrositeProgramSelect,
    }),
    prisma.activationSession.update({
      where: { id: session.id },
      data: {
        consumedAt: new Date(),
        consumedDeviceLabel: deviceLabel,
        challenge: null,
      },
    }),
  ]);

  return buildResult({
    cardRef: updatedCard.cardRef,
    credentialId,
    program: updatedCard.program,
    mode: 'register',
  });
}

// ---------------------------------------------------------------------------
// Assert path — preregistered credential, WebAuthn assertion with extended
// credential ID.  Chip is expected to have processed the URL+CMAC tail via
// its T4T applet during this ceremony.
// ---------------------------------------------------------------------------

async function finishAssert(
  session: { id: string; cardId: string; challenge: string | null },
  response: AuthenticationResponseJSON,
  deviceLabel: string | undefined,
): Promise<FinishResult> {
  if (!session.challenge) {
    throw badRequest('no_pending_challenge', 'Call /begin first');
  }

  // The client returns the credentialId that the authenticator echoed.
  // Some authenticators return the full extended blob; others strip the
  // tail and return just the real credential ID.  Try both forms against
  // our DB.
  const returnedCredId = response.id;
  if (!returnedCredId) {
    throw badRequest('missing_credential_id', 'Assertion response missing credential id');
  }
  const returnedBytes = Buffer.from(returnedCredId, 'base64url');

  // Card has at most one preregistered cred — fetch it plus any others.
  const credentials = await prisma.webAuthnCredential.findMany({
    where: { cardId: session.cardId },
    select: {
      id: true,
      credentialId: true,
      publicKey: true,
      counter: true,
      transports: true,
      preregistered: true,
    },
  });
  // Match either as-is or by stripping a tail.
  const cred = credentials.find((c) => {
    const stored = Buffer.from(c.credentialId, 'base64url');
    if (stored.equals(returnedBytes)) return true;
    if (returnedBytes.length > stored.length &&
        returnedBytes.subarray(0, stored.length).equals(stored)) {
      return true;
    }
    return false;
  });
  if (!cred) {
    throw unauthorized('credential_not_found', 'Assertion credential does not match any card credential');
  }

  // @simplewebauthn's verifier expects the canonical credentialId on both
  // sides (response.id AND authenticator.credentialID).  If the authenticator
  // returned the extended blob, rewrite the response.id to the stored one so
  // the library's equality check passes.  The signed authData hash is
  // unaffected.
  const normalizedResponse: AuthenticationResponseJSON = {
    ...response,
    id: cred.credentialId,
    rawId: cred.credentialId,
  };

  const verification = await verifyAuthentication({
    response: normalizedResponse,
    expectedChallenge: session.challenge,
    credential: {
      credentialId: cred.credentialId,
      publicKey: cred.publicKey,
      counter: cred.counter,
      transports: cred.transports,
    },
    requireUserVerification: false,
  });
  if (!verification.verified) {
    throw unauthorized('assertion_verify_failed', 'WebAuthn assertion failed');
  }
  const newCounter = verification.authenticationInfo?.newCounter ?? Number(cred.counter);

  const [, , updatedCard] = await prisma.$transaction([
    prisma.webAuthnCredential.update({
      where: { id: cred.id },
      data: {
        counter: BigInt(newCounter),
        lastUsedAt: new Date(),
        deviceName: deviceLabel ?? undefined,
      },
    }),
    prisma.activationSession.update({
      where: { id: session.id },
      data: {
        consumedAt: new Date(),
        consumedDeviceLabel: deviceLabel,
        challenge: null,
      },
    }),
    prisma.card.update({
      where: { id: session.cardId },
      data: { status: CardStatus.ACTIVATED },
      select: micrositeProgramSelect,
    }),
  ]);

  return buildResult({
    cardRef: updatedCard.cardRef,
    credentialId: cred.credentialId,
    program: updatedCard.program,
    mode: 'assert',
  });
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const micrositeProgramSelect = {
  cardRef: true,
  program: {
    select: {
      id: true,
      preActivationNdefUrlTemplate: true,
      postActivationNdefUrlTemplate: true,
      micrositeEnabled: true,
      micrositeActiveVersion: true,
    },
  },
} as const;

interface ProgramFields {
  id: string;
  preActivationNdefUrlTemplate: string | null;
  postActivationNdefUrlTemplate: string | null;
  micrositeEnabled: boolean;
  micrositeActiveVersion: string | null;
}

function buildResult(input: {
  cardRef: string;
  credentialId: string;
  program: ProgramFields | null;
  mode: 'register' | 'assert';
}): FinishResult {
  const config = getActivationConfig();
  const { postActivation } = renderNdefUrls({
    cardRef: input.cardRef,
    preActivationTemplate: input.program?.preActivationNdefUrlTemplate ?? null,
    postActivationTemplate: input.program?.postActivationNdefUrlTemplate ?? null,
  });

  const micrositeUrl =
    input.program?.micrositeEnabled && input.program.micrositeActiveVersion
      ? `${config.MICROSITE_CDN_URL.replace(/\/$/, '')}/programs/${input.program.id}/?card=${encodeURIComponent(
          input.cardRef,
        )}&activated=true`
      : null;

  return {
    cardActivated: true,
    credentialId: input.credentialId,
    postActivationNdefUrl: postActivation,
    mode: input.mode,
    micrositeUrl,
  };
}

// Re-export to satisfy imports; finishAssert also needs the route schema
// to accept the assertion response shape.
export type { AuthenticationResponseJSON, RegistrationResponseJSON };
