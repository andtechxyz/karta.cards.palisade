import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
} from '@simplewebauthn/server';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';
import { CardStatus } from '@prisma/client';
import { prisma } from '@palisade/db';
import { notFound, conflict, internal, aesCmac, decrypt } from '@palisade/core';
import {
  buildNfcCardRegistrationOptions,
  buildAuthenticationOptions,
} from '@palisade/webauthn';
import { renderNdefUrls } from '../programs/ndef.js';
import { getCardFieldKeyProvider } from '../cards/key-provider.js';
import { loadActiveSession } from './session.js';

// First leg of the activation ceremony.
//
// Two modes are returned depending on whether the card already carries a
// pre-registered FIDO credential:
//
//   1. Card has a preregistered credential (perso-time FIDO mint):
//         → mode="assert"
//      Server derives the card's post-activation URL, computes
//      AES-CMAC(sdmFileReadKey, url), and emits url+cmac to the
//      authenticator via TWO parallel channels:
//        (a) an extended credential ID tail — <credId>||<url>||<cmac> —
//            consumed by the applet's CTAP1 u2FAuthenticate path on
//            Android Chrome (CTAP1/U2F over NFC), AND by the CTAP2
//            allowList fallback;
//        (b) a WebAuthn extension `karta-url` carrying the same
//            <url>||<cmac> bytes — consumed by the applet's CTAP2
//            getAssertion extension parser, used when the browser
//            truncates cred IDs (observed on iOS Safari).
//      The applet uses setUrlWithMac() via SIO to rotate its own baseUrl
//      and state to ACTIVATED.  Whichever channel delivers, the chip
//      flips.  A real WebAuthn assertion is also performed; /finish
//      verifies the signature and flips Card.status to ACTIVATED.
//
//   2. No preregistered credential:
//         → mode="register"
//      The legacy flow — frontend runs startRegistration(), /finish
//      verifies the attestation, inserts a new WebAuthnCredential.

export type BeginActivationResponse =
  | { mode: 'register'; options: PublicKeyCredentialCreationOptionsJSON }
  | { mode: 'assert'; options: PublicKeyCredentialRequestOptionsJSON };

export async function beginActivationRegistration(
  sessionToken: string,
): Promise<BeginActivationResponse> {
  const session = await loadActiveSession(sessionToken);
  const card = await prisma.card.findUnique({
    where: { id: session.cardId },
    select: {
      id: true,
      cardRef: true,
      status: true,
      sdmFileReadKeyEncrypted: true,
      keyVersion: true,
      program: {
        select: {
          urlCode: true,
          preActivationNdefUrlTemplate: true,
          postActivationNdefUrlTemplate: true,
        },
      },
      credentials: {
        select: {
          credentialId: true,
          kind: true,
          preregistered: true,
          transports: true,
        },
      },
    },
  });
  if (!card) throw notFound('card_not_found', 'Card not found for session');
  if (card.status === CardStatus.ACTIVATED) {
    throw conflict('card_already_activated', 'Card is already activated');
  }

  const preReg = card.credentials.find((c) => c.preregistered);

  // -------------------------------------------------------------------------
  // Assert path — preregistered credential exists.  Build the extended
  // credential ID (credId || postActivationUrl || cmac) so the chip can
  // self-update during the assertion ceremony.
  // -------------------------------------------------------------------------
  if (preReg) {
    // Resolve the post-activation URL from the program template.  The
    // applet's baseUrl is the host+path WITHOUT scheme and WITHOUT the
    // `?e=.&m=.` query (the chip appends that itself on every tap).
    const { postActivation: postActivationUrl } = renderNdefUrls({
      cardRef: card.cardRef,
      urlCode: card.program?.urlCode ?? null,
      preActivationTemplate: card.program?.preActivationNdefUrlTemplate ?? null,
      postActivationTemplate: card.program?.postActivationNdefUrlTemplate ?? null,
    });
    const bakedBase = stripUrlForChip(postActivationUrl);
    const urlBytes = Buffer.from(bakedBase, 'utf8');

    // Decrypt the card's sdmFileReadKey — same key the T4T applet's macKey
    // is loaded from at install time.  Needed to compute a CMAC the applet
    // will accept.
    const fileReadKeyHex = decrypt(
      {
        ciphertext: card.sdmFileReadKeyEncrypted,
        keyVersion: card.keyVersion,
      },
      getCardFieldKeyProvider(),
    );
    const fileReadKey = Buffer.from(fileReadKeyHex, 'hex');
    if (fileReadKey.length !== 16) {
      throw internal('bad_file_read_key', 'sdmFileReadKey is not 16 bytes');
    }
    const cmac = aesCmac(fileReadKey, urlBytes); // 16 bytes
    fileReadKey.fill(0); // scrub

    // Build the extended credential ID bytes: <realCredId> || <url> || <cmac>
    // Channel (a) — present in allowCredentials[0].id, picked up by the
    // applet's CTAP1 path AND its CTAP2 allowList tail-stripping logic.
    const realCredId = Buffer.from(preReg.credentialId, 'base64url');
    const extended = Buffer.concat([realCredId, urlBytes, cmac]);
    const extendedB64u = extended.toString('base64url');

    // Channel (b) — `karta-url` WebAuthn extension carrying <url>||<cmac>
    // (no real cred ID prefix needed; allowList delivers that already).
    // This is the ONLY channel that survives iOS Safari's cred-ID
    // truncation; the applet's CTAP2 extension parser consumes it.
    const kartaUrlPayload = Buffer.concat([urlBytes, cmac]).toString('base64url');

    const opts = buildAuthenticationOptions({
      credentials: [
        {
          id: extendedB64u,
          kind: preReg.kind,
          transports: preReg.transports,
        },
      ],
    });
    const options = await generateAuthenticationOptions(opts);

    // Attach the karta-url extension.  @simplewebauthn types only know
    // about the standard WebAuthn extensions, so we widen to Record to
    // attach a custom one.  Browsers that don't recognise it should
    // ignore it (per WebAuthn §9.4); browsers that pass it through
    // deliver the url+cmac to the authenticator.
    const ext = { ...(options.extensions ?? {}), 'karta-url': kartaUrlPayload };
    options.extensions = ext as typeof options.extensions;

    await prisma.activationSession.update({
      where: { id: session.id },
      data: { challenge: options.challenge },
    });

    return { mode: 'assert', options };
  }

  // -------------------------------------------------------------------------
  // Register path — no preregistered cred.  Fresh WebAuthn registration.
  // -------------------------------------------------------------------------
  const excludeCredentialIds = card.credentials
    .filter((c) => c.kind === 'CROSS_PLATFORM' && !c.preregistered)
    .map((c) => c.credentialId);

  const regOpts = buildNfcCardRegistrationOptions({
    userHandle: card.id,
    userLabel: `card_${card.id.slice(0, 8)}`,
    excludeCredentialIds,
  });
  const options = await generateRegistrationOptions(regOpts);

  await prisma.activationSession.update({
    where: { id: session.id },
    data: { challenge: options.challenge },
  });

  return { mode: 'register', options };
}

/**
 * Strip `https://` and any trailing `?e=.*&m=.*` from a URL template.  The
 * T4T applet stores the bare host+path; its URI-code prefix (0x04) adds
 * `https://` on the wire and the SDM crypto appends `?e=<hex>&m=<hex>` on
 * every tap.  Placeholders like `{PICCData}` / `{CMAC}` aren't meaningful
 * here — the applet builds those itself — so we drop the whole query.
 */
function stripUrlForChip(url: string): string {
  let s = url;
  if (s.toLowerCase().startsWith('https://')) s = s.slice('https://'.length);
  else if (s.toLowerCase().startsWith('http://')) s = s.slice('http://'.length);
  const q = s.indexOf('?');
  if (q >= 0) s = s.slice(0, q);
  return s;
}
