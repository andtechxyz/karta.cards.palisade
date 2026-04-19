import { Router, type RequestHandler } from 'express';
import { z } from 'zod';
import { prisma, CredentialKind } from '@palisade/db';
import { notFound, validateBody } from '@palisade/core';

// ---------------------------------------------------------------------------
// Pay-gated WebAuthn credential endpoints.
//
// Used by Vera's pay service to resolve / create / bump WebAuthn credentials
// without reaching into Palisade's Postgres.  Mounted on the activation
// service behind the PAY_AUTH_KEYS HMAC gate (keyId='pay') in index.ts.
//
// Two routers are exposed so the card-nested routes (/api/cards/:cardId/...)
// can fall through to the provisioning-authed /api/cards mount for requests
// they don't match:
//
//   cardScoped (mounted at /api/cards):
//     GET  /:cardId/webauthn-credentials
//     POST /:cardId/webauthn-credentials
//
//   credentialScoped (mounted at /api/webauthn-credentials):
//     GET   /:credentialId
//     PATCH /:credentialId/counter
//
// Response shape for a credential row:
//   { id, credentialId, publicKey, counter (string — BigInt), deviceName,
//     kind, createdAt, lastUsedAt }
//
// Note: the underlying column is WebAuthnCredential.counter (BigInt),
// NOT signCounter.  Returned as a JSON string to avoid BigInt-in-JSON
// serialisation issues.
// ---------------------------------------------------------------------------

const cardIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, 'invalid cardId shape');

// WebAuthn credentialId is base64url — up to ~1024 chars for long FIDO CTAP1
// key handles.  Cap conservatively; real auth is the HMAC gate upstream.
const credentialIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,2048}$/, 'invalid credentialId shape');

// Zod validator for POST body.  `kind` is the Prisma CredentialKind enum
// (PLATFORM | CROSS_PLATFORM).  signCounter in the spec → counter column.
const createCredentialSchema = z.object({
  credentialId: credentialIdSchema,
  publicKey: z.string().min(1).max(4096),
  // Accept number or string so BigInt can round-trip through JSON.  Coerce
  // to bigint downstream.
  signCounter: z.union([z.number().int().nonnegative(), z.string().regex(/^\d+$/)]),
  deviceName: z.string().max(128).optional(),
  kind: z.nativeEnum(CredentialKind),
});

const updateCounterSchema = z.object({
  signCounter: z.union([z.number().int().nonnegative(), z.string().regex(/^\d+$/)]),
});

type CredentialRow = {
  id: string;
  credentialId: string;
  publicKey: string;
  counter: bigint;
  deviceName: string | null;
  kind: CredentialKind;
  createdAt: Date;
  lastUsedAt: Date | null;
};

// Serialise a credential row for the wire.  BigInt → string so JSON.stringify
// doesn't throw and the pay side can read it as a numeric string.
function serialiseCredential(cred: CredentialRow): Record<string, unknown> {
  return {
    id: cred.id,
    credentialId: cred.credentialId,
    publicKey: cred.publicKey,
    signCounter: cred.counter.toString(),
    deviceName: cred.deviceName,
    kind: cred.kind,
    createdAt: cred.createdAt.toISOString(),
    lastUsedAt: cred.lastUsedAt ? cred.lastUsedAt.toISOString() : null,
  };
}

const credentialSelect = {
  id: true,
  credentialId: true,
  publicKey: true,
  counter: true,
  deviceName: true,
  kind: true,
  createdAt: true,
  lastUsedAt: true,
} as const;

export interface WebAuthnRouters {
  /** Mount at /api/cards — GET/POST /:cardId/webauthn-credentials. */
  cardScoped: Router;
  /** Mount at /api/webauthn-credentials — GET / PATCH /:credentialId*. */
  credentialScoped: Router;
}

export function createWebAuthnRouters(payGate: RequestHandler): WebAuthnRouters {
  const cardScoped: Router = Router();
  const credentialScoped: Router = Router();

  // ---------------------------------------------------------------------
  // Card-scoped: /api/cards/:cardId/webauthn-credentials
  // ---------------------------------------------------------------------

  cardScoped.get('/:cardId/webauthn-credentials', payGate, async (req, res) => {
    const cardId = cardIdSchema.parse(req.params.cardId);

    // findMany with no match returns []; mirrors the spec's "empty array if
    // none".  We still 404 if the card itself doesn't exist so pay can tell
    // an unknown-card from a known-card-with-no-creds apart.
    const card = await prisma.card.findUnique({ where: { id: cardId }, select: { id: true } });
    if (!card) throw notFound('card_not_found', 'Card not found');

    const creds = await prisma.webAuthnCredential.findMany({
      where: { cardId },
      select: credentialSelect,
      orderBy: { createdAt: 'asc' },
    });
    res.json(creds.map(serialiseCredential));
  });

  cardScoped.post(
    '/:cardId/webauthn-credentials',
    payGate,
    validateBody(createCredentialSchema),
    async (req, res) => {
      const cardId = cardIdSchema.parse(req.params.cardId);
      const body = req.body as z.infer<typeof createCredentialSchema>;

      const card = await prisma.card.findUnique({ where: { id: cardId }, select: { id: true } });
      if (!card) throw notFound('card_not_found', 'Card not found');

      const created = await prisma.webAuthnCredential.create({
        data: {
          cardId,
          credentialId: body.credentialId,
          publicKey: body.publicKey,
          counter: BigInt(body.signCounter),
          deviceName: body.deviceName,
          kind: body.kind,
          transports: [],
        },
        select: credentialSelect,
      });
      res.status(201).json(serialiseCredential(created));
    },
  );

  // ---------------------------------------------------------------------
  // Credential-scoped: /api/webauthn-credentials/:credentialId
  // ---------------------------------------------------------------------

  credentialScoped.get('/:credentialId', payGate, async (req, res) => {
    const credentialId = credentialIdSchema.parse(req.params.credentialId);

    // Task spec says findFirst (not findUnique) in case credentialId isn't
    // uniquely indexed.  Schema confirms it IS @unique, but sticking to
    // findFirst keeps the endpoint resilient to schema drift + matches the
    // spec exactly.
    const cred = await prisma.webAuthnCredential.findFirst({
      where: { credentialId },
      select: credentialSelect,
    });
    if (!cred) throw notFound('credential_not_found', 'WebAuthn credential not found');

    res.json(serialiseCredential(cred));
  });

  credentialScoped.patch(
    '/:credentialId/counter',
    payGate,
    validateBody(updateCounterSchema),
    async (req, res) => {
      const credentialId = credentialIdSchema.parse(req.params.credentialId);
      const body = req.body as z.infer<typeof updateCounterSchema>;
      const now = new Date();

      // updateMany lets us turn "no row" into a clean 404 (plain update would
      // throw P2025 and surface as 500 via the error middleware).
      const { count } = await prisma.webAuthnCredential.updateMany({
        where: { credentialId },
        data: {
          counter: BigInt(body.signCounter),
          lastUsedAt: now,
        },
      });
      if (count === 0) {
        throw notFound('credential_not_found', 'WebAuthn credential not found');
      }

      res.json({
        signCounter: BigInt(body.signCounter).toString(),
        lastUsedAt: now.toISOString(),
      });
    },
  );

  return { cardScoped, credentialScoped };
}
