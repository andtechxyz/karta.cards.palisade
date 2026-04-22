import { Router } from 'express';
import { Prisma, CredentialKind } from '@prisma/client';
import { z } from 'zod';
import { validateBody, badRequest, notFound, conflict } from '@palisade/core';
import { prisma } from '@palisade/db';

// GET   /api/cards                            — list cards for admin Cards tab
// PATCH /api/cards/:id                        — admin-only program reassignment
// POST  /api/cards/:cardRef/mark-sold         — flip retail card SHIPPED → SOLD
// POST  /api/cards/:cardRef/credentials       — inject a pre-registered FIDO cred
// GET   /api/cards/:cardRef/credentials       — list creds (for the admin UI)
// DELETE /api/cards/:cardRef/credentials/:id  — remove a pre-registered cred
// Registration (POST /api/cards/register) belongs to the activation service.

const router: Router = Router();

// GET /api/cards
//
// Cards list for the admin SPA's Cards tab.  Returns the shape the
// frontend's `Card` interface expects (services/admin/frontend/src/
// features/cards/types.ts in the Vera repo): card row + program join
// + credentials (pre-registered FIDO creds from the Credential
// table) + activation sessions.
//
// vaultEntry is intentionally omitted at list time — vault lookups
// are an extra cross-service call per row, expensive at scale.  The
// drawer view fetches vaultEntry on demand for one card via the
// vault-proxy.  Frontend Card type already has vaultEntry as
// optional so this matches the contract.
//
// Pagination: simple LIMIT 500 + offset.  Card count at prototype
// scale is ~hundreds; will need cursor pagination + filters before
// we hit ~10k.
const listQuerySchema = z.object({
  limit: z.coerce.number().int().positive().max(500).default(500),
  offset: z.coerce.number().int().nonnegative().default(0),
});

router.get('/', async (req, res) => {
  const parsed = listQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    throw badRequest('validation_failed', 'Bad limit/offset query params');
  }
  const { limit, offset } = parsed.data;

  const cards = await prisma.card.findMany({
    take: limit,
    skip: offset,
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      cardRef: true,
      status: true,
      retailSaleStatus: true,
      retailSoldAt: true,
      chipSerial: true,
      programId: true,
      // NOTE: frontend Card type expects program.currency but Program
      // schema has no currency field today.  Frontend renders undefined
      // for currency until a follow-up adds Program.currency + a
      // migration to backfill from BIN tables.
      program: {
        select: { id: true, name: true, programType: true },
      },
      batchId: true,
      createdAt: true,
      credentials: {
        select: {
          id: true,
          kind: true,
          deviceName: true,
          createdAt: true,
          lastUsedAt: true,
        },
      },
      activationSessions: {
        select: {
          id: true,
          expiresAt: true,
          consumedAt: true,
          consumedDeviceLabel: true,
          createdAt: true,
        },
        orderBy: { createdAt: 'desc' },
      },
    },
  });
  res.json(cards);
});

const patchSchema = z
  .object({
    programId: z.string().min(1).max(64).nullable().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, {
    message: 'at least one field must be supplied',
  });

router.patch('/:id', validateBody(patchSchema), async (req, res) => {
  const body = req.body as z.infer<typeof patchSchema>;
  const data: Prisma.CardUpdateInput = {};
  if (body.programId !== undefined) {
    data.program = body.programId
      ? { connect: { id: body.programId } }
      : { disconnect: true };
  }

  try {
    const card = await prisma.card.update({
      where: { id: req.params.id },
      data,
      select: {
        id: true,
        cardRef: true,
        programId: true,
        program: { select: { id: true, name: true } },
      },
    });
    res.json(card);
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2025') {
      const cause = typeof err.meta?.cause === 'string' ? err.meta.cause : '';
      if (/No ['"]Program['"] record/i.test(cause)) {
        throw badRequest('program_not_found', `Program ${body.programId} not found`);
      }
      throw notFound('card_not_found', `Card ${req.params.id} not found`);
    }
    throw err;
  }
});

// POST /api/cards/:cardRef/mark-sold
//
// Flips a retail card's retailSaleStatus from SHIPPED to SOLD.  Admin-only
// path — partner API has its own bulk equivalent mounted under /api/partners.
// Idempotent: calling on an already-SOLD card is a no-op (204).  Calling on
// a non-retail card returns 409 so accidental clicks don't silently change
// non-retail behaviour.
router.post('/:cardRef/mark-sold', async (req, res) => {
  const cardRef = req.params.cardRef;
  const card = await prisma.card.findUnique({
    where: { cardRef },
    select: {
      id: true,
      retailSaleStatus: true,
      program: { select: { programType: true } },
    },
  });
  if (!card) throw notFound('card_not_found', `Card ${cardRef} not found`);
  if (card.program?.programType !== 'RETAIL') {
    throw conflict('not_retail', 'Only RETAIL program cards have a sale status');
  }
  if (card.retailSaleStatus === 'SOLD') {
    res.status(204).end();
    return;
  }
  const updated = await prisma.card.update({
    where: { id: card.id },
    data: { retailSaleStatus: 'SOLD', retailSoldAt: new Date() },
    select: { cardRef: true, retailSaleStatus: true, retailSoldAt: true },
  });
  res.json(updated);
});

// ---------------------------------------------------------------------------
// Pre-registered FIDO credentials.
//
// During card personalisation the perso tool drives the FIDO applet to
// generate a credential on the chip via CTAP-NFC.  The applet returns the
// credentialId + COSE public key + transports.  The perso tool then POSTs
// that material here so the activation flow can short-circuit the runtime
// WebAuthn ceremony.  The activation service lives in the Palisade repo
// (services/activation/src/activation/begin.service.ts over there).
//
// Trust model:
//   - This endpoint is mounted under adminAuth (Cognito group=admin OR the
//     legacy X-Admin-Key header).  Only the perso operator can call it.
//   - Card must be in PERSONALISED status — refusing to inject against
//     ACTIVATED/SUSPENDED/REVOKED prevents an admin from quietly attaching
//     a backdoor cred to a card that's already in use.
//   - At most one preregistered credential per card (DB partial unique
//     index enforces this; we 409 here for a friendlier error).
// ---------------------------------------------------------------------------

const credentialSchema = z.object({
  // base64url with no padding — what the FIDO applet returns and what
  // @simplewebauthn stores in the DB.  112 chars = 84 bytes covers the
  // typical NFC key handle; we cap at 1024 to avoid abusive inputs.
  credentialId: z.string().min(1).max(1024).regex(/^[A-Za-z0-9_-]+$/, 'credentialId must be base64url'),
  // COSE-encoded public key, also base64url.  ~150-300 bytes typical; the
  // 4096 cap is generous (and bounded so we never blow up Prisma's JSON-
  // parameter pipeline with a malformed input).
  publicKey: z.string().min(1).max(4096).regex(/^[A-Za-z0-9_-]+$/, 'publicKey must be base64url'),
  transports: z.array(z.string().min(1).max(32)).max(8).default(['nfc']),
  deviceName: z.string().max(128).optional(),
});

router.post(
  '/:cardRef/credentials',
  validateBody(credentialSchema),
  async (req, res) => {
    const { cardRef } = req.params;
    const body = req.body as z.infer<typeof credentialSchema>;

    const card = await prisma.card.findUnique({
      where: { cardRef },
      select: { id: true, status: true },
    });
    if (!card) throw notFound('card_not_found', `Card ${cardRef} not found`);
    // Pre-registration only makes sense before the user has activated the
    // card.  SHIPPED is the normal case (fresh register); PERSONALISED
    // means the provisioning agent has already loaded EMV data, so the
    // user has either already activated or we're racing with that flow.
    if (card.status !== 'SHIPPED') {
      throw conflict(
        'card_not_shipped',
        `Card is ${card.status} — pre-registration only valid in SHIPPED state`,
      );
    }

    // Friendly 409 if a pre-reg credential already exists.  The DB partial
    // unique index would also catch this, but the error there is cryptic.
    const existing = await prisma.webAuthnCredential.findFirst({
      where: { cardId: card.id, preregistered: true },
      select: { id: true },
    });
    if (existing) {
      throw conflict(
        'preregistered_already_exists',
        'Card already has a pre-registered credential — DELETE it first to replace',
      );
    }

    try {
      const created = await prisma.webAuthnCredential.create({
        data: {
          credentialId: body.credentialId,
          publicKey: body.publicKey,
          counter: BigInt(0),
          kind: CredentialKind.CROSS_PLATFORM,
          transports: body.transports,
          deviceName: body.deviceName ?? 'Pre-registered (perso)',
          cardId: card.id,
          preregistered: true,
        },
        select: {
          id: true,
          credentialId: true,
          deviceName: true,
          transports: true,
          createdAt: true,
        },
      });
      res.status(201).json(created);
    } catch (err) {
      // Same credentialId on a different card → unique-constraint violation.
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        throw conflict('credential_id_taken', 'credentialId is already registered to another card');
      }
      throw err;
    }
  },
);

router.get('/:cardRef/credentials', async (req, res) => {
  const { cardRef } = req.params;
  const card = await prisma.card.findUnique({
    where: { cardRef },
    select: { id: true },
  });
  if (!card) throw notFound('card_not_found', `Card ${cardRef} not found`);

  const creds = await prisma.webAuthnCredential.findMany({
    where: { cardId: card.id },
    select: {
      id: true,
      credentialId: true,
      kind: true,
      transports: true,
      deviceName: true,
      preregistered: true,
      createdAt: true,
      lastUsedAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });
  res.json(creds);
});

router.delete('/:cardRef/credentials/:credId', async (req, res) => {
  const { cardRef, credId } = req.params;
  const card = await prisma.card.findUnique({
    where: { cardRef },
    select: { id: true },
  });
  if (!card) throw notFound('card_not_found', `Card ${cardRef} not found`);

  // Scope check — the credential must belong to this card.  Avoids one
  // admin accidentally deleting another card's cred via a typo'd cardRef.
  const cred = await prisma.webAuthnCredential.findUnique({
    where: { id: credId },
    select: { id: true, cardId: true, preregistered: true },
  });
  if (!cred || cred.cardId !== card.id) {
    throw notFound('credential_not_found', `Credential ${credId} not found on this card`);
  }
  // Defensive: only allow deleting pre-registered credentials this way.
  // Real user-registered credentials should be revoked through a separate
  // admin path that audits the action and notifies the cardholder.
  if (!cred.preregistered) {
    throw badRequest(
      'not_preregistered',
      'This credential was registered by the cardholder; use the credential-revoke flow instead',
    );
  }

  await prisma.webAuthnCredential.delete({ where: { id: credId } });
  res.status(204).end();
});

export default router;
