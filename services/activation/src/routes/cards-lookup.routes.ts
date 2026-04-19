import { Router, type RequestHandler } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { notFound } from '@palisade/core';

// ---------------------------------------------------------------------------
// Pay-gated cross-repo card endpoints.
//
// Used by Vera's pay service to resolve transaction-auth state + to bump the
// ATC counter without reaching into Palisade's Postgres.  Mounted on the
// activation service behind the service-auth HMAC gate (keyId='pay') in
// index.ts via createCardsPayRouter().
//
// Routes defined here:
//   GET   /lookup/:cardId        — minimal card projection pay needs today
//                                  (id, cardRef, status, programId,
//                                   retailSaleStatus, chipSerial, panLast4,
//                                   panBin, cardholderName)
//   PATCH /:cardId/atc-increment — atomic +1 on Card.atc, returns new value
//                                  (ARQC replay prevention on pay side).
//
// Both routes live on the same router so they share a single express.json
// mount + can fall through to the provisioning-authed /api/cards router for
// requests they don't match (e.g. POST /register).  The pay gate is attached
// per-route so the fall-through path isn't blocked on unsigned provisioning
// calls.
// ---------------------------------------------------------------------------

// cuid shape validation — same pattern Prisma uses for its default IDs.
// Accepts cuid v1 ("c" + 24 chars base36) and cuid2 (24 chars base36) as well
// as the snake-case dev IDs used in tests (e.g. "card_1").  This is cheap
// shape-prefiltering — real auth is the HMAC gate upstream of this router.
const cardIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, 'invalid cardId shape');

/**
 * Build the pay-gated cards router.  The HMAC gate is applied per-route so
 * unmatched paths (e.g. POST /api/cards/register) fall through to the
 * provisioning-authed mount that lives at the same /api/cards prefix.
 */
export function createCardsPayRouter(payGate: RequestHandler): Router {
  const router: Router = Router();

  router.get('/lookup/:cardId', payGate, async (req, res) => {
    const cardId = cardIdSchema.parse(req.params.cardId);

    const card = await prisma.card.findUnique({
      where: { id: cardId },
      select: {
        id: true,
        cardRef: true,
        status: true,
        programId: true,
        retailSaleStatus: true,
        chipSerial: true,
        panLast4: true,
        panBin: true,
        cardholderName: true,
        // vaultToken = opaque Vera VaultEntry id (the cross-repo FK
        // surrogate from Phase 2 FK cut).  Pay stamps this onto
        // Transaction.vaultEntryId at create time so the payment-auth
        // path can mint retrieval tokens without a second round-trip.
        vaultToken: true,
      },
    });
    if (!card) throw notFound('card_not_found', 'Card not found');

    res.json(card);
  });

  // Atomic increment of Card.atc — ARQC replay-prevention counter on the pay
  // side.  Uses `updateMany` so a missing cardId gives us a count=0 we can
  // turn into a clean 404 (plain `update` throws P2025 that the error
  // middleware would return as 500).
  router.patch('/:cardId/atc-increment', payGate, async (req, res) => {
    const cardId = cardIdSchema.parse(req.params.cardId);

    const { count } = await prisma.card.updateMany({
      where: { id: cardId },
      data: { atc: { increment: 1 } },
    });
    if (count === 0) throw notFound('card_not_found', 'Card not found');

    // Re-read the new atc value.  `updateMany` doesn't return rows; a
    // follow-up `findUnique` is cheap and keeps the handler simple.
    const card = await prisma.card.findUnique({
      where: { id: cardId },
      select: { atc: true },
    });
    if (!card) throw notFound('card_not_found', 'Card not found');

    res.json({ atc: card.atc });
  });

  return router;
}
