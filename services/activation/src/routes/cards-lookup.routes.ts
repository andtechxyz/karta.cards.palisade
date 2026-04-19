import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { notFound } from '@palisade/core';

// ---------------------------------------------------------------------------
// GET /api/cards/lookup/:cardId — cross-repo card-state lookup.
//
// Used by Vera's pay service to resolve transaction-auth state without
// reaching into Palisade's Postgres.  Mounted on the activation service
// behind the service-auth HMAC gate (keyId='pay') in index.ts.
//
// Response shape is the minimum pay needs today:
//   id, cardRef, status, programId, retailSaleStatus, chipSerial,
//   panLast4, panBin, cardholderName
// — mirroring the fields pay used to read directly from Vera's Card table
// pre-split.  Extending the shape is cheap (no pan ciphertext, no keys,
// nothing that would widen the pay blast radius).
// ---------------------------------------------------------------------------

// cuid shape validation — same pattern Prisma uses for its default IDs.
// Accepts cuid v1 ("c" + 24 chars base36) and cuid2 (24 chars base36) as well
// as the snake-case dev IDs used in tests (e.g. "card_1").  This is cheap
// shape-prefiltering — real auth is the HMAC gate upstream of this router.
const cardIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/, 'invalid cardId shape');

const cardsLookupRouter: Router = Router();

cardsLookupRouter.get('/:cardId', async (req, res) => {
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
    },
  });
  if (!card) throw notFound('card_not_found', 'Card not found');

  res.json(card);
});

export default cardsLookupRouter;
