import { Router } from 'express';
import { prisma } from '@palisade/db';
import { notFound } from '@palisade/core';
import { createCognitoAuthMiddleware } from '@palisade/cognito-auth';
import { getActivationConfig } from '../env.js';

export function createCardsMineRouter(): Router {
  const router = Router();
  const config = getActivationConfig();

  const cognitoAuth = createCognitoAuthMiddleware({
    userPoolId: config.COGNITO_USER_POOL_ID,
    clientId: config.COGNITO_CLIENT_ID,
  });

  // PAN metadata (last4, expiry, cardholderName) now lives directly on the
  // Card row after the Phase 2 FK cut — no vault join at read time.

  // GET /api/cards/mine — list cards belonging to authenticated mobile user
  router.get('/', cognitoAuth, async (req, res) => {
    const sub = req.cognitoUser!.sub;

    const cards = await prisma.card.findMany({
      where: { cognitoSub: sub },
      select: {
        id: true,
        cardRef: true,
        status: true,
        panLast4: true,
        cardholderName: true,
        panExpiryMonth: true,
        panExpiryYear: true,
        program: {
          select: {
            name: true,
            financialInstitution: { select: { name: true } },
          },
        },
        credentials: {
          select: { id: true, kind: true, deviceName: true, createdAt: true },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    res.json(
      cards.map((c) => ({
        id: c.id,
        cardRef: c.cardRef,
        status: c.status,
        panLast4: c.panLast4 ?? null,
        cardholderName: c.cardholderName ?? null,
        panExpiryMonth: c.panExpiryMonth ?? null,
        panExpiryYear: c.panExpiryYear ?? null,
        programName: c.program?.name ?? null,
        financialInstitutionName:
          c.program?.financialInstitution?.name ?? null,
        credentials: c.credentials,
      })),
    );
  });

  // GET /api/cards/mine/:cardId — single card detail
  router.get('/:cardId', cognitoAuth, async (req, res) => {
    const sub = req.cognitoUser!.sub;
    const card = await prisma.card.findFirst({
      where: { id: req.params.cardId, cognitoSub: sub },
      select: {
        id: true,
        cardRef: true,
        status: true,
        panLast4: true,
        cardholderName: true,
        panExpiryMonth: true,
        panExpiryYear: true,
        program: {
          select: {
            name: true,
            financialInstitution: { select: { name: true } },
          },
        },
        credentials: {
          select: { id: true, kind: true, deviceName: true, createdAt: true },
        },
      },
    });
    if (!card) throw notFound('card_not_found', 'Card not found or not yours');

    res.json({
      id: card.id,
      cardRef: card.cardRef,
      status: card.status,
      panLast4: card.panLast4 ?? null,
      cardholderName: card.cardholderName ?? null,
      panExpiryMonth: card.panExpiryMonth ?? null,
      panExpiryYear: card.panExpiryYear ?? null,
      programName: card.program?.name ?? null,
      financialInstitutionName:
        card.program?.financialInstitution?.name ?? null,
      credentials: card.credentials,
    });
  });

  return router;
}
