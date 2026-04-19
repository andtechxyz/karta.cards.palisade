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

  // GET /api/cards/mine — list cards belonging to authenticated mobile user
  router.get('/', cognitoAuth, async (req, res) => {
    const sub = req.cognitoUser!.sub;

    const cards = await prisma.card.findMany({
      where: { cognitoSub: sub },
      select: {
        id: true,
        cardRef: true,
        status: true,
        vaultEntry: {
          select: { panLast4: true, cardholderName: true, panExpiryMonth: true, panExpiryYear: true },
        },
        program: { select: { name: true } },
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
        panLast4: c.vaultEntry?.panLast4 ?? null,
        cardholderName: c.vaultEntry?.cardholderName ?? null,
        panExpiryMonth: c.vaultEntry?.panExpiryMonth ?? null,
        panExpiryYear: c.vaultEntry?.panExpiryYear ?? null,
        programName: c.program?.name ?? null,
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
        vaultEntry: {
          select: { panLast4: true, cardholderName: true, panExpiryMonth: true, panExpiryYear: true },
        },
        program: { select: { name: true } },
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
      panLast4: card.vaultEntry?.panLast4 ?? null,
      cardholderName: card.vaultEntry?.cardholderName ?? null,
      panExpiryMonth: card.vaultEntry?.panExpiryMonth ?? null,
      panExpiryYear: card.vaultEntry?.panExpiryYear ?? null,
      programName: card.program?.name ?? null,
      credentials: card.credentials,
    });
  });

  return router;
}
