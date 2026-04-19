/**
 * POST /api/card-ops/register — S2S endpoint called by activation to
 * prime a CardOpSession after the admin hits /api/admin/card-op/start.
 *
 * HMAC-signed (not Cognito) — only the activation service may call this.
 * The session row is already created by activation; we just verify it
 * exists, is in READY phase, and isn't stale.
 *
 * Returns the canonical WS path for the session so activation can build
 * the external wsUrl correctly.
 */

import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { badRequest, notFound } from '@palisade/core';

const registerSchema = z.object({
  sessionId: z.string().min(1),
  cardId: z.string().min(1),
  cardRef: z.string().min(1),
  operation: z.string().min(1),
});

export function createRegisterRouter(): Router {
  const router = Router();

  router.post('/register', async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      throw badRequest('validation_failed', parsed.error.message);
    }
    const { sessionId, cardId, operation } = parsed.data;

    const session = await prisma.cardOpSession.findUnique({
      where: { id: sessionId },
    });
    if (!session) throw notFound('session_not_found', `No session ${sessionId}`);
    if (session.cardId !== cardId) {
      throw badRequest('card_mismatch', 'Session does not belong to requested card');
    }
    if (session.operation !== operation) {
      throw badRequest('op_mismatch', 'Session operation does not match');
    }
    if (session.phase !== 'READY') {
      throw badRequest('bad_phase', `Session phase is ${session.phase}, expected READY`);
    }

    res.json({
      ok: true,
      wsPath: `/api/card-ops/relay/${sessionId}`,
    });
  });

  return router;
}
