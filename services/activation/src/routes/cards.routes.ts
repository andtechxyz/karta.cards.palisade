import { Router } from 'express';
import { z } from 'zod';
import { validateBody, hexKey, badRequest, notFound } from '@palisade/core';
import { prisma } from '@palisade/db';
import { registerCard } from '../cards/index.js';
import { metrics } from '../metrics.js';

const router: Router = Router();

const registerSchema = z.object({
  cardRef: z.string().regex(/^[A-Za-z0-9_-]{4,64}$/, 'cardRef must be 4-64 alphanumeric / _ / -'),
  uid: hexKey(7),
  chipSerial: z.string().max(64).optional(),
  programId: z.string().max(64).optional(),
  batchId: z.string().max(64).optional(),
  card: z.object({
    pan: z.string().min(12).max(23),
    cvc: z.string().optional(),
    expiryMonth: z.string().regex(/^(0[1-9]|1[0-2])$/),
    expiryYear: z.string().regex(/^[0-9]{2,4}$/),
    cardholderName: z.string().min(1).max(128),
  }),
});

router.post('/register', validateBody(registerSchema), async (req, res) => {
  try {
    const result = await registerCard({
      ...req.body,
      ip: req.ip,
      ua: req.get('user-agent') ?? undefined,
    });
    metrics().counter('activation.register.ok', 1);
    res.status(201).json(result);
  } catch (err) {
    // Classify known failure modes so the dashboard can separate
    // "duplicate card" (expected churn) from "vault rejected" (real
    // problem).  Everything else becomes `other` so alarms on a spike
    // of unclassified failures still fire.
    const code =
      err && typeof err === 'object' && 'code' in err
        ? String((err as { code?: string }).code)
        : 'other';
    const reason =
      code === 'card_already_registered' ? 'duplicate'
      : code.startsWith('vault_') ? 'vault_rejected'
      : code === 'validation_failed' ? 'validation'
      : 'other';
    metrics().counter('activation.register.fail', 1, { reason });
    throw err;
  }
});

// RCA fires this callback after its $transaction has ALREADY flipped
// Card.status to PROVISIONED, so by the time we land here the expected
// state is usually PROVISIONED, not ACTIVATED.  Idempotent on both:
// - ACTIVATED → we do the flip (rare path: RCA's async commit hadn't
//   landed yet, we're racing ahead of it)
// - PROVISIONED → no-op success (normal case post-RCA-commit)
// - anything else → genuine invalid state, reject
router.post('/:cardRef/provision-complete', async (req, res) => {
  const { chipSerial } = req.body as { chipSerial?: string };
  const card = await prisma.card.findUnique({ where: { cardRef: req.params.cardRef } });
  if (!card) {
    metrics().counter('activation.provision_complete.fail', 1, { reason: 'card_not_found' });
    throw notFound('card_not_found', 'Unknown cardRef');
  }

  // Already PROVISIONED — common case (RCA's $transaction committed
  // before fireCallback ran).  Echo success; maybe fill in chipSerial
  // if the callback carries fresher info than what's on the row.
  if (card.status === 'PROVISIONED') {
    if (chipSerial && chipSerial !== card.chipSerial) {
      await prisma.card.update({
        where: { id: card.id },
        data: { chipSerial },
      });
    }
    metrics().counter('activation.provision_complete.ok', 1, { path: 'idempotent' });
    res.json({ cardRef: card.cardRef, status: 'PROVISIONED' });
    return;
  }

  if (card.status !== 'ACTIVATED') {
    metrics().counter('activation.provision_complete.fail', 1, {
      reason: 'invalid_status',
      status: card.status,
    });
    throw badRequest('invalid_status', `Card is ${card.status}, expected ACTIVATED or PROVISIONED`);
  }

  // ACTIVATED — we race RCA's commit.  updateMany with status guard so
  // we don't overwrite if RCA beats us to the row between findUnique
  // and update.
  const { count } = await prisma.card.updateMany({
    where: { id: card.id, status: 'ACTIVATED' },
    data: {
      status: 'PROVISIONED',
      provisionedAt: new Date(),
      chipSerial: chipSerial ?? card.chipSerial,
    },
  });
  metrics().counter('activation.provision_complete.ok', 1, {
    path: count === 1 ? 'fresh' : 'raced',
  });

  res.json({ cardRef: card.cardRef, status: 'PROVISIONED' });
});

export default router;
