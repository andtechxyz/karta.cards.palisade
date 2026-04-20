/**
 * Data prep API routes.
 *
 * POST /api/data-prep/prepare  — Stage SAD for a card
 * GET  /api/data-prep/sad/:proxyCardId — Retrieve encrypted SAD (internal, RCA calls this)
 * DELETE /api/data-prep/sad/:proxyCardId — Revoke SAD
 */

import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { badRequest, notFound } from '@palisade/core';

import { DataPrepService } from '../services/data-prep.service.js';
import { metrics } from '../metrics.js';

const prepareSchema = z.object({
  cardId: z.string().min(1),
  pan: z.string().regex(/^\d{13,19}$/),
  expiryYymm: z.string().regex(/^\d{4}$/),
  serviceCode: z.string().regex(/^\d{3}$/).optional(),
  cardSequenceNumber: z.string().regex(/^\d{2}$/).optional(),
  chipSerial: z.string().optional(),
  programId: z.string().min(1),
});

export function createDataPrepRouter(): Router {
  const router = Router();
  const service = new DataPrepService();

  // POST /api/data-prep/prepare
  router.post('/prepare', async (req, res) => {
    const parsed = prepareSchema.safeParse(req.body);
    if (!parsed.success) {
      // eslint-disable-next-line no-console
      console.log(
        `[err] data-prep/prepare validation_failed paths=[${parsed.error.issues.map((i) => i.path.join('.')).join(',')}]`,
      );
      metrics().counter('data-prep.prepare.fail', 1, { reason: 'validation' });
      throw badRequest('validation_failed', 'Request failed validation');
    }

    const startedAt = Date.now();
    try {
      const result = await service.prepareCard(parsed.data);
      metrics().counter('data-prep.prepare.ok', 1);
      metrics().timing('data-prep.prepare.duration_ms', Date.now() - startedAt);
      res.status(201).json(result);
    } catch (err) {
      // Classify known failure surfaces so the dashboard separates a KMS
      // outage from an APC misconfig from a missing issuer profile.
      const msg = err instanceof Error ? err.message.toLowerCase() : '';
      const reason =
        msg.includes('issuerprofile') || msg.includes('issuer profile') ? 'issuer_profile_missing'
        : msg.includes('kms') ? 'kms_error'
        : msg.includes('paymentcryptography') || msg.includes('apc') ? 'apc_error'
        : 'other';
      metrics().counter('data-prep.prepare.fail', 1, { reason });
      metrics().timing('data-prep.prepare.duration_ms', Date.now() - startedAt);
      throw err;
    }
  });

  // GET /api/data-prep/sad/:proxyCardId
  router.get('/sad/:proxyCardId', async (req, res) => {
    const record = await prisma.sadRecord.findUnique({
      where: { proxyCardId: req.params.proxyCardId },
    });

    if (!record) throw notFound('sad_not_found', 'SAD record not found');
    if (record.status === 'REVOKED') {
      res.status(410).json({ error: { code: 'sad_revoked', message: 'SAD record has been revoked' } });
      return;
    }
    if (record.status !== 'READY') {
      res.status(409).json({
        error: { code: 'sad_not_ready', message: `SAD record status is '${record.status}', expected 'READY'` },
      });
      return;
    }

    res.json({
      proxyCardId: record.proxyCardId,
      cardId: record.cardId,
      sadEncrypted: record.sadEncrypted.toString('base64'),
      sadKeyVersion: record.sadKeyVersion,
      chipSerial: record.chipSerial,
      status: record.status,
      expiresAt: record.expiresAt.toISOString(),
    });
  });

  // DELETE /api/data-prep/sad/:proxyCardId
  router.delete('/sad/:proxyCardId', async (req, res) => {
    const record = await prisma.sadRecord.findUnique({
      where: { proxyCardId: req.params.proxyCardId },
    });

    if (!record) throw notFound('sad_not_found', 'SAD record not found');

    await prisma.sadRecord.update({
      where: { id: record.id },
      data: { status: 'REVOKED' },
    });

    res.json({ proxyCardId: record.proxyCardId, status: 'REVOKED' });
  });

  return router;
}
