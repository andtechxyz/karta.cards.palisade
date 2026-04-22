/**
 * Data prep API routes.
 *
 * POST   /api/data-prep/prepare            — Stage SAD for a card
 * GET    /api/data-prep/sad/:proxyCardId   — Retrieve encrypted SAD (internal, RCA calls this)
 * DELETE /api/data-prep/sad/:proxyCardId   — Revoke SAD
 * POST   /api/data-prep/attestation/issue  — Mint per-card attestation material (patent C16/C23)
 */

import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { badRequest, notFound } from '@palisade/core';

import { DataPrepService } from '../services/data-prep.service.js';
import {
  issueCardCert,
  makeKmsIssuerSigner,
  CPLC_LEN,
} from '../services/attestation-issuer.js';
import { getDataPrepConfig } from '../env.js';
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
      // Use the router — routes to prepareCard (SAD_LEGACY, default) or
      // prepareParamBundle (PARAM_BUNDLE) based on the programId's
      // ChipProfile.provisioningMode.  Every existing programId has
      // SAD_LEGACY so this is byte-identical to the old behaviour for
      // legacy callers; only cards whose ChipProfile was flipped get the
      // new path.
      const result = await service.prepare(parsed.data);
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

  // -----------------------------------------------------------------------
  // POST /api/data-prep/attestation/issue — patent C16/C23 per-card
  // attestation material.  Callers pass the chip's CPLC (42 bytes hex)
  // and receive back the three blobs that flow into the card via
  // STORE_ATTESTATION P1=0x01/0x02/0x03:
  //
  //   cardAttestPrivRaw (32 B)  — raw P-256 private scalar, STORE P1=0x01
  //   cardCert          (~179 B)— card_pubkey || cplc || sig,  STORE P1=0x02
  //   cplc              (42 B)  — echoed back as-is,            STORE P1=0x03
  //
  // Caller is card-ops/install-pa (post-install) or the one-shot
  // `scripts/load-attestation-on-card.ts` loader for the trial card.
  // Signing happens via KMS alias/palisade-attestation-issuer —
  // data-prep's IAM role must grant kms:Sign on that key.
  //
  // SECURITY: the returned `cardAttestPrivRaw` is a per-card ECDSA
  // private scalar.  It's transported over the internal ALB + HMAC-
  // signed service-auth envelope and written straight into the chip's
  // EEPROM via STORE_ATTESTATION P1=0x01.  Caller MUST scrub its
  // local copy after the APDU round-trip.  No DB persistence — if
  // the install-pa session fails mid-flight, the operator re-runs
  // and a fresh keypair gets minted.
  // -----------------------------------------------------------------------
  const attestationIssueSchema = z.object({
    cplc: z
      .string()
      .regex(/^[0-9a-fA-F]+$/, 'cplc must be hex')
      // 42 bytes = 84 hex chars — CPLC is fixed-width per ISO 7816-6.
      .length(CPLC_LEN * 2, `cplc must be exactly ${CPLC_LEN * 2} hex chars`),
  });

  router.post('/attestation/issue', async (req, res) => {
    const parsed = attestationIssueSchema.safeParse(req.body);
    if (!parsed.success) {
      metrics().counter('data-prep.attestation.fail', 1, { reason: 'validation' });
      throw badRequest(
        'validation_failed',
        `Invalid request: ${parsed.error.issues.map((i) => i.path.join('.') + ':' + i.message).join(', ')}`,
      );
    }
    const cplc = Buffer.from(parsed.data.cplc, 'hex');

    const cfg = getDataPrepConfig();
    if (!cfg.KMS_ATTESTATION_ISSUER_ARN) {
      // Fail loud in production — missing ARN means the IAM grant
      // hasn't landed or Secrets Manager isn't wired.  Do NOT fall
      // back to an in-memory signer here: cards issued under a
      // non-KMS issuer key would never chain-verify against the
      // pinned Issuer cert blob, and the operator would only
      // discover it at tap time.
      metrics().counter('data-prep.attestation.fail', 1, { reason: 'unconfigured' });
      throw badRequest(
        'attestation_unconfigured',
        'KMS_ATTESTATION_ISSUER_ARN is empty; data-prep cannot mint attestation material',
      );
    }
    const signer = makeKmsIssuerSigner(cfg.KMS_ATTESTATION_ISSUER_ARN, cfg.AWS_REGION);

    const started = Date.now();
    try {
      const bundle = await issueCardCert(cplc, signer);
      metrics().timing('data-prep.attestation.ms', Date.now() - started, {});
      metrics().counter('data-prep.attestation.ok', 1, {});

      res.json({
        // Hex everywhere — parses trivially on the card-ops side where
        // STORE_ATTESTATION APDUs want raw bytes.  base64 would force
        // a decode step; hex maps 1:1 to the hex-dump we log on failure.
        cardAttestPrivRaw: bundle.cardAttestPrivRaw.toString('hex'),
        cardCert: bundle.cardCert.toString('hex'),
        cardPubkeyRaw: bundle.cardPubkeyRaw.toString('hex'),
        cplc: cplc.toString('hex'),
      });
    } catch (err) {
      metrics().counter('data-prep.attestation.fail', 1, { reason: 'signer' });
      // eslint-disable-next-line no-console
      console.error('[data-prep] attestation issuance failed:', err);
      throw err;
    }
  });

  return router;
}
