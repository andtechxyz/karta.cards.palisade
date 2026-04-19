/**
 * POST /api/admin/card-op/start — initiate an admin-operated card
 * management session.
 *
 * Flow:
 *   1. Cognito JWT required with `admin` group AND email on the
 *      ADMIN_EMAIL_ALLOWLIST (shared with mobile).  Defence in depth —
 *      group membership alone would let any admin drive destructive
 *      operations; the allowlist tightens this to the breakglass set.
 *   2. Body validated by Zod — operation must be one of the known values,
 *      cardRef must match an existing Card row.
 *   3. A CardOpSession is created with phase='READY'.
 *   4. Activation calls card-ops /api/card-ops/register (HMAC-signed S2S)
 *      to prime the session on the card-ops side.
 *   5. Activation returns { sessionId, wsUrl } to the admin client; the
 *      client opens a WebSocket to card-ops and drives the GP operation.
 *
 * The wsUrl is built from CARD_OPS_PUBLIC_WS_BASE; when unset we fall
 * back to the inbound host (dev convenience).  The mobile app / admin
 * UI never talks directly to card-ops — it only knows the wsUrl we hand
 * back here.
 */

import { Router } from 'express';
import { z } from 'zod';
import { request } from 'undici';
import { prisma } from '@palisade/db';
import { badRequest, notFound, internal } from '@palisade/core';
import { createCognitoAuthMiddleware } from '@palisade/cognito-auth';
import { signRequest } from '@palisade/service-auth';
import { getAdminEmails } from '@palisade/admin-config';
import { getActivationConfig } from '../env.js';

// Explicit enum so Zod rejects typos at the router boundary.  Keep this
// list in sync with services/card-ops/src/operations/index.ts — adding
// a new op requires both ends to know about it.
const OPERATIONS = [
  'list_applets',
  'install_pa',
  'install_t4t',
  'install_receiver',
  'reset_pa_state',
  'uninstall_pa',
  'uninstall_t4t',
  'uninstall_receiver',
  'wipe_card',
] as const;

const startSchema = z.object({
  operation: z.enum(OPERATIONS),
  cardRef: z.string().min(1),
});

export function createCardOpRouter(): Router {
  const router = Router();
  const config = getActivationConfig();

  // Bind the allowlist snapshot into the middleware closure.  Read
  // through getAdminEmails() so tests that mutate process.env between
  // runs are visible.  The list is re-read on every request (cheap).
  const cognitoAdmin = createCognitoAuthMiddleware({
    userPoolId: config.COGNITO_USER_POOL_ID,
    clientId: config.COGNITO_CLIENT_ID,
    requiredGroup: 'admin',
    // Pass a getter-backed proxy so each request re-reads the env.
    // A plain `emailAllowlist: getAdminEmails()` would freeze at module
    // load time, which is fine in prod but surprising in tests.
    get emailAllowlist() {
      return getAdminEmails();
    },
  } as any);

  router.post('/start', cognitoAdmin, async (req, res) => {
    const parsed = startSchema.safeParse(req.body);
    if (!parsed.success) {
      throw badRequest('validation_failed', parsed.error.message);
    }
    const { operation, cardRef } = parsed.data;

    const card = await prisma.card.findUnique({
      where: { cardRef },
      select: { id: true, cardRef: true },
    });
    if (!card) throw notFound('card_not_found', `No card with cardRef ${cardRef}`);

    const cognitoUser = req.cognitoUser!;

    // Create the session BEFORE the S2S call so if card-ops is down we
    // still have the audit trail.  Phase starts READY; card-ops flips
    // it to RUNNING the moment the WS connects.
    const session = await prisma.cardOpSession.create({
      data: {
        cardId: card.id,
        operation,
        initiatedBy: cognitoUser.sub,
        phase: 'READY',
      },
    });

    if (!config.CARD_OPS_URL) {
      // Local dev / test without card-ops running — still return a sessionId
      // + wsUrl so admin tooling can round-trip.  Port 3009 matches the
      // default in services/card-ops/src/env.ts.
      const wsUrl = `ws://localhost:3009/api/card-ops/relay/${session.id}`;
      res.status(201).json({ sessionId: session.id, wsUrl });
      return;
    }

    // S2S — mirror the RCA start pattern in provisioning.routes.ts.
    const path = '/api/card-ops/register';
    const bodyBytes = Buffer.from(
      JSON.stringify({
        sessionId: session.id,
        cardId: card.id,
        cardRef: card.cardRef,
        operation,
      }),
      'utf8',
    );
    const authorization = signRequest({
      method: 'POST',
      pathAndQuery: path,
      body: bodyBytes,
      keyId: 'activation',
      secret: config.SERVICE_AUTH_CARD_OPS_SECRET,
    });

    const resp = await request(`${config.CARD_OPS_URL}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization },
      body: bodyBytes,
    });

    if (resp.statusCode >= 400) {
      const errText = await resp.body.text();
      // Best-effort — we don't delete the row, it stays as a failed
      // attempt for audit.  Mark it FAILED so nobody tries to consume it.
      await prisma.cardOpSession.update({
        where: { id: session.id },
        data: {
          phase: 'FAILED',
          failedAt: new Date(),
          failureReason: `card_ops_register_${resp.statusCode}`,
        },
      }).catch(() => {
        /* swallow — the outer throw is what the caller sees */
      });
      console.error(`[activation] card-ops register ${resp.statusCode}: ${errText}`);
      throw internal('card_ops_error', 'Failed to register card-op session');
    }

    // card-ops might want to report back a canonical WS path; prefer
    // its response if given, otherwise build from our own config.
    const body = (await resp.body.json()) as { wsPath?: string } | null;
    const wsPath = body?.wsPath ?? `/api/card-ops/relay/${session.id}`;
    const wsUrl = config.CARD_OPS_PUBLIC_WS_BASE
      ? `${config.CARD_OPS_PUBLIC_WS_BASE.replace(/\/$/, '')}${wsPath}`
      : `${req.secure ? 'wss' : 'ws'}://${req.get('host') ?? 'localhost:3009'}${wsPath}`;

    res.status(201).json({ sessionId: session.id, wsUrl });
  });

  return router;
}
