import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { prisma } from '@palisade/db';
import { badRequest, notFound } from '@palisade/core';
import { verifyHandoff } from '@palisade/handoff';
import { createCognitoAuthMiddleware } from '@palisade/cognito-auth';
import { requireSignedRequest, signRequest } from '@palisade/service-auth';
import { request } from 'undici';
import { getActivationConfig } from '../env.js';

export function createProvisioningRouter(): Router {
  const router = Router();
  const config = getActivationConfig();

  const cognitoAuth = createCognitoAuthMiddleware({
    userPoolId: config.COGNITO_USER_POOL_ID,
    clientId: config.COGNITO_CLIENT_ID,
  });

  // POST /api/provisioning/start — start provisioning session (Cognito-authed)
  router.post('/start', cognitoAuth, async (req, res) => {
    const { handoffToken } = req.body as { handoffToken?: string };
    if (!handoffToken) throw badRequest('missing_token', 'handoffToken is required');

    // Verify handoff token — must be from tap service with provisioning purpose.
    const payload = verifyHandoff({
      token: handoffToken,
      expectedPurpose: 'provisioning',
      secretHex: config.TAP_HANDOFF_SECRET,
      allowedIssuers: ['tap'],
    });

    // Look up card
    const card = await prisma.card.findUnique({
      where: { id: payload.sub },
      select: { id: true, cardRef: true, status: true, proxyCardId: true, cognitoSub: true },
    });
    if (!card) throw notFound('card_not_found', 'Card not found');
    if (card.status !== 'ACTIVATED') throw badRequest('invalid_status', `Card is ${card.status}, expected ACTIVATED`);
    // Guard: SAD must have been staged at register-time (or via the admin
    // re-stage endpoint).  If proxyCardId is null, data-prep was unreachable
    // when the card was first registered and SAD never landed — fail loudly
    // with an actionable error instead of forwarding null to RCA and getting
    // back a cryptic Zod validation 400.
    if (!card.proxyCardId) {
      throw badRequest(
        'sad_not_staged',
        'No SAD staged for this card (proxyCardId is null) — data-prep was unreachable at registration. Ask an admin to re-stage SAD.',
      );
    }

    // When PALISADE_RCA_URL is unset, run in mock mode so local dev + e2e
    // tests can exercise the full mobile provisioning flow without a real
    // RCA backing service.  NEVER used in production — an unset
    // PALISADE_RCA_URL in prod is a config error the operator must fix.
    let sessionId: string;
    let wsUrl: string;

    if (!config.PALISADE_RCA_URL) {
      const mockId = randomUUID();
      sessionId = `mock-${mockId}`;
      wsUrl = `ws://localhost:4000/mock-rca/${mockId}`;
    } else {
      // Call RCA's /api/provision/start.  HMAC-signed with the same
      // SERVICE_AUTH_PROVISIONING_SECRET we use for data-prep — RCA's
      // PROVISION_AUTH_KEYS["activation"] must be the same hex value.
      const path = '/api/provision/start';
      const bodyBytes = Buffer.from(
        JSON.stringify({ proxyCardId: card.proxyCardId }),
        'utf8',
      );
      const authorization = signRequest({
        method: 'POST',
        pathAndQuery: path,
        body: bodyBytes,
        keyId: 'activation',
        secret: config.SERVICE_AUTH_PROVISIONING_SECRET,
      });

      const rcaResp = await request(`${config.PALISADE_RCA_URL}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization },
        body: bodyBytes,
      });

      if (rcaResp.statusCode >= 400) {
        // Surface the RCA's body to logs so we can debug auth/contract drift.
        const errText = await rcaResp.body.text();
        console.error(`[activation] RCA /provision/start ${rcaResp.statusCode}: ${errText}`);
        throw badRequest('rca_error', 'Failed to start provisioning session');
      }

      const rcaBody = (await rcaResp.body.json()) as { sessionId: string; wsUrl: string };
      sessionId = rcaBody.sessionId;
      wsUrl = rcaBody.wsUrl;
    }

    // Look up the SadRecord by proxyCardId so we can satisfy the FK at
    // insert time.  The previous code passed sadRecordId='' which violated
    // ProvisioningSession_sadRecordId_fkey on every call.
    //
    // Pick the most-recently-created READY record — there might be multiple
    // historic ones from earlier register attempts; we want the live one.
    const sadRecord = await prisma.sadRecord.findFirst({
      where: { proxyCardId: card.proxyCardId, status: 'READY' },
      orderBy: { createdAt: 'desc' },
      select: { id: true },
    });
    if (!sadRecord) {
      throw badRequest(
        'sad_not_ready',
        `No READY SAD record for proxyCardId ${card.proxyCardId} — re-stage via admin and retry.`,
      );
    }

    // Create local provisioning session
    await prisma.provisioningSession.create({
      data: {
        cardId: card.id,
        sadRecordId: sadRecord.id,
        proxyCardId: card.proxyCardId,
        rcaSessionId: sessionId,
        phase: 'INIT',
      },
    });

    // Link card to mobile user on first provisioning
    const cognitoUser = req.cognitoUser!;
    if (!card.cognitoSub) {
      await prisma.card.update({
        where: { id: card.id },
        data: { cognitoSub: cognitoUser.sub },
      });
    }

    res.status(201).json({
      sessionId,
      wsUrl,
    });
  });

  // POST /api/provisioning/callback — RCA completion callback (HMAC-signed, NOT Cognito)
  const hmacGate = requireSignedRequest({ keys: config.PROVISION_AUTH_KEYS });
  router.post('/callback', hmacGate, async (req, res) => {
    // This endpoint is called by the RCA service, not the mobile app.
    // It's HMAC-signed via the requireSignedRequest middleware mounted in index.ts.
    const { proxy_card_id, session_id, provisioned_at } = req.body as {
      proxy_card_id?: string;
      session_id?: string;
      provisioned_at?: string;
      [key: string]: unknown;
    };

    if (!proxy_card_id) throw badRequest('missing_field', 'proxy_card_id is required');

    // Find the card by proxyCardId
    const card = await prisma.card.findFirst({
      where: { proxyCardId: proxy_card_id },
    });
    if (!card) throw notFound('card_not_found', `No card with proxyCardId ${proxy_card_id}`);

    // Transition card to PROVISIONED
    await prisma.card.update({
      where: { id: card.id },
      data: {
        status: 'PROVISIONED',
        provisionedAt: provisioned_at ? new Date(provisioned_at) : new Date(),
      },
    });

    // Update local provisioning session if it exists
    if (session_id) {
      const session = await prisma.provisioningSession.findFirst({
        where: { rcaSessionId: session_id },
      });
      if (session) {
        await prisma.provisioningSession.update({
          where: { id: session.id },
          data: { phase: 'COMPLETE', completedAt: new Date() },
        });
      }
    }

    res.json({ status: 'ok', cardRef: card.cardRef });
  });

  return router;
}
