import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { prisma } from '@palisade/db';
import { badRequest, notFound } from '@palisade/core';
import { verifyHandoff } from '@palisade/handoff';
import { createCognitoAuthMiddleware } from '@palisade/cognito-auth';
import { requireSignedRequest, signRequest } from '@palisade/service-auth';
import { request } from 'undici';
import { getActivationConfig } from '../env.js';
import { metrics } from '../metrics.js';

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

    // Look up card.  Include paramRecord so we can dispatch to the
    // prototype readiness gate instead of the SAD one when the card
    // is on the PARAM_BUNDLE flow.
    const card = await prisma.card.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        cardRef: true,
        status: true,
        proxyCardId: true,
        cognitoSub: true,
        paramRecordId: true,
        paramRecord: { select: { id: true, status: true, proxyCardId: true } },
      },
    });
    if (!card) {
      metrics().counter('activation.provision_start.fail', 1, { reason: 'card_not_found' });
      throw notFound('card_not_found', 'Card not found');
    }
    if (card.status !== 'ACTIVATED') {
      metrics().counter('activation.provision_start.fail', 1, {
        reason: 'invalid_status',
        status: card.status,
      });
      throw badRequest('invalid_status', `Card is ${card.status}, expected ACTIVATED`);
    }

    // Determine which readiness gate applies.  Prototype cards
    // (PARAM_BUNDLE flow) must have a READY ParamRecord; legacy cards
    // must have a non-null Card.proxyCardId + a READY SadRecord.  A
    // single proxyCardId is forwarded to rca either way so the wire
    // contract stays stable — rca tells the two apart by looking up
    // ParamRecord first, then SadRecord.  Truthy check, not !== null,
    // so select()-omitted fields land on the legacy path (safer default).
    const usingParamBundle = !!card.paramRecordId;
    if (usingParamBundle) {
      if (!card.paramRecord || card.paramRecord.status !== 'READY') {
        metrics().counter('activation.provision_start.fail', 1, {
          reason: 'param_not_ready',
          status: card.paramRecord?.status ?? 'missing',
        });
        throw badRequest(
          'param_not_ready',
          `No READY ParamRecord for card ${card.cardRef} (current: ${card.paramRecord?.status ?? 'missing'}). Re-stage via admin reprovision and retry.`,
        );
      }
    } else {
      // Legacy guard: SAD must have been staged at register-time (or
      // via the admin re-stage endpoint).  If proxyCardId is null,
      // data-prep was unreachable when the card was first registered
      // and SAD never landed — fail loudly with an actionable error
      // instead of forwarding null to RCA and getting back a cryptic
      // Zod validation 400.
      if (!card.proxyCardId) {
        metrics().counter('activation.provision_start.fail', 1, { reason: 'sad_not_staged' });
        throw badRequest(
          'sad_not_staged',
          'No SAD staged for this card (proxyCardId is null) — data-prep was unreachable at registration. Ask an admin to re-stage SAD.',
        );
      }
    }

    // When PALISADE_RCA_URL is unset, run in mock mode so local dev + e2e
    // tests can exercise the full mobile provisioning flow without a real
    // RCA backing service.  NEVER used in production — an unset
    // PALISADE_RCA_URL in prod is a config error the operator must fix.
    let sessionId: string;
    let wsUrl: string;

    // Pick the proxyCardId that gets forwarded to rca.  For prototype
    // cards we use ParamRecord.proxyCardId (pxy_* namespace, set by
    // data-prep.prepareParamBundle); for legacy cards we use
    // Card.proxyCardId (proxy_* namespace, set at original SAD
    // register).  rca.startSession does a ParamRecord lookup first
    // then falls back to SadRecord, so both shapes work on the wire.
    const outboundProxyCardId = usingParamBundle
      ? card.paramRecord!.proxyCardId
      : card.proxyCardId!;

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
        JSON.stringify({ proxyCardId: outboundProxyCardId }),
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
        metrics().counter('activation.provision_start.fail', 1, {
          reason: 'rca_failed',
          status: String(rcaResp.statusCode),
        });
        throw badRequest('rca_error', 'Failed to start provisioning session');
      }

      const rcaBody = (await rcaResp.body.json()) as { sessionId: string; wsUrl: string };
      sessionId = rcaBody.sessionId;
      wsUrl = rcaBody.wsUrl;
    }

    // Look up a SadRecord to satisfy the ProvisioningSession.sadRecordId
    // FK at insert time.  (Schema still has this as NOT NULL even
    // though prototype cards don't consume the SAD bytes — proper fix
    // is making sadRecordId nullable, deferred to a dedicated schema
    // migration.  See TODO in packages/db/prisma/schema.prisma's
    // ProvisioningSession model.)
    //
    // For legacy cards: require status=READY (unchanged — gates
    // re-staging if the previous tap completed).
    // For prototype cards: accept ANY SadRecord for the same card as
    // the FK placeholder; actual readiness is ParamRecord-gated above.
    // Falls back to the most-recent SadRecord regardless of status,
    // because prototype cards typically have a historic CONSUMED one
    // from register time and we just need a valid id to satisfy FK.
    const sadRecord = await prisma.sadRecord.findFirst({
      where: usingParamBundle
        ? { cardId: card.id }
        : { proxyCardId: card.proxyCardId!, status: 'READY' },
      orderBy: { createdAt: 'desc' },
      select: { id: true },
    });
    if (!sadRecord) {
      const reason = usingParamBundle ? 'sad_fk_missing' : 'sad_not_ready';
      metrics().counter('activation.provision_start.fail', 1, { reason });
      throw badRequest(
        reason,
        usingParamBundle
          ? `No SadRecord exists for card ${card.cardRef} — prototype cards still need a historic SadRecord for FK. Ask an admin to seed one.`
          : `No READY SAD record for proxyCardId ${card.proxyCardId} — re-stage via admin and retry.`,
      );
    }

    // Create local provisioning session + link cognitoSub in parallel.
    // Both are writes the caller doesn't need to wait for individually;
    // Promise.all cuts the two sequential round-trips to one (~20-40 ms
    // saved on DB-RTT-bound hot path — latency audit opts #10 + partial #4).
    const cognitoUser = req.cognitoUser!;
    await Promise.all([
      prisma.provisioningSession.create({
        data: {
          cardId: card.id,
          sadRecordId: sadRecord.id,
          // Match the proxy we forwarded to rca so audit trails align
          // and the completion callback can find the session by rca's
          // proxyCardId.  Legacy cards use Card.proxyCardId (proxy_*);
          // prototype cards use ParamRecord.proxyCardId (pxy_*).
          proxyCardId: outboundProxyCardId,
          rcaSessionId: sessionId,
          phase: 'INIT',
        },
      }),
      card.cognitoSub
        ? Promise.resolve()
        : prisma.card.update({
            where: { id: card.id },
            data: { cognitoSub: cognitoUser.sub },
          }),
    ]);

    metrics().counter('activation.provision_start.ok', 1);
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
