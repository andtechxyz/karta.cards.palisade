/**
 * POST /api/provision/start — Initiate a provisioning session.
 *
 * Returns { sessionId, wsUrl } for the mobile app to connect.
 */

import { Router } from 'express';
import { z } from 'zod';
import { badRequest } from '@palisade/core';
import { signHandoff } from '@palisade/handoff';

import { SessionManager } from '../services/session-manager.js';
import { getRcaConfig } from '../env.js';

const startSchema = z.object({
  proxyCardId: z.string().min(1),
});

export function createProvisionRouter(): Router {
  const router = Router();
  const sessionManager = new SessionManager();
  const config = getRcaConfig();

  router.post('/start', async (req, res) => {
    const parsed = startSchema.safeParse(req.body);
    if (!parsed.success) {
      // eslint-disable-next-line no-console
      console.log(
        `[err] rca/provision/start validation_failed paths=[${parsed.error.issues.map((i) => i.path.join('.')).join(',')}]`,
      );
      throw badRequest('validation_failed', 'Request failed validation');
    }

    const session = await sessionManager.startSession(parsed.data.proxyCardId);

    // Build WebSocket URL.  If RCA_PUBLIC_WS_BASE is configured (prod),
    // hand the mobile app the public-reachable origin (CloudFront →
    // public ALB → us).  Otherwise (local dev) fall back to whatever the
    // caller used to reach us.
    let wsUrl: string;
    if (config.RCA_PUBLIC_WS_BASE) {
      const base = config.RCA_PUBLIC_WS_BASE.replace(/\/$/, '');
      wsUrl = `${base}/api/provision/relay/${session.sessionId}`;
    } else {
      const host = req.get('host') ?? 'localhost:3007';
      const proto = req.secure ? 'wss' : 'ws';
      wsUrl = `${proto}://${host}/api/provision/relay/${session.sessionId}`;
    }

    // PCI 8.3 — H-8 from the overnight audit: the cuid sessionId alone is
    // not enough auth for the WS upgrade (any side-channel leak gives a
    // short-lived but full-auth provisioning channel).  Mint a signed
    // token bound to (sessionId, exp=WS_TIMEOUT_SECONDS) and append as
    // `?tok=`.  The WS server verifies tok → sessionId + exp before
    // accepting the upgrade.  Leaks after exp are useless; forgery
    // requires the WS_TOKEN_SECRET (HSM-backed Secrets Manager).
    const token = signHandoff(
      {
        sub: session.sessionId,
        purpose: 'provisioning',
        iss: 'rca',
        ttlSeconds: config.WS_TIMEOUT_SECONDS,
      },
      config.WS_TOKEN_SECRET,
    );
    wsUrl = `${wsUrl}?tok=${encodeURIComponent(token)}`;

    res.status(201).json({
      sessionId: session.sessionId,
      wsUrl,
      proxyCardId: session.proxyCardId,
    });
  });

  return router;
}
