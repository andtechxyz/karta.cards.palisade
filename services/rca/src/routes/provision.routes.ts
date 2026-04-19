/**
 * POST /api/provision/start — Initiate a provisioning session.
 *
 * Returns { sessionId, wsUrl } for the mobile app to connect.
 */

import { Router } from 'express';
import { z } from 'zod';
import { badRequest } from '@palisade/core';

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
    if (!parsed.success) throw badRequest('validation_failed', parsed.error.message);

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

    res.status(201).json({
      sessionId: session.sessionId,
      wsUrl,
      proxyCardId: session.proxyCardId,
    });
  });

  return router;
}
