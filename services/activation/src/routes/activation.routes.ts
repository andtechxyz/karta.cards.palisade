import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '@palisade/core';
import {
  beginActivationRegistration,
  finishActivationRegistration,
  exchangeHandoffForSession,
} from '../activation/index.js';

const router: Router = Router();

// POST /api/activation/handoff
//   Frontend extracts #hand=<token> from URL fragment, POSTs here.
const handoffSchema = z.object({
  token: z.string().min(1),
});

router.post('/handoff', validateBody(handoffSchema), async (req, res) => {
  const result = await exchangeHandoffForSession(
    req.body.token,
    req.ip,
    req.get('user-agent') ?? undefined,
  );
  res.json(result);
});

// POST /api/activation/sessions/:token/begin
router.post('/sessions/:token/begin', async (req, res) => {
  const options = await beginActivationRegistration(req.params.token);
  res.json(options);
});

// POST /api/activation/sessions/:token/finish
//
// Accepts either a RegistrationResponseJSON (register mode) or an
// AuthenticationResponseJSON (assert mode).  The finish service
// distinguishes by looking for the `signature` field on the inner response.
const finishSchema = z.object({
  response: z.unknown(),
  deviceLabel: z.string().max(128).optional(),
});

router.post('/sessions/:token/finish', validateBody(finishSchema), async (req, res) => {
  const body = req.body as z.infer<typeof finishSchema>;
  const result = await finishActivationRegistration({
    sessionToken: req.params.token,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    response: body.response as any,
    deviceLabel: body.deviceLabel,
  });
  res.json(result);
});

export default router;
