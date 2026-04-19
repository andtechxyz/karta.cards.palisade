import { prisma } from '@palisade/db';
import { verifyHandoff, HandoffError } from '@palisade/handoff';
import { unauthorized } from '@palisade/core';
import { getActivationConfig } from '../env.js';

// Exchange a tap→activation handoff token for an internal ActivationSession.
// The session ID is then used as the sessionToken for begin/finish.
//
// Design choice: we exchange the handoff for a DB session immediately on
// /activate (frontend extracts #hand= fragment, POSTs here), then proceed
// using the session ID.  This keeps begin/finish identical to the old row-based
// flow and lets us drop the handoff token after one use.

export interface ExchangeHandoffResult {
  sessionToken: string;
  expiresAt: Date;
}

const SESSION_TTL_SECONDS = 60;

export async function exchangeHandoffForSession(
  handoffToken: string,
  ip?: string,
  ua?: string,
): Promise<ExchangeHandoffResult> {
  const config = getActivationConfig();

  let payload;
  try {
    payload = verifyHandoff({
      token: handoffToken,
      secretHex: config.TAP_HANDOFF_SECRET,
      expectedPurpose: 'activation',
      allowedIssuers: ['tap'],
    });
  } catch (err) {
    const code = err instanceof HandoffError ? err.code : 'handoff_invalid';
    throw unauthorized(code, `Handoff token rejected: ${code}`);
  }

  const session = await prisma.activationSession.create({
    data: {
      cardId: payload.sub,
      readCounter: typeof payload.ctx?.readCounter === 'number' ? payload.ctx.readCounter : 0,
      expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000),
      createdIp: ip,
      createdUa: ua,
    },
    select: { id: true, expiresAt: true },
  });

  return { sessionToken: session.id, expiresAt: session.expiresAt };
}
