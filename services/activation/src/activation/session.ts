import { prisma } from '@palisade/db';
import { gone, notFound } from '@palisade/core';

export async function loadActiveSession(sessionToken: string) {
  const session = await prisma.activationSession.findUnique({
    where: { id: sessionToken },
  });
  if (!session) throw notFound('session_not_found', 'Activation session not found');
  if (session.consumedAt) throw gone('session_consumed', 'Activation session already used');
  if (session.expiresAt < new Date()) {
    throw gone('session_expired', 'Activation session expired — tap the card again');
  }
  return session;
}
