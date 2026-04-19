/**
 * WebSocket relay handler for card-ops sessions.
 *
 * The handler coordinates a single operation against a single card.
 * It loads the CardOpSession row by id, dispatches to the appropriate
 * operation driver, and manages phase transitions + audit logging.
 *
 * Each operation is a coroutine — it drives APDUs out, expects responses
 * back.  When the op completes or fails we update the DB row and close
 * the socket.  Partial operations (admin disconnects mid-flow) stay in
 * RUNNING until a sweeper cleans them up; that's intentional so nothing
 * silently moves a card into a mystery state.
 */

import type { WebSocket } from 'ws';
import { prisma } from '@palisade/db';
import { Prisma } from '@prisma/client';
import { runOperation } from './operation-runner.js';
import type { WSMessage } from './messages.js';
import { isOperation } from '../operations/index.js';

export async function handleRelayConnection(
  ws: WebSocket,
  sessionId: string,
): Promise<void> {
  console.log(`[card-ops-ws] relay connected: session=${sessionId}`);

  const session = await prisma.cardOpSession.findUnique({
    where: { id: sessionId },
    include: { card: true },
  });
  if (!session) {
    ws.close(4001, 'Unknown session');
    return;
  }
  if (!isOperation(session.operation)) {
    ws.close(4001, `Unknown operation ${session.operation}`);
    return;
  }

  // Transition READY → RUNNING.  We don't gate on READY strictly — if a
  // reconnect lands on a RUNNING session the handler below will send
  // error('session_busy') instead.  This write is the marker that the
  // admin client actually connected.
  await prisma.cardOpSession.update({
    where: { id: sessionId },
    data: { phase: 'RUNNING' },
  });

  // Send helper that never throws — a closed socket during a send is
  // common and the op runner must continue to DB-finalize.
  const send = (msg: WSMessage): void => {
    if (ws.readyState === ws.OPEN) {
      try {
        ws.send(JSON.stringify(msg));
      } catch (err) {
        console.error(`[card-ops-ws] send failed for session ${sessionId}:`, err);
      }
    }
  };

  // Bridge incoming WS messages into the runner as a promise-returning
  // channel.  The runner pulls one at a time via await.
  let pendingResolve: ((msg: WSMessage) => void) | null = null;
  let pendingReject: ((err: Error) => void) | null = null;
  const inboundQueue: WSMessage[] = [];

  ws.on('message', (raw) => {
    let parsed: WSMessage;
    try {
      parsed = JSON.parse(raw.toString()) as WSMessage;
    } catch {
      send({ type: 'error', code: 'BAD_JSON', message: 'Malformed JSON' });
      ws.close(1003, 'Bad JSON');
      return;
    }
    if (pendingResolve) {
      const r = pendingResolve;
      pendingResolve = null;
      pendingReject = null;
      r(parsed);
    } else {
      inboundQueue.push(parsed);
    }
  });

  ws.on('close', (code, _reason) => {
    console.log(`[card-ops-ws] relay closed: session=${sessionId}, code=${code}`);
    if (pendingReject) {
      const r = pendingReject;
      pendingResolve = null;
      pendingReject = null;
      r(new Error('ws_closed'));
    }
  });

  ws.on('error', (err) => {
    console.error(`[card-ops-ws] relay error: session=${sessionId}`, err);
  });

  const nextInbound = (): Promise<WSMessage> => {
    if (inboundQueue.length > 0) return Promise.resolve(inboundQueue.shift()!);
    return new Promise<WSMessage>((resolve, reject) => {
      pendingResolve = resolve;
      pendingReject = reject;
    });
  };

  try {
    await runOperation({
      session,
      send,
      next: nextInbound,
    });
  } catch (err) {
    console.error(`[card-ops-ws] operation failed for session ${sessionId}:`, err);
    const message = err instanceof Error ? err.message : 'operation_error';
    send({ type: 'error', code: 'INTERNAL', message });
    await prisma.cardOpSession.update({
      where: { id: sessionId },
      data: {
        phase: 'FAILED',
        failedAt: new Date(),
        failureReason: message,
        scpState: Prisma.DbNull,
      },
    }).catch(() => { /* best-effort */ });
  } finally {
    if (ws.readyState === ws.OPEN) ws.close(1000, 'Session ended');
  }
}
