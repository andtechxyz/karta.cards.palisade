/**
 * Operation runner — dispatches to the per-op handler.
 *
 * Each handler drives APDUs via {send, next} and returns a terminal
 * WSMessage (complete or error).  The runner forwards that to the WS
 * and finalizes the CardOpSession row.
 */

import { prisma } from '@palisade/db';
import { Prisma } from '@prisma/client';
import type { WSMessage } from './messages.js';
import { isOperation, notImplemented, type Operation } from '../operations/index.js';
import { runListApplets } from '../operations/list-applets.js';
import { runInstallPa } from '../operations/install-pa.js';
import { runResetPaState } from '../operations/reset-pa-state.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

export interface OperationContext {
  session: CardOpSessionWithCard;
  send: (msg: WSMessage) => void;
  next: () => Promise<WSMessage>;
}

export async function runOperation(ctx: OperationContext): Promise<void> {
  const { session, send, next } = ctx;

  if (!isOperation(session.operation)) {
    send({ type: 'error', code: 'UNKNOWN_OP', message: session.operation });
    await markFailed(session.id, `unknown_op:${session.operation}`);
    return;
  }

  const op = session.operation as Operation;

  let terminal: WSMessage;
  try {
    switch (op) {
      case 'list_applets':
        terminal = await runListApplets(session, { send, next });
        break;
      case 'install_pa':
        terminal = await runInstallPa(session, { send, next });
        break;
      case 'reset_pa_state':
        terminal = await runResetPaState(session, { send, next });
        break;
      // Phase 3 stubs — wired up so the plumbing is exercised.
      //
      // TODO(phase-3):
      //   install_t4t — same shape as install_pa, needs PalisadeT4T.cap
      //                 + applet AID routing (spec: Palisade/tools/jcbuild).
      //   install_receiver — same shape, test-receiver.cap.
      //   uninstall_pa / uninstall_t4t / uninstall_receiver — DELETE
      //                 instance + package with SCP03 (mirror install_pa
      //                 minus the LOAD steps).
      //   wipe_card — GP LIST enumerate all instances, DELETE each,
      //               then DELETE packages.  Guard with an explicit
      //               "yes I'm sure" header from the admin client.
      case 'install_t4t':
      case 'install_receiver':
      case 'uninstall_pa':
      case 'uninstall_t4t':
      case 'uninstall_receiver':
      case 'wipe_card':
        terminal = notImplemented(op);
        break;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'operation_error';
    terminal = { type: 'error', code: 'OP_FAILED', message };
  }

  send(terminal);

  if (terminal.type === 'complete') {
    // Handlers that fully completed already marked the row COMPLETE;
    // ensure idempotence for any path that didn't (stub / error-before-
    // commit).  The write is cheap and a no-op on re-apply.
    await prisma.cardOpSession.update({
      where: { id: session.id },
      data: {
        phase: 'COMPLETE',
        completedAt: new Date(),
        scpState: Prisma.DbNull,
      },
    }).catch(() => { /* best-effort */ });
  } else if (terminal.type === 'error') {
    await markFailed(session.id, terminal.code ?? 'unknown_error');
  }
}

async function markFailed(sessionId: string, reason: string): Promise<void> {
  await prisma.cardOpSession.update({
    where: { id: sessionId },
    data: {
      phase: 'FAILED',
      failedAt: new Date(),
      failureReason: reason,
      scpState: Prisma.DbNull,
    },
  }).catch(() => { /* best-effort */ });
}
