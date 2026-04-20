/**
 * Operation runner — dispatches to the per-op handler.
 *
 * Each handler drives APDUs via {send, next, audit} and returns a
 * terminal WSMessage (complete or error).  The runner forwards that
 * to the WS and finalizes the CardOpSession row.
 *
 * APDU audit ownership:
 *   - The runner owns the lifecycle of an ApduAuditLogger for the
 *     session.  It creates the logger, threads it into DriveIO for
 *     the handler, and flushes the buffer at every phase transition
 *     so a WS disconnect mid-op still leaves a partial transcript.
 *   - Phase transitions we flush at:
 *       runner entry (READY → RUNNING, marked by relay-handler)
 *       terminal transition (RUNNING → COMPLETE | FAILED)
 *     Non-terminal progress mileposts inside a handler are not flushed
 *     individually — the handler calls audit.flush() explicitly if it
 *     wants tighter granularity.
 */

import { prisma } from '@palisade/db';
import { Prisma } from '@prisma/client';
import type { WSMessage } from './messages.js';
import { isOperation, notImplemented, type Operation } from '../operations/index.js';
import { runListApplets } from '../operations/list-applets.js';
import { runInstallPa } from '../operations/install-pa.js';
import { runInstallPaymentApplet } from '../operations/install-payment-applet.js';
import { runPersonalisePaymentApplet } from '../operations/personalise-payment-applet.js';
import { runResetPaState } from '../operations/reset-pa-state.js';
import { runReprovisionCard } from '../operations/reprovision-card.js';
import { runActivateCard } from '../operations/activate-card.js';
import { runRevokeCard } from '../operations/revoke-card.js';
import { ApduAuditLogger } from './apdu-audit.js';

type CardOpSessionWithCard = Prisma.CardOpSessionGetPayload<{ include: { card: true } }>;

export interface OperationContext {
  session: CardOpSessionWithCard;
  send: (msg: WSMessage) => void;
  next: () => Promise<WSMessage>;
  /**
   * Optional logger override — tests can inject a pre-built logger to
   * observe entries directly.  Production always builds one from
   * session.id.
   */
  audit?: ApduAuditLogger;
}

export async function runOperation(ctx: OperationContext): Promise<void> {
  const { session, send, next } = ctx;
  const audit = ctx.audit ?? new ApduAuditLogger(session.id);

  // Flush an empty log immediately on entry — makes the RUNNING
  // transition visible in the DB row even before any APDU flows.
  // Best-effort; logger swallows DB errors internally.
  await audit.flush();

  if (!isOperation(session.operation)) {
    send({ type: 'error', code: 'UNKNOWN_OP', message: session.operation });
    await audit.flush();
    await markFailed(session.id, `unknown_op:${session.operation}`);
    return;
  }

  const op = session.operation as Operation;

  let terminal: WSMessage;
  try {
    const io = { send, next, audit };
    switch (op) {
      case 'list_applets':
        terminal = await runListApplets(session, io);
        break;
      case 'install_pa':
        terminal = await runInstallPa(session, io);
        break;
      case 'install_payment_applet':
        terminal = await runInstallPaymentApplet(session, io);
        break;
      case 'personalise_payment_applet':
        terminal = await runPersonalisePaymentApplet(session, io);
        break;
      case 'reset_pa_state':
        terminal = await runResetPaState(session, io);
        break;
      case 'reprovision_card':
        terminal = await runReprovisionCard(session, io);
        break;
      case 'activate_card':
        terminal = await runActivateCard(session, io);
        break;
      case 'revoke_card':
        terminal = await runRevokeCard(session, io);
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

  // Flush the audit trail BEFORE the terminal update so apduLog is in
  // place if somebody queries the row right as phase flips.  The
  // terminal update itself clears scpState (Prisma.DbNull) and sets
  // completedAt / failedAt.
  await audit.flush();

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
