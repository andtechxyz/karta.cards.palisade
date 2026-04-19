/**
 * Operation dispatcher for card-ops.
 *
 * Each operation is a small state machine that drives APDU traffic over
 * the WS relay.  The handler returns an async iterator of outbound
 * messages.  On `error` / `complete` the session is terminated and the
 * CardOpSession row is updated.
 *
 * Stubbed operations emit `{type:'error', code:'NOT_IMPLEMENTED'}` —
 * they are wired through so the overall plumbing (auth, session row,
 * WS connect, phase transitions) is exercised end-to-end.
 */

import type { WSMessage } from '../ws/messages.js';

export const OPERATIONS = [
  'list_applets',
  'install_pa',
  'install_t4t',
  'install_receiver',
  'reset_pa_state',
  'uninstall_pa',
  'uninstall_t4t',
  'uninstall_receiver',
  'wipe_card',
] as const;

export type Operation = (typeof OPERATIONS)[number];

export function isOperation(v: unknown): v is Operation {
  return typeof v === 'string' && (OPERATIONS as readonly string[]).includes(v);
}

/** Uniform "not implemented" error — used by stubbed ops. */
export function notImplemented(op: Operation): WSMessage {
  return {
    type: 'error',
    code: 'NOT_IMPLEMENTED',
    message: `Operation ${op} is not yet implemented`,
  };
}
