# IN-FLIGHT: `card_done` WS message for early NFC dismissal

**Status:** designed, not implemented.  Pick up from here on next session.

**Origin:** mobile team asked for a WS signal they can trust to dismiss the
NFC modal as soon as the chip finishes, not 1–2s later after the server
finalises DB writes.  Today the modal hangs because:

- In **plan mode**, server emits `{type:'complete'}` only AFTER the
  `$transaction` (COMPLETE/PROVISIONED/CONSUMED atomic flip) lands — mobile
  waits on it to dismiss.
- In **classical mode**, `{type:'complete'}` arrives BEFORE the phone even
  runs `CONFIRM` on the chip (commit `8bf5434` made the $transaction async),
  so the phone can't tell "chip is done" from the WS signal alone.

Mobile wants one universal message that means "the chip has ACKed the last
APDU, it's safe to close NFC."  Server-side writes can finish in the
background.

## Wire semantics (what to add)

Add a new WS message:

```ts
{ type: 'card_done' }
```

Emitted **the instant the server confirms the chip has ACKed the last APDU
with SW=9000, BEFORE any `$transaction` runs.**  Followed by `{type:'complete', proxyCardId}` once the DB writes commit.

| When | Message |
|---|---|
| Chip ACKs CONFIRM with 9000 (last APDU) | Server emits `{type:'card_done'}` |
| Server's `$transaction` commits (session → COMPLETE, card → PROVISIONED, sad → CONSUMED) | Server emits `{type:'complete', proxyCardId}` |
| On failure at any point | Server emits `{type:'error', ...}` (unchanged) |

Mobile handler:
- On `card_done` → **dismiss NFC modal immediately**
- On `complete` → update app state to PROVISIONED, close WS
- On `error` → error UX, close WS

## Implementation sketch (server-side)

### 1. Add to WSMessage type (`services/rca/src/services/session-manager.ts`)

```ts
export interface WSMessage {
  type: 'apdu' | 'response' | 'complete' | 'error' | 'pa_fci' | 'plan' | 'card_done';
  //                                                                     ^^^^^^^^^^^
  ...
}
```

### 2. Thread a late-send callback through `handleMessage`

`handleMessage` currently returns `WSMessage[]` and the relay handler sends
them all synchronously.  For `complete` to arrive AFTER an async commit, we
need a way to send a message later.

Simplest: pass an optional `sendLater` callback through:

```ts
// services/rca/src/ws/relay-handler.ts
const responses = await sessionManager.handleMessage(sessionId, msg, {
  sendLater: (m) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(m));
  },
});
for (const r of responses) ws.send(JSON.stringify(r));

// services/rca/src/services/session-manager.ts
async handleMessage(
  sessionId: string,
  message: WSMessage,
  opts: { sendLater?: (m: WSMessage) => void } = {},
): Promise<WSMessage[]> { ... }
```

Thread `opts.sendLater` through to `handlePlanResponse` → `handlePlanConfirm`
and `handleCardResponse` → `handleFinalStatus`.

### 3. Plan mode — `handlePlanConfirm`

```ts
private async handlePlanConfirm(
  sessionId: string,
  opts: { sendLater?: (m: WSMessage) => void } = {},
): Promise<WSMessage[]> {
  // The chip ACKed CONFIRM before we got here (SW=9000 checked by
  // handlePlanResponse).  Physical card work is DONE — emit card_done
  // immediately so mobile can close the NFC modal.

  const commitPromise = prisma.$transaction(async (tx) => {
    // ... existing commit logic ...
  });

  commitPromise
    .then((s) => {
      console.log(`[rca] plan-mode provisioning complete: ...`);
      metrics().counter('rca.provisioning.complete', 1, { mode: 'plan' });
      clearPlanStepState(sessionId);
      this.fireCallback(s.card.cardRef, s.card.chipSerial ?? '').catch(...);
      // Send complete AFTER the commit lands.
      opts.sendLater?.({
        type: 'complete',
        proxyCardId: s.sadRecord.proxyCardId,
      });
    })
    .catch((err) => { /* log + alert, but card_done already sent */ });

  // Return card_done synchronously.  complete fires from the .then() above.
  return [{ type: 'card_done' }];
}
```

### 4. Classical mode — add post-CONFIRM handler

Classical flow currently has no handler for the phone's CONFIRM response
(handleFinalStatus is the last phase).  Two options:

**Option A (quick):** Send `card_done` inline with `[CONFIRM apdu, complete]`
in handleFinalStatus — mobile gets the signal AT apdu emission time, not
after chip ACK.  Not technically accurate (chip hasn't finished yet) but
works for the modal-close UX because the phone is about to run CONFIRM
locally anyway and can dismiss on that local 9000.  Simple, no new phase.

**Option B (correct):** Add a post-CONFIRM phase so the phone sends back
the CONFIRM response and the server emits card_done on receipt.  Needs a
new phase state + handler.  Matches plan mode exactly.

Option B is correct; Option A is pragmatic.  Plan mode is the primary
target anyway (the mobile is about to switch to it).  Start with A for
classical, B for plan.

### 5. Update `services/rca/src/ws/relay-handler.ts`

Thread `sendLater` into `handleMessage` calls.  Ensure `ws.readyState`
is checked before sending (WS may be closed by the time commit finishes).

### 6. Update `packages/retention` / session-manager timeout?

Not required for this change.  Async commit was already in place
(commit `8bf5434`); this just adds an earlier signal ahead of it.

### 7. Tests

Add to `services/rca/src/services/session-manager.test.ts`:

```ts
it('plan mode: emits card_done before the async commit, then complete', async () => {
  const sent: WSMessage[] = [];
  const sendLater = (m: WSMessage) => sent.push(m);

  // ... setup: session state, mocks, seed plan step cursor to i=3 ...

  const responses = await mgr.handleMessage(
    'session_01',
    { type: 'response', i: 4, hex: '', sw: '9000' } as WSMessage,
    { sendLater },
  );

  // Synchronous: card_done only
  expect(responses).toEqual([{ type: 'card_done' }]);

  // Microtask flush lets the commit .then fire
  await new Promise((r) => setImmediate(r));

  // sendLater was called with complete
  expect(sent).toHaveLength(1);
  expect(sent[0].type).toBe('complete');
});
```

Similar for classical if Option B.

## Mobile-patch-spec update

Add to `docs/runbooks/mobile-patch-spec.md` under the plan-mode section:

```
**Terminal messages (ordered):**

{ "type": "card_done" }                              ← dismiss NFC modal here
{ "type": "complete", "proxyCardId": "pxy_..." }     ← server state committed
```

And an entry in the error-codes table confirming `card_done` is never
paired with an error (if server errors before the chip finishes, it emits
`{type:'error'}` without a prior `card_done`).

## Order of work when resuming

1. Reset the card + DB for another tap test if still in `PROVISIONED` state
   (the last successful test at 16:49 left it provisioned — check DB before
   picking this up)
2. Add `card_done` to the `WSMessage` type
3. Thread `sendLater` through `handleMessage` + `handlePlanResponse` +
   `handlePlanConfirm`
4. Add test (block above)
5. Update relay-handler.ts
6. Update mobile-patch-spec.md
7. Do classical Option A inline in `handleFinalStatus`
8. Commit + push
9. Tell mobile team the shape + that they can listen for it

Estimated time: 45–75 min for the plan-mode implementation + tests.  Adding
classical Option B would add another 30–45 min.

## Gotchas

- If the WS closes between `card_done` and the commit finishing,
  `ws.readyState !== ws.OPEN` — check before sending `complete`.  Callback
  still fires to activation regardless.
- Don't send `card_done` in error paths (attestation failure, step-cursor
  rejection, PA_FAILED).  Only on the happy path where the chip ACKed
  every APDU cleanly.
- The mobile-patch-spec error-code table already covers `plan_step_invalid` /
  `CARD_ERROR` / `attestation_failed` — no changes needed there.
