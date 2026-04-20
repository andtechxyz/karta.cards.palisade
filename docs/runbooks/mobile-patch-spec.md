# Mobile app patch spec — post-split

Exact changes to apply in the mobile app (React Native) after the
Vera/Palisade repo split + the plan-mode + card-ops work of
2026-04-19.

This doc assumes the mobile repo is separate from both Vera and
Palisade.  Every snippet is a diff-able patch; apply in the order
given.

---

## 1. API base URL split

The mobile app previously hit one backend host.  Post-split it hits
two:

- **Vera** (vault + pay + transactions): `https://vera-<env>.karta.cards`
- **Palisade** (card + chip): `https://palisade-<env>.karta.cards`

### Patch — env + config

```ts
// src/config/api.ts  (new file, or extend existing config)
export const API = {
  vera: process.env.VERA_BASE_URL ?? 'https://vera.karta.cards',
  palisade: process.env.PALISADE_BASE_URL ?? 'https://palisade.karta.cards',
} as const;
```

### Route map

| Endpoint | Backend |
|---|---|
| `POST /api/tap/verify/:urlCode` | **palisade** |
| `POST /api/cards/register` | **palisade** |
| `POST /api/provisioning/start` | **palisade** |
| `POST /api/activation/begin` | **palisade** |
| `POST /api/admin/card-op/start` | **palisade** |
| WS `/api/provision/relay/:sessionId` | **palisade** |
| WS `/api/card-ops/relay/:sessionId` | **palisade** |
| `POST /api/tx/...` | **vera** |
| `GET /api/tx/:rlid` | **vera** |
| `POST /api/webauthn/...` (pay flow) | **vera** |
| Cognito auth (ID + refresh) | **vera** (user pool managed there) |

Replace every `api.post('/api/...')` with `api.palisade.post(...)` or
`api.vera.post(...)` per the table.

---

## 2. Plan-mode WebSocket protocol (new)

The RCA's provisioning WebSocket has an opt-in protocol that trades
4 server round-trips for 0 during the NFC exchange.  Savings ~2 s on
500 ms-RTT phone↔server links.  Classical mode still works — no
mobile-side changes required unless you want the speedup.

### Enable with one query-param

```diff
- const ws = new WebSocket(wsUrl);
+ const ws = new WebSocket(wsUrl + '?mode=plan');
```

(If `wsUrl` already has a query string, append `&mode=plan`.)

### New message shapes

**Server → phone** sends ONE message on connect:

```jsonc
{
  "type": "plan",
  "version": 1,
  "steps": [
    { "i": 0, "apdu": "00A4040008A00000006250414C", "phase": "select_pa",      "progress": 0.05, "expectSw": "9000" },
    { "i": 1, "apdu": "80E000000101",               "phase": "key_generation", "progress": 0.25, "expectSw": "9000" },
    { "i": 2, "apdu": "80E2...",                    "phase": "provisioning",   "progress": 0.55, "expectSw": "9000" },
    { "i": 3, "apdu": "80E6000000",                 "phase": "finalizing",     "progress": 0.80, "expectSw": "9000" },
    { "i": 4, "apdu": "80E8000000",                 "phase": "confirming",     "progress": 0.95, "expectSw": "9000" }
  ]
}
```

**Phone → server** sends one `response` message per executed step:

```jsonc
{ "type": "response", "i": 0, "hex": "<full response incl SW>", "sw": "9000" }
```

**Server → phone** terminal messages:

```jsonc
{ "type": "complete", "proxyCardId": "pxy_..." }
// or
{ "type": "error", "code": "CARD_ERROR", "message": "..." }
```

### Error codes

Mobile handler should treat every `error` as terminal for the current
WebSocket (session is FAILED server-side, retrying on the same `wsUrl`
will not recover it — the phone must ask the backend for a fresh
sessionId via `POST /api/provisioning/start`).

| code | Cause | Mobile action |
|---|---|---|
| `CARD_ERROR` | Chip returned non-9000 at a step | Show chip error; offer retry via fresh session |
| `NFC_ERROR` | Phone's NFC transceive failed | "Hold card steady"; retry via fresh session |
| `PA_FAILED` | PA applet's FINAL_STATUS byte != 0x01 | Hard failure; contact support |
| `attestation_failed` | Strict-mode attestation rejected chip | Card may be counterfeit; do not retry |
| `plan_step_invalid` | Plan-mode step cursor rejected the response | Always fetch a fresh session via `/api/provisioning/start` before retrying (see below) |

#### `plan_step_invalid` subcodes

The `message` field carries a specific reason the server-side step
cursor rejected the response.  All of them require the mobile to
start over — never resend the same response on the same WebSocket.

| subcode in `message` | Meaning |
|---|---|
| `plan_step_state_missing` | Server lost the cursor (e.g. rca restarted mid-session).  Fresh session needed. |
| `plan_step_state_expired` | Session sat idle past its TTL.  Fresh session needed. |
| `plan_step_out_of_range` | Response carried an `i` outside `[0, stepCount)`.  Bug in mobile. |
| `plan_step_replay` | Response's `i` ≤ last accepted step.  Phone double-sent; de-dupe locally. |
| `plan_step_skip` | Response's `i` jumped forward past the next expected step.  Bug in mobile. |

Recovery flow:

```ts
ws.onmessage = async (evt) => {
  const msg = JSON.parse(evt.data as string);
  if (msg.type === 'error') {
    ws.close();
    if (msg.code === 'plan_step_invalid') {
      // Cursor lost — fetch a fresh session and retry from scratch.
      await startNewProvisioningSession();
    } else {
      showError(msg.code, msg.message);
    }
    return;
  }
  // ... other handlers
};
```

### Reference implementation (TypeScript)

```ts
async function runPlanProvisioning(wsUrl: string, nfc: NfcTransceiver) {
  const ws = new WebSocket(wsUrl + '?mode=plan');
  await new Promise<void>((resolve, reject) => {
    ws.onopen = () => resolve();
    ws.onerror = reject;
  });

  return new Promise<{proxyCardId: string}>((resolve, reject) => {
    ws.onmessage = async (evt) => {
      const msg = JSON.parse(evt.data as string);

      if (msg.type === 'plan') {
        // Run each step against the chip, stream responses as we go
        for (const step of msg.steps as PlanStep[]) {
          updateProgress(step.phase, step.progress);
          let respHex: string;
          try {
            respHex = await nfc.transceive(step.apdu);
          } catch (err) {
            ws.send(JSON.stringify({
              type: 'error',
              code: 'NFC_TRANSCEIVE_FAILED',
              message: `step ${step.i}: ${String(err)}`,
            }));
            return;
          }
          const sw = respHex.slice(-4).toUpperCase();
          if (sw !== step.expectSw) {
            ws.send(JSON.stringify({
              type: 'error',
              code: 'UNEXPECTED_SW',
              message: `step ${step.i}: got ${sw}, expected ${step.expectSw}`,
            }));
            return;
          }
          ws.send(JSON.stringify({
            type: 'response',
            i: step.i,
            hex: respHex,
            sw,
          }));
        }
      } else if (msg.type === 'complete') {
        ws.close();
        resolve({ proxyCardId: msg.proxyCardId });
      } else if (msg.type === 'error') {
        ws.close();
        reject(new Error(`${msg.code}: ${msg.message}`));
      }
    };
  });
}

interface PlanStep {
  i: number;
  apdu: string;
  phase: string;
  progress: number;
  expectSw: string;
}
```

### Classical fallback

Keep the classical handler as a fallback.  If plan mode hits a
protocol error (e.g. server responds with classical APDU on connect),
reconnect without `?mode=plan`.

### Rollout plan

1. Ship mobile build with plan-mode as feature flag, default **off**
2. Enable for 10% of taps via remote config
3. Monitor (provisioning success rate, wall-clock duration vs
   classical) — server logs in Palisade RCA tag plan-mode sessions
4. Ramp to 100% over a week
5. Remove classical-mode code path in a later release

---

## 3. Admin card-ops screen (new)

New feature: operator / admin user can run GlobalPlatform operations
against a physical card — install applets, list applets, reset PA
state, wipe card.  The mobile acts as the NFC bridge between the card
and Palisade's card-ops service.

### Who sees it

Gate the entry point on two criteria:

- User is in Cognito group `admin`, AND
- User's Cognito email is in the `ADMIN_EMAIL_ALLOWLIST` (build-time
  env, comma-separated)

Both checks happen client-side to hide the UI; server-side the
allowlist is enforced on Palisade activation's `POST /api/admin/card-op/start`.

### Patch — entry flow

```ts
// 1. Request operation start
const res = await api.palisade.post('/api/admin/card-op/start', {
  operation: 'install_pa', // or any of the supported ops below
  cardRef: 'ref_xyz',
});
// { sessionId, wsUrl }

// 2. Open the WS — same protocol as provisioning (apdu / response /
//    complete / error) minus plan-mode.  Operations drive APDUs
//    interactively; there's no plan.
const ws = new WebSocket(res.wsUrl);

ws.onmessage = async (evt) => {
  const msg = JSON.parse(evt.data as string);
  if (msg.type === 'apdu') {
    const resp = await nfc.transceive(msg.hex);
    ws.send(JSON.stringify({
      type: 'response',
      hex: resp,
      sw: resp.slice(-4),
    }));
    if (msg.progress !== undefined) updateProgress(msg.phase, msg.progress);
  } else if (msg.type === 'complete') {
    showSuccess(msg);
    ws.close();
  } else if (msg.type === 'error') {
    showError(msg.code, msg.message);
    ws.close();
  }
};
```

### Supported operations (body.operation values)

| Op | Status | Notes |
|---|---|---|
| `list_applets` | ✅ implemented | Server returns `{type: 'complete', applets: [{aid, lifecycle, privileges}, ...]}` |
| `install_pa` | ✅ implemented | DELETE + INSTALL [load] + LOAD × N + INSTALL [install+selectable] |
| `install_payment_applet` | ✅ implemented | Same pipeline, target AID from IssuerProfile.aid.  Requires NXP CAP in `cap-files/` |
| `personalise_payment_applet` | ✅ implemented | STORE DATA stream from decrypted SadRecord |
| `reset_pa_state` | ✅ implemented | SELECT PA auto-resets to IDLE |
| `install_t4t` | 🟡 NOT_IMPLEMENTED | Needs T4T CAP file |
| `install_receiver` | 🟡 NOT_IMPLEMENTED | Needs receiver CAP file |
| `uninstall_pa` | 🟡 NOT_IMPLEMENTED | |
| `uninstall_t4t` | 🟡 NOT_IMPLEMENTED | |
| `uninstall_receiver` | 🟡 NOT_IMPLEMENTED | |
| `wipe_card` | 🟡 NOT_IMPLEMENTED | Needs GP LIST + enumerate |

Stubbed operations return `{type:'error', code:'NOT_IMPLEMENTED'}` from
the server — the UI should grey those out rather than let users fire
them.

### Admin-email allowlist — client-side gate

```ts
// src/features/admin/allowlist.ts
const ADMIN_EMAIL_ALLOWLIST = (process.env.ADMIN_EMAIL_ALLOWLIST ?? '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

export function isAdminUser(email: string | undefined): boolean {
  if (!email) return false;
  return ADMIN_EMAIL_ALLOWLIST.includes(email.toLowerCase());
}
```

```ts
// In the nav / tab config
import { isAdminUser } from './allowlist';
const user = useCognitoUser(); // or similar
const showAdmin = isAdminUser(user?.email) && user?.groups?.includes('admin');

{showAdmin && <Tab name="Admin Card Ops" ...>}
```

Keep the env var in lockstep with Palisade's `ADMIN_EMAIL_ALLOWLIST` on
activation.  If they drift, server will 403 with `email_not_allowed`
after the mobile UI let the user try.

---

## 4. Post-activation URL handling (verify)

The PA applet bakes `postProvisionUrl` into the chip's NDEF URL during
activation.  Current value from the 545490 + Karta USA seed script is
`tap.karta.cards`.  The chip emits `https://tap.karta.cards/<urlCode>`
on tap after provisioning.

Mobile app's deep-link handler should already parse this pattern.
Confirm that:

- iOS: `tap.karta.cards` is a Universal Link in the Associated Domains
  entitlement
- Android: `tap.karta.cards` matches an `<intent-filter android:autoVerify="true">`
  with `<data android:host="tap.karta.cards" />`

If the pre-split mobile app pointed at a different host
(`activation.karta.cards`?), add `tap.karta.cards` alongside it.

---

## 5. Cross-repo handoff token (unchanged)

The registration flow remains:

1. Tap → PICC SDM decode → `POST /api/tap/verify` (Palisade tap)
2. Tap service redirects to `/activate/:cardRef` (via `urlCode` SDM URL)
3. Mobile calls `POST /api/activation/begin` (Palisade activation)
4. Activation calls Vera `POST /api/vault/register` internally; returns
   `{sessionId, handoffToken}` to mobile
5. Mobile calls `POST /api/provisioning/start` with the handoffToken;
   gets `{wsUrl}`
6. Mobile opens `wsUrl` with `?mode=plan` (new)

None of steps 1-5 changed wire-format — just different backend host
for the activation / provisioning calls (now Palisade).

---

## 6. Build environment

Add to mobile's build env (both iOS + Android):

| Var | Dev | Staging | Prod |
|---|---|---|---|
| `VERA_BASE_URL` | `http://localhost:3005` (admin) or per-service | `https://vera-staging.karta.cards` | `https://vera.karta.cards` |
| `PALISADE_BASE_URL` | `http://localhost:3002` (activation) or per-service | `https://palisade-staging.karta.cards` | `https://palisade.karta.cards` |
| `ADMIN_EMAIL_ALLOWLIST` | developer emails, comma-separated | ops emails | ops emails |
| `COGNITO_USER_POOL_ID` | (unchanged from pre-split) |  |  |
| `COGNITO_CLIENT_ID` | (unchanged) |  |  |

---

## 7. Testing

### Unit

No API-shape changes on mobile beyond URL routing + the new plan-mode
handler.  Existing test mocks should just get their base URLs flipped
per the route map.

### Integration (manual)

After mobile build is deployed to a test device:

1. Register a card via the existing flow — cold tap → activation →
   provisioning → card PROVISIONED
2. Run again but with plan-mode enabled — measure tap duration vs
   classical (should be ~2 s faster on any non-LAN connection)
3. Log in as an admin-allowlist user, run `list_applets` against a
   test card — verify AID list returned
4. Run `install_payment_applet` once NXP CAPs land — verify chip has
   the new applet + transacts at a test POS

### Server logs to watch

Plan-mode sessions log `[rca] plan-mode provisioning complete:
session=..., card=...` on success.  Classical mode logs
`[rca] provisioning complete: session=..., card=...` (no `plan-mode`
tag).  Filter on those to confirm rollout.

---

## 8. What you don't have to change

- Authentication (Cognito bearer still passed to both backends)
- SUN tap decode — it's server-side now
- WebAuthn auth flow on pay — unchanged (still hits Vera pay)
- Transaction flows — unchanged (still hits Vera pay)
- Frontend admin SPA (not mobile — that's the web admin)

---

## 9. Rollout checklist

- [ ] `api.vera` / `api.palisade` split in config
- [ ] All existing `api.*` call sites routed to the correct backend per
      the route table
- [ ] `?mode=plan` added behind feature flag on the RCA WebSocket
- [ ] Admin card-ops screen behind Cognito group + allowlist gate
- [ ] `tap.karta.cards` in deep-link entitlements (both platforms)
- [ ] `VERA_BASE_URL` + `PALISADE_BASE_URL` + `ADMIN_EMAIL_ALLOWLIST`
      in build env for dev/staging/prod
- [ ] Manual smoke: register + tap + classical provisioning still works
- [ ] Manual smoke: plan-mode provisioning works end-to-end
- [ ] Manual smoke (admin): list_applets against a real card returns
      the expected AIDs
- [ ] App store build with plan-mode on 10% rollout
- [ ] Monitor for 1 week → ramp to 100%
- [ ] Remove classical-mode fallback in a later release

---

## Reference

- Plan-mode protocol lives in
  `/Users/danderson/Palisade/services/rca/src/services/plan-builder.ts`
- Admin card-op entrypoint:
  `/Users/danderson/Palisade/services/activation/src/routes/card-op.routes.ts`
- Card-ops service (WebSocket endpoint):
  `/Users/danderson/Palisade/services/card-ops/src/ws/relay-handler.ts`
- Admin allowlist:
  `/Users/danderson/Palisade/packages/admin-config/`
