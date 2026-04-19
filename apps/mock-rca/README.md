# mock-rca

Mock Palisade RCA middleware for local testing of the mobile NFC APDU relay flow.

## Why

The real Palisade RCA does live SCP11 crypto against a physical card in a secure element. For wiring up the mobile app's WebSocket relay loop, we don't need any of that — we just need something that:

1. Accepts `POST /api/v1/provision/start` and returns a session + WebSocket URL
2. Accepts the WebSocket connection, walks a scripted APDU sequence, and expects responses back from the app

This lets you verify:
- Deep link → mobile app → provisioning endpoint
- Backend → mock RCA → session creation
- Mobile app → WebSocket → APDU round-trip with the phone's NFC stack
- Progress UI updates (phase + progress fields)
- Completion + cleanup

## Run

```bash
cd apps/mock-rca
npm install
npm start    # listens on :4000
```

## Point the Palisade activation backend at it

Set `PALISADE_RCA_URL=http://localhost:4000` in the activation service env.

## Point the mobile app at it directly (bypass backend)

For faster iteration, you can also call it from the app directly without the Palisade activation backend.

## What it emulates

- 8-step APDU sequence covering the 6 provisioning phases (SCP11 auth, SSD creation, applet install, key generation, SAD transfer ×3, final commit)
- Phase labels: `scp11_auth`, `key_generation`, `sad_transfer`, `confirming`
- Progress values from 0.10 → 0.98
- Completion message with `proxy_card_id`
- Clean WebSocket close after completion

## What it does NOT do

- No real SCP11 crypto — APDU hex bytes are placeholders
- No SAD decryption from KMS
- No attestation verification
- No callback to Palisade activation backend (you can uncomment a fetch call if you want to test the callback handler)
- No retry / error injection (could add scripted failures later)
