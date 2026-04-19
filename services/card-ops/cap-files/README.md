# CAP files shipped with card-ops

This directory is the resolution root for every CAP file card-ops loads
at runtime. Two resolution paths:

- **Dictionary keys** (`loadCap(key)` in `src/gp/cap-loader.ts`) — three
  canonical keys baked into `CAP_NAMES`:
  - `pa` → `pa.cap`
  - `t4t` → `PalisadeT4T.cap`
  - `receiver` → `test-receiver.cap`
- **Filename lookup** (`loadCapByFilename(filename)`) — used by the
  generic `install_payment_applet` op; reads the filename from
  `ChipProfile.paymentAppletCapFilename` and resolves it here.

## Files currently in this directory

| Filename | Status | Source |
|---|---|---|
| `pa.cap` | present | built from `Palisade/tools/jcbuild/` in the reference tree; also lives at `Palisade/pa.cap` |
| `PalisadeT4T.cap` | **missing** | drop in from palisade-t4t build; `t4t` key is wired but ops will throw `CAP_FILE_MISSING` until the file arrives |
| `test-receiver.cap` | **missing** | drop in from test harness; same behaviour |
| `mchip_advance_v1.2.3.cap` | **missing** | NXP M/Chip Advance v1.2.3 (CVN 18); linked from 545490 Pty Ltd's `ChipProfile.paymentAppletCapFilename`; ships in the M/Chip Advance license delivery |
| `vsdc_v2.9.2.cap` | **missing** | Visa VSDC 2.9.2 (CVN 22); linked from Karta USA Inc's `ChipProfile.paymentAppletCapFilename`; ships via the VPA toolchain or direct licensee drop |

The two payment-applet CAPs are expected to arrive this week per the
external gates tracked in `docs/SESSION-HANDOFF-2026-04-19.md` (Vera
side). Neither is blocking card-ops service startup — the
`install_payment_applet` op only needs the CAP at call time, and
returns `CAP_FILE_MISSING` cleanly over the WS if absent.

## Adding a new payment-applet CAP

The install operation resolves the CAP via
`ChipProfile.paymentAppletCapFilename`, so adding a new version is:

1. Drop the CAP binary into this directory.
2. Update the `ChipProfile` row (via admin SPA or `psql`) so
   `paymentAppletCapFilename` matches the new filename.
3. No code change or deploy required if the filename is already in the
   DB — the CAP loader reads from disk on each call.

## Build-time embedding

The Dockerfile copies this whole directory into the runtime image:

```
COPY --from=builder /app/services/card-ops/cap-files/ services/card-ops/cap-files/
```

The service resolves files via `process.env.CAP_FILES_DIR` (set in env)
or defaults to `services/card-ops/cap-files/` relative to the compiled
service — this works identically in dev (`tsx` running from `src/`) and
in prod (compiled `dist/`).
