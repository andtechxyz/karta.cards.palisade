# CAP files shipped with card-ops

The card-ops service ships the following CAP files so admin install
operations always deploy the current applet binaries:

- `pa.cap` — Palisade Provisioning Agent applet (package AID `A0000000625041`)
- `PalisadeT4T.cap` — Tap-For-Tap applet (TODO: drop in from palisade-t4t build)
- `test-receiver.cap` — test receiver applet (TODO: drop in from test harness)
- `mchip_advance_v1.2.3.cap` — NXP M/Chip Advance v1.2.3 payment applet
  (CVN 18).  Referenced by `ChipProfile.paymentAppletCapFilename` on
  545490 Pty Ltd's Mastercard AU program.  **TODO**: sourced from NXP;
  drop in here when the CAP ships.
- `vsdc_v2.9.2.cap` — Visa VSDC 2.9.2 payment applet (CVN 22).
  Referenced by `ChipProfile.paymentAppletCapFilename` on Karta USA's
  Visa US program.  **TODO**: sourced from Visa / the VPA; drop in here
  when the CAP ships.

## Sourcing

- `pa.cap` is built from `Palisade/tools/jcbuild/` in the reference tree and
  also lives at `Palisade/pa.cap` for direct consumption.
- `PalisadeT4T.cap` and `test-receiver.cap` TODOs are tracked for a future
  session — placeholders live here so the build wiring and CAP parser still
  link, and the install operations will reject with `CAP_FILE_MISSING` at
  runtime if their file is absent.
- `mchip_advance_v1.2.3.cap` comes from NXP as part of the M/Chip Advance
  license delivery.  File must be a standard JC-converter CAP (zipped
  Header.cap, Directory.cap, Applet.cap, etc.).  The install operation
  resolves it via `ChipProfile.paymentAppletCapFilename`, so adding a
  new version is an admin UI write followed by dropping the binary
  here — no code change required.
- `vsdc_v2.9.2.cap` comes from Visa via the VPA (Visa Personalization
  Assistant) toolchain or the direct licensee drop.  Same drop-in
  convention as the M/Chip CAP above.

## Build-time embedding

The Dockerfile copies this whole directory into the runtime image:

```
COPY --from=builder /app/services/card-ops/cap-files/ services/card-ops/cap-files/
```

The service resolves files via `process.env.CAP_FILES_DIR` (set in env) or
defaults to the `cap-files/` directory alongside the compiled `dist/`.
