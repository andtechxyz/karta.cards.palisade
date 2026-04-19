# CAP files shipped with card-ops

The card-ops service ships the following CAP files so admin install
operations always deploy the current applet binaries:

- `pa.cap` — Palisade Provisioning Agent applet (package AID `A0000000625041`)
- `PalisadeT4T.cap` — Tap-For-Tap applet (TODO: drop in from palisade-t4t build)
- `test-receiver.cap` — test receiver applet (TODO: drop in from test harness)

## Sourcing

- `pa.cap` is built from `Palisade/tools/jcbuild/` in the reference tree and
  also lives at `Palisade/pa.cap` for direct consumption.
- `PalisadeT4T.cap` and `test-receiver.cap` TODOs are tracked for a future
  session — placeholders live here so the build wiring and CAP parser still
  link, and the install operations will reject with `CAP_FILE_MISSING` at
  runtime if their file is absent.

## Build-time embedding

The Dockerfile copies this whole directory into the runtime image:

```
COPY --from=builder /app/services/card-ops/cap-files/ services/card-ops/cap-files/
```

The service resolves files via `process.env.CAP_FILES_DIR` (set in env) or
defaults to the `cap-files/` directory alongside the compiled `dist/`.
