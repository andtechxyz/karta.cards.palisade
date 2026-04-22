# CAP signing — Stage H.1 cosign supplement

Status: **CI verification active**; bundle production is an operator-run step.

## Why

Pairs with the H.1 sha256 manifest (`services/card-ops/cap-files/cap-manifest.json`).
The manifest pin prevents a CAP from being silently swapped out without
a matching manifest edit (visible in code review). Cosign adds **identity
binding**: an attacker who tampers with both the CAP and the manifest
must also hold a GitHub-OIDC identity that matches the accepted
signer-regex. Without the signing identity, the CI `cosign verify-blob`
step fails and the tampered CAP never lands in the card-ops container
image.

## Scope

- CI (deploy.yml, card-ops matrix only) runs `cosign verify-blob` on
  every `services/card-ops/cap-files/*.cap` that has a sibling
  `*.cap.bundle`.
- Missing bundles are **warned** (transitional). Existing CAPs can roll
  into signed mode one at a time.
- Mismatched or invalid bundles **fail CI** — the Docker image build is
  gated on this step.
- Runtime (card-ops itself) does NOT re-verify cosign — the sha256
  pin in cap-manifest.json is the runtime check. Cosign is a build-time
  supply-chain gate.

## How to sign a CAP (operator playbook)

Once per new CAP build. Assumes you're on a commit branch, `cosign` is
installed locally (`brew install cosign` or
`curl -sL https://…/cosign-darwin-arm64 > cosign && chmod +x cosign`),
and you're authenticated in GitHub (for the OIDC identity).

```bash
# 1. Build the CAP (off-pipeline; ant build in applets/pa-v3/).
cd applets/pa-v3 && ant clean build

# 2. Copy to card-ops's cap-files directory.
cp build/pa-v3.cap ../../services/card-ops/cap-files/pa-v3.cap

# 3. Sign the CAP.  Writes the Sigstore bundle (cert + signature +
#    transparency-log entry) to the .bundle sidecar.  Keyless mode
#    uses your GitHub identity via Fulcio — no long-lived key.
cosign sign-blob \
  --bundle ../../services/card-ops/cap-files/pa-v3.cap.bundle \
  --yes \
  ../../services/card-ops/cap-files/pa-v3.cap

# 4. Compute sha256 + update cap-manifest.json.
cd ../../services/card-ops/cap-files
NEW_SHA=$(shasum -a 256 pa-v3.cap | awk '{print $1}')
echo "new sha256: $NEW_SHA"
# … edit cap-manifest.json's entries.pa-v3.sha256 + version +
#   builtAt + builtBy.

# 5. Commit all three together.
git add pa-v3.cap pa-v3.cap.bundle cap-manifest.json
git commit -m 'chore(card-ops): refresh pa-v3.cap to <version> with cosign bundle'
```

CI will now run `cosign verify-blob --bundle pa-v3.cap.bundle
--certificate-identity-regexp '…' pa-v3.cap` and fail the build if the
bundle is invalid or the identity doesn't match the allowlist regex.

## Accepted signer identities

The current allowlist regex (in `.github/workflows/deploy.yml`):

```
https://github\.com/(andtechxyz|.+@.+)
```

Matches:
- `https://github.com/andtechxyz` (org-level)
- Anything that looks like an email-authenticated OIDC token (signed via
  `cosign sign-blob` without --identity-token override, using the user's
  GitHub account)

Tighten once the human signer set is settled — e.g.
`'https://github\.com/andtechxyz/(karta\.cards\.palisade|karta\.cards\.vera)/\.github/workflows/.+'`
restricts to signatures produced by CI runs of these specific repos
(useful once the CAP build moves into GHA itself).

## Rotating / revoking a signer

- Remove their identity pattern from `COSIGN_ID_REGEX` in deploy.yml.
- Next CI run gates future merges.
- Past signatures remain in the Sigstore transparency log (rekor) —
  auditable but no longer trust-anchoring new deploys.

## Troubleshooting

- `no matching certificates were found` — regex didn't match the
  signer's OIDC identity. Check the signer's GitHub login vs.
  `COSIGN_ID_REGEX`.
- `no such file or directory: *.bundle` — operator forgot step 3, or
  the bundle path was wrong. Re-run `cosign sign-blob`.
- `bundle signature invalid` — the CAP was modified after signing.
  Rebuild + re-sign (step 1-3 above).
