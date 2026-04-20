# ---------------------------------------------------------------------------
# Palisade — single multi-stage Dockerfile for all card-domain services.
#
# Build:  docker build --build-arg SERVICE=tap -t palisade-tap .
# Run:    docker run -p 3001:3001 --env-file .env palisade-tap
#
# SERVICE must be one of: tap, activation, admin, data-prep, rca, batch-processor
# (SFTP builds from services/sftp/Dockerfile — it needs sshd.)
# ---------------------------------------------------------------------------

# --- Stage 1: install + compile everything -----------------------------------
FROM node:22-alpine AS builder

# OpenSSL is needed so `prisma generate` detects the correct engine
# binary (linux-musl-openssl-3.0.x) instead of defaulting to 1.1.x.
RUN apk add --no-cache openssl

WORKDIR /app

# Copy workspace root files first (for npm ci cache efficiency)
COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./

# Copy all package.json files so `npm ci` can resolve the workspace graph
COPY packages/core/package.json                 packages/core/
COPY packages/db/package.json                   packages/db/
COPY packages/webauthn/package.json             packages/webauthn/
COPY packages/handoff/package.json              packages/handoff/
COPY packages/vault-client/package.json         packages/vault-client/
COPY packages/card-programs/package.json        packages/card-programs/
COPY packages/service-auth/package.json         packages/service-auth/
COPY packages/retention/package.json            packages/retention/
COPY packages/cognito-auth/package.json         packages/cognito-auth/
COPY packages/emv/package.json                  packages/emv/
COPY packages/provisioning-client/package.json  packages/provisioning-client/
COPY packages/sdm-keys/package.json             packages/sdm-keys/
COPY packages/admin-config/package.json         packages/admin-config/
COPY packages/metrics/package.json              packages/metrics/
COPY services/tap/package.json                  services/tap/
COPY services/activation/package.json           services/activation/
COPY services/admin/package.json                services/admin/
COPY services/data-prep/package.json            services/data-prep/
COPY services/rca/package.json                  services/rca/
COPY services/batch-processor/package.json      services/batch-processor/
COPY services/sftp/package.json                 services/sftp/
COPY services/card-ops/package.json             services/card-ops/
COPY services/activation/frontend/package.json  services/activation/frontend/

RUN npm ci

# Copy source code (after npm ci to leverage Docker layer cache)
COPY packages/ packages/
COPY services/ services/
COPY scripts/  scripts/

# Generate Prisma client
RUN npx prisma generate --schema packages/db/prisma/schema.prisma

# Compile all TypeScript (backend — project references)
RUN npx tsc -b

# Rewrite package exports from ./src/index.ts → ./dist/index.js so `node`
# (not tsx) can resolve workspace packages at runtime.
RUN node scripts/fix-exports.mjs

# Build frontend (activation is the only service with a cardholder-facing
# frontend in this image — admin's SPA ships from Vera).  Ensure the
# directory always exists so the COPY in the runner stage never fails for
# services without a frontend.
ARG SERVICE
RUN if [ -d "services/${SERVICE}/frontend/src" ]; then \
      npm run build -w "@palisade/${SERVICE}-frontend"; \
    else \
      mkdir -p "services/${SERVICE}/frontend/dist"; \
    fi

# --- Stage 2: production image (only what the target SERVICE needs) ----------
FROM node:22-alpine AS runner

RUN apk add --no-cache tini openssl
WORKDIR /app

# Copy the whole workspace — npm workspaces resolves via symlinks in
# node_modules, so we can't cherry-pick without breaking resolution.
# The .dockerignore already strips git, tests, .env files, etc.
COPY --from=builder /app/package.json          ./
COPY --from=builder /app/node_modules/         node_modules/

# Copy all compiled packages (dist/ + package.json)
COPY --from=builder /app/packages/core/dist/                 packages/core/dist/
COPY --from=builder /app/packages/core/package.json          packages/core/
COPY --from=builder /app/packages/db/dist/                   packages/db/dist/
COPY --from=builder /app/packages/db/package.json            packages/db/
COPY --from=builder /app/packages/db/prisma/                 packages/db/prisma/
COPY --from=builder /app/packages/webauthn/dist/             packages/webauthn/dist/
COPY --from=builder /app/packages/webauthn/package.json      packages/webauthn/
COPY --from=builder /app/packages/handoff/dist/              packages/handoff/dist/
COPY --from=builder /app/packages/handoff/package.json       packages/handoff/
COPY --from=builder /app/packages/vault-client/dist/         packages/vault-client/dist/
COPY --from=builder /app/packages/vault-client/package.json  packages/vault-client/
COPY --from=builder /app/packages/card-programs/dist/        packages/card-programs/dist/
COPY --from=builder /app/packages/card-programs/package.json packages/card-programs/
COPY --from=builder /app/packages/service-auth/dist/         packages/service-auth/dist/
COPY --from=builder /app/packages/service-auth/package.json  packages/service-auth/
COPY --from=builder /app/packages/retention/dist/            packages/retention/dist/
COPY --from=builder /app/packages/retention/package.json     packages/retention/
COPY --from=builder /app/packages/cognito-auth/dist/         packages/cognito-auth/dist/
COPY --from=builder /app/packages/cognito-auth/package.json  packages/cognito-auth/
COPY --from=builder /app/packages/emv/dist/                  packages/emv/dist/
COPY --from=builder /app/packages/emv/package.json           packages/emv/
COPY --from=builder /app/packages/provisioning-client/dist/         packages/provisioning-client/dist/
COPY --from=builder /app/packages/provisioning-client/package.json  packages/provisioning-client/
COPY --from=builder /app/packages/sdm-keys/dist/             packages/sdm-keys/dist/
COPY --from=builder /app/packages/sdm-keys/package.json      packages/sdm-keys/
COPY --from=builder /app/packages/admin-config/dist/         packages/admin-config/dist/
COPY --from=builder /app/packages/admin-config/package.json  packages/admin-config/
COPY --from=builder /app/packages/metrics/dist/              packages/metrics/dist/
COPY --from=builder /app/packages/metrics/package.json       packages/metrics/

# Copy ALL services' compiled dist/ + package.json — cross-service imports
# (e.g. rca imports @palisade/data-prep/services/data-prep.service) resolve
# via npm-workspace symlinks in node_modules, and those symlinks point at
# services/<name>/ which must exist at runtime or node throws ERR_MODULE_NOT_FOUND.
# Each service's image still only *runs* its own entrypoint (see CMD), but
# the full compiled set is available for import resolution.
COPY --from=builder /app/services/tap/dist/                       services/tap/dist/
COPY --from=builder /app/services/tap/package.json                services/tap/
COPY --from=builder /app/services/activation/dist/                services/activation/dist/
COPY --from=builder /app/services/activation/package.json         services/activation/
COPY --from=builder /app/services/data-prep/dist/                 services/data-prep/dist/
COPY --from=builder /app/services/data-prep/package.json          services/data-prep/
COPY --from=builder /app/services/rca/dist/                       services/rca/dist/
COPY --from=builder /app/services/rca/package.json                services/rca/
COPY --from=builder /app/services/batch-processor/dist/           services/batch-processor/dist/
COPY --from=builder /app/services/batch-processor/package.json    services/batch-processor/
COPY --from=builder /app/services/admin/dist/                     services/admin/dist/
COPY --from=builder /app/services/admin/package.json              services/admin/
COPY --from=builder /app/services/card-ops/dist/                  services/card-ops/dist/
COPY --from=builder /app/services/card-ops/package.json           services/card-ops/
COPY --from=builder /app/services/sftp/dist/                      services/sftp/dist/
COPY --from=builder /app/services/sftp/package.json               services/sftp/

# The SERVICE arg still selects which one runs at container start (see CMD).
ARG SERVICE

# Copy built frontend (may be empty for tap/admin/data-prep/rca/batch-processor
# — builder ensures dir exists)
COPY --from=builder /app/services/${SERVICE}/frontend/dist/ services/${SERVICE}/frontend/dist/

# Copy scripts/ so one-off tasks (seed, regen-sad-e2e, etc.) can run via
# `ecs run-task` with a command override.  Not used by the normal service
# process; kept in every image so any of them doubles as a one-off shell.
COPY --from=builder /app/scripts/ scripts/
COPY --from=builder /app/tsconfig.json /app/tsconfig.base.json ./

# Bake the service name into an ENV so CMD can reference it at runtime
# (ARG is build-time only).
ENV SERVICE_NAME=${SERVICE}

# Non-root user for production
RUN addgroup -S palisade && adduser -S palisade -G palisade \
    && chown -R palisade:palisade node_modules/.prisma node_modules/@prisma
USER palisade

ENV NODE_ENV=production

# tini handles PID 1 correctly (signal forwarding, zombie reaping)
ENTRYPOINT ["tini", "--"]
CMD ["sh", "-c", "node services/${SERVICE_NAME}/dist/index.js"]
