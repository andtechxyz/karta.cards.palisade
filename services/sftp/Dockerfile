# ---------------------------------------------------------------------------
# Vera SFTP service — standalone Dockerfile.  The main multi-stage Dockerfile
# can't share a runner here because SFTP needs openssh-server and a bash
# entrypoint that runs sshd alongside the Node ingester.
#
# Build:  docker build -f services/sftp/Dockerfile -t vera-sftp .
# Run:    docker run -p 2222:22 --env-file .env vera-sftp
# ---------------------------------------------------------------------------

# --- Stage 1: install + compile everything (mirrors the main Dockerfile) ---
FROM node:22-alpine AS builder

RUN apk add --no-cache openssl

WORKDIR /app

COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./

# package.json fan-out so `npm ci` resolves the whole workspace graph.
COPY packages/core/package.json              packages/core/
COPY packages/db/package.json                packages/db/
COPY packages/webauthn/package.json          packages/webauthn/
COPY packages/handoff/package.json           packages/handoff/
COPY packages/vault-client/package.json      packages/vault-client/
COPY packages/programs/package.json          packages/programs/
COPY packages/service-auth/package.json      packages/service-auth/
COPY packages/retention/package.json         packages/retention/
COPY packages/emv/package.json               packages/emv/
COPY packages/provisioning-client/package.json packages/provisioning-client/
COPY packages/cognito-auth/package.json      packages/cognito-auth/
COPY services/tap/package.json               services/tap/
COPY services/activation/package.json        services/activation/
COPY services/pay/package.json               services/pay/
COPY services/vault/package.json             services/vault/
COPY services/admin/package.json             services/admin/
COPY services/data-prep/package.json         services/data-prep/
COPY services/rca/package.json               services/rca/
COPY services/batch-processor/package.json   services/batch-processor/
COPY services/sftp/package.json              services/sftp/
COPY services/activation/frontend/package.json services/activation/frontend/
COPY services/pay/frontend/package.json      services/pay/frontend/
COPY services/admin/frontend/package.json    services/admin/frontend/

RUN npm ci

COPY packages/ packages/
COPY services/ services/
COPY scripts/  scripts/

RUN npx prisma generate --schema packages/db/prisma/schema.prisma
RUN npx tsc -b
RUN node scripts/fix-exports.mjs

# --- Stage 2: runner — sshd + Node ingester in one container ---------------
FROM node:22-alpine AS runner

# openssh-server for the SFTP daemon, jq for the provisioning script's JSON
# parsing, bash for `wait -n` in the entrypoint, tini to reap zombies,
# openssl so Prisma picks the right engine.
RUN apk add --no-cache tini openssl openssh-server bash jq \
    && ssh-keygen -A

WORKDIR /app

# Whole workspace (prisma engine, @palisade/* symlinks, all deps).  Same pattern
# as the shared Dockerfile — workspace resolution breaks if we cherry-pick.
COPY --from=builder /app/package.json          ./
COPY --from=builder /app/node_modules/         node_modules/

COPY --from=builder /app/packages/core/dist/          packages/core/dist/
COPY --from=builder /app/packages/core/package.json   packages/core/
COPY --from=builder /app/packages/db/dist/            packages/db/dist/
COPY --from=builder /app/packages/db/package.json     packages/db/
COPY --from=builder /app/packages/db/prisma/          packages/db/prisma/

COPY --from=builder /app/services/sftp/dist/          services/sftp/dist/
COPY --from=builder /app/services/sftp/package.json   services/sftp/

# sshd + entrypoint.  Copied straight from source, not through the builder.
COPY services/sftp/sshd_config          /etc/ssh/sshd_config
COPY services/sftp/provision-users.sh   /app/services/sftp/provision-users.sh
COPY services/sftp/entrypoint.sh        /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/services/sftp/provision-users.sh

ENV NODE_ENV=production

# SFTP on 22.  NLB terminates public-facing :22 directly at this port.
EXPOSE 22

ENTRYPOINT ["tini", "--"]
CMD ["/app/entrypoint.sh"]
