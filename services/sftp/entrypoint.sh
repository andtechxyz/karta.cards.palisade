#!/bin/bash
# ---------------------------------------------------------------------------
# SFTP service container entrypoint.  Provisions SFTP users, then launches
# sshd and the Node ingester in parallel.  If either exits, the other is
# killed and the container exits non-zero so ECS restarts the whole task.
# ---------------------------------------------------------------------------
set -e

/app/services/sftp/provision-users.sh

# sshd in foreground (-D) with errors to stderr (-e) so CloudWatch picks them
# up.  Run as a child so we can wait on it.
/usr/sbin/sshd -D -e &
SSHD_PID=$!
echo "[entrypoint] sshd started (pid=$SSHD_PID)"

# Node ingester as the supervised worker.
node /app/services/sftp/dist/index.js &
NODE_PID=$!
echo "[entrypoint] ingester started (pid=$NODE_PID)"

# wait -n is a bashism; alpine's default /bin/sh (ash) doesn't support it,
# which is why the shebang is /bin/bash and the Dockerfile apk-adds bash.
set +e
wait -n $SSHD_PID $NODE_PID
EXIT_CODE=$?
echo "[entrypoint] child exited (code=$EXIT_CODE), shutting down siblings"
kill $SSHD_PID $NODE_PID 2>/dev/null || true
wait
exit $EXIT_CODE
