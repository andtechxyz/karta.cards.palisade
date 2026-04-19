#!/bin/sh
# ---------------------------------------------------------------------------
# Idempotent SFTP user provisioning.  Reads SFTP_USERS (JSON array) from the
# environment and creates a Linux account for each.  Called once at container
# start before sshd + the Node ingester launch.
#
# SFTP_USERS example:
#   [
#     {
#       "username": "incomm",
#       "uid": 1001,
#       "sshPublicKey": "ssh-ed25519 AAAAC3NzaC1... ops@incomm.com"
#     }
#   ]
#
# The username MUST match a FinancialInstitution.slug — the Node ingester
# looks up the FI by that slug to authorise uploaded batches.
# ---------------------------------------------------------------------------
set -eu

if [ -z "${SFTP_USERS:-}" ] || [ "${SFTP_USERS:-}" = "[]" ]; then
  echo "[provision] SFTP_USERS is empty — no users configured"
  exit 0
fi

# sftponly group — sshd's Match block applies chroot + internal-sftp only
# to members of this group, so there's no risk of giving root or node a
# chrooted shell by mistake.
if ! getent group sftponly >/dev/null 2>&1; then
  addgroup -S sftponly
  echo "[provision] created group: sftponly"
fi

# Iterate users.  Using `jq -c` so each user is a single line — trivial to
# stream through a `while read` loop without intermediate tempfiles.
echo "$SFTP_USERS" | jq -c '.[]' | while IFS= read -r USER_JSON; do
  USERNAME=$(echo "$USER_JSON" | jq -r '.username // empty')
  UID_VAL=$(echo "$USER_JSON" | jq -r '.uid // empty')
  PUBKEY=$(echo "$USER_JSON" | jq -r '.sshPublicKey // empty')

  if [ -z "$USERNAME" ] || [ -z "$UID_VAL" ] || [ -z "$PUBKEY" ]; then
    echo "[provision] skipping malformed entry: $USER_JSON"
    continue
  fi

  # adduser is alpine's BusyBox builtin: -D no-password, -H no-homedir,
  # -s /sbin/nologin (no shell — sshd's Match ForceCommand gives them
  # internal-sftp instead), -G primary group, -u explicit uid.
  if ! id "$USERNAME" >/dev/null 2>&1; then
    adduser -D -H -s /sbin/nologin -G sftponly -u "$UID_VAL" "$USERNAME"
    echo "[provision] created user: $USERNAME (uid=$UID_VAL)"
  fi

  # Home directory.  ChrootDirectory requires the chroot root (the home
  # dir) to be root-owned and not writable by the user — if this is wrong
  # sshd disconnects with "bad ownership or modes".  Hence the three dirs
  # under /home/<user>/ (upload, processed, failed) that are user-owned.
  mkdir -p "/home/$USERNAME"
  chown root:root "/home/$USERNAME"
  chmod 755 "/home/$USERNAME"

  for dir in upload processed failed; do
    mkdir -p "/home/$USERNAME/$dir"
    chown "$USERNAME:sftponly" "/home/$USERNAME/$dir"
    chmod 755 "/home/$USERNAME/$dir"
  done

  # Public key — overwritten each boot so key rotation just needs a task
  # restart after updating the SFTP_USERS secret.
  mkdir -p "/home/$USERNAME/.ssh"
  printf '%s\n' "$PUBKEY" > "/home/$USERNAME/.ssh/authorized_keys"
  chown -R "$USERNAME:sftponly" "/home/$USERNAME/.ssh"
  chmod 700 "/home/$USERNAME/.ssh"
  chmod 600 "/home/$USERNAME/.ssh/authorized_keys"

  echo "[provision] ok: $USERNAME"
done
