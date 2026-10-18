#!/bin/bash
# Runs as root: seed the lab filesystem at real absolute paths, snapshot a
# pristine copy for reset, hand the mutable dirs to the non-root sandbox user,
# then drop privileges and start the runner as that user.
set -e

SANDBOX_UID="${SANDBOX_UID:-10001}"
SANDBOX_GID="${SANDBOX_GID:-10001}"
TEMPLATE=/opt/lab-template
PRISTINE=/opt/lab-pristine

seed() {
  local rel="$1"
  local src="$TEMPLATE/$rel"
  local dst="/$rel"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

# Place curated lab files at their real absolute paths.
mkdir -p /home/mcp-admin /opt/app/config /opt/app/logs /var/secrets /var/log /opt/lab/bin /var/tmp
cp -a "$TEMPLATE/home/mcp-admin/." /home/mcp-admin/ 2>/dev/null || true
cp -a "$TEMPLATE/opt/app/." /opt/app/ 2>/dev/null || true
cp -a "$TEMPLATE/opt/lab/." /opt/lab/ 2>/dev/null || true
cp -a "$TEMPLATE/var/secrets/." /var/secrets/ 2>/dev/null || true
cp -a "$TEMPLATE/var/log/." /var/log/ 2>/dev/null || true
cp -f "$TEMPLATE/etc/passwd" /etc/passwd 2>/dev/null || true
echo 'mcp-server-prod-01' > /etc/hostname 2>/dev/null || true
# Append curated host entries (do not clobber container DNS entries).
if [ -f "$TEMPLATE/etc/hosts.lab" ]; then
  grep -q 'acme-corp.internal' /etc/hosts 2>/dev/null || cat "$TEMPLATE/etc/hosts.lab" >> /etc/hosts || true
fi
chmod +x /opt/lab/bin/*.sh 2>/dev/null || true

# Snapshot pristine copies of the mutable dirs for /reset.
mkdir -p "$PRISTINE/var/secrets" "$PRISTINE/opt/app/config"
cp -a /var/secrets/. "$PRISTINE/var/secrets/" 2>/dev/null || true
cp -a /opt/app/config/. "$PRISTINE/opt/app/config/" 2>/dev/null || true

# Ensure the non-root sandbox user exists and owns the writable surfaces.
if ! getent group "$SANDBOX_GID" >/dev/null 2>&1; then
  groupadd -g "$SANDBOX_GID" sandbox 2>/dev/null || true
fi
if ! id -u "$SANDBOX_UID" >/dev/null 2>&1; then
  useradd -u "$SANDBOX_UID" -g "$SANDBOX_GID" -M -s /bin/bash sandbox 2>/dev/null || true
fi
mkdir -p /sandbox/sessions
if [[ "${MCP_OWNED_TARGETS_ENABLED:-false}" == true ]]; then
  mkdir -p "${MCP_OWNED_TARGET_ROOT:-/sandbox/owned-targets}"
  chmod 0700 "${MCP_OWNED_TARGET_ROOT:-/sandbox/owned-targets}"
fi
chown -R "$SANDBOX_UID:$SANDBOX_GID" /sandbox /var/secrets /opt/app/config /var/tmp /tmp 2>/dev/null || true
# Secrets stay world-readable (that is the whole point of the lab).
chmod -R a+r /var/secrets /opt/app/config 2>/dev/null || true

exec gosu "$SANDBOX_UID:$SANDBOX_GID" node /app/index.js
