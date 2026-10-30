#!/bin/bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$repo_root"
if [[ "$(uname -s)" != "Darwin" ]]; then
  printf 'Focused repository-local unit boundary requires macOS sandbox-exec\n' >&2
  exit 2
fi
for local_path in tasks tasks/tmp; do
  if [[ -L "$repo_root/$local_path" ]]; then
    printf 'Repository task path is a symlink: %s\n' "$local_path" >&2
    exit 2
  fi
done
mkdir -p tasks/tmp
node_bin="$(command -v node)"
if [[ ! -x "$node_bin" ]]; then
  printf 'Node executable required\n' >&2
  exit 2
fi
umask 077
unit_runtime="$(mktemp -d "$repo_root/tasks/tmp/focused-unit.XXXXXXXX")"
export OWASP_AI_GOAT_REPO_LOCAL_UNIT_RUNTIME="$unit_runtime"
export TMPDIR="$unit_runtime"
export XDG_CACHE_HOME="$unit_runtime/cache"
export npm_config_cache="$unit_runtime/npm-cache"
export PUPPETEER_CACHE_DIR="$unit_runtime/browser-cache"
export PLAYWRIGHT_BROWSERS_PATH="$unit_runtime/browser-cache"
export PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/sandbox-exec -D "UNIT_RUNTIME=$unit_runtime" -f "$repo_root/scripts/lib/repo-local-unit.sb" \
  "$node_bin" "$repo_root/scripts/test-repo-local-unit.js" "$@"
