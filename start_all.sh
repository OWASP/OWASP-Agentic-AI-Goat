#!/usr/bin/env bash
# PostgreSQL application launcher. Dependencies/configuration: npm run setup.
# --init-db applies idempotent migrations/seeds; it never deletes existing data.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source "$SCRIPT_DIR/scripts/install/runtime-path.sh"
if ! command -v node >/dev/null 2>&1; then
  echo 'Node.js is required. Install a supported runtime before running npm run setup.' >&2
  exit 1
fi
exec node scripts/start-application.js "$@"
