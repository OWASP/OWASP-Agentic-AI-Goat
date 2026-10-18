#!/usr/bin/env bash
# Installs missing macOS prerequisites, then provisions the fresh application.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
exec bash "$ROOT/scripts/install/bootstrap-unix.sh" Darwin "$@"
