#!/usr/bin/env bash
# Compatibility entrypoint for an already cloned checkout; installs missing prerequisites.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install-owasp-ai-goat-ubuntu.sh" "$@"
