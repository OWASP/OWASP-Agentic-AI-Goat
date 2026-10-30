#!/usr/bin/env bash
# Non-mutating macOS development helper. It intentionally does not install
# packages, edit shell profiles, create editor tasks, or delete databases.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

"$ROOT/scripts/install/Mac/install-macos.sh" --plan
cat <<'EOF'

Fresh setup: bash scripts/install/Mac/install-macos.sh
Start:       ./start_all.sh
Migrate:     ./start_all.sh --init-db
Plan:        ./start_all.sh --plan
Stop:        ./stop_all.sh

Optional aliases to add manually to your shell profile:
  alias owasp-ai-goat-start='./start_all.sh'
  alias owasp-ai-goat-stop='./stop_all.sh'
  alias owasp-ai-goat-migrate='./start_all.sh --init-db'
  alias owasp-ai-goat-test='npm test'

There is no database-delete alias. Workshop resets use authenticated controls;
existing installations must follow the PostgreSQL migration documentation.
EOF
