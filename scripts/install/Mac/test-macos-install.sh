#!/usr/bin/env bash
# Read-only installation diagnostics (browser check uses a temporary profile).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
[[ "$(uname -s)" == Darwin ]] || { echo 'This diagnostic is for macOS.' >&2; exit 1; }
source "$ROOT/scripts/install/runtime-path.sh"
for component in node npm git ollama; do
  command -v "$component" >/dev/null || { echo "$component is missing; run the macOS installer." >&2; exit 1; }
done
source "$ROOT/scripts/install/runtime-version-policy.sh"
validate_node || { echo "Unix installer runtime target not met; requires Node.js ${DVAIA_MINIMUM_NODE_VERSION}+ and npm ${DVAIA_MINIMUM_NPM_VERSION}+." >&2; exit 1; }
OLLAMA_HOST=http://127.0.0.1:11434 ollama show llama3.1:8b >/dev/null
node - <<'JS'
const { verifyInstalledComponents, verifyBrowserRuntime } = require('./scripts/setup-application');
(async () => {
  const installed = await verifyInstalledComponents(process.cwd());
  await verifyBrowserRuntime({ executablePath: process.env.PUPPETEER_EXECUTABLE_PATH });
  console.log('Frameworks and sandboxed browser verified:', installed);
})().catch(error => { console.error(error.message); process.exitCode = 1; });
JS
printf '%s\n' 'Local model and application dependencies verified. Database/application health is checked after ./start_all.sh.'
