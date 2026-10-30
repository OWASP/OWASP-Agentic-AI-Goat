#!/usr/bin/env bash
# Locate a supported standard installation without rewriting shell profiles.
owasp_ai_goat_runtime_guard="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/application-node-runtime.js"
owasp_ai_goat_supported_node() {
  "$1" -e 'require(process.argv[1]).assertSupportedApplicationNodeVersion(process.versions.node)' \
    "$owasp_ai_goat_runtime_guard" >/dev/null 2>&1
}
if ! command -v node >/dev/null 2>&1 || ! owasp_ai_goat_supported_node "$(command -v node)"; then
  for owasp_ai_goat_node_bin in /opt/homebrew/bin /usr/local/bin; do
    if [[ -x "$owasp_ai_goat_node_bin/node" ]] && owasp_ai_goat_supported_node "$owasp_ai_goat_node_bin/node"; then
      export PATH="$owasp_ai_goat_node_bin:$PATH"
      break
    fi
  done
fi
if ! command -v node >/dev/null 2>&1 || ! owasp_ai_goat_supported_node "$(command -v node)"; then
  echo 'Unsupported Node.js runtime. OWASP-AI-GOAT requires Node.js 26.10.0 or newer.' >&2
  unset -f owasp_ai_goat_supported_node
  unset owasp_ai_goat_node_bin
  unset owasp_ai_goat_runtime_guard
  return 1 2>/dev/null || exit 1
fi
unset -f owasp_ai_goat_supported_node
unset owasp_ai_goat_node_bin
unset owasp_ai_goat_runtime_guard
