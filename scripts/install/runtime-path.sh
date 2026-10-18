#!/usr/bin/env bash
# Locate a supported standard installation without rewriting shell profiles.
dvaia_runtime_guard="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/application-node-runtime.js"
dvaia_supported_node() {
  "$1" -e 'require(process.argv[1]).assertSupportedApplicationNodeVersion(process.versions.node)' \
    "$dvaia_runtime_guard" >/dev/null 2>&1
}
if ! command -v node >/dev/null 2>&1 || ! dvaia_supported_node "$(command -v node)"; then
  for dvaia_node_bin in /opt/homebrew/bin /usr/local/bin; do
    if [[ -x "$dvaia_node_bin/node" ]] && dvaia_supported_node "$dvaia_node_bin/node"; then
      export PATH="$dvaia_node_bin:$PATH"
      break
    fi
  done
fi
if ! command -v node >/dev/null 2>&1 || ! dvaia_supported_node "$(command -v node)"; then
  echo 'Unsupported Node.js runtime. DVAIA requires Node.js 26.10.0 or newer.' >&2
  unset -f dvaia_supported_node
  unset dvaia_node_bin
  unset dvaia_runtime_guard
  return 1 2>/dev/null || exit 1
fi
unset -f dvaia_supported_node
unset dvaia_node_bin
unset dvaia_runtime_guard
