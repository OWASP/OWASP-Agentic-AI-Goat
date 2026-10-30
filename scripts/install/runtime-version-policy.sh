#!/usr/bin/env bash
# Sourced by Unix installers. Keep the qualified runtime floor in one place.
OWASP_AI_GOAT_MINIMUM_NODE_VERSION=26.10.0
OWASP_AI_GOAT_MINIMUM_NPM_VERSION=12.1.0

version_at_least() {
  local actual="${1#v}" required="${2#v}"
  [[ "$actual" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
  local a0="${BASH_REMATCH[1]}" a1="${BASH_REMATCH[2]}" a2="${BASH_REMATCH[3]}"
  [[ "$required" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
  local r0="${BASH_REMATCH[1]}" r1="${BASH_REMATCH[2]}" r2="${BASH_REMATCH[3]}"
  ((10#$a0 > 10#$r0)) ||
    ((10#$a0 == 10#$r0 && 10#$a1 > 10#$r1)) ||
    ((10#$a0 == 10#$r0 && 10#$a1 == 10#$r1 && 10#$a2 >= 10#$r2))
}

validate_node_binary() {
  command -v node >/dev/null 2>&1 && version_at_least "$(node --version 2>/dev/null)" "$OWASP_AI_GOAT_MINIMUM_NODE_VERSION"
}

validate_npm() {
  command -v npm >/dev/null 2>&1 && version_at_least "$(npm --version 2>/dev/null)" "$OWASP_AI_GOAT_MINIMUM_NPM_VERSION"
}

validate_node() { validate_node_binary && validate_npm; }
