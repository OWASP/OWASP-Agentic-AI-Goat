#!/usr/bin/env bash
# Compatibility helpers for application-level callers. No system installation,
# SQLite initialization, credential replacement, or automatic database reset.
_PF_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
pf_command_exists() { command -v "$1" >/dev/null 2>&1; }
pf_detect_os() {
  case "$(uname -s 2>/dev/null)" in
    Darwin) PF_OS=macos ;; Linux) PF_OS=linux ;; MINGW*|MSYS*|CYGWIN*) PF_OS=windows ;; *) PF_OS=unknown ;;
  esac
  PF_PKG=unknown
  export PF_OS PF_PKG
}
pf_detect_system_tools() { pf_command_exists node && pf_command_exists npm && pf_command_exists git; }
pf_ensure_system_tools() {
  if ! pf_detect_system_tools; then
    echo 'Install a supported Node.js runtime, npm and Git, then run npm run setup.' >&2
    return 1
  fi
}
pf_ensure_node_deps() { (cd "$_PF_ROOT" && npm ci && npm --prefix client ci); }
pf_ensure_env_and_jwt() {
  (cd "$_PF_ROOT" && node -e 'require("dotenv").config({quiet:true}); if(process.env.PLATFORM_DATABASE_ENGINE!=="postgres") throw Object.assign(new Error("PostgreSQL configuration required"),{code:"INVALID_CONFIGURATION"}); require("./server/services/platformSigningConfiguration").assertPlatformSigningConfiguration(process.env);' 2>/dev/null) || {
    echo 'Private PostgreSQL application configuration is required. Fresh install: npm run setup. Existing data: explicit migration.' >&2
    return 1
  }
}
pf_ensure_databases() { (cd "$_PF_ROOT" && node db/postgres/initialize-application.js); }
pf_ensure_ollama() {
  if ! pf_command_exists ollama; then echo 'Ollama is optional for startup; install it and pull llama3.1:8b for local inference.' >&2; fi
}
pf_ensure_lmstudio_embeddings() { echo 'Embedding/provider configuration is explicit in .env; no external service is installed by preflight.'; }
pf_ensure_dirs() { mkdir -p "$_PF_ROOT/server/logs" "$_PF_ROOT/server/uploads"; }
