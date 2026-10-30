#!/usr/bin/env bash
# Shared macOS / Ubuntu / Debian fresh-install entrypoint.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXPECTED_OS="${1:?Expected Darwin or Linux}"
shift
INSTALL_ARGS=("$@")
die() { echo "$*" >&2; exit 1; }
as_root() { if [[ "$(id -u)" == 0 ]]; then "$@"; else sudo "$@"; fi; }
prepare_os_prerequisites() {
  if [[ "$EXPECTED_OS" == Darwin ]]; then
    source "$ROOT/scripts/install/macos-prerequisites.sh"
    install_macos_prerequisites "$REPAIR"
  else
    source "$ROOT/scripts/install/linux-prerequisites.sh"
    install_linux_prerequisites
  fi
}
wait_for_local_ollama() {
  export OLLAMA_HOST=127.0.0.1:11434
  local attempt
  for attempt in {1..60}; do
    if curl --fail --silent --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null; then return 0; fi
    [[ "$attempt" != 60 ]] || die 'Ollama did not become ready on localhost:11434. Check its service logs and rerun.'
    sleep 1
  done
}
source "$ROOT/scripts/install/runtime-version-policy.sh"
PLAN=false
UPGRADE=false
REPAIR=false
OWNED_ANALYTICS=false
ENABLE_ANALYTICS=false
OWNED_SYSTEM=false
OWNED_LISTINGS=false
ENABLE_LISTINGS=false
OWNED_PRICING=false
OWNED_COUPONS=false
QUALIFIED_SECURESHOP=false
OWNED_MCP_REGISTRY=false
ENABLE_MCP_REGISTRY=false
OWNED_POLICY_RENDERER=false
ENABLE_POLICY_RENDERER=false
for argument in "$@"; do
  case "$argument" in
    --plan) PLAN=true ;;
    --upgrade) UPGRADE=true ;;
    --repair) REPAIR=true; UPGRADE=true ;;
    --no-install) ;;
    --owned-analytics) OWNED_ANALYTICS=true ;;
    --enable-owned-analytics) OWNED_ANALYTICS=true; ENABLE_ANALYTICS=true ;;
    --owned-coupons) OWNED_COUPONS=true; OWNED_ANALYTICS=true ;;
    --owned-listings) OWNED_LISTINGS=true ;;
    --enable-owned-listings) ENABLE_LISTINGS=true ;;
    --owned-pricing) OWNED_PRICING=true ;;
    --owned-system) OWNED_SYSTEM=true ;;
    --qualified-secureshop) QUALIFIED_SECURESHOP=true ;;
    --owned-mcp-registry) OWNED_MCP_REGISTRY=true ;;
    --enable-owned-mcp-registry) OWNED_MCP_REGISTRY=true; ENABLE_MCP_REGISTRY=true ;;
    --owned-policy-renderer) OWNED_POLICY_RENDERER=true ;;
    --enable-owned-policy-renderer) ENABLE_POLICY_RENDERER=true ;;
    --help) echo 'Usage: OS installer [--plan] [--no-install] [--upgrade|--repair] [--owned-analytics] [--owned-coupons] [--enable-owned-analytics] [--owned-system] [--owned-listings] [--enable-owned-listings] [--owned-pricing] [--qualified-secureshop] [--owned-mcp-registry] [--enable-owned-mcp-registry] [--owned-policy-renderer] [--enable-owned-policy-renderer]. --upgrade is database-only; --repair also prepares missing local prerequisites and locked dependencies.'; exit 0 ;;
    *) die "Unknown installation argument: $argument" ;;
  esac
done
[[ "$(uname -s)" == "$EXPECTED_OS" ]] || die "This installer requires $EXPECTED_OS."
if "$QUALIFIED_SECURESHOP" && ! "$OWNED_SYSTEM"; then
  die 'Qualified SecureShop setup requires --qualified-secureshop --owned-system together.'
fi
if "$ENABLE_LISTINGS" && ! "$OWNED_LISTINGS"; then
  die '--enable-owned-listings requires --owned-listings.'
fi
if "$ENABLE_POLICY_RENDERER" && ! "$OWNED_POLICY_RENDERER"; then
  die '--enable-owned-policy-renderer requires --owned-policy-renderer.'
fi
if "$PLAN"; then
  if "$OWNED_MCP_REGISTRY" || "$QUALIFIED_SECURESHOP"; then
    echo 'Owned MCP registry: build or verify the pinned image and private loopback service after bound SecureShop prerequisites. ARM64 qualified only; Linux AMD64 remains unqualified. Plan performs no build, provisioning or activation.'
    if "$ENABLE_MCP_REGISTRY"; then
      echo 'Owned MCP registry explicit enablement: enables only after prerequisite and readiness checks.'
    else
      echo 'Owned MCP registry preparation preserves existing disabled preferences; overriding those preferences requires --enable-owned-mcp-registry. Fresh requested setup may activate after prerequisite and readiness checks.'
    fi
  fi
  if "$OWNED_PRICING"; then
    echo 'Owned Pricing opt-in: delegates readiness and existing prerequisite checks to application setup; preserves existing configuration and data. Plan performs no provisioning or activation.'
  fi
  if "$OWNED_POLICY_RENDERER"; then
    echo 'Owned strict policy renderer: ARM64 macOS/Linux only. Application setup verifies the actual Node and selected Docker-daemon architecture before renderer provisioning; this wrapper does not infer it from uname.'
    echo 'Its pinned Node base image and Debian build packages may require network access when absent. The renderer source manifest and Docker --pull=false do not make a cold build offline. Plan performs no build, provisioning or activation.'
    if "$ENABLE_POLICY_RENDERER"; then
      echo 'Owned strict policy renderer explicit enablement: activates only after the paired private renderer is provisioned, source-bound and ready.'
    else
      echo 'Owned strict policy renderer preparation preserves an existing disabled preference.'
    fi
  fi
  if "$OWNED_LISTINGS"; then
    if "$ENABLE_LISTINGS"; then
      echo 'Owned Listings activation: ARM64 only; verifies exact qualified manager, source, authority, schema and cleanup bindings before enabling the retained private record. Application restart is required; plan changes nothing.'
    else
      echo 'Owned Listings preparation: ARM64 only; verifies checked-in package qualification and recorded Docker authority, then automatically installs the exact workspace AppArmor profile. Stages one shared manager without enabling application capability.'
    fi
  fi
  if "$OWNED_COUPONS"; then
    echo "Owned coupons: explicit opt-in reuses isolated Analytics, applies additive review migrations, and enables only after readiness. Existing disabled preferences are preserved."
  fi
  if "$OWNED_ANALYTICS"; then
    if "$ENABLE_ANALYTICS"; then
      echo 'Owned Analytics explicit enablement: verifies its private cluster and application request schema before enabling a staged or disabled feature.'
    else
      echo 'Owned Analytics opt-in: requires bound SecureShop; verifies a separate private PostgreSQL cluster and application request schema before activation; preserves existing disabled preferences.'
    fi
  fi
  if "$OWNED_SYSTEM"; then
    echo 'Owned System opt-in: ARM64 only. Explicit setup verifies the selected local Docker authority and prepares a missing exact sandbox profile before private service provisioning; conflicts fail closed. Plan performs no installation or activation.'
  fi
  if "$UPGRADE"; then
    if "$REPAIR"; then
      cat <<'PLAN'
Existing-install repair plan (no commands that change the machine are executed):
1. Require the existing private .env and provisioning manifest; preserve both.
2. Install missing supported Node/npm, Git, native build tools, Docker/Compose and Ollama.
3. Install locked backend/client dependencies, a missing browser and local model;
   verify sandboxed browser, local generation and embedding cache.
4. Run the supported additive PostgreSQL upgrade, retaining administrator
   credentials, existing configuration and learner records.
PLAN
    else
      cat <<'PLAN'
Additive upgrade plan (no commands that change the machine are executed):
1. Require the existing private .env and provisioning manifest.
2. Verify their exact database credential binding against PostgreSQL18.
3. Provision and initialize only appended stores.
4. Atomically append only their URL pairs; preserve every existing setting.
No packages, model, browser, administrator, AWS asset or existing row is changed.
PLAN
    fi
    exit 0
  fi
  cat <<'PLAN'
Fresh setup plan (no commands that change the machine are executed):
1. Refuse an existing .env before installing packages or starting services.
2. Install missing supported Node/npm, Git, native build tools and Ollama.
   macOS: Homebrew; Docker/Compose plus the explicit Colima profile used by the owned runner.
   Ubuntu/Debian: apt prerequisites, verified Node binary, Docker Engine/Compose if needed.
   Local exercise sidecars require Docker even when PostgreSQL is external.
3. Start local Ollama; download llama3.1:8b only when missing.
4. npm ci for backend/client installs locked LangChain, LangGraph and browser runtime.
5. Provision PostgreSQL18 in a persistent loopback-only Docker container, or use
   PG_ADMIN_DATABASE_URL; initialize all stores, write private credentials/.env,
   then provision the ordinary owned MCP/CodeBot runner and local services;
   activate staged capabilities only after their readiness checks pass.
Administrative package installation may request your OS password. No AWS changes.
This preview describes intended local actions; it is not clean-host qualification,
and the frozen AWS Node 18 deployment is incompatible with this build.
PLAN
  exit 0
fi
cd "$ROOT"
if "$UPGRADE"; then
  [[ -f .env && ! -L .env ]] || die 'Additive upgrade requires the existing private .env.'
  if "$REPAIR"; then
    [[ "$(id -u)" != 0 ]] || die 'Run repair as your normal user, not with sudo.'
    case "$(uname -m)" in x86_64|arm64|aarch64) ;; *) die 'Only 64-bit Intel/AMD and ARM machines are supported.' ;; esac
    prepare_os_prerequisites
  fi
  validate_node || die 'A supported Node.js runtime and npm are required for additive upgrade.'
  if "$REPAIR"; then wait_for_local_ollama; fi
  if [[ -z "${PG_ADMIN_DATABASE_URL:-}" ]]; then
    docker info >/dev/null 2>&1 || die 'Docker is unavailable for PostgreSQL upgrade; check the owned setup service or set PG_ADMIN_DATABASE_URL.'
  fi
  exec npm run setup -- ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
fi
[[ ! -e .env && ! -L .env ]] || die 'An .env already exists. Fresh setup will not overwrite it; use the documented PostgreSQL migration/configuration commands.'
[[ "$(id -u)" != 0 ]] || die 'Run the installer as your normal user, not with sudo. It requests administrative access only for system packages; the exercise browser requires a user sandbox.'
case "$(uname -m)" in x86_64|arm64|aarch64) ;; *) die 'Only 64-bit Intel/AMD and ARM machines are supported.' ;; esac
prepare_os_prerequisites
validate_node || die 'A supported Node.js runtime and npm are still unavailable. Check PATH and rerun setup.'
command -v git >/dev/null || die 'Git installation failed.'
command -v ollama >/dev/null || die 'Ollama installation failed.'
wait_for_local_ollama
if [[ -z "${PG_ADMIN_DATABASE_URL:-}" ]]; then
  if [[ "$EXPECTED_OS" == Darwin ]]; then
    docker --context "$OWASP_AI_GOAT_MCP_OWNED_COLIMA_PROFILE" info >/dev/null 2>&1 ||
      die 'The selected Colima Docker daemon is unavailable for PostgreSQL provisioning; inspect that profile and rerun.'
  else
    docker info >/dev/null 2>&1 || die 'Docker is unavailable for PostgreSQL provisioning; check the service and user permissions.'
  fi
fi
exec npm run setup -- ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
