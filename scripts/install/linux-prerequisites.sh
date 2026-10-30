#!/usr/bin/env bash
# Sourced by the guarded common installer. No actions occur when sourced.

source "$ROOT/scripts/install/runtime-version-policy.sh"

install_linux_prerequisites() {
  [[ "$(uname -s)" == Linux ]] || die 'Linux prerequisites require Linux.'
  local arch release distro node_arch package tmp current_user missing=() libraries=()
  arch="$(uname -m)"
  case "$arch" in x86_64) node_arch=x64 ;; aarch64|arm64) node_arch=arm64 ;; *) die "Unsupported Linux architecture: $arch" ;; esac
  [[ -r /etc/os-release ]] || die 'Cannot identify Linux distribution.'
  distro="$(. /etc/os-release; printf '%s' "${ID:-}")"
  case "$distro" in ubuntu|debian) ;; *) die 'Automatic prerequisites support Ubuntu and Debian only.' ;; esac
  command -v apt-get >/dev/null 2>&1 || die 'apt-get is required.'
  # Puppeteer 25's bundled Chrome for Testing has no compatible Linux ARM64
  # download. On Ubuntu, install Canonical's confined Chromium Snap instead.
  # A non-systemd environment cannot start snapd safely, so fail before package
  # changes there rather than pretending its browser sandbox is ready.
  if [[ "$node_arch" == arm64 && "$distro" == ubuntu && -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]]; then
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || die 'Ubuntu ARM64 automatic Chromium installation requires a systemd host so snapd can run. Supply a sandbox-capable browser with PUPPETEER_EXECUTABLE_PATH in non-systemd environments.'
  fi
  if [[ -n "${PUPPETEER_EXECUTABLE_PATH:-}" ]]; then
    [[ "$PUPPETEER_EXECUTABLE_PATH" == /* && -x "$PUPPETEER_EXECUTABLE_PATH" ]] || die 'PUPPETEER_EXECUTABLE_PATH must be an absolute executable browser path.'
    export PUPPETEER_EXECUTABLE_PATH PUPPETEER_SKIP_DOWNLOAD=true
  fi
  as_root apt-get update
  for package in git curl ca-certificates build-essential python3 xz-utils zstd apparmor; do
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q '^install ok installed$'; then missing+=("$package"); fi
  done
  # Chromium/Puppeteer runtime libraries. Noble and newer Debian use t64 names.
  for package in libasound2 libatk1.0-0 libatk-bridge2.0-0 libcups2 libgtk-3-0; do
    if apt-cache show "${package}t64" >/dev/null 2>&1; then libraries+=("${package}t64"); else libraries+=("$package"); fi
  done
  libraries+=(libnss3 libnspr4 libdrm2 libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libx11-xcb1 libxcb1 libxext6 libxshmfence1 fonts-liberation)
  as_root apt-get install -y --no-install-recommends ${missing[@]+"${missing[@]}"} "${libraries[@]}"
  if [[ "$node_arch" == arm64 && -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]]; then
    if [[ "$distro" == debian ]]; then
      as_root apt-get install -y --no-install-recommends chromium
      [[ -x /usr/bin/chromium ]] || die 'Debian Chromium installation did not provide /usr/bin/chromium.'
      export PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
    else
      as_root apt-get install -y --no-install-recommends snapd
      as_root systemctl enable --now snapd.socket
      local attempt
      for attempt in {1..30}; do
        snap version >/dev/null 2>&1 && break
        [[ "$attempt" != 30 ]] || die 'snapd did not become ready for Ubuntu Chromium installation.'
        sleep 1
      done
      if ! snap list chromium >/dev/null 2>&1; then
        as_root snap install chromium
      fi
      [[ -x /snap/bin/chromium ]] || die 'Ubuntu Chromium Snap installation did not provide /snap/bin/chromium.'
      export PUPPETEER_EXECUTABLE_PATH=/snap/bin/chromium
    fi
    export PUPPETEER_SKIP_DOWNLOAD=true
  fi

  # The verified Node archive supplies both node and npm. A standalone node
  # binary is not a complete supported runtime and cannot bootstrap npm by
  # invoking a command that does not exist.
  if ! validate_node_binary || ! command -v npm >/dev/null 2>&1; then
    release="v${OWASP_AI_GOAT_MINIMUM_NODE_VERSION}"
    tmp="$(mktemp -d)" || die 'Cannot create Node download directory.'
    local archive="node-${release}-linux-${node_arch}.tar.xz"
    if ! curl --fail --location --proto '=https' --tlsv1.2 "https://nodejs.org/dist/${release}/${archive}" -o "$tmp/$archive" ||
       ! curl --fail --location --proto '=https' --tlsv1.2 "https://nodejs.org/dist/${release}/SHASUMS256.txt" -o "$tmp/SHASUMS256.txt"; then
      rm -rf "$tmp"; die 'Official Node download failed.'
    fi
    if ! (cd "$tmp" && awk -v name="$archive" '$2==name {print; found++} END {if(found!=1) exit 1}' SHASUMS256.txt > selected.sha256 && sha256sum -c selected.sha256); then
      rm -rf "$tmp"; die 'Node SHA256 verification failed.'
    fi
    if ! as_root tar -xJf "$tmp/$archive" -C /usr/local --strip-components=1 --no-same-owner; then
      rm -rf "$tmp"; die 'Node installation failed.'
    fi
    rm -rf "$tmp"
    export PATH="/usr/local/bin:$PATH"
  fi
  hash -r
  command -v node >/dev/null 2>&1 || die 'Node.js is unavailable after installation.'
  command -v npm >/dev/null 2>&1 || die 'npm is unavailable after Node.js installation.'
  if ! validate_npm; then
    as_root env NODE_USE_SYSTEM_CA=1 npm install --global "npm@${OWASP_AI_GOAT_MINIMUM_NPM_VERSION}"
    hash -r
  fi
  validate_node || die 'A compatible Node.js and npm are required after installation.'

  # Local exercise sidecars require Docker even with an external PostgreSQL store.
  {
    if ! command -v docker >/dev/null 2>&1; then as_root apt-get install -y docker.io; fi
    if ! docker info >/dev/null 2>&1; then
      if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        as_root systemctl enable --now docker
      else
        as_root service docker start
      fi
    fi
    if ! docker info >/dev/null 2>&1; then
      # Only repair group access when the daemon actually works as root.
      as_root docker info >/dev/null 2>&1 || die 'Docker daemon is unavailable; start Docker and rerun.'
      current_user="$(id -un)"
      [[ "$current_user" != root ]] || die 'Docker is unavailable to the current user.'
      [[ "${OWASP_AI_GOAT_INSTALL_GROUP_REFRESHED:-}" != 1 ]] || die 'Docker permissions are still unavailable after refreshing groups. Sign out/in and rerun.'
      as_root usermod -aG docker "$current_user"
      echo 'Docker access granted. Continuing as your user with refreshed groups. Sign out/in once before using Docker from other terminal sessions.'
      export OWASP_AI_GOAT_INSTALL_GROUP_REFRESHED=1
      # sudo initializes supplementary groups for the target user. Values stay in
      # the environment, never in command arguments; no shell command is built.
      local preserved_setup_environment
      preserved_setup_environment='PATH,PUPPETEER_EXECUTABLE_PATH,PUPPETEER_SKIP_DOWNLOAD,XENOVA_CACHE,HF_HUB_OFFLINE,TRANSFORMERS_OFFLINE,PG_ADMIN_DATABASE_URL,PG_TLS,DOCKER_HOST,DOCKER_CONTEXT,DOCKER_CONFIG,IPI_EMAIL_PROVIDER,MCP_SIDECARS_AUTOSTART,SANDBOX_RUNNER_URL,TEAM_ID,ECS_CONTAINER_METADATA_URI_V4,LEGACY_SENSITIVE_FILES_ROOT,OWASP_AI_GOAT_APP_DATA_ROOT,NODE_USE_SYSTEM_CA,NODE_EXTRA_CA_CERTS,SSL_CERT_FILE,SSL_CERT_DIR,NODE_OPTIONS,npm_config_cafile,NPM_CONFIG_CAFILE,npm_config_ca,NPM_CONFIG_CA,HTTP_PROXY,HTTPS_PROXY,NO_PROXY,http_proxy,https_proxy,no_proxy,OWASP_AI_GOAT_INSTALL_GROUP_REFRESHED'
      exec sudo "--preserve-env=$preserved_setup_environment" --user "$current_user" -- bash "$ROOT/scripts/install/Ubuntu/install-owasp-ai-goat-ubuntu.sh" ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
    fi
  }

  ensure_linux_compose
  ensure_linux_buildx

  if ! command -v ollama >/dev/null 2>&1; then
    tmp="$(mktemp -d)" || die 'Cannot create Ollama download directory.'
    if ! curl --fail --location --proto '=https' --tlsv1.2 https://ollama.com/install.sh -o "$tmp/install.sh"; then
      rm -rf "$tmp"; die 'Official Ollama installer download failed.'
    fi
    if ! as_root sh "$tmp/install.sh"; then rm -rf "$tmp"; die 'Ollama installation failed.'; fi
    rm -rf "$tmp"
  fi
  if ! OLLAMA_HOST=127.0.0.1:11434 ollama list >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] && systemctl cat ollama.service >/dev/null 2>&1; then
      as_root systemctl enable --now ollama
    else
      tmp="$(mktemp -d "${TMPDIR:-/tmp}/owasp-ai-goat-ollama.XXXXXXXX")" || die 'Cannot create private Ollama log directory.'
      (umask 077; OLLAMA_HOST=127.0.0.1:11434 nohup ollama serve > "$tmp/ollama.log" 2>&1 < /dev/null &)
      printf 'Local Ollama startup log: %s/ollama.log\n' "$tmp"
    fi
    local attempt
    for attempt in {1..30}; do
      if OLLAMA_HOST=127.0.0.1:11434 ollama list >/dev/null 2>&1; then return 0; fi
      sleep 1
    done
    die 'Ollama did not become ready on 127.0.0.1:11434; inspect its service or private startup log.'
  fi
}

ensure_linux_compose() {
  local package
  if ! docker compose version >/dev/null 2>&1; then
    local compose_package=''
    for package in docker-compose-v2 docker-compose-plugin; do
      if apt-cache show "$package" >/dev/null 2>&1; then compose_package="$package"; break; fi
    done
    [[ -n "$compose_package" ]] || die 'Docker Compose v2 is required by owned runner provisioning but is unavailable from configured apt repositories.'
    as_root apt-get install -y --no-install-recommends "$compose_package"
    docker compose version >/dev/null 2>&1 || die 'Docker Compose v2 installation did not provide the required Docker CLI plugin.'
  fi
}

ensure_linux_buildx() {
  docker buildx version >/dev/null 2>&1 && return 0
  local package buildx_package=''
  for package in docker-buildx docker-buildx-plugin; do
    if apt-cache show "$package" >/dev/null 2>&1; then buildx_package="$package"; break; fi
  done
  [[ -n "$buildx_package" ]] || die 'Docker Buildx is required for owned image builds but is unavailable from configured apt repositories.'
  as_root apt-get install -y --no-install-recommends "$buildx_package"
  docker buildx version >/dev/null 2>&1 || die 'Docker Buildx installation did not provide the required Docker CLI plugin.'
}
