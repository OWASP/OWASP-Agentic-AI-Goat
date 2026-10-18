#!/usr/bin/env bash
# Sourced by bootstrap-unix.sh; never run package managers as root on macOS.
install_macos_prerequisites() {
  local repair_existing="${1:-false}"
  [[ "$repair_existing" == true || "$repair_existing" == false ]] || die 'Invalid macOS prerequisite mode.'
  [[ "$(id -u)" != 0 ]] || die 'Run the macOS installer as your normal user, not with sudo; Homebrew requests privileges when needed.'
  # A new shell may not yet include Homebrew's standard installation prefix.
  if ! command -v brew >/dev/null 2>&1; then
    for brew_prefix in /opt/homebrew /usr/local; do
      if [[ -x "$brew_prefix/bin/brew" ]]; then export PATH="$brew_prefix/bin:$PATH"; break; fi
    done
  fi
  if ! command -v brew >/dev/null 2>&1; then
    local brew_script
    brew_script="$(mktemp -t dvaia-homebrew.XXXXXX)"
    curl --fail --show-error --location --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o "$brew_script" || { rm -f "$brew_script"; die 'Homebrew download failed.'; }
    /bin/bash "$brew_script" || { rm -f "$brew_script"; die 'Homebrew installation failed; complete any macOS developer-tool prompt and rerun.'; }
    rm -f "$brew_script"
    for brew_prefix in /opt/homebrew /usr/local; do
      if [[ -x "$brew_prefix/bin/brew" ]]; then export PATH="$brew_prefix/bin:$PATH"; break; fi
    done
  fi
  command -v brew >/dev/null || die 'Homebrew is unavailable after installation.'
  if ! xcode-select -p >/dev/null 2>&1; then
    xcode-select --install || true
    echo 'Complete the macOS Command Line Tools dialog. Waiting up to 10 minutes...'
    local attempt
    for attempt in {1..300}; do
      xcode-select -p >/dev/null 2>&1 && break
      [[ "$attempt" != 300 ]] || die 'Command Line Tools installation is not complete; rerun after it finishes.'
      sleep 2
    done
  fi
  # Upgrade npm independently when the existing Node binary is qualified.
  if ! validate_node_binary || ! command -v npm >/dev/null 2>&1; then
    if brew list --formula node >/dev/null 2>&1; then brew upgrade node; else brew install node; fi
    hash -r
    if ! validate_node; then
      local node_prefix
      node_prefix="$(brew --prefix node)"
      [[ "$node_prefix" == /* && -x "$node_prefix/bin/node" ]] || die 'Homebrew Node installation is unavailable.'
      export PATH="$node_prefix/bin:$PATH"
      hash -r
    fi
  fi
  if ! validate_npm; then
    env NODE_USE_SYSTEM_CA=1 npm install --global "npm@${DVAIA_MINIMUM_NPM_VERSION}"
    hash -r
  fi
  validate_node || die 'The qualified Node.js and npm runtime is unavailable after Homebrew installation.'
  command -v git >/dev/null 2>&1 || brew install git
  command -v python3 >/dev/null 2>&1 || brew install python
  # The owned runner is installed later by normal application setup. Bind it to
  # an explicit Colima VM instead of whichever Docker context happens to be active.
  command -v docker >/dev/null 2>&1 || brew install docker
  command -v colima >/dev/null 2>&1 || brew install colima
  local owned_profile="${DVAIA_MCP_OWNED_COLIMA_PROFILE:-colima-default}"
  if ! "$repair_existing"; then
    [[ "$owned_profile" =~ ^colima-[a-z0-9][a-z0-9-]{0,47}$ ]] || die 'DVAIA_MCP_OWNED_COLIMA_PROFILE must be colima-<profile>.'
    colima start --profile "${owned_profile#colima-}" --cpu 2 --memory 4
    export DVAIA_MCP_OWNED_COLIMA_PROFILE="$owned_profile"
  fi
  # Local exercise sidecars require Docker even with an external PostgreSQL store.
  if ! docker info >/dev/null 2>&1; then
    if "$repair_existing"; then
      die 'Repair requires the previously bound local Docker daemon to be running. Start that daemon or its recorded Colima profile, then rerun; repair will not start a different Docker service.'
    fi
    if [[ -d /Applications/Docker.app ]]; then
      open -a Docker
    else
      colima start --profile "${owned_profile#colima-}" --cpu 2 --memory 4
    fi
    local attempt
    for attempt in {1..120}; do
      docker info >/dev/null 2>&1 && break
      [[ "$attempt" != 120 ]] || die 'Docker did not become ready. Finish any macOS application prompts and rerun.'
      sleep 1
    done
  fi
  ensure_macos_compose
  command -v ollama >/dev/null 2>&1 || brew install ollama
  if ! curl --fail --silent --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null; then
    if brew list --formula ollama >/dev/null 2>&1; then
      OLLAMA_HOST=127.0.0.1:11434 brew services start ollama
    elif [[ -d /Applications/Ollama.app ]]; then
      open -a Ollama
    else
      local ollama_log_dir
      ollama_log_dir="$(mktemp -d "${TMPDIR:-/tmp}/dvaia-ollama.XXXXXXXX")"
      (umask 077; OLLAMA_HOST=127.0.0.1:11434 nohup ollama serve > "$ollama_log_dir/ollama.log" 2>&1 < /dev/null &)
      printf 'Local Ollama startup log: %s/ollama.log\n' "$ollama_log_dir"
    fi
  fi
}

ensure_macos_compose() {
  docker compose version >/dev/null 2>&1 && return 0
  if ! brew list --formula docker-compose >/dev/null 2>&1; then brew install docker-compose; fi

  # Owned-runner provisioning binds an exact daemon with `docker --host ...
  # compose`; a standalone docker-compose binary is not the same capability.
  # Homebrew installs the plugin in its prefix but Docker does not search that
  # directory by default. Expose it through the user's plugin directory without
  # rewriting an existing Docker config or replacing an existing plugin.
  local brew_prefix plugin_source plugin_root plugin_link
  brew_prefix="$(brew --prefix)"
  plugin_source="$brew_prefix/lib/docker/cli-plugins/docker-compose"
  [[ "$plugin_source" == /* && -x "$plugin_source" ]] || die 'Homebrew Docker Compose did not provide an executable CLI plugin.'
  plugin_root="${DOCKER_CONFIG:-$HOME/.docker}"
  [[ "$plugin_root" == /* ]] || die 'DOCKER_CONFIG must be an absolute path for supported setup.'
  plugin_link="$plugin_root/cli-plugins/docker-compose"
  if [[ -e "$plugin_link" || -L "$plugin_link" ]]; then
    [[ -L "$plugin_link" && "$(readlink "$plugin_link")" == "$plugin_source" ]] ||
      die 'An existing Docker Compose plugin is not usable; preserve it and repair Docker Compose before rerunning setup.'
  else
    (umask 077; mkdir -p "$plugin_root/cli-plugins"; ln -s "$plugin_source" "$plugin_link")
  fi
  docker compose version >/dev/null 2>&1 || die 'Docker Compose v2 is required by owned runner provisioning but the Docker CLI plugin is unavailable.'
}
