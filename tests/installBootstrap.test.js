'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const sourceRoot = path.resolve(__dirname, '..');
const bootstrapSource = path.join(sourceRoot, 'scripts/install/bootstrap-unix.sh');
const macSource = path.join(sourceRoot, 'scripts/install/macos-prerequisites.sh');
const linuxSource = path.join(sourceRoot, 'scripts/install/linux-prerequisites.sh');
const linuxWrapperSource = path.join(sourceRoot, 'scripts/install/Ubuntu/install-owasp-ai-goat-ubuntu.sh');
const runtimePolicySource = path.join(sourceRoot, 'scripts/install/runtime-version-policy.sh');

// Transform only fixture boundaries; never materialize production shell bodies.
function shellQuote(value) { return "'" + value.replaceAll("'", "'\\''") + "'"; }
function replaceExact(source, before, after, count = 1) {
  assert.equal(source.split(before).length - 1, count, `unexpected shell overlay count: ${before}`);
  return source.split(before).join(after);
}
function fixtureBody(root, kind) {
  const policy = 'source ' + shellQuote(runtimePolicySource);
  if (kind === 'wrapper') return replaceExact(fs.readFileSync(linuxWrapperSource, 'utf8'),
    'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"', 'ROOT=' + shellQuote(root));
  let body = fs.readFileSync(bootstrapSource, 'utf8');
  body = replaceExact(body, 'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"', 'ROOT=' + shellQuote(root));
  body = replaceExact(body, 'source "$ROOT/scripts/install/runtime-version-policy.sh"', policy);
  let mac = replaceExact(fs.readFileSync(macSource, 'utf8'), '/opt/homebrew /usr/local', '"$FAKE_BREW_PREFIX"', 2);
  let linux = fs.readFileSync(linuxSource, 'utf8');
  linux = replaceExact(linux, 'source "$ROOT/scripts/install/runtime-version-policy.sh"', policy);
  linux = replaceExact(linux, '/etc/os-release', '"$FAKE_OS_RELEASE"', 2);
  linux = replaceExact(linux, '/usr/local', '"$FAKE_USR_LOCAL"', 2);
  linux = replaceExact(linux, '/run/systemd/system', '"$FAKE_SYSTEMD_ROOT"', 3);
  linux = replaceExact(linux, '[[ -x /snap/bin/chromium ]]', '[[ -x "$FAKE_CHROMIUM" ]]');
  linux = replaceExact(linux, 'export PUPPETEER_EXECUTABLE_PATH=/snap/bin/chromium',
    'export PUPPETEER_EXECUTABLE_PATH="$FAKE_CHROMIUM"');
  body = replaceExact(body, 'source "$ROOT/scripts/install/macos-prerequisites.sh"', 'eval ' + shellQuote(mac));
  return replaceExact(body, 'source "$ROOT/scripts/install/linux-prerequisites.sh"', 'eval ' + shellQuote(linux));
}
function installDispatcher(root, bin) {
  const config = { bootstrapSource, macSource, linuxSource, linuxWrapperSource, runtimePolicySource };
  const body = `#!${process.execPath}\n'use strict';\nconst fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');\nconst {spawnSync}=require('node:child_process');\nconst {bootstrapSource,macSource,linuxSource,linuxWrapperSource,runtimePolicySource}=${JSON.stringify(config)};\n${shellQuote.toString()}\n${replaceExact.toString()}\n${fixtureBody.toString()}\nconst root=${JSON.stringify(root)},requested=process.argv[2];\nconst routes=new Map([[path.join(root,'scripts/install/Ubuntu/install-owasp-ai-goat-ubuntu.sh'),'wrapper'],[path.join(root,'scripts/install/bootstrap-unix.sh'),'bootstrap']]);\nassert.ok(routes.has(requested),'Unknown fixture bash route');\nconst result=spawnSync('/bin/bash',['-s','--',...process.argv.slice(3)],{input:fixtureBody(root,routes.get(requested)),env:process.env,stdio:['pipe','inherit','inherit']});\nif(result.error)throw result.error;process.exit(result.status===null?1:result.status);\n`;
  fs.writeFileSync(path.join(bin, 'bash'), body, { mode: 0o700 });
}
function invokeBootstrap(value, osName, args) {
  return spawnSync('/bin/bash', ['-s', '--', osName, ...args], {
    input: fixtureBody(value.root, 'bootstrap'), cwd: value.root, env: value.env, encoding: 'utf8', timeout: 10000,
  });
}

test('Linux installer pins the verified current Node release and its checksum manifest', () => {
  const source = fs.readFileSync(linuxSource, 'utf8');
  assert.match(source, /release="v\$\{OWASP_AI_GOAT_MINIMUM_NODE_VERSION\}"/);
  assert.match(source, /nodejs\.org\/dist\/\$\{release\}\/SHASUMS256\.txt/);
  assert.match(source, /sha256sum -c selected\.sha256/);
});

function fixture({ commands = [], osName = 'Darwin', withCurl = true,
  composePluginInstall = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-install-bootstrap-'));
  const scripts = path.join(root, 'scripts/install');
  const bin = path.join(root, 'fake-bin');
  const log = path.join(root, 'commands.log');
  const usrLocal = path.join(root, 'usr-local');
  const brewPrefix = path.join(root, 'fake-brew');
  fs.mkdirSync(scripts, { recursive: true });
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(usrLocal, { recursive: true });
  fs.mkdirSync(path.join(brewPrefix, 'bin'), { recursive: true });
  installDispatcher(root, bin);
  const write = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/bin/sh\n${body}\n`, { mode: 0o700 });
  write('uname', 'if [ "$1" = "-s" ]; then echo "${FAKE_OS}"; else echo x86_64; fi');
  write('node', 'if [ "$1" = "--version" ]; then echo v26.10.0; fi; exit 0');
  write('npm', 'if [ "$1" = "--version" ]; then echo 12.1.0; else echo "npm $*" >> "$FAKE_LOG"; fi; exit 0');
  write('git', 'exit 0');
  write('installed-node', 'if [ "$1" = "--version" ]; then echo v26.10.0; fi; exit 0');
  write('installed-npm', 'if [ "$1" = "--version" ]; then echo 12.1.0; else echo "npm $*" >> "$FAKE_LOG"; fi; exit 0');
  write('installed-git', 'exit 0');
  write('installed-ollama', 'exit 0');
  write('installed-colima', 'exit 0');
  write('brew', `echo "brew $*" >> "$FAKE_LOG"
if [ "${composePluginInstall ? '1' : '0'}" = 1 ]; then
  if [ "$1" = --prefix ]; then echo "$FAKE_BREW_PREFIX"; exit 0; fi
  if [ "$1" = list ] && [ "$3" = docker-compose ]; then [ -x "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-compose" ]; exit; fi
fi
if [ "$1" = install ] || [ "$1" = upgrade ]; then
  for package in "$@"; do case "$package" in
    node) cp "$FAKE_BIN/installed-node" "$FAKE_BIN/node"; cp "$FAKE_BIN/installed-node" "$FAKE_USR_LOCAL/node"; cp "$FAKE_BIN/installed-npm" "$FAKE_BIN/npm"; cp "$FAKE_BIN/installed-npm" "$FAKE_USR_LOCAL/npm"; chmod +x "$FAKE_BIN/node" "$FAKE_BIN/npm" "$FAKE_USR_LOCAL/node" "$FAKE_USR_LOCAL/npm" ;;
    git|ollama|colima) cp "$FAKE_BIN/installed-$package" "$FAKE_BIN/$package"; cp "$FAKE_BIN/installed-$package" "$FAKE_USR_LOCAL/$package"; chmod +x "$FAKE_BIN/$package" "$FAKE_USR_LOCAL/$package" ;;
    docker-compose) mkdir -p "$FAKE_BREW_PREFIX/lib/docker/cli-plugins"; printf '#!/bin/sh\\nexit 0\\n' > "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-compose"; chmod +x "$FAKE_BREW_PREFIX/lib/docker/cli-plugins/docker-compose" ;;
  esac; done
fi
exit 0`);
  write('xcode-select', 'exit 0');
  write('curl', withCurl ? 'exit 0' : 'out=""; previous=""; for arg in "$@"; do if [ "$previous" = "-o" ]; then out="$arg"; fi; previous="$arg"; done; if [ -n "$out" ]; then printf "#!/bin/sh\\nexit 7\\n" > "$out"; chmod +x "$out"; fi; exit 0');
  write('docker', composePluginInstall
    ? '[ "$1" != compose ] || [ -x "$HOME/.docker/cli-plugins/docker-compose" ]'
    : 'exit 0');
  if (composePluginInstall) write('docker-compose', 'exit 0');
  write('ollama', 'exit 0');
  for (const command of commands) fs.rmSync(path.join(bin, command), { force: true });
  return { root, bin, log, brewPrefix, env: {
    PATH: `${bin}:/usr/bin:/bin`, FAKE_BIN: bin, FAKE_USR_LOCAL: usrLocal, FAKE_BREW_PREFIX: brewPrefix, FAKE_LOG: log, FAKE_OS: osName,
    PG_ADMIN_DATABASE_URL: 'postgresql://fixture.invalid/admin', HOME: root, TMPDIR: root,
  } };
}

function runFixture(value, args = []) { return invokeBootstrap(value, 'Darwin', args); }

function cleanup(value) { fs.rmSync(value.root, { recursive: true, force: true }); }

test('Unix opt-in plans accept Analytics and combined System options without executing setup',()=>{
 for(const osName of ['Darwin','Linux']){
  const value=fixture({osName});try{
   const result=invokeBootstrap(value,osName,['--plan','--owned-analytics','--owned-system','--qualified-secureshop']);
   assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/Owned Analytics opt-in/);assert.match(result.stdout,/ARM64 only/);assert.equal(fs.existsSync(value.log),false);
   const bad=invokeBootstrap(value,osName,['--plan','--qualified-secureshop']);
   assert.equal(bad.status,1);assert.match(bad.stderr,/requires.*together/);assert.equal(fs.existsSync(value.log),false);
  }finally{cleanup(value);}
 }
});

test('Unix policy-renderer flags are paired, nonmutating in plan, and forwarded exactly',()=>{
 for(const osName of ['Darwin','Linux']){
  const value=osName==='Linux'?linuxFixture():fixture({osName});
  const invoke=osName==='Linux'?(args=>runLinuxFixture(value,args)):(args=>invokeBootstrap(value,osName,args));
  try{
   const plan=invoke(['--plan','--owned-policy-renderer','--enable-owned-policy-renderer']);
   assert.equal(plan.status,0,plan.stderr);assert.match(plan.stdout,/ARM64 macOS\/Linux only/);assert.match(plan.stdout,/pinned Node base image and Debian build packages/);assert.equal(fs.existsSync(value.log),false);
   const preparePlan=invoke(['--plan','--owned-policy-renderer']);
   assert.equal(preparePlan.status,0,preparePlan.stderr);assert.match(preparePlan.stdout,/preparation preserves an existing disabled preference/);assert.equal(fs.existsSync(value.log),false);
   const bad=invoke(['--plan','--enable-owned-policy-renderer']);
   assert.equal(bad.status,1);assert.match(bad.stderr,/requires --owned-policy-renderer/);assert.equal(fs.existsSync(value.log),false);
   const prepare=invoke(['--owned-policy-renderer']);
   assert.equal(prepare.status,0,prepare.stderr);const prepareLog=fs.readFileSync(value.log,'utf8').trim().split('\n');assert(prepareLog.includes('npm run setup -- --owned-policy-renderer'));
   const run=invoke(['--owned-policy-renderer','--enable-owned-policy-renderer']);
   assert.equal(run.status,0,run.stderr);const log=fs.readFileSync(value.log,'utf8');assert.match(log,/npm run setup -- --owned-policy-renderer --enable-owned-policy-renderer/);
  }finally{cleanup(value);}
 }
});

function linuxFixture({ distro = 'ubuntu', arch = 'x86_64', aptFails = false, missingNpm = false,
  refreshDockerGroup = false, legacyComposeOnly = false, composePluginInstall = false,
  snapInstalled = false, snapInstallFails = false } = {}) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'owasp-ai-goat-install-linux-'));
  const scripts = path.join(root, 'scripts/install');
  const bin = path.join(root, 'fake-bin');
  const log = path.join(root, 'commands.log');
  const osRelease = path.join(root, 'os-release');
  const usrLocal = path.join(root, 'usr-local');
  const systemdRoot = path.join(root, 'run/systemd/system');
  const chromium = path.join(root, 'snap/bin/chromium');
  const snapMarker = path.join(root, 'chromium-installed');
  fs.mkdirSync(scripts, { recursive: true });
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(path.join(usrLocal, 'bin'), { recursive: true });
  fs.mkdirSync(systemdRoot, { recursive: true });
  fs.mkdirSync(path.dirname(chromium), { recursive: true });
  if (snapInstalled) {
    fs.writeFileSync(snapMarker, 'installed');
    fs.writeFileSync(chromium, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
  }
  fs.writeFileSync(osRelease, `ID=${distro}\n`);
  const write = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/bin/sh\n${body}\n`, { mode: 0o700 });
  installDispatcher(root, bin);
  write('uname', 'case "$1" in -s) echo Linux ;; -m) echo "$FAKE_ARCH" ;; *) exit 1 ;; esac');
  write('systemctl', 'echo "systemctl $*" >> "$FAKE_LOG"; exit 0');
  write('snap', `
echo "snap $*" >> "$FAKE_LOG"
case "$1" in
  version) exit 0 ;;
  list) [ "$2" = chromium ] && [ -f "$FAKE_SNAP_MARKER" ] ;;
  install)
    [ "$2" = chromium ] || exit 3
    [ "$FAKE_SNAP_INSTALL_FAIL" != 1 ] || exit 42
    : > "$FAKE_SNAP_MARKER"
    printf '#!/bin/sh\\nexit 0\\n' > "$FAKE_CHROMIUM"
    chmod +x "$FAKE_CHROMIUM" ;;
  *) exit 3 ;;
esac`);
  write('id', 'case "$1" in -u) echo 1000 ;; -un) echo fixtureuser ;; *) exit 1 ;; esac');
  write('sudo', refreshDockerGroup ? `
echo "sudo $*" >> "$FAKE_LOG"
case "$1" in
  --preserve-env=*)
    keep=",\${1#*=},"
    shift
    [ "$1" = --user ] && shift 2
    [ "$1" = -- ] && shift
    for name in XENOVA_CACHE HF_HUB_OFFLINE TRANSFORMERS_OFFLINE PG_ADMIN_DATABASE_URL PG_TLS DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG IPI_EMAIL_PROVIDER MCP_SIDECARS_AUTOSTART SANDBOX_RUNNER_URL TEAM_ID ECS_CONTAINER_METADATA_URI_V4 LEGACY_SENSITIVE_FILES_ROOT OWASP_AI_GOAT_APP_DATA_ROOT NODE_USE_SYSTEM_CA NODE_EXTRA_CA_CERTS SSL_CERT_FILE SSL_CERT_DIR NODE_OPTIONS npm_config_cafile NPM_CONFIG_CAFILE npm_config_ca NPM_CONFIG_CA UNLISTED_INSTALL_SENTINEL; do
      case "$keep" in
        *,"$name",*) ;;
        *) unset "$name" ;;
      esac
    done
    exec "$@"
    ;;
  *) FAKE_SUDO_ROOT=1 "$@" ;;
esac` : 'echo "sudo $*" >> "$FAKE_LOG"; "$@"');
  write('node', 'if [ "$1" = "--version" ]; then echo "node --version" >> "$FAKE_LOG"; echo v26.10.0; fi; exit 0');
  write('npm', refreshDockerGroup
    ? `if [ "$1" = "--version" ]; then echo 12.1.0; else
      echo "npm $*" >> "$FAKE_LOG"
      case "\${XENOVA_CACHE-}" in */existing-model-cache) ;; *) exit 23 ;; esac
      [ "\${IPI_EMAIL_PROVIDER-}" = gmail ] || exit 23
      [ "\${MCP_SIDECARS_AUTOSTART-}" = 0 ] || exit 23
      [ "\${SANDBOX_RUNNER_URL-}" = https://sandbox.example.invalid ] || exit 23
      [ "\${DOCKER_CONTEXT-}" = fixture-context ] || exit 23
      case "\${DOCKER_CONFIG-}" in */docker-config) ;; *) exit 23 ;; esac
      case "\${NODE_EXTRA_CA_CERTS-}" in */private-ca.pem) ;; *) exit 23 ;; esac
      [ -z "\${UNLISTED_INSTALL_SENTINEL-}" ] || exit 23
      echo "embedding-env XENOVA_CACHE=\${XENOVA_CACHE-} HF_HUB_OFFLINE=\${HF_HUB_OFFLINE-} TRANSFORMERS_OFFLINE=\${TRANSFORMERS_OFFLINE-} UNLISTED_INSTALL_SENTINEL=\${UNLISTED_INSTALL_SENTINEL-}" >> "$FAKE_LOG"
      echo preserved-setup-inputs >> "$FAKE_LOG"
    fi; exit 0`
    : 'if [ "$1" = "--version" ]; then echo 12.1.0; else echo "npm $*" >> "$FAKE_LOG"; fi; exit 0');
  write('installed-npm', 'if [ "$1" = "--version" ]; then echo "npm --version" >> "$FAKE_LOG"; echo 12.1.0; else echo "npm $*" >> "$FAKE_LOG"; fi; exit 0');
  write('git', 'exit 0');
  write('ollama', 'if [ "$1" = list ]; then exit 0; fi; exit 0');
  write('curl', 'echo "curl $*" >> "$FAKE_LOG"; out=""; previous=""; for arg in "$@"; do if [ "$previous" = "-o" ]; then out="$arg"; fi; previous="$arg"; done; if [ -n "$out" ]; then case "$out" in *SHASUMS256.txt) printf "fixture  node-v26.10.0-linux-x64.tar.xz\\n" > "$out" ;; *) : > "$out" ;; esac; fi; exit 0');
  write('apt-get', aptFails ? 'echo "apt-get $*" >> "$FAKE_LOG"; exit 9'
    : composePluginInstall
      ? 'echo "apt-get $*" >> "$FAKE_LOG"; case " $* " in *" docker-compose-plugin "*) : > "$FAKE_COMPOSE_MARKER" ;; esac; exit 0'
      : 'echo "apt-get $*" >> "$FAKE_LOG"; exit 0');
  write('dpkg-query', 'exit 1');
  write('apt-cache', composePluginInstall
    ? '[ "$1" = show ] && [ "$2" = docker-compose-plugin ]'
    : 'exit 1');
  write('docker', refreshDockerGroup
    ? 'echo "docker $*" >> "$FAKE_LOG"; if [ "$1" = info ] && [ "${FAKE_SUDO_ROOT:-0}" != 1 ] && [ "${OWASP_AI_GOAT_INSTALL_GROUP_REFRESHED:-0}" != 1 ]; then exit 1; fi; exit 0'
    : legacyComposeOnly
      ? 'echo "docker $*" >> "$FAKE_LOG"; [ "$1" = compose ] && exit 9; exit 0'
      : composePluginInstall
        ? 'echo "docker $*" >> "$FAKE_LOG"; if [ "$1" = compose ]; then [ -f "$FAKE_COMPOSE_MARKER" ]; else exit 0; fi'
      : 'echo "docker $*" >> "$FAKE_LOG"; exit 0');
  if (legacyComposeOnly) write('docker-compose', 'exit 0');
  write('service', 'echo "service $*" >> "$FAKE_LOG"; exit 0');
  write('usermod', 'echo "usermod $*" >> "$FAKE_LOG"; exit 0');
  write('sha256sum', 'echo "sha256sum $*" >> "$FAKE_LOG"; exit 0');
  write('tar', 'echo "tar $*" >> "$FAKE_LOG"; cp "$FAKE_BIN/installed-npm" "$FAKE_USR_LOCAL/bin/npm"; chmod +x "$FAKE_USR_LOCAL/bin/npm"; exit 0');
  if (missingNpm) {
    fs.rmSync(path.join(bin, 'npm'));
    const hostPath = process.env.PATH || '';
    for (const name of ['awk', 'chmod', 'cp', 'dirname', 'env', 'grep', 'mktemp', 'rm']) {
      const source = hostPath.split(path.delimiter).map(directory => path.join(directory, name)).find(candidate => {
        try { fs.accessSync(candidate, fs.constants.X_OK); return true; } catch { return false; }
      });
      assert.ok(source, `required host test utility is unavailable: ${name}`);
      if (name === 'mktemp') {
        // macOS mktemp -d can choose its per-user default rather than TMPDIR.
        // Keep the Linux installer fixture's temporary data inside its owned root.
        write(name, `if [ "$#" = 1 ] && [ "$1" = -d ]; then
  exec ${shellQuote(source)} -d "$TMPDIR/node-download.XXXXXXXX"
fi
exec ${shellQuote(source)} "$@"`);
      } else fs.symlinkSync(source, path.join(bin, name));
    }
  }
  return {
    root,
    log,
    env: {
      PATH: missingNpm ? bin : `${bin}:/usr/bin:/bin`, FAKE_BIN: bin, FAKE_USR_LOCAL: usrLocal,
      FAKE_LOG: log, FAKE_OS_RELEASE: osRelease, FAKE_ARCH: arch,
      FAKE_SYSTEMD_ROOT: systemdRoot, FAKE_CHROMIUM: chromium,
      FAKE_SNAP_MARKER: snapMarker, FAKE_SNAP_INSTALL_FAIL: snapInstallFails ? '1' : '0',
      FAKE_COMPOSE_MARKER: path.join(root, 'compose-v2-ready'),
      PG_ADMIN_DATABASE_URL: 'postgresql://fixture.invalid/admin', HOME: root, TMPDIR: root,
    },
  };
}

function runLinuxFixture(value, args = []) { return invokeBootstrap(value, 'Linux', args); }

test('plan is connection-free and performs no prerequisite or setup commands', () => {
  const value = fixture({ commands: ['node', 'npm', 'git', 'brew', 'ollama'] });
  try {
    const result = runFixture(value, ['--plan']);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Fresh setup plan/);
    assert.equal(fs.existsSync(value.log), false);
  } finally { cleanup(value); }
});

test('existing .env is rejected before package or service commands', () => {
  const value = fixture();
  try {
    fs.writeFileSync(path.join(value.root, '.env'), 'fixture=private\n', { mode: 0o600 });
    const result = runFixture(value);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /An \.env already exists/);
    assert.equal(fs.existsSync(value.log), false);
  } finally { cleanup(value); }
});
test('additive upgrade preserves existing env and skips prerequisite installation', () => {
  const value = fixture({ commands: ['git', 'brew', 'ollama'] });
  try {
    fs.writeFileSync(path.join(value.root, '.env'), 'PRIVATE=value\n', { mode: 0o600 });
    const result = runFixture(value, ['--upgrade']);
    assert.equal(result.status, 0, result.stderr);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /npm run setup -- --upgrade/);
    assert.doesNotMatch(log, /brew|ollama/);
    assert.equal(fs.readFileSync(path.join(value.root, '.env'), 'utf8'), 'PRIVATE=value\n');
  } finally { cleanup(value); }
});
test('additive upgrade plan and missing-env failure perform no commands', () => {
  const value = fixture();
  try {
    const plan = runFixture(value, ['--upgrade', '--plan']);
    assert.equal(plan.status, 0, plan.stderr);
    assert.match(plan.stdout, /Additive upgrade plan/);
    assert.equal(fs.existsSync(value.log), false);
    const missing = runFixture(value, ['--upgrade']);
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /requires the existing private \.env/);
    assert.equal(fs.existsSync(value.log), false);
  } finally { cleanup(value); }
});

test('unsupported OS is rejected before prerequisites', () => {
  const value = fixture({ osName: 'Linux' });
  try {
    const result = runFixture(value);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /requires Darwin/);
    assert.equal(fs.existsSync(value.log), false);
  } finally { cleanup(value); }
});

test('missing Node is installed through mocked Homebrew and setup delegates', () => {
  const value = fixture({ commands: ['node', 'npm', 'git', 'ollama'] });
  try {
    const result = runFixture(value, ['--no-install']);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}\n${fs.existsSync(value.log) ? fs.readFileSync(value.log, 'utf8') : '(no command log)'}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /brew (?:install|upgrade) node/);
    assert.match(log, /brew install ollama/);
    assert.match(log, /npm run setup -- --no-install/);
  } finally { cleanup(value); }
});

test('macOS fresh setup rechecks its selected Colima context, not an unavailable default context', () => {
  const value = fixture();
  delete value.env.PG_ADMIN_DATABASE_URL;
  fs.writeFileSync(path.join(value.bin, 'docker'), `#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
if [ "$1" = --context ] && [ "$2" = colima-default ] && [ "$3" = info ]; then exit 0; fi
if [ "$1" = info ]; then exit 9; fi
exit 0
`, { mode: 0o700 });
  try {
    const result = runFixture(value, ['--no-install']);
    assert.equal(result.status, 0, result.stderr);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.equal((log.match(/^docker --context colima-default info$/gm) || []).length, 2);
    assert.doesNotMatch(log, /^docker info$/m);
    assert.match(log, /^npm run setup -- --no-install$/m);
  } finally { cleanup(value); }
});

test('Linux fresh setup retains its ordinary Docker availability check', () => {
  const value = linuxFixture();
  delete value.env.PG_ADMIN_DATABASE_URL;
  try {
    const result = runLinuxFixture(value, ['--no-install']);
    assert.equal(result.status, 0, result.stderr);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /^docker info$/m);
    assert.doesNotMatch(log, /^docker --context /m);
    assert.match(log, /^npm run setup -- --no-install$/m);
  } finally { cleanup(value); }
});

test('prerequisite command failures return nonzero without invoking setup', () => {
  const value = fixture({ commands: ['brew'], withCurl: false });
  try {
    const result = runFixture(value);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /failed|unavailable|required/i);
    assert.doesNotMatch(fs.existsSync(value.log) ? fs.readFileSync(value.log, 'utf8') : '', /npm run setup/);
  } finally { cleanup(value); }
});

test('macOS installs and exposes the Compose v2 plugin even when a standalone binary exists', () => {
  const value = fixture({ composePluginInstall: true });
  try {
    const result = runFixture(value, ['--no-install']);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /^brew install docker-compose$/m);
    assert.match(log, /npm run setup -- --no-install/);
    const link = path.join(value.root, '.docker/cli-plugins/docker-compose');
    assert.equal(fs.lstatSync(link).isSymbolicLink(), true);
    assert.equal(fs.realpathSync(link), fs.realpathSync(path.join(value.brewPrefix, 'lib/docker/cli-plugins/docker-compose')));
  } finally { cleanup(value); }
});


test('Linux preinstalled runtime runs mocked apt provisioning and delegates setup', () => {
  const value = linuxFixture();
  try {
    const result = runLinuxFixture(value, ['--no-install']);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}\n${fs.existsSync(value.log) ? fs.readFileSync(value.log, 'utf8') : '(no command log)'}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /apt-get update/);
    assert.match(log, /docker info/);
    assert.match(log, /docker compose version/);
    assert.match(log, /apt-get install -y --no-install-recommends/);
    assert.match(log, /npm run setup -- --no-install/);
  } finally { cleanup(value); }
});

test('Linux Docker group refresh preserves reviewed setup inputs without retaining unrelated values', () => {
  const value = linuxFixture({ refreshDockerGroup: true });
  const cache = path.join(value.root, 'existing-model-cache');
  value.env.XENOVA_CACHE = cache;
  value.env.HF_HUB_OFFLINE = '1';
  value.env.TRANSFORMERS_OFFLINE = '1';
  value.env.IPI_EMAIL_PROVIDER = 'gmail';
  value.env.MCP_SIDECARS_AUTOSTART = '0';
  value.env.SANDBOX_RUNNER_URL = 'https://sandbox.example.invalid';
  value.env.DOCKER_CONTEXT = 'fixture-context';
  value.env.DOCKER_CONFIG = path.join(value.root, 'docker-config');
  value.env.NODE_EXTRA_CA_CERTS = path.join(value.root, 'private-ca.pem');
  value.env.UNLISTED_INSTALL_SENTINEL = 'must-not-survive';
  try {
    const result = runLinuxFixture(value, ['--no-install']);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}\n${fs.existsSync(value.log) ? fs.readFileSync(value.log, 'utf8') : '(no command log)'}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.equal((log.match(/^usermod -aG docker fixtureuser$/gm) || []).length, 1,
      'Docker group membership must be changed exactly once before the refreshed-user reexec');
    assert.equal((log.match(/^sudo --preserve-env=/gm) || []).length, 1,
      'the installer must perform exactly one refreshed-user reexec');
    assert.match(log, new RegExp(`^embedding-env XENOVA_CACHE=${cache.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 UNLISTED_INSTALL_SENTINEL=$`, 'm'));
    assert.match(log, /^preserved-setup-inputs$/m);
    assert.doesNotMatch(log, /postgresql:\/\/fixture\.invalid\/admin|private-ca\.pem/,
      'preserved configuration values must not be copied into command diagnostics');
    assert.equal(fs.existsSync(path.join(value.root, '.env')), false);
  } finally { cleanup(value); }
});

test('Linux rejects standalone legacy Compose before setup because owned provisioning requires Compose v2', () => {
  const value = linuxFixture({ legacyComposeOnly: true });
  try {
    const result = runLinuxFixture(value, ['--no-install']);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Compose v2 is required by owned runner provisioning/);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /^docker compose version$/m);
    assert.doesNotMatch(log, /npm run setup/);
  } finally { cleanup(value); }
});

test('Linux installs an available Compose v2 plugin before delegating setup', () => {
  const value = linuxFixture({ composePluginInstall: true });
  try {
    const result = runLinuxFixture(value, ['--no-install']);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /apt-get install -y --no-install-recommends docker-compose-plugin/);
    assert.match(log, /npm run setup -- --no-install/);
  } finally { cleanup(value); }
});

test('Ubuntu ARM64 Chromium installation is repeatable when Snap is already installed', () => {
  const value = linuxFixture({ arch: 'aarch64' });
  try {
    const first = runLinuxFixture(value, ['--no-install']);
    assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);
    assert.equal(fs.existsSync(value.env.FAKE_CHROMIUM), true);
    const second = runLinuxFixture(value, ['--no-install']);
    assert.equal(second.status, 0, `${second.stdout}\n${second.stderr}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.equal((log.match(/^snap install chromium$/gm) || []).length, 1);
    assert.equal((log.match(/^snap list chromium$/gm) || []).length, 2);
    assert.equal((log.match(/^npm run setup -- --no-install$/gm) || []).length, 2);
  } finally { cleanup(value); }
});

test('Ubuntu ARM64 Chromium failures remain fatal, including a missing executable after Snap reports installed', () => {
  for (const options of [{ snapInstallFails: true }, { snapInstalled: true }]) {
    const value = linuxFixture({ arch: 'aarch64', ...options });
    try {
      if (options.snapInstalled) fs.unlinkSync(value.env.FAKE_CHROMIUM);
      const result = runLinuxFixture(value, ['--no-install']);
      assert.notEqual(result.status, 0);
      const log = fs.readFileSync(value.log, 'utf8');
      assert.doesNotMatch(log, /npm run setup/);
      assert.equal((log.match(/^snap install chromium$/gm) || []).length, options.snapInstalled ? 0 : 1);
      if (options.snapInstalled) assert.match(result.stderr, /did not provide/);
    } finally { cleanup(value); }
  }
});

test('Linux reinstalls the verified Node distribution when node exists but npm is absent', () => {
  const value = linuxFixture({ missingNpm: true });
  try {
    const precondition = spawnSync('/bin/bash', ['-c', 'command -v node >/dev/null && ! command -v npm >/dev/null'], {
      cwd: value.root, env: value.env, encoding: 'utf8', timeout: 1000,
    });
    assert.equal(precondition.status, 0, 'fixture must begin with a valid node command and no npm command');
    const result = runLinuxFixture(value, ['--no-install']);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}\n${fs.existsSync(value.log) ? fs.readFileSync(value.log, 'utf8') : '(no command log)'}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /nodejs\.org\/dist\/v26\.10\.0\/node-v26\.10\.0-linux-x64\.tar\.xz/);
    assert.match(log, /nodejs\.org\/dist\/v26\.10\.0\/SHASUMS256\.txt/);
    assert.match(log, /sha256sum -c selected\.sha256/);
    assert.ok(log.includes(`-o ${value.root}/node-download.`), 'download must use the owned fixture directory');
    assert.match(log, /tar -xJf .*node-v26\.10\.0-linux-x64\.tar\.xz -C .*usr-local --strip-components=1 --no-same-owner/);
    const installedAt = log.indexOf('tar -xJf');
    assert.ok(log.indexOf('node --version', installedAt) > installedAt,
      'the installed Node command must be revalidated after extraction');
    assert.ok(log.indexOf('npm --version', installedAt) > installedAt,
      'the installed npm command must be revalidated after extraction');
    assert.ok(installedAt < log.indexOf('npm run setup -- --no-install'),
      'verified Node/npm provisioning must complete before npm runs setup');
    assert.doesNotMatch(log, /npm install --global/);
  } finally { cleanup(value); }
});

test('Linux unsupported distro fails before apt or setup', () => {
  const value = linuxFixture({ distro: 'arch' });
  try {
    const result = runLinuxFixture(value);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Ubuntu and Debian only/);
    assert.doesNotMatch(fs.existsSync(value.log) ? fs.readFileSync(value.log, 'utf8') : '', /apt-get|npm run setup/);
  } finally { cleanup(value); }
});

test('Linux apt failure is nonzero and never delegates setup', () => {
  const value = linuxFixture({ aptFails: true });
  try {
    const result = runLinuxFixture(value);
    assert.notEqual(result.status, 0);
    const log = fs.existsSync(value.log) ? fs.readFileSync(value.log, 'utf8') : '';
    assert.match(log, /apt-get update/);
    assert.doesNotMatch(log, /npm run setup/);
  } finally { cleanup(value); }
});


test('macOS upgrades separately outdated npm without replacing a qualified Node installation', () => {
  const value = fixture();
  try {
    fs.writeFileSync(path.join(value.bin, 'npm'), `#!/bin/sh
if [ "$1" = --version ]; then echo 11.19.1; exit 0; fi
echo "npm $*" >> "$FAKE_LOG"
if [ "$1" = install ] && [ "$2" = --global ] && [ "$3" = npm@12.1.0 ]; then
  cp "$FAKE_BIN/installed-npm" "$FAKE_BIN/npm"
  exit 0
fi
exit 8
`, { mode: 0o755 });
    const result = runFixture(value, ['--no-install']);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.doesNotMatch(log, /brew (?:install|upgrade) node/);
    assert.match(log, /npm install --global npm@12\.1\.0/);
    assert.match(log, /npm run setup -- --no-install/);
  } finally { cleanup(value); }
});


test('both Unix wrappers accept Pricing plan and forward additive upgrade without changing configuration', () => {
  for (const osName of ['Darwin', 'Linux']) {
    const value = fixture({ osName });
    const invoke = args => invokeBootstrap(value, osName, args);
    try {
      const plan = invoke(['--plan', '--owned-pricing']);
      assert.equal(plan.status, 0, plan.stderr);
      assert.match(plan.stdout, /Owned Pricing opt-in/);
      assert.equal(fs.existsSync(value.log), false);
      const unknown = invoke(['--plan', '--owned-pricing-unknown']);
      assert.notEqual(unknown.status, 0);
      assert.match(unknown.stderr, /Unknown installation argument/);
      assert.equal(fs.existsSync(value.log), false);
      const envPath = path.join(value.root, '.env');
      fs.writeFileSync(envPath, 'PRIVATE=preserved\n', { mode: 0o600 });
      const upgrade = invoke(['--upgrade', '--owned-pricing', '--no-install']);
      assert.equal(upgrade.status, 0, upgrade.stderr);
      assert.equal(fs.readFileSync(value.log, 'utf8').trim(), 'npm run setup -- --upgrade --owned-pricing --no-install');
      assert.equal(fs.readFileSync(envPath, 'utf8'), 'PRIVATE=preserved\n');
    } finally { cleanup(value); }
  }
});

test('repair plan is nonmutating and existing-install repair prepares prerequisites before setup', () => {
  const value = fixture({ commands: ['ollama'] });
  try {
    const plan = runFixture(value, ['--plan', '--repair']);
    assert.equal(plan.status, 0, plan.stderr);
    assert.match(plan.stdout, /Existing-install repair plan/);
    assert.doesNotMatch(plan.stdout, /No packages, model, browser/);
    assert.equal(fs.existsSync(value.log), false);

    const missing = runFixture(value, ['--repair', '--no-install']);
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /requires the existing private \.env/);
    assert.equal(fs.existsSync(value.log), false);

    const envPath = path.join(value.root, '.env');
    fs.writeFileSync(envPath, 'PRIVATE=preserved\n', { mode: 0o600 });
    fs.writeFileSync(path.join(value.bin, 'colima'), '#!/bin/sh\necho "colima $*" >> "$FAKE_LOG"\nexit 0\n', { mode: 0o700 });
    fs.writeFileSync(path.join(value.bin, 'curl'), '#!/bin/sh\necho "curl $*" >> "$FAKE_LOG"\ncount_file="$FAKE_BIN/curl-count"\ncount=0\n[ ! -f "$count_file" ] || count="$(cat "$count_file")"\ncount=$((count + 1))\necho "$count" > "$count_file"\n[ "$count" -ge 2 ]\n', { mode: 0o700 });
    const repaired = runFixture(value, ['--repair', '--no-install']);
    assert.equal(repaired.status, 0, repaired.stderr);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.match(log, /brew install ollama/);
    assert.equal((log.match(/^curl /gm) || []).length, 2, 'repair waits for Ollama after service startup');
    assert.doesNotMatch(log, /^colima start /m, 'repair must not start a different Colima profile');
    assert.match(log, /npm run setup -- --repair --no-install/);
    assert.equal(fs.readFileSync(envPath, 'utf8'), 'PRIVATE=preserved\n');
  } finally { cleanup(value); }
});

test('macOS repair refuses a stopped Docker daemon without starting another profile', () => {
  const value = fixture();
  try {
    fs.writeFileSync(path.join(value.root, '.env'), 'PRIVATE=preserved\n', { mode: 0o600 });
    fs.writeFileSync(path.join(value.bin, 'docker'), '#!/bin/sh\necho "docker $*" >> "$FAKE_LOG"\n[ "$1" != info ]\n', { mode: 0o700 });
    fs.writeFileSync(path.join(value.bin, 'colima'), '#!/bin/sh\necho "colima $*" >> "$FAKE_LOG"\nexit 0\n', { mode: 0o700 });
    const result = runFixture(value, ['--repair', '--no-install']);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /previously bound local Docker daemon/);
    const log = fs.readFileSync(value.log, 'utf8');
    assert.doesNotMatch(log, /^colima start /m);
    assert.doesNotMatch(log, /npm run setup/);
  } finally { cleanup(value); }
});


test('Unix MCP registry flags preserve explicit enablement and connection-free plans', () => {
  for (const osName of ['Darwin', 'Linux']) {
    const value = fixture({ osName });
    try {
      for (const flag of ['--owned-mcp-registry', '--enable-owned-mcp-registry']) {
        const result = invokeBootstrap(value, osName, ['--plan', flag]);
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /Plan performs no build, provisioning or activation/);
        assert.match(result.stdout, /Linux AMD64 remains unqualified/);
        assert.match(result.stdout, flag === '--owned-mcp-registry'
          ? /preparation preserves existing disabled preferences; overriding those preferences requires --enable-owned-mcp-registry\. Fresh requested setup may activate after prerequisite and readiness checks/
          : /explicit enablement: enables only after prerequisite and readiness checks/);
        assert.equal(fs.existsSync(value.log), false);
      }
      const invalid = invokeBootstrap(value, osName, ['--plan', '--owned-mcp-registry', '--qualified-secureshop']);
      assert.equal(invalid.status, 1);
      assert.match(invalid.stderr, /requires.*together/);
      const unknown = invokeBootstrap(value, osName, ['--plan', '--enable-owned-mcp-registry-typo']);
      assert.equal(unknown.status, 1);
      assert.match(unknown.stderr, /Unknown installation argument/);
      assert.equal(fs.existsSync(value.log), false);
    } finally { cleanup(value); }
  }
});

test('Unix MCP registry upgrade forwards exact flags without implicit activation', () => {
  for (const osName of ['Darwin', 'Linux']) {
    for (const flags of [[], ['--owned-mcp-registry'], ['--enable-owned-mcp-registry'], ['--owned-mcp-registry', '--enable-owned-mcp-registry']]) {
      const value = fixture({ osName, commands: ['git', 'brew', 'ollama'] });
      try {
        const args = ['--upgrade', '--no-install', ...flags];
        const missing = invokeBootstrap(value, osName, args);
        assert.equal(missing.status, 1);
        assert.match(missing.stderr, /requires the existing private/);
        assert.equal(fs.existsSync(value.log), false);
        fs.writeFileSync(path.join(value.root, '.env'), 'SYNTHETIC=unchanged\n', { mode: 0o600 });
        const result = invokeBootstrap(value, osName, args);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(fs.readFileSync(value.log, 'utf8'), `npm run setup -- ${args.join(' ')}\n`);
        assert.equal(fs.readFileSync(path.join(value.root, '.env'), 'utf8'), 'SYNTHETIC=unchanged\n');
      } finally { cleanup(value); }
    }
  }
});
