'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');
const unixInstallers = [
  'scripts/install/Mac/install-macos.sh',
  'scripts/install/Ubuntu/install-owasp-ai-goat-ubuntu.sh',
];
const unixBootstrap = read('scripts/install/bootstrap-unix.sh');
const macPrerequisites = read('scripts/install/macos-prerequisites.sh');
const linuxPrerequisites = read('scripts/install/linux-prerequisites.sh');

test('OS installers delegate fresh setup while preserving the PostgreSQL-only path', () => {
  for (const relative of unixInstallers) {
    const source = read(relative);
    assert.match(unixBootstrap, /npm run setup/);
    assert.match(source, /bootstrap-unix\.sh/, relative);
    assert.match(unixBootstrap, /PG_ADMIN_DATABASE_URL/);
    assert.match(unixBootstrap, /macos-prerequisites\.sh|linux-prerequisites\.sh/);
    assert.match(unixBootstrap, /--owned-policy-renderer/);
    assert.match(unixBootstrap, /--enable-owned-policy-renderer requires --owned-policy-renderer/);
    assert.match(macPrerequisites, /brew\s+install/);
    assert.match(linuxPrerequisites, /apt-get/);
    assert.match(unixBootstrap, /An \.env already exists\. Fresh setup will not overwrite it/);
    assert.match(unixBootstrap, /Upgrade|UPGRADE|upgrade/, relative);
    assert.doesNotMatch(source, /sqlite|\.db\*?|initialize-db|deploy-fresh/i, relative);
  }
});

test('owned System plan describes profile preparation without performing setup',
  {skip: !['darwin','linux'].includes(process.platform)}, () => {
  const platform = process.platform === 'darwin' ? 'Mac/install-macos.sh' : 'Linux/install-linux.sh';
  const result = spawnSync('bash', [path.join(root, 'scripts/install', platform), '--plan', '--owned-system'], {
    cwd:root, encoding:'utf8', env:process.env,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /prepares a missing exact sandbox profile/);
  assert.match(result.stdout, /Plan performs no installation or activation/);
  assert.doesNotMatch(result.stdout, /prerequisites are not automatically established/);
});

test('native Windows install and repair use qualified handoff while plans require no Node', () => {
  const source = read('scripts/install/Windows/install-windows.ps1');
  assert.match(source, /\[switch\]\$Plan/);
  assert.match(source, /\[switch\]\$Repair/);
  assert.match(source, /\[switch\]\$Upgrade/);
  assert.match(source, /if \(\$Plan\) \{/);
  assert.match(source, /did not require Node\.js/);
  assert.match(source, /Join-Path \$PSScriptRoot 'wrapper-handoff\.ps1'/);
  assert.match(source, /-CompositionReady \$true/);
  assert.match(source, /WINDOWS_HOST_PREFLIGHT_DENIED/);
  assert.doesNotMatch(source, /&\s*(?:npm|docker|node|winget)|Start-Process|Invoke-WebRequest|\.env['"]\s*,/i);
  assert.ok(source.indexOf('if ($Plan)') < source.indexOf("throw 'WINDOWS_HOST_PREFLIGHT_DENIED"));
});

test('Windows PowerShell plan runs without Node and performs no Execute operations', { skip: process.platform !== 'win32' }, () => {
  const shell = path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const installer = path.join(root, 'scripts/install/Windows/install-windows.ps1');
  const startup = path.join(root, 'scripts/install/Windows/start_all.ps1');
  const noNodeEnv = { ...process.env, PATH: path.join(os.tmpdir(), 'owasp-ai-goat-empty-path') };
  const run = (script, args) => spawnSync(shell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args],
    { cwd: os.tmpdir(), env: noNodeEnv, encoding: 'utf8', windowsHide: true });
  for (const [script, args] of [[installer, ['-Plan', '-Repair']], [startup, ['-Plan', '-InitDb']]]) {
    const result = run(script, args);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /did not require Node\.js/);
  }
});

test('Windows setup/start share read-only host admission before execution while Stop remains owned cleanup', () => {
  const shared = read('scripts/install/Windows/wrapper-handoff.ps1');
  assert.match(shared, /Join-Path \$PSScriptRoot 'host-preflight\.ps1'/);
  assert.match(shared, /Invoke-OwaspAiGoatWindowsHostPreflight/);
  assert.match(shared, /\$result.hostAdmission = & \$ObserveHost/);
  assert.ok(shared.indexOf('$result.hostAdmission = & $ObserveHost') < shared.indexOf('& $Provision $request'));
  for (const filename of ['install-windows.ps1', 'start_all.ps1']) {
    const source = read('scripts/install/Windows/' + filename);
    assert.match(source, /Join-Path \$PSScriptRoot 'wrapper-handoff\.ps1'/);
    assert.match(source, /Invoke-OwaspAiGoatWindowsWrapperHandoff/);
    assert.match(source, /WINDOWS_HOST_PREFLIGHT_DENIED/);
    assert.ok(source.indexOf('Invoke-OwaspAiGoatWindowsWrapperHandoff') < source.indexOf('if ($Plan)'));
    assert.ok(source.indexOf('Invoke-OwaspAiGoatWindowsWrapperHandoff') < source.indexOf("throw 'WINDOWS_HOST_PREFLIGHT_DENIED"));
    if (filename === 'start_all.ps1') assert.ok(source.indexOf('if ($Stop)') < source.indexOf('Invoke-OwaspAiGoatWindowsWrapperHandoff'));
  }
});

test('Windows startup uses qualified canonical handoff and Stop invokes only the owned controller', () => {
  const windows = read('scripts/install/Windows/start_all.ps1');
  assert.match(windows, /-CompositionReady \$true/);
  assert.match(windows, /if \(\$Plan\) \{/);
  assert.match(windows, /did not require Node\.js/);
  assert.match(windows, /scripts\/launcher-control\.js/);
  assert.match(windows, /Startup never deletes databases/);
  assert.doesNotMatch(windows, /scripts\/start-application\.js|stop_all\.sh|WSL|&\s*npm|&\s*docker/);
  assert.ok(windows.indexOf('if ($Stop)') < windows.indexOf('if ($Plan)'));
  assert.ok(windows.indexOf('if ($Plan)') < windows.indexOf("throw 'WINDOWS_HOST_PREFLIGHT_DENIED"));
});

test('compatibility Unix launchers contain no destructive reset', () => {
  const quick = read('scripts/install/Ubuntu/quick-start.sh');
  const macDev = read('scripts/install/Mac/macos-dev-setup.sh');

  assert.match(quick, /install-owasp-ai-goat-ubuntu\.sh/);
  assert.match(macDev, /start_all\.sh --init-db/);
  for (const [relative, source] of [['quick-start.sh', quick], ['macos-dev-setup.sh', macDev]]) {
    assert.doesNotMatch(source, /rm\s+-f[^\n]*\.db|Remove-Item[^\n]*\.db|server\/database\/init|db:legacy:initialize/i, relative);
  }
});

test('Ubuntu ARM64 provisions confined Chromium instead of requiring a manual browser', () => {
  assert.match(linuxPrerequisites, /apt-get install -y --no-install-recommends snapd/);
  assert.match(linuxPrerequisites, /snap install chromium/);
  assert.match(linuxPrerequisites, /PUPPETEER_EXECUTABLE_PATH=\/snap\/bin\/chromium/);
  assert.match(linuxPrerequisites, /systemd host so snapd can run/);
  assert.doesNotMatch(linuxPrerequisites, /Ubuntu ARM64 requires an installed sandbox-capable Chromium browser/);
  assert.doesNotMatch(linuxPrerequisites, /--no-sandbox/);
});

test('Unix installers require the Compose v2 command used by owned provisioning', () => {
  for (const [name, source] of [['macOS', macPrerequisites], ['Linux', linuxPrerequisites]]) {
    assert.match(source, name==='macOS' ? /ensure_macos_docker_plugin compose/ : /docker compose version/, name);
    assert.doesNotMatch(source, /docker-compose version/, name);
  }
  assert.match(macPrerequisites, /cli-plugins\/docker-\$plugin/);
  assert.match(macPrerequisites, /existing Docker \$plugin plugin is not usable/);
  assert.doesNotMatch(linuxPrerequisites, /for package in docker-compose-v2 docker-compose-plugin docker-compose/);
});
