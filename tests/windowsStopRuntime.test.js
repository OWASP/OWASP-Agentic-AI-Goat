'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const filename = path.join(root, 'scripts/install/Windows/start_all.ps1');
const source = fs.readFileSync(filename, 'utf8');
const quote = value => "'" + value.replaceAll("'", "''") + "'";
const interpreter = ['pwsh', 'powershell'].find(command => spawnSync(command, ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'], { encoding: 'utf8', timeout: 5000 }).status === 0);
const skip = !interpreter && 'PowerShell unavailable; controlled interpreter tests not run; no live OS tests requested';

function fixture(steer = '') {
  const program = `
. ${quote(filename)}
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:version = 'v26.10.0'; $script:privateVersion = 'v26.10.0'; $script:fail = $false; $script:privatePresent = $true
$profile = [IO.Path]::GetTempPath()
$installed = Join-Path $profile 'controlled PATH node.exe'
$find = { $installed }
$exists = { param($File) if ($File -eq $installed) { return $true }; return $script:privatePresent }
$runner = { param($Request)
 if ($Request.arguments.Count -ne 1 -or $Request.arguments[0] -ne '--version' -or $Request.timeoutMs -ne 10000 -or $Request.elevate) { throw 'UNSAFE_PROBE' }
 $script:events.Add($Request.executable)
 if ($Request.executable -eq $installed) {
  if ($script:fail) { throw 'WINDOWS_PREREQUISITE_TIMEOUT' }
  return @{ exitCode = 0; output = $script:version }
 }
 return @{ exitCode = 0; output = $script:privateVersion }
}
${steer}
try { $selected = Get-DvaiaWindowsStopNode -RepoRoot ${quote(root)} -UserProfile $profile -Find $find -Exists $exists -Runner $runner; @{ selected = $selected; events = @($script:events) } | ConvertTo-Json -Compress }
catch { @{ code = $_.Exception.Message; events = @($script:events) } | ConvertTo-Json -Compress }
`;
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  return JSON.parse(run.stdout);
}

test('Stop reads shared runtime policy and checks only exact managed Node fallback with bounded runner', () => {
  assert.match(source, /runtime-version-policy\.sh/);
  assert.match(source, /\$matches.Count -ne 1/);
  assert.match(source, /\.dvaia\\tools\\node-v.*-win-x64\\node\.exe/);
  assert.match(source, /Invoke-DvaiaPrerequisiteProcess/);
  assert.match(source, /IsPathRooted\(\$candidate\)/);
  assert.match(source, /Test-Path -LiteralPath \$File -PathType Leaf/);
  assert.match(source, /FileAttributes\]::ReparsePoint/);
  assert.match(source, /arguments = @\('--version'\); capture = \$true; timeoutMs = 10000/);
  assert.match(source, /\[version\]\$version.Substring\(1\) -ge \[version\]\$minimum/);
  assert.doesNotMatch(source, /Set-ExecutionPolicy|Start-Process|Stop-Process|taskkill|Remove-Item|Set-Content|\.env|winget|npm install|EnvironmentVariables|SetEnvironmentVariable/);
});

test('startup uses qualified composition and reset/conflict guards precede runtime selection', () => {
  assert.match(source, /-CompositionReady \$true/);
  assert.match(source, /if \(\$MyInvocation.InvocationName -ne '\.'\)/);
  assert.match(source, /if \(\$Reset\)/);
  assert.match(source, /if \(\$Plan -or \$InitDb\)/);
  assert.ok(source.indexOf('if ($Reset)') < source.indexOf('$node = Get-DvaiaWindowsStopNode'));
  assert.ok(source.indexOf('if ($Plan -or $InitDb)') < source.indexOf('$node = Get-DvaiaWindowsStopNode'));
  assert.match(source, /& \$node \(Join-Path \$RepoRoot 'scripts\/launcher-control\.js'\)/);
  assert.match(source, /exit \$LASTEXITCODE/);
  assert.match(source, /did not require Node\.js/);
});

test('controlled compatible PATH node is preferred and invoked by absolute path', { skip }, () => {
  const value = fixture();
  assert.ok(value.selected.endsWith('controlled PATH node.exe'));
  assert.equal(value.events.length, 1);
});

test('controlled missing/unsupported/timed-out PATH node falls back to verified managed runtime', { skip }, () => {
  for (const steer of ["$find = { $null }", "$script:version = 'v24.15.0'", '$script:fail = $true']) {
    const value = fixture(steer);
    assert.match(value.selected, /node-v26\.10\.0-win-x64[\\/]node\.exe$/);
    assert.equal(value.events.at(-1), value.selected);
  }
});

test('controlled invalid candidates and unavailable private runtime fail closed', { skip }, () => {
  const unavailable = fixture("$script:version = 'v24.15.0'; $script:privatePresent = $false");
  assert.equal(unavailable.code, 'WINDOWS_STOP_RUNTIME_UNAVAILABLE');
  const relative = fixture("$find = { 'relative node.exe' }; $script:privatePresent = $false");
  assert.equal(relative.code, 'WINDOWS_STOP_RUNTIME_UNAVAILABLE');
  assert.deepEqual(relative.events, []);
  const privateUnsupported = fixture("$find = { $null }; $script:privateVersion = 'v26.9.0'");
  assert.equal(privateUnsupported.code, 'WINDOWS_STOP_RUNTIME_UNAVAILABLE');
});

test('function-scope library import preserves caller startup switches and dot-source is inert', { skip }, () => {
  const program = `
. ${quote(filename)}
$Plan = $true; $Stop = $true; $InitDb = $true
try { Get-DvaiaWindowsStopNode -RepoRoot ${quote(root)} -UserProfile ([IO.Path]::GetTempPath()) -Find { $null } -Exists { $false } | Out-Null } catch { }
@{ plan = [bool]$Plan; stop = [bool]$Stop; initDb = [bool]$InitDb } | ConvertTo-Json -Compress
`;
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { plan: true, stop: true, initDb: true });
});

test('direct Plan still runs entrypoint without importing runtime probes', { skip }, () => {
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-File', filename, '-Plan'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /did not require Node\.js/);
});
