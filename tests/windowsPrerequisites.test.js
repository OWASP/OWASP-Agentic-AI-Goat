'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const filename = path.join(root, 'scripts/install/Windows/prerequisites.ps1');
const source = fs.readFileSync(filename, 'utf8');
const psQuote = value => "'" + value.replaceAll("'", "''") + "'";
const interpreter = ['pwsh', 'powershell'].find(command => spawnSync(command, ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'], { encoding: 'utf8', timeout: 5000 }).status === 0);
const skip = !interpreter && 'PowerShell unavailable; controlled interpreter and native Windows tests not run';

function fixture(override = '', execute = true) {
  const program = `
. ${psQuote(filename)}
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:marker = $false; $script:npmInstalled = $false; $script:expanded = $false
$script:failNpm = $false; $script:badHash = $false; $script:hostPresent = $true; $script:elevated = $false
$inventory = { param($Root) [pscustomobject]@{
 runtimePolicy = @{ nodeMinimum = '26.10.0'; npmMinimum = '12.1.0' }
 dependencies = @('windowsHost','node','npm','git','python','ollama','cppBuildTools','windowsSdk','docker','compose','linuxDockerDaemon') | ForEach-Object { [pscustomobject]@{ id = $_; status = $(if ($_ -eq 'windowsHost' -and $script:hostPresent) { 'present' } else { 'missing' }) } }
} }
$runner = { param($Request)
 $script:events.Add($Request.id)
 if ($Request.id -eq 'privateDirectory') { return @{ exitCode = 0; output = '{"version":1,"ok":true}' } }
 if ($Request.id -eq 'verifyNode') { return @{ exitCode = 0; output = 'v26.10.0' } }
 if ($Request.id -eq 'npmOperationJournal') {
  $wire = $Request.input | ConvertFrom-Json; $script:marker = $true
  return @{ exitCode = 0; output = (@{ version = 1; ok = $true; operation = 'createPrivateFile'; path = $wire.path; size = [Convert]::FromBase64String($wire.bytesBase64).Length; identity = @{ volumeSerial = 1; fileId = '0123456789abcdef' } } | ConvertTo-Json -Depth 4 -Compress) }
 }
 if ($Request.id -eq 'npmBootstrap') {
  if ($Request.elevate -or $Request.arguments -notcontains '--ignore-scripts' -or $Request.arguments -notcontains '--strict-ssl=true') { throw 'UNSAFE_NPM' }
  if ($script:failNpm) { throw 'WINDOWS_PREREQUISITE_TIMEOUT' }
  $script:npmInstalled = $true; return @{ exitCode = 0; output = 'DO_NOT_RETURN_SECRET' }
 }
 if ($Request.id -eq 'verifyNpm') { return @{ exitCode = 0; output = '12.1.0' } }
 if ($Request.id -eq 'npmOperationRetire') {
  $wire = $Request.input | ConvertFrom-Json
  if ($wire.operation -ne 'deleteMatchingPrivateFile' -or $wire.expectedIdentity.fileId -ne '0123456789abcdef' -or -not $wire.bytesBase64) { throw 'UNBOUND_DELETE' }
  $script:marker = $false; return @{ exitCode = 0; output = '{"version":1,"ok":true,"deleted":true}' }
 }
 throw 'UNEXPECTED_PROCESS'
}
$exists = { param($File)
 if ($File -match 'npm-bootstrap-operation.json$') { return $script:marker }
 if ($File -match 'npm-12.1.0.*npm-cli.js$') { return $script:npmInstalled }
 if ($File -match 'npm-cli.js$') { return $true }
 if ($File -match 'node.exe$') { return $script:expanded }
 return $false
}
$download = { param($Uri,$File) $script:events.Add('download'); if ($Uri -notmatch '^https://nodejs.org/dist/v26.10.0/') { throw 'BAD_URL' } }
$read = { param($File) ('a' * 64) + '  node-v26.10.0-win-x64.zip' }
$hash = { param($File) if ($script:badHash) { 'b' * 64 } else { 'a' * 64 } }
$expand = { param($File,$Destination,$ExpectedRoot) if ($ExpectedRoot -ne 'node-v26.10.0-win-x64') { throw 'BAD_ROOT' }; $script:events.Add('expand'); $script:expanded = $true }
$cleanup = { param($File) if ($File -match 'npm-bootstrap-operation') { throw 'UNBOUND_CLEANUP' }; $script:events.Add('tempCleanup') }
${override}
try {
 $plan = Invoke-DvaiaWindowsPrerequisites -ExecuteMode $${execute} -RepoRoot ${psQuote(root)} -UserProfile ${psQuote(path.join(root, 'controlled profile'))} -SystemRoot ${psQuote(path.join(root, 'controlled system'))} -Inventory $inventory -Runner $runner -Download $download -ReadText $read -Hash $hash -Expand $expand -Exists $exists -DirectoryExists { param($Dir) $false } -Find { param($Name) $null } -Cleanup $cleanup -IsElevated { $script:elevated }
 @{ plan = $plan; events = @($script:events.ToArray()); marker = $script:marker } | ConvertTo-Json -Depth 8
} catch { @{ code = $_.Exception.Message; events = @($script:events.ToArray()); marker = $script:marker } | ConvertTo-Json -Depth 8 }
`;
  const result = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('prerequisite component is opt-in and delegates full installation to the canonical wrapper', () => {
  assert.match(source, /^#Requires -Version 5\.1/m);
  assert.match(source, /\[bool\]\$ExecuteMode = \$false/);
  assert.ok(source.indexOf('if (-not $ExecuteMode)') < source.indexOf('foreach ($directory'));
  assert.match(source, /installationBlocked = \$true; nativeQualified = \$false/);
  assert.match(source, /delegated =.*independent packages\.ps1 Git\/Python\/MSVC\/Windows SDK\/Ollama/);
  assert.doesNotMatch(source, /WINDOWS_PACKAGE_PROVISIONING_UNIMPLEMENTED/);
  assert.match(source, /WINDOWS_NATIVE_BUILD_PREREQUISITES_UNQUALIFIED/);
  assert.match(source, /WINDOWS_OWNED_SANDBOX_BACKEND_UNDECIDED/);
  const wrapper = fs.readFileSync(path.join(root, 'scripts/install/Windows/install-windows.ps1'), 'utf8');
  assert.ok(!wrapper.includes('prerequisites.ps1'));
  assert.match(wrapper, /Invoke-DvaiaWindowsWrapperHandoff -Kind setup/);
  assert.match(wrapper, /-CompositionReady \$true/);
  assert.match(wrapper, /WINDOWS_HOST_PREFLIGHT_DENIED/);
});

test('bootstrap binds exact shared versions, native pre-Node authority and named verified archive', () => {
  assert.match(source, /\$snapshot\.runtimePolicy\.nodeMinimum/);
  assert.match(source, /\$snapshot\.runtimePolicy\.npmMinimum/);
  assert.match(source, /scripts\\windows\\windows-private-state.ps1/);
  assert.match(source, /input = \$request; capture = \$true/);
  assert.match(source, /SHASUMS256\.txt/);
  assert.match(source, /\$matches.Count -ne 1/);
  assert.match(source, /\$ExpectedRoot.*node-v/);
  assert.match(source, /StartsWith\(\$ExpectedRoot/);
  assert.match(source, /WINDOWS_NODE_PARTIAL_RUNTIME/);
  assert.match(source, /npmExecpath = \$npmCli/);
  assert.match(source, /'--registry', 'https:\/\/registry.npmjs.org', '--strict-ssl=true'/);
  assert.match(source, /'--ignore-scripts'/);
});

test('downloads and process output are bounded without bypasses or implicit privileges', () => {
  assert.match(source, /AllowAutoRedirect = \$false/);
  assert.match(source, /if \(-not \$reading.Wait\(\$remaining\)\)/);
  assert.ok(source.indexOf('if ($total -gt 200MB)') < source.indexOf('$file.Write($buffer'));
  assert.match(source, /\$cancel.Cancel\(\)/);
  assert.match(source, /if \(!capture\) continue;/);
  assert.match(source, /text.Length \+ count > 65536/);
  assert.match(source, /Task\]::WaitAll.*10000/);
  assert.doesNotMatch(source, /ReadToEndAsync|\.Result\b|CopyToAsync|Set-ExecutionPolicy|ServerCertificateValidationCallback|--no-sandbox|Restart-Computer|--allow-reboot|Verb RunAs|winget install/i);
  assert.match(source, /if \(\$Request.elevate\) \{ throw/);
});

test('uncertain npm operation cannot replay and journal retirement binds bytes plus identity after verification', () => {
  assert.ok(source.indexOf('WINDOWS_NPM_OPERATION_INDETERMINATE') < source.indexOf("id = 'verifyNode'"));
  assert.ok(source.indexOf("id = 'npmOperationJournal'") < source.indexOf("id = 'npmBootstrap'"));
  assert.ok(source.indexOf("id = 'verifyNpm'") < source.indexOf("id = 'npmOperationRetire'"));
  assert.match(source, /operation = 'deleteMatchingPrivateFile'.*bytesBase64.*expectedIdentity = \$journal.identity/);
  assert.doesNotMatch(source, /\$Cleanup \$operation/);
  assert.match(source, /WINDOWS_NPM_OPERATION_RETIRE_UNCERTAIN/);
});

test('controlled plan invokes no mutation seam', { skip }, () => {
  const result = fixture('', false);
  assert.deepEqual(result.events, []);
  assert.equal(result.plan.nonMutating, true);
  assert.equal(result.plan.componentSucceeded, false);
  assert.equal(result.plan.installationBlocked, true);
});

test('controlled fresh bootstrap verifies hash, binds npm, retires journal after verification and stays blocked', { skip }, () => {
  const result = fixture();
  assert.ok(result.plan.runtime.npmCli.includes('npm-12.1.0'));
  assert.equal(result.plan.installationBlocked, true);
  assert.equal(result.plan.nativeQualified, false);
  assert.equal(result.plan.componentSucceeded, true);
  assert.equal(result.marker, false);
  assert.ok(result.events.indexOf('npmOperationJournal') < result.events.indexOf('npmBootstrap'));
  assert.ok(result.events.indexOf('verifyNpm') < result.events.indexOf('npmOperationRetire'));
  assert.ok(!JSON.stringify(result).includes('DO_NOT_RETURN_SECRET'));
});

test('controlled checksum failure cleans only nonce downloads without executing npm', { skip }, () => {
  const result = fixture('$script:badHash = $true');
  assert.equal(result.code, 'WINDOWS_NODE_CHECKSUM_MISMATCH');
  assert.equal(result.events.filter(event => event === 'tempCleanup').length, 2);
  assert.ok(!result.events.includes('expand'));
  assert.ok(!result.events.includes('npmBootstrap'));
});

test('controlled npm timeout retains marker and existing marker prevents replay', { skip }, () => {
  const failed = fixture('$script:failNpm = $true');
  assert.equal(failed.code, 'WINDOWS_PREREQUISITE_TIMEOUT');
  assert.equal(failed.marker, true);
  assert.ok(!failed.events.includes('npmOperationRetire'));
  const retry = fixture('$script:marker = $true');
  assert.ok(retry.plan.blockers.includes('WINDOWS_NPM_OPERATION_INDETERMINATE'));
  assert.ok(!retry.events.includes('npmBootstrap'));
  assert.ok(!retry.events.includes('download'));
});


test('Execute CLI success requires verified component binding independently of full installation blocks', () => {
  assert.match(source, /componentSucceeded = \$false/);
  assert.ok(source.indexOf('$result.componentSucceeded = $true') > source.indexOf("id = 'verifyNpm'"));
  assert.ok(source.indexOf('$result.componentSucceeded = $true') > source.indexOf('$result.runtime ='));
  assert.match(source, /if \(\$Execute -and -not \$output\.componentSucceeded\) \{ exit 1 \}/);
});

test('controlled unsupported host, elevated caller and retained npm journal cannot report component success', { skip }, () => {
  for (const [steer, code] of [
    ['$script:hostPresent = $false', 'WINDOWS_HOST_UNSUPPORTED'],
    ['$script:elevated = $true', 'WINDOWS_RUN_AS_NORMAL_USER'],
    ['$script:marker = $true', 'WINDOWS_NPM_OPERATION_INDETERMINATE'],
  ]) {
    const result = fixture(steer);
    assert.equal(result.plan.componentSucceeded, false);
    assert.equal(result.plan.runtime, null);
    assert.ok(result.plan.blockers.includes(code));
    assert.ok(!result.events.includes('verifyNode'));
    assert.ok(!result.events.includes('npmBootstrap'));
  }
});

test('controlled actual CLI footer returns Execute error and Plan or verified component success codes', { skip }, () => {
  // Invoke the exact CLI footer against a controlled component result; no native
  // process or installer seam runs, and full-install blockers remain present.
  const footer = source.slice(source.lastIndexOf("if ($MyInvocation.InvocationName -ne '.')"));
  for (const [execute, succeeded, status] of [[true, false, 1], [false, false, 0], [true, true, 0]]) {
    const program = `
. ${psQuote(filename)}
function Invoke-DvaiaWindowsPrerequisites { param([bool]$ExecuteMode) [pscustomobject]@{ componentSucceeded = $${succeeded}; installationBlocked = $true; runtime = $(if ($${succeeded}) { @{ nodeExecutable = 'controlled node'; npmCli = 'controlled npm' } } else { $null }) } }
$Plan = $false; $Execute = $${execute}
${footer}
`;
    const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, status, run.stderr);
    const result = JSON.parse(run.stdout);
    assert.equal(result.componentSucceeded, succeeded);
    assert.equal(result.installationBlocked, true);
  }
});
