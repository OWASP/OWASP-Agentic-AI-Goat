'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const filename = path.join(root, 'scripts/install/Windows/host-preflight.ps1');
const source = fs.readFileSync(filename, 'utf8');
const quote = value => "'" + value.replaceAll("'", "''") + "'";
const interpreter = ['pwsh', 'powershell'].find(command => spawnSync(command, ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'], { encoding: 'utf8', timeout: 5000 }).status === 0);
const skip = !interpreter && 'PowerShell unavailable; injected interpreter checks skipped; no live host qualification requested';
const approved = [4,27,48,49,70,72,84,121,122,125,126,129,130,161,162,164,165];

function fixture(steer = '') {
  const program = `
. ${quote(filename)}
$cpu = @{ Architecture = 9; AddressWidth = 64; VirtualizationFirmwareEnabled = $true; SecondLevelAddressTranslationExtensions = $true; VMMonitorModeExtensions = $true }
$observed = @{ os = @{ ProductType = 1; OperatingSystemSKU = 48; Version = '10.0.26100'; BuildNumber = '26100'; Caption = 'synthetic Home localized label ignored' }; processors = @($cpu); features = @(@{ Name = 'Microsoft-Hyper-V'; InstallState = 1 },@{ Name = 'Microsoft-Hyper-V-Hypervisor'; InstallState = 1 }); hypervisorPresent = $true; rebootPending = $false; hypervAdministrator = $true; hypervPowerShellAvailable = $true; private = 'private synthetic host identity' }
$script:calls = 0
${steer}
$observe = { $script:calls++; return $observed }
$result = Invoke-OwaspAiGoatWindowsHostPreflight -Observe $observe
@{ result = $result; calls = $script:calls } | ConvertTo-Json -Depth 7 -Compress
`;
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(run.stdout, /private synthetic host identity|localized label/);
  return JSON.parse(run.stdout);
}
const codes = value => value.result.blockers.map(blocker => blocker.code);

test('canonical host policy uses documented exact edition IDs and numeric client/x64 evidence', () => {
  assert.match(source, new RegExp('\\$allowedSkus = @\\(' + approved.join(',') + '\\)'));
  assert.match(source, /nf-sysinfoapi-getproductinfo/);
  assert.match(source, /win32metadata\/blob\/main.*winnt\.h/);
  assert.match(source, /ProductType -ne 1/);
  assert.match(source, /Architecture -ne 9.*AddressWidth -ne 64/);
  assert.match(source, /BuildNumber -lt 19045/);
  assert.doesNotMatch(source, /\.Caption|\.OSArchitecture|PROCESSOR_ARCHITECTURE/);
});

test('observer is read-only, bounded CIM and fixed servicing probes with safe projection', () => {
  assert.match(source, /OperationTimeoutSec 10 -ErrorAction Stop/);
  assert.match(source, /Microsoft-Hyper-V-Hypervisor/);
  assert.match(source, /RebootPending/);
  assert.match(source, /RebootRequired/);
  assert.doesNotMatch(source, /Enable-WindowsOptionalFeature|Restart-Computer|New-VM|Set-Item|Start-Process|Invoke-WebRequest|\.SerialNumber|\.CSName/);
  assert.match(source, /catch \{ \$observed = \$null \}/);
  assert.match(source, /WINDOWS_HOST_OBSERVATION_UNKNOWN/);
});

test('running hypervisor capability evidence precedes CPU flag requirements', () => {
  const live = source.indexOf('if ($Observation.hypervisorPresent)');
  const cpu = source.indexOf('foreach ($key in @(');
  assert.ok(live >= 0 && live < cpu);
  assert.match(source, /capabilityEvidence = 'running-hypervisor'/);
  assert.match(source, /hostSupported = \(\$result.blockers.Count -eq 0\)/);
});

test('approved edition families pass independently of localized captions and unavailable suppressed flags', { skip }, () => {
  for (const sku of approved) {
    const value = fixture(`$observed.os.OperatingSystemSKU = ${sku}; $cpu.VirtualizationFirmwareEnabled = $null; $cpu.SecondLevelAddressTranslationExtensions = $false; $cpu.VMMonitorModeExtensions = $null`);
    assert.equal(value.calls, 1);
    assert.equal(value.result.hostSupported, true);
    assert.equal(value.result.capabilityEvidence, 'running-hypervisor');
  }
});

test('Home unknown Server ARM64 and old builds deny with actionable closed codes', { skip }, () => {
  for (const [steer, code] of [
    ['$observed.os.OperatingSystemSKU = 101', 'WINDOWS_HOST_EDITION_UNSUPPORTED'],
    ['$observed.os.OperatingSystemSKU = 999', 'WINDOWS_HOST_EDITION_UNSUPPORTED'],
    ['$observed.os.ProductType = 3', 'WINDOWS_HOST_CLIENT_REQUIRED'],
    ['$cpu.Architecture = 12', 'WINDOWS_HOST_X64_REQUIRED'],
    ["$observed.os.BuildNumber = '19044'", 'WINDOWS_HOST_BUILD_UNSUPPORTED'],
    ["$observed.os.Version = '6.3.9600'", 'WINDOWS_HOST_BUILD_UNSUPPORTED'],
  ]) {
    const value = fixture(steer);
    assert.equal(value.result.hostSupported, false);
    assert.ok(codes(value).includes(code));
    assert.ok(value.result.blockers.every(blocker => blocker.remedy.length > 10));
  }
});

test('disabled missing duplicate unknown features or reboot pending never pass with a running hypervisor', { skip }, () => {
  for (const [steer, code] of [
    ['$observed.features[0].InstallState = 2', 'WINDOWS_HOST_HYPERV_DISABLED'],
    ['$observed.features = @()', 'WINDOWS_HOST_OBSERVATION_UNKNOWN'],
    ['$observed.features += $observed.features[0]', 'WINDOWS_HOST_OBSERVATION_UNKNOWN'],
    ['$observed.features[1].InstallState = 4', 'WINDOWS_HOST_OBSERVATION_UNKNOWN'],
    ['$observed.rebootPending = $true', 'WINDOWS_HOST_RESTART_PENDING'],
    ['$observed.rebootPending = $null', 'WINDOWS_HOST_OBSERVATION_UNKNOWN'],
  ]) assert.ok(codes(fixture(steer)).includes(code));
});

test('stopped hypervisor requires flags but remains blocked until running; unknown flags fail closed', { skip }, () => {
  assert.ok(codes(fixture('$observed.hypervisorPresent = $false')).includes('WINDOWS_HOST_HYPERV_NOT_RUNNING'));
  assert.ok(codes(fixture('$observed.hypervisorPresent = $false; $cpu.SecondLevelAddressTranslationExtensions = $false')).includes('WINDOWS_HOST_VIRTUALIZATION_UNAVAILABLE'));
  assert.ok(codes(fixture('$observed.hypervisorPresent = $false; $cpu.VirtualizationFirmwareEnabled = $null')).includes('WINDOWS_HOST_OBSERVATION_UNKNOWN'));
  assert.ok(codes(fixture('$observed.hypervisorPresent = $null')).includes('WINDOWS_HOST_OBSERVATION_UNKNOWN'));
});

test('observer failure is sanitized without printing host diagnostics', { skip }, () => {
  const program = `. ${quote(filename)}; Invoke-OwaspAiGoatWindowsHostPreflight -Observe { throw 'synthetic private host diagnostic' } | ConvertTo-Json -Depth 5 -Compress`;
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(run.stdout, /synthetic private host diagnostic/);
  const value = JSON.parse(run.stdout);
  assert.equal(value.hostSupported, false);
  assert.equal(value.blockers[0].code, 'WINDOWS_HOST_OBSERVATION_UNKNOWN');
});

test('normal-user host gate checks enabled token SID and canonical installed Hyper-V command without VM enumeration', () => {
  assert.match(source, /WindowsIdentity\]::GetCurrent\(\)/);
  assert.match(source, /IsInRole.*S-1-5-32-578/);
  assert.match(source, /finally \{ \$identity.Dispose\(\) \}/);
  assert.match(source, /Get-Module -ListAvailable -Name Hyper-V/);
  assert.match(source, /Import-Module -Name \$module.Path -ErrorAction Stop/);
  assert.match(source, /Get-Command -Name 'Hyper-V\\Get-VM'/);
  assert.match(source, /\$command.Module.ModuleBase/);
  assert.doesNotMatch(source, /Add-LocalGroupMember|net localgroup|Get-LocalGroupMember|Hyper-V\\Get-VM -|Get-VM -Name|Get-VMHost/);
});
test('missing current-token Hyper-V access or system PowerShell module is actionable and unknown evidence stays denied', { skip }, () => {
  for (const [steer, code] of [
    ['$observed.hypervAdministrator = $false', 'WINDOWS_HOST_HYPERV_PERMISSION_REQUIRED'],
    ['$observed.hypervPowerShellAvailable = $false', 'WINDOWS_HOST_HYPERV_POWERSHELL_REQUIRED'],
    ['$observed.hypervAdministrator = $null', 'WINDOWS_HOST_OBSERVATION_UNKNOWN'],
    ['$observed.hypervPowerShellAvailable = $null', 'WINDOWS_HOST_OBSERVATION_UNKNOWN'],
  ]) { const value = fixture(steer); assert.equal(value.result.hostSupported, false); assert.ok(codes(value).includes(code)); }
});
