'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const filename = path.join(root, 'scripts/install/Windows/packages.ps1');
const source = fs.readFileSync(filename, 'utf8');
const quote = value => "'" + value.replaceAll("'", "''") + "'";
const interpreter = ['pwsh', 'powershell'].find(command => spawnSync(command, ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'], { encoding: 'utf8', timeout: 5000 }).status === 0);
const skip = !interpreter && 'PowerShell unavailable; controlled interpreter and native Windows package qualification not run';

function probeFixture(steer = '', id = 'multipass') {
  const program = `
. ${quote(filename)}
$env:ProgramFiles = [IO.Path]::GetTempPath(); $env:SystemRoot = [IO.Path]::GetTempPath()
$script:signature = $true; $script:driver = 'hyperv'; $script:exitCode = 0
$script:version = "multipass 1.16.4+win\`nmultipassd 1.16.4+win"
function Test-Path { param($LiteralPath,$PathType) return $true }
function Test-DvaiaPackageSignature { param($File,$Publisher) return $script:signature }
$script:events = New-Object 'System.Collections.Generic.List[string]'
$runner = { param($Request)
 if ($Request.timeoutMs -ne 10000 -or -not [IO.Path]::IsPathRooted($Request.executable)) { throw 'UNSAFE_PROBE' }
 $script:events.Add($Request.id)
 if ($Request.id -eq 'probeMultipassDriver') { return @{ exitCode = $script:exitCode; output = $script:driver } }
 return @{ exitCode = $script:exitCode; output = $script:version }
}
${steer}
try { $result = Get-DvaiaNativePackageProbe -Id ${quote(id)} -Runner $runner; @{ result = $result; events = @($script:events) } | ConvertTo-Json -Depth 5 -Compress }
catch { @{ code = $_.Exception.Message; events = @($script:events) } | ConvertTo-Json -Compress }
`;
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  return JSON.parse(run.stdout);
}

function fixture(override = '', execute = true, second = false, secondOverride = '') {
  const program = `
. ${quote(filename)}
$env:ProgramFiles = [IO.Path]::GetTempPath()
\${env:ProgramFiles(x86)} = [IO.Path]::GetTempPath()
$env:LOCALAPPDATA = [IO.Path]::GetTempPath()
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:marker = $false; $script:receipt = $false; $script:journalWire = $null; $script:receiptWire = $null; $script:boot = '100'; $script:hostHash = ('a' * 64); $script:retireFail = $false; $script:corrupt = $false; $script:fail = $false; $script:restart = $false; $script:restartCode = -1978334967; $script:sourceBad = $false; $script:verifyBad = $false
$script:states = @{ winget = 'present'; git = 'present'; python = 'present'; buildTools = 'present'; ollama = 'present'; ollamaService = 'present'; multipass = 'present'; opensshClient = 'present'; hyperVHost = 'present' }
$script:modify = $false
$probe = { param($Id,$Runner)
 $script:events.Add('probe:' + $Id)
 $value = @{ id = $Id; status = $script:states[$Id]; path = 'trusted.exe' }
 if ($Id -eq 'buildTools' -and $script:modify) { $value.modifyPath = Join-Path $env:ProgramFiles 'Microsoft Visual Studio/2022/BuildTools' }
 return $value
}
$runner = { param($Request)
 $script:events.Add($Request.id)
 if ($Request.id -eq 'packagePrivateDirectory') { return @{ exitCode = 0; output = '{"version":1,"ok":true}' } }
 if ($Request.id -eq 'packageOperationJournal') {
  $wire = $Request.input | ConvertFrom-Json; $script:marker = $true; $script:journalWire = $wire
  return @{ exitCode = 0; output = (@{ version = 1; ok = $true; operation = 'createPrivateFile'; path = $wire.path; size = [Convert]::FromBase64String($wire.bytesBase64).Length; identity = @{ volumeSerial = 1; fileId = '0123456789abcdef' } } | ConvertTo-Json -Depth 4 -Compress) }
 }
 if ($Request.id -eq 'packageRestartReceipt') {
  $wire = $Request.input | ConvertFrom-Json; $script:receipt = $true; $script:receiptWire = $wire
  return @{ exitCode = 0; output = (@{ version = 1; ok = $true; operation = 'createPrivateFile'; path = $wire.path; size = [Convert]::FromBase64String($wire.bytesBase64).Length; identity = @{ volumeSerial = 1; fileId = 'fedcba9876543210' } } | ConvertTo-Json -Depth 4 -Compress) }
 }
 if ($Request.id -match '^packageResumeRead(journal|receipt)$') {
  $key = $Matches[1]; $wire = $Request.input | ConvertFrom-Json
  $saved = $(if ($key -eq 'journal') { $script:journalWire } else { $script:receiptWire })
  $identity = $(if ($key -eq 'journal') { '0123456789abcdef' } else { 'fedcba9876543210' })
  if ($script:corrupt -and $key -eq 'journal') { $identity = '1111111111111111' }
  return @{ exitCode = 0; output = (@{ version = 1; ok = $true; operation = 'readPrivateFile'; path = $wire.path; size = [Convert]::FromBase64String($saved.bytesBase64).Length; bytesBase64 = $saved.bytesBase64; identity = @{ volumeSerial = 1; fileId = $identity } } | ConvertTo-Json -Depth 4 -Compress) }
 }
 if ($Request.id -match '^packageResumeRetire(journal|receipt)$') {
  $key = $Matches[1]; $wire = $Request.input | ConvertFrom-Json
  $saved = $(if ($key -eq 'journal') { $script:journalWire } else { $script:receiptWire })
  $identity = $(if ($key -eq 'journal') { '0123456789abcdef' } else { 'fedcba9876543210' })
  if ($wire.operation -ne 'deleteMatchingPrivateFile' -or $wire.expectedIdentity.fileId -ne $identity -or $wire.bytesBase64 -cne $saved.bytesBase64) { throw 'UNBOUND_DELETE' }
  if ($key -eq 'receipt' -and $script:retireFail) { throw 'WINDOWS_PACKAGE_RESTART_RETIRE_UNCERTAIN' }
  if ($key -eq 'journal') { $script:marker = $false } else { $script:receipt = $false }
  return @{ exitCode = 0; output = '{"version":1,"ok":true,"deleted":true}' }
 }
 if ($Request.id -eq 'packageOperationRetire') {
  $wire = $Request.input | ConvertFrom-Json
  if ($wire.operation -ne 'deleteMatchingPrivateFile' -or $wire.expectedIdentity.fileId -ne '0123456789abcdef' -or -not $wire.bytesBase64) { throw 'UNBOUND_DELETE' }
  $script:marker = $false; return @{ exitCode = 0; output = '{"version":1,"ok":true,"deleted":true}' }
 }
 if ($Request.id -eq 'wingetSource') {
  $url = $(if ($script:sourceBad) { 'https://evil.invalid' } else { 'https://cdn.winget.microsoft.com/cache' })
  return @{ exitCode = 0; output = (@{ Name = 'winget'; Arg = $url; Identifier = 'Microsoft.Winget.Source_8wekyb3d8bbwe'; Type = 'Microsoft.PreIndexed.Package' } | ConvertTo-Json -Compress) }
 }
 if (-not $script:marker) { throw 'UNJOURNALED_MUTATION' }
 if ($script:fail) { throw 'WINDOWS_PREREQUISITE_TIMEOUT' }
 if ($script:restart) { return @{ exitCode = $script:restartCode } }
 if ($Request.id -eq 'wingetBootstrap') {
  if (($Request.arguments -join ' ') -match 'AllUsers|ExecutionPolicy|SecurityProtocol') { throw 'UNSAFE_BOOTSTRAP' }
  $script:states.winget = 'present'
 } elseif ($Request.id -eq 'visualStudioModify') {
  if ($Request.arguments -contains '--remove' -or $Request.arguments -notcontains '--norestart' -or $Request.arguments -notcontains 'Microsoft.VisualStudio.Component.Windows11SDK.26100') { throw 'DESTRUCTIVE_VS_MODIFY' }
  $script:states.buildTools = 'present'
 } elseif ($Request.id -eq 'ollamaStart') { $script:states.ollamaService = 'present' }
 elseif ($Request.id -eq 'installopensshClient') {
  if (($Request.arguments -join '|') -cne '/Online|/Add-Capability|/CapabilityName:OpenSSH.Client~~~~0.0.1.0|/NoRestart|/Quiet') { throw 'UNSAFE_OPENSSH_CAPABILITY' }
  if (-not $script:verifyBad) { $script:states.opensshClient = 'present' }
 }
 elseif ($Request.id -match '^install(git|python|buildTools|ollama|multipass)$') {
  $id = $Matches[1]
  if ($Request.elevate -or $Request.arguments -notcontains '--exact' -or $Request.arguments -notcontains '--source' -or $Request.arguments -contains '--allow-reboot') { throw 'UNSAFE_PACKAGE' }
  if ($id -eq 'multipass' -and ($Request.arguments -notcontains '1.16.4' -or $Request.arguments -notcontains '--no-upgrade' -or $Request.arguments -notcontains '/qn /norestart DRIVER=hyperv REMOVE_DATA=no')) { throw 'UNSAFE_MULTIPASS_INSTALL' }
  if (-not $script:verifyBad) { $script:states[$id] = 'present' }
 } else { throw 'UNEXPECTED_PROCESS' }
 return @{ exitCode = 0; output = 'DO_NOT_RETURN_SECRET' }
}
$exists = { param($File) if ($File -match 'windows-package-restart.json$') { return $script:receipt }; return $script:marker }
$bootObservation = { param($Runner,$PowerShell,$Root) $script:events.Add('boot'); [pscustomobject]@{ hostSha256 = $script:hostHash; bootFileTime = $script:boot; currentSid = 'S-1-5-21-1-2-3-1000' } }
${override}
$params = @{ ExecuteMode = $${execute}; RepoRoot = ${quote(root)}; UserProfile = [IO.Path]::GetTempPath(); SystemRoot = [IO.Path]::GetTempPath(); Runner = $runner; Probe = $probe; Exists = $exists; HostSupported = { $true }; IsElevated = { $false }; Pause = {}; BootObservation = $bootObservation }
$result = Invoke-DvaiaWindowsPackages @params
${second ? secondOverride + '\n$second = Invoke-DvaiaWindowsPackages @params' : '$second = $null'}
@{ result = $result; second = $second; events = @($script:events); marker = $script:marker; receipt = $script:receipt } | ConvertTo-Json -Depth 10 -Compress
`;
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 15000 });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(run.stdout, /DO_NOT_RETURN_SECRET/);
  return JSON.parse(run.stdout.trim());
}

test('package Plan returns before any probes or process/helper launch', () => {
  const body = source.slice(source.indexOf('function Invoke-DvaiaWindowsPackages'));
  const gate = body.indexOf('if (-not $ExecuteMode)');
  assert.ok(gate > 0);
  assert.ok(gate < body.indexOf('& $HostSupported'));
  assert.ok(gate < body.indexOf('& $Runner'));
  assert.ok(gate < body.indexOf('& $Probe'));
  assert.match(source, /packageExecuteFlag = \$Execute/);
});

test('official exact packages, supported build floors and lifecycle overlay are explicit', () => {
  for (const id of ['Git.Git', 'Python.Python.3.13', 'Microsoft.VisualStudio.2022.BuildTools', 'Ollama.Ollama']) assert.ok(source.includes(id));
  assert.match(source, /\[17\.14,19\.0\)/);
  assert.match(source, /14\.44\.0/);
  assert.match(source, /3\\\.\(11\|12\|13\|14\)/);
  assert.match(source, /Microsoft\.VisualStudio\.Component\.Windows11SDK\.26100/);
  assert.match(source, /WINDOWS_LOCKED_NODE_GYP_POLICY_UNQUALIFIED/);
  assert.match(source, /PrependPath=0 AppendPath=0 Include_launcher=0/);
  assert.match(source, /PathOption=BashOnly/);
  assert.match(source, /O=Ollama Inc/);
  assert.match(source, /https:\/\/cdn\.winget\.microsoft\.com\/cache/);
  assert.match(source, /Microsoft\.Winget\.Source_8wekyb3d8bbwe/);
});

test('mutation journal and restart receipt bind identity and bytes without blind replay', () => {
  assert.match(source, /createPrivateFile/);
  assert.match(source, /deleteMatchingPrivateFile/);
  assert.match(source, /expectedIdentity = \$ack\.identity/);
  assert.match(source, /WINDOWS_PACKAGE_RESTART_BOOT_UNCHANGED/);
  assert.match(source, /WINDOWS_PACKAGE_RESTART_RECEIPT_DENIED/);
  assert.match(source, /windows-process-identity\.ps1/);
  assert.match(source, /\$hasMarker -or \$hasReceipt/);
  assert.match(source, /componentSucceeded/);
  assert.match(source, /if \(\$Execute -and -not \$output\.componentSucceeded\)/);
  assert.match(source, /WINDOWS_PACKAGE_OPERATION_INDETERMINATE/);
  assert.doesNotMatch(source, /Remove-Item|--allow-reboot|--ignore-security-hash|--disable-security-hash|Set-ExecutionPolicy|SecurityProtocol|NODE_TLS_REJECT_UNAUTHORIZED/);
  assert.match(source, /installationBlocked = \$true; nativeQualified = \$false/);
});

test('trusted UAC is limited to exact additive VS and OpenSSH client actions; normal bounded runner is reused', () => {
  assert.match(source, /Invoke-DvaiaPrerequisiteProcess \$Request/);
  assert.match(source, /WINDOWS_VS_ARGUMENTS_DENIED/);
  assert.match(source, /WINDOWS_VS_INSTALL_PATH_DENIED/);
  assert.match(source, /Test-DvaiaPackageSignature \$expected/);
  assert.match(source, /WaitForExit\(\$Request\.timeoutMs\)/);
  assert.doesNotMatch(source, /ReadToEnd|\.Result\b|--remove|includeRecommended|NativeDesktop/);
});

test('released Multipass Hyper-V and client-only OpenSSH are explicit preserved prerequisites', () => {
  assert.match(source, /Canonical\.Multipass.*version = '1\.16\.4'/);
  assert.match(source, /--version','1\.16\.4','--no-upgrade/);
  assert.match(source, /\/qn \/norestart DRIVER=hyperv REMOVE_DATA=no/);
  assert.match(source, /Test-DvaiaMultipassExistingFootprint/);
  assert.match(source, /GetEnvironmentVariable\('MULTIPASS_STORAGE','Machine'\)/);
  assert.match(source, /WINDOWS_MULTIPASS_EXISTING_INSTALLATION_UNSUPPORTED/);
  assert.match(source, /probeMultipassDriver.*arguments = @\('get','local.driver'\)/);
  assert.match(source, /driver.output.Trim\(\) -cne 'hyperv'/);
  assert.match(source, /Probe 'hyperVHost'.*WINDOWS_MULTIPASS_HYPERV_HOST_REQUIRED/);
  assert.match(source, /Join-Path \$env:SystemRoot 'System32\\OpenSSH\\ssh.exe'/);
  assert.match(source, /CapabilityName:OpenSSH.Client~~~~0.0.1.0','\/NoRestart','\/Quiet/);
  assert.match(source, /WINDOWS_OPENSSH_INSTALL_ACTION_DENIED/);
  assert.match(source, /installmultipass = 'multipass'; installopensshClient = 'opensshClient'/);
  assert.doesNotMatch(source, /OpenSSH\.Server|Add-WindowsCapability|Enable-WindowsOptionalFeature|Restart-Computer|arguments = @\('set'|arguments = @\('stop'|arguments = @\('delete'|Docker Desktop/);
});

test('missing Multipass provisions pinned new package and returns explicit dependency bindings', { skip }, () => {
  const value = fixture("$script:states.multipass = 'missing'");
  assert.equal(value.result.componentSucceeded, true);
  assert.deepEqual(value.result.completed, ['installmultipass']);
  assert.equal(value.events.filter(event => event === 'installmultipass').length, 1);
  assert.ok(value.events.indexOf('probe:hyperVHost') < value.events.indexOf('installmultipass'));
  assert.ok(value.result.dependencies.some(item => item.id === 'multipass' && item.status === 'present' && item.path));
});

test('existing incompatible Multipass and disabled Hyper-V deny before any installer bootstrap', { skip }, () => {
  for (const steer of ["$script:states.multipass = 'versionUnsupported'", "$script:states.hyperVHost = 'versionUnsupported'"]) {
    const value = fixture(steer + "; $script:states.winget = 'missing'");
    assert.equal(value.result.componentSucceeded, false);
    assert.ok(!value.events.includes('wingetBootstrap'));
    assert.ok(!value.events.some(event => event.startsWith('install')));
    assert.equal(value.marker, false);
  }
});

test('missing OpenSSH uses only journaled client capability without WinGet or other service changes', { skip }, () => {
  const value = fixture("$script:states.opensshClient = 'missing'; $script:states.winget = 'missing'");
  assert.equal(value.result.componentSucceeded, true);
  assert.deepEqual(value.result.completed, ['installopensshClient']);
  assert.ok(!value.events.includes('probe:winget'));
  assert.ok(!value.events.includes('ollamaStart'));
  assert.equal(value.marker, false);
});

test('OpenSSH and Multipass timeout uncertainty prevent repeat and acknowledged reboot resumes without replay', { skip }, () => {
  for (const id of ['opensshClient', 'multipass']) {
    const failed = fixture(`$script:states.${id} = 'missing'; $script:fail = $true`, true, true);
    assert.equal(failed.marker, true);
    assert.ok(failed.second.blockers.includes('WINDOWS_PACKAGE_OPERATION_INDETERMINATE'));
    assert.equal(failed.events.filter(event => event === 'install' + id).length, 1);
    const resumed = fixture(`$script:states.${id} = 'missing'; $script:restart = $true; $script:restartCode = 3010`, true, true,
      `$params.ResumeRestart = $true; $script:boot = '200'; $script:states.${id} = 'present'; $script:restart = $false`);
    assert.equal(resumed.second.componentSucceeded, true);
    assert.equal(resumed.marker, false);
    assert.equal(resumed.receipt, false);
    assert.equal(resumed.events.filter(event => event === 'install' + id).length, 1);
  }
});

test('default Multipass read-only probe requires both stable compatible versions, canonical signature and hyperv without changing driver', { skip }, () => {
  const admitted = probeFixture();
  assert.equal(admitted.result.status, 'present');
  assert.equal(admitted.result.version, '1.16.4');
  assert.equal(admitted.result.driver, 'hyperv');
  assert.deepEqual(admitted.events, ['probeMultipassVersion','probeMultipassDriver']);
  for (const steer of [
    "$script:version = 'multipass 1.16.4+win'",
    '$script:version = "multipass 1.16.4+win`nmultipass 1.16.4+win"',
    '$script:version = "multipass 1.16.4+win`nmultipassd 1.16.3+win"',
    '$script:version = "multipass 1.17.0-rc1+win`nmultipassd 1.17.0-rc1+win"',
    "$script:driver = 'virtualbox'", "$script:driver = 'hcs'", '$script:exitCode = 1',
  ]) assert.equal(probeFixture(steer).result.status, 'versionUnsupported');
  const denied = probeFixture('$script:signature = $false');
  assert.equal(denied.code, 'WINDOWS_MULTIPASS_SIGNATURE_DENIED');
  assert.deepEqual(denied.events, []);
});

test('default OpenSSH probe selects only trusted fixed client path and version invocation', { skip }, () => {
  const admitted = probeFixture("$script:version = 'OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2'", 'opensshClient');
  assert.equal(admitted.result.status, 'present');
  assert.equal(admitted.result.version, '9.5p1');
  assert.match(admitted.result.path, /System32[\\/]OpenSSH[\\/]ssh.exe$/);
  assert.deepEqual(admitted.events, ['probeOpenSSHClient']);
  assert.equal(probeFixture("$script:version = 'OpenSSH_9.5p1 unqualified'", 'opensshClient').result.status, 'versionUnsupported');
  assert.equal(probeFixture('$script:signature = $false', 'opensshClient').code, 'WINDOWS_OPENSSH_SIGNATURE_DENIED');
});

test('controlled Plan executes no seams', { skip }, () => {
  const value = fixture('', false);
  assert.deepEqual(value.events, []);
  assert.equal(value.result.installationBlocked, true);
});

test('supported installed packages are preserved without mutations', { skip }, () => {
  const value = fixture();
  assert.equal(value.marker, false);
  assert.deepEqual(value.result.completed, []);
  assert.ok(!value.events.includes('packageOperationJournal'));
  assert.equal(value.result.nativeQualified, false);
});

test('missing WinGet and packages provision then verify before journal retirement', { skip }, () => {
  const value = fixture("$script:states.winget = 'missing'; $script:states.git = 'missing'; $script:states.python = 'versionUnsupported'; $script:states.ollama = 'missing'; $script:states.ollamaService = 'missing'");
  assert.equal(value.marker, false);
  assert.deepEqual(value.result.completed, ['wingetBootstrap','installgit','installpython','installollama','ollamaStart']);
  assert.equal(value.events.filter(item => item === 'packageOperationJournal').length, 5);
  assert.equal(value.events.filter(item => item === 'packageOperationRetire').length, 5);
});

test('supported VS installation receives additive components rather than duplicate package', { skip }, () => {
  const value = fixture("$script:states.buildTools = 'versionUnsupported'; $script:modify = $true");
  assert.ok(value.events.includes('visualStudioModify'));
  assert.ok(!value.events.includes('installbuildTools'));
  assert.equal(value.marker, false);
});

test('timeouts and failed verification retain journal and block replay', { skip }, () => {
  for (const flag of ['fail','verifyBad']) {
    const value = fixture(`$script:states.python = 'missing'; $script:${flag} = $true`, true, true);
    assert.equal(value.marker, true);
    assert.equal(value.result.operationRetained, true);
    assert.ok(value.second.blockers.includes('WINDOWS_PACKAGE_OPERATION_INDETERMINATE'));
    assert.equal(value.events.filter(item => item === 'installpython').length, 1);
    assert.ok(!value.events.includes('packageOperationRetire'));
  }
});

test('known restart requirement is honest and refuses automatic replay', { skip }, () => {
  const value = fixture("$script:states.git = 'missing'; $script:restart = $true", true, true);
  assert.equal(value.result.restartRequired, true);
  assert.ok(value.result.blockers.includes('WINDOWS_PACKAGE_RESTART_REQUIRED'));
  assert.equal(value.receipt, true);
  assert.ok(value.second.blockers.includes('WINDOWS_PACKAGE_RESTART_RESUME_REQUIRED'));
  assert.equal(value.marker, true);
  assert.equal(value.events.filter(item => item === 'installgit').length, 1);
});

test('spoofed winget source fails before any package mutation', { skip }, () => {
  const value = fixture("$script:sourceBad = $true; $script:states.git = 'missing'");
  assert.ok(value.result.blockers.includes('WINDOWS_WINGET_SOURCE_DENIED'));
  assert.ok(!value.events.includes('packageOperationJournal'));
});


test('explicit restart resume verifies new boot and supported tool, retires both exact records without installer replay', { skip }, () => {
  const value = fixture("$script:states.git = 'missing'; $script:restart = $true", true, true, "$script:boot = '200'; $script:states.git = 'present'; $params.ResumeRestart = $true");
  assert.equal(value.second.componentSucceeded, true);
  assert.equal(value.marker, false);
  assert.equal(value.receipt, false);
  assert.deepEqual(value.second.completed, ['installgit']);
  assert.equal(value.events.filter(item => item === 'installgit').length, 1);
  assert.ok(value.events.indexOf('probe:git', value.events.indexOf('packageResumeReadreceipt')) < value.events.indexOf('packageResumeRetirejournal'));
});

test('resume denies same boot, changed host, unsupported tool and journal identity substitution', { skip }, () => {
  const cases = [
    ['', 'WINDOWS_PACKAGE_RESTART_BOOT_UNCHANGED'],
    ["$script:boot = '200'; $script:hostHash = ('b' * 64)", 'WINDOWS_PACKAGE_RESTART_HOST_DENIED'],
    ["$script:boot = '200'", 'WINDOWS_PACKAGE_RESTART_POSTCONDITION_DENIED'],
    ["$script:boot = '200'; $script:corrupt = $true", 'WINDOWS_PACKAGE_RESTART_RECEIPT_DENIED'],
  ];
  for (const [steer, code] of cases) {
    const value = fixture("$script:states.git = 'missing'; $script:restart = $true", true, true, steer + '; $params.ResumeRestart = $true');
    assert.ok(value.second.blockers.includes(code), JSON.stringify(value.second));
    assert.equal(value.marker, true);
    assert.equal(value.receipt, true);
    assert.ok(!value.events.includes('packageResumeRetirejournal'));
    assert.equal(value.events.filter(item => item === 'installgit').length, 1);
  }
});

test('interrupted retirement leaves orphan receipt blocking unrelated automatic provisioning', { skip }, () => {
  const value = fixture("$script:states.git = 'missing'; $script:restart = $true", true, true, "$script:boot = '200'; $script:states.git = 'present'; $script:retireFail = $true; $params.ResumeRestart = $true");
  assert.ok(value.second.blockers.includes('WINDOWS_PACKAGE_RESTART_RETIRE_UNCERTAIN'));
  assert.equal(value.second.operationRetained, true);
  assert.equal(value.marker, false);
  assert.equal(value.receipt, true);
  const orphan = fixture("$script:receipt = $true; $script:states.python = 'missing'");
  assert.ok(orphan.result.blockers.includes('WINDOWS_PACKAGE_OPERATION_INDETERMINATE'));
  assert.ok(!orphan.events.includes('installpython'));
});


test('restart required before installation never creates a completed-install receipt or authorizes resume', { skip }, () => {
  const value = fixture("$script:states.git = 'missing'; $script:restart = $true; $script:restartCode = -1978334966", true, true, '$params.ResumeRestart = $true');
  assert.equal(value.result.restartRequired, true);
  assert.ok(value.result.blockers.includes('WINDOWS_PACKAGE_RESTART_INSTALL_INCOMPLETE'));
  assert.equal(value.marker, true);
  assert.equal(value.receipt, false);
  assert.ok(value.second.blockers.includes('WINDOWS_PACKAGE_OPERATION_INDETERMINATE'));
  assert.ok(!value.events.includes('packageRestartReceipt'));
});


test('WinGet bootstrap/source admission is conditional on an actual package install', () => {
  const gate = source.indexOf('if ($needsWinGet)');
  assert.ok(gate > source.indexOf('$observations = @{}'));
  assert.ok(gate < source.indexOf("$winget = & $Probe 'winget' $Runner"));
  assert.match(source, /\$before.status -ne 'present' -and \$package.id -ne 'opensshClient' -and -not \(\$package.id -eq 'buildTools' -and \$before.modifyPath\)/);
  assert.match(source, /\$before = \$observations\[\$package.id\]/);
  assert.ok(source.indexOf('$hasMarker -or $hasReceipt') < source.indexOf('$observations = @{}'));
});

test('all supported packages succeed without absent WinGet bootstrap or source probing', { skip }, () => {
  const value = fixture("$script:states.winget = 'missing'");
  assert.equal(value.result.componentSucceeded, true);
  assert.ok(!value.events.includes('probe:winget'));
  assert.ok(!value.events.includes('wingetBootstrap'));
  assert.ok(!value.events.includes('wingetSource'));
  assert.ok(!value.events.includes('packageOperationJournal'));
});

test('VS additive repair and Ollama service start operate independently of absent WinGet', { skip }, () => {
  const value = fixture("$script:states.winget = 'missing'; $script:states.buildTools = 'versionUnsupported'; $script:modify = $true; $script:states.ollamaService = 'missing'");
  assert.equal(value.result.componentSucceeded, true);
  assert.ok(value.events.includes('visualStudioModify'));
  assert.ok(value.events.includes('ollamaStart'));
  assert.ok(!value.events.includes('probe:winget'));
  assert.ok(!value.events.includes('wingetBootstrap'));
  assert.ok(!value.events.includes('wingetSource'));
});

test('missing packages bootstrap WinGet once and verify its exact source before installation', { skip }, () => {
  const value = fixture("$script:states.winget = 'missing'; $script:states.git = 'missing'; $script:states.python = 'missing'");
  assert.equal(value.result.componentSucceeded, true);
  assert.equal(value.events.filter(item => item === 'wingetBootstrap').length, 1);
  assert.equal(value.events.filter(item => item === 'wingetSource').length, 1);
  assert.ok(value.events.indexOf('wingetSource') < value.events.indexOf('installgit'));
  assert.ok(value.events.indexOf('wingetSource') < value.events.indexOf('installpython'));
});

test('retained uncertain journal denies before prerequisite or WinGet probing', { skip }, () => {
  const value = fixture("$script:marker = $true; $script:states.winget = 'missing'; $script:states.git = 'missing'");
  assert.equal(value.result.componentSucceeded, false);
  assert.equal(value.result.operationRetained, true);
  assert.ok(value.result.blockers.includes('WINDOWS_PACKAGE_OPERATION_INDETERMINATE'));
  assert.deepEqual(value.events, []);
});
