'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const filename = path.join(root, 'scripts/install/Windows/wrapper-handoff.ps1');
const source = fs.readFileSync(filename, 'utf8');
const read = name => fs.readFileSync(path.join(root,'scripts/install/Windows',name),'utf8');
const quote = value => "'" + value.replaceAll("'", "''") + "'";
const interpreter = ['pwsh','powershell'].find(command => spawnSync(command,['-NoProfile','-NonInteractive','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8',timeout:5000}).status === 0);
const skip = !interpreter && 'PowerShell unavailable; controlled composition tests skipped; no real installation/OS/VM execution requested';

function fixture(steer = '', kind = 'setup') {
  const program = `
. ${quote(filename)}
$script:events = New-Object 'System.Collections.Generic.List[string]'
$base = [IO.Path]::GetTempPath()
$bindings = @{ nodeExecutable = (Join-Path $base 'node folder/node.exe'); npmCli = (Join-Path $base 'npm folder/npm-cli.js'); npmExecpath = (Join-Path $base 'npm folder/npm-cli.js'); gitExecutable = (Join-Path $base 'git folder/git.exe'); pythonExecutable = (Join-Path $base 'python folder/python.exe'); visualStudioInstallation = (Join-Path $base 'VS folder'); ollamaExecutable = (Join-Path $base 'ollama folder/ollama.exe'); multipassExecutable = (Join-Path $base 'multipass folder/multipass.exe'); sshExecutable = (Join-Path $base 'SSH folder/ssh.exe') }
$caller = @{ Path = 'prior path'; TOKEN = 'synthetic private token'; VCINSTALLDIR = 'unrelated VS'; OWASP_AI_GOAT_WINDOWS_SSH_EXECUTABLE = 'unrelated SSH' }
$script:ok = $true; $script:retained = $false; $script:restart = $false; $script:exitCode = 0; $script:privateFailure = $false; $script:captured = $null
$provider = { param($Request) return @{ componentSucceeded = $script:ok; bindings = $bindings; restartRequired = $script:restart; operationRetained = $script:retained; operationUncertain = $false; childEnvironment = @{ TOKEN = 'malicious supplied environment' } } }
$provision = { param($Request) $script:events.Add('provision'); & $provider $Request }
$discover = { param($Request) $script:events.Add('discover'); & $provider $Request }
$runner = { param($Request)
 $script:events.Add('canonical')
 if ($script:privateFailure) { throw 'synthetic private error not printable' }
 $script:captured = @{ executable = $Request.executable; arguments = @($Request.arguments); secretPreserved = ($Request.environment['TOKEN'] -ceq $caller['TOKEN']); inheritedVsRemoved = (-not $Request.environment.ContainsKey('VCINSTALLDIR')); ssh = $Request.environment['OWASP_AI_GOAT_WINDOWS_SSH_EXECUTABLE']; multipass = $Request.environment['OWASP_AI_GOAT_WINDOWS_MULTIPASS_EXECUTABLE']; npm = $Request.environment['npm_execpath'] }
 return @{ exitCode = $script:exitCode }
}
$params = @{ Kind = '${kind}'; CompositionReady = $true; RepoRoot = ${quote(root)}; UserProfile = $base; SystemRoot = $base; Environment = $caller; ObserveHost = { $script:events.Add('host'); @{ hostSupported = $true } }; RootEnvironmentExists = { param($File) $script:events.Add('rootEnv'); return $false }; IsElevated = { $false }; Provision = $provision; Discover = $discover; Runner = $runner }
${steer}
$result = Invoke-OwaspAiGoatWindowsWrapperHandoff @params
@{ result = $result; events = @($script:events); captured = $script:captured; callerPreserved = ($caller.TOKEN -ceq 'synthetic private token' -and $caller.VCINSTALLDIR -ceq 'unrelated VS' -and $caller.OWASP_AI_GOAT_WINDOWS_SSH_EXECUTABLE -ceq 'unrelated SSH') } | ConvertTo-Json -Depth 8 -Compress
`;
  const run = spawnSync(interpreter,['-NoProfile','-NonInteractive','-Command',program],{encoding:'utf8',timeout:10000});
  assert.equal(run.status,0,run.stderr);
  assert.doesNotMatch(run.stdout,/synthetic private token|synthetic private error|malicious supplied environment/);
  return JSON.parse(run.stdout);
}

test('wrappers enable qualified composition and retain host admission with Stop before that gate', () => {
  for (const name of ['install-windows.ps1','start_all.ps1']) {
    const wrapper = read(name);
    assert.match(wrapper,/wrapper-handoff\.ps1/);
    assert.match(wrapper,/Invoke-OwaspAiGoatWindowsWrapperHandoff/);
    assert.match(wrapper,/-CompositionReady \$true/);
    assert.doesNotMatch(wrapper,/WINDOWS_NATIVE_(?:INSTALL|START)_UNQUALIFIED|remains blocked|integration remain incomplete/);
    assert.match(wrapper,/if \(\$MyInvocation.InvocationName -ne '\.'\)/);
    assert.match(wrapper,/did not require Node\.js/);
  }
  assert.ok(read('start_all.ps1').indexOf('if ($Stop)') < read('start_all.ps1').indexOf('wrapper-handoff.ps1'));
});

test('canonical runner replaces full child environment, direct argv and bounded setup while start owns foreground lifetime', () => {
  assert.match(source,/EnvironmentVariables.Clear\(\)/);
  assert.match(source,/UseShellExecute = \$false/);
  assert.match(source,/ConvertTo-OwaspAiGoatProcessArgument/);
  assert.match(source,/WorkingDirectory = \$Request.repoRoot/);
  assert.match(source,/WaitForExit\(3600000\)/);
  assert.match(source,/if \(\$Request.kind -ceq 'start'\).*?[\s\S]*?\$child.WaitForExit\(\)/);
  assert.doesNotMatch(source,/SetEnvironmentVariable|Set-ExecutionPolicy|SecurityProtocol|powershell.*Bypass|&\s*npm|cmd\.exe|ReadToEnd|\.Kill\(/);
});

test('fresh guard and Plan precede provisioning; upgrade/start discovery cannot install or start services', () => {
  const invoke = source.slice(source.indexOf('function Invoke-OwaspAiGoatWindowsWrapperHandoff'));
  assert.ok(invoke.indexOf('WINDOWS_FRESH_ENVIRONMENT_EXISTS') < invoke.indexOf('& $Provision'));
  assert.ok(invoke.indexOf('if ($PlanMode -or $result.blockers.Count') < invoke.indexOf('& $Provision'));
  assert.match(invoke,/-not \$Upgrade -or \$Repair/);
  assert.match(invoke,/WINDOWS_WRAPPER_RUN_AS_NORMAL_USER/);
  const discover = source.slice(source.indexOf('function Get-OwaspAiGoatWindowsWrapperBindings'),source.indexOf('function New-OwaspAiGoatWindowsCanonicalProcessInfo'));
  assert.match(discover,/npm-bootstrap-operation.json','windows-package-operation.json','windows-package-restart.json/);
  assert.match(discover,/runtimePolicy|Get-OwaspAiGoatDependencyCoordinatorPolicy/);
  assert.doesNotMatch(discover,/Invoke-OwaspAiGoatWindowsDependencies|Invoke-OwaspAiGoatWindowsPackages|Invoke-OwaspAiGoatWindowsPrerequisites|Start-Process|install.*arguments/i);
});

test('controlled fresh and no-install native provisioning precedes canonical argv with safe child environment', { skip }, () => {
  for (const steer of ['', '$params.NoInstall = $true']) {
    const value = fixture(steer);
    assert.deepEqual(value.events,['host','rootEnv','provision','canonical']);
    assert.equal(value.result.componentSucceeded,true);
    assert.equal(value.captured.secretPreserved,true);
    assert.equal(value.captured.inheritedVsRemoved,true);
    assert.equal(value.captured.ssh,value.result.bindings.sshExecutable);
    assert.equal(value.captured.multipass,value.result.bindings.multipassExecutable);
    assert.equal(value.captured.npm,value.result.bindings.npmCli);
    assert.equal(value.callerPreserved,true);
    assert.equal(value.captured.arguments.includes('--no-install'), Boolean(steer));
  }
});

test('controlled additive upgrade discovers existing bindings; repair provisions native dependencies and maps canonical flag', { skip }, () => {
  const upgrade = fixture('$params.Upgrade = $true');
  assert.deepEqual(upgrade.events,['host','discover','canonical']);
  assert.equal(upgrade.captured.arguments.at(-1),'--upgrade');
  const repair = fixture('$params.Repair = $true');
  assert.deepEqual(repair.events,['host','provision','canonical']);
  assert.equal(repair.captured.arguments.at(-1),'--repair');
  const repairNoInstall = fixture('$params.Repair = $true; $params.NoInstall = $true');
  assert.deepEqual(repairNoInstall.events,['host','provision','canonical']);
  assert.deepEqual(repairNoInstall.captured.arguments.slice(1),['--no-install','--repair']);
  assert.equal(repairNoInstall.captured.secretPreserved,true);
  assert.equal(repairNoInstall.captured.inheritedVsRemoved,true);
  const upgradeNoInstall = fixture('$params.Upgrade = $true; $params.NoInstall = $true');
  assert.deepEqual(upgradeNoInstall.events,['host','discover','canonical']);
  assert.deepEqual(upgradeNoInstall.captured.arguments.slice(1),['--no-install','--upgrade']);
});

test('controlled Plan composition pending unsupported host fresh existing env and elevated caller deny all mutation', { skip }, () => {
  for (const steer of [
    '$params.PlanMode = $true', '$params.CompositionReady = $false',
    '$params.ObserveHost = { @{ hostSupported = $false } }',
    '$params.RootEnvironmentExists = { $true }', '$params.IsElevated = { $true }',
  ]) {
    const value = fixture(steer);
    assert.equal(value.result.componentSucceeded,false);
    assert.ok(!value.events.includes('provision'));
    assert.ok(!value.events.includes('canonical'));
  }
});

test('controlled retained uncertain restart and canonical failure never claim success or replay', { skip }, () => {
  for (const steer of ['$script:ok = $false','$script:retained = $true','$script:restart = $true','$script:exitCode = 1','$script:privateFailure = $true']) {
    const value = fixture(steer);
    assert.equal(value.result.componentSucceeded,false);
    assert.equal(value.events.filter(event => event === 'provision').length,1);
    assert.ok(value.result.blockers.some(code => /^WINDOWS_WRAPPER_/.test(code)));
  }
});

test('controlled startup only discovers dependencies and maps additive init-db without provisioning', { skip }, () => {
  const value = fixture('$params.InitDb = $true','start');
  assert.deepEqual(value.events,['host','discover','canonical']);
  assert.equal(value.result.componentSucceeded,true);
  assert.equal(value.captured.arguments.at(-1),'--init-db');
  assert.match(value.captured.arguments[0],/scripts[\\/]start-application.js$/);
  assert.equal(value.captured.secretPreserved,true);
  assert.equal(value.captured.inheritedVsRemoved,true);
  assert.equal(value.captured.npm,value.result.bindings.npmCli);
  assert.equal(value.callerPreserved,true);
});

test('controlled host denial precedes every fresh repair upgrade startup and Plan provider flavor', { skip }, () => {
  for (const [kind, flags] of [['setup',''],['setup','$params.NoInstall = $true'],['setup','$params.Repair = $true'],['setup','$params.Upgrade = $true'],['start',''],['start','$params.InitDb = $true'],['setup','$params.PlanMode = $true'],['start','$params.PlanMode = $true']]) {
    const value = fixture(flags + '; $params.ObserveHost = { $script:events.Add("deniedHost"); @{ hostSupported = $false } }',kind);
    assert.equal(value.result.componentSucceeded,false);
    assert.ok(value.result.blockers.includes('WINDOWS_HOST_PREFLIGHT_DENIED'));
    assert.ok(value.events.every(event => ['deniedHost','rootEnv'].includes(event)));
    assert.equal(value.captured,null);
  }
});

test('controlled process descriptor clears inherited environment and quotes paths with spaces without spawning', { skip }, () => {
  const program = `. ${quote(filename)}; $base = [IO.Path]::GetTempPath(); $request = @{ kind = 'setup'; repoRoot = ${quote(root)}; executable = (Join-Path $base 'Node with spaces/node.exe'); arguments = @((Join-Path ${quote(root)} 'scripts/setup-application.js'),'--repair'); environment = @{ TOKEN = 'private synthetic token'; Path = 'bound child path' } }; $info = New-OwaspAiGoatWindowsCanonicalProcessInfo $request; @{ shell = $info.UseShellExecute; file = $info.FileName; arguments = $info.Arguments; count = $info.EnvironmentVariables.Count; hasOnlyRequested = ($info.EnvironmentVariables['TOKEN'] -ceq 'private synthetic token' -and $info.EnvironmentVariables['Path'] -ceq 'bound child path') } | ConvertTo-Json -Compress`;
  const run = spawnSync(interpreter,['-NoProfile','-NonInteractive','-Command',program],{encoding:'utf8',timeout:10000});
  assert.equal(run.status,0,run.stderr);
  const value = JSON.parse(run.stdout);
  assert.equal(value.shell,false);
  assert.equal(value.count,2);
  assert.equal(value.hasOnlyRequested,true);
  assert.match(value.arguments,/^".*setup-application.js" "--repair"$/);
});

test('controlled actual discovery prefers compatible PATH Node, exact private npm and managed fallback without mutation', { skip }, () => {
  for (const variant of ['installed','fallback','retained','missingNpm','missingPackage']) {
    const program = `
. ${quote(filename)}
$base = [IO.Path]::GetTempPath(); $script:events = New-Object 'System.Collections.Generic.List[string]'
$request = @{ repoRoot = ${quote(root)}; userProfile = $base; systemRoot = $base; environment = @{ TOKEN = 'synthetic private caller token'; Path = 'prior tools' } }
$find = { Join-Path $base 'installed Node/node.exe' }
$exists = { param($File) if ($File -match 'operation.json$|restart.json$') { return ${variant === 'retained' ? '$true' : '$false'} }; return $true }
$runner = { param($Request)
 $script:events.Add($Request.id)
 if ($Request.id -eq 'wrapperNodeVersion') { return @{ exitCode = 0; output = $(if (${variant === 'fallback' ? '$true' : '$false'} -and $Request.executable -match 'installed Node') { 'v26.9.0' } else { 'v26.10.0' }) } }
 if ($Request.id -eq 'wrapperNpmVersion') { return @{ exitCode = 0; output = ${variant === 'missingNpm' ? "'11.19.1'" : "'12.1.0'"} } }
 throw 'UNEXPECTED_MUTATION'
}
$probe = { param($Id,$Runner) $script:events.Add('probe:' + $Id); return @{ id = $Id; status = $(if (${variant === 'missingPackage' ? '$true' : '$false'} -and $Id -eq 'multipass') { 'missing' } else { 'present' }); path = (Join-Path $base ($Id + '/owned path')) } }
try { $result = Get-OwaspAiGoatWindowsWrapperBindings -Request $request -Runner $runner -Probe $probe -Find $find -Exists $exists -NormalFile { $true }; @{ bindings = $result.bindings; events = @($script:events); copied = ($result.childEnvironment['TOKEN'] -ceq $request.environment.TOKEN) } | ConvertTo-Json -Depth 5 -Compress }
catch { @{ code = $_.Exception.Message; events = @($script:events) } | ConvertTo-Json -Compress }
`;
    const run = spawnSync(interpreter,['-NoProfile','-NonInteractive','-Command',program],{encoding:'utf8',timeout:10000});
    assert.equal(run.status,0,run.stderr);
    assert.doesNotMatch(run.stdout,/synthetic private caller token/);
    const value = JSON.parse(run.stdout);
    if (variant === 'retained') {
      assert.equal(value.code,'WINDOWS_WRAPPER_OPERATION_RETAINED');
      assert.deepEqual(value.events,[]);
    } else if (variant === 'missingNpm') assert.equal(value.code,'WINDOWS_WRAPPER_NPM_UNAVAILABLE');
    else if (variant === 'missingPackage') assert.equal(value.code,'WINDOWS_WRAPPER_PACKAGE_UNAVAILABLE');
    else {
      assert.equal(value.copied,true);
      assert.match(value.bindings.nodeExecutable,variant === 'fallback' ? /node-v26\.10\.0-win-x64/ : /installed Node/);
      assert.match(value.bindings.npmCli,/npm-12\.1\.0/);
      assert.equal(Object.keys(value.bindings).length,9);
      assert.ok(value.events.every(event => /Version$|^probe:/.test(event)));
    }
  }
});
