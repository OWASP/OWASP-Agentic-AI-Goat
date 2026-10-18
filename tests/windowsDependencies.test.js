'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const filename = path.join(root, 'scripts/install/Windows/dependencies.ps1');
const source = fs.readFileSync(filename, 'utf8');
const quote = value => "'" + value.replaceAll("'", "''") + "'";
const interpreter = ['pwsh', 'powershell'].find(command => spawnSync(command, ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'], { encoding: 'utf8', timeout: 5000 }).status === 0);
const skip = !interpreter && 'PowerShell unavailable; controlled interpreter tests not run; no live OS/package execution requested';

function fixture(steer = '', execute = true) {
  const program = `
. ${quote(filename)}
$script:events = New-Object 'System.Collections.Generic.List[string]'
$script:bootstrapOk = $true; $script:throwBootstrap = $false; $script:packagesOk = $true; $script:restart = $false; $script:retained = $false; $script:npmVersion = '12.1.0'; $script:badBinding = $false; $script:labMode = ''
$base = [IO.Path]::GetTempPath()
$script:runtime = @{ nodeExecutable = (Join-Path $base 'managed node/node.exe'); npmCli = (Join-Path $base 'managed npm/npm-cli.js'); npmExecpath = (Join-Path $base 'managed npm/npm-cli.js') }
$bootstrap = { param($Request)
 $script:events.Add('bootstrap')
 if ($script:throwBootstrap) { throw 'private secret must not escape' }
 return [pscustomobject]@{ schemaVersion = 1; component = 'windows-native-prerequisites'; componentSucceeded = $script:bootstrapOk; runtime = $script:runtime; blockers = @('WINDOWS_GLOBAL_INSTALL_UNQUALIFIED'); restartRequired = $false; diagnostic = 'private secret must not escape' }
}
$packages = { param($Request)
 $script:events.Add('packages')
 if ($Request.runtime.nodeExecutable -cne $script:runtime.nodeExecutable -or $Request.runtime.npmCli -cne $script:runtime.npmCli) { throw 'MISSING_EXPLICIT_RUNTIME' }
 $dependencies = @('git','python','buildTools','ollama','multipass','opensshClient') | ForEach-Object { [pscustomobject]@{ id = $_; status = 'present'; path = (Join-Path $base ($_ + '/owned binary')) } }
 if ($script:badBinding) { $dependencies[1].path = 'relative.exe' }
 if ($script:labMode -eq 'missing') { $dependencies = @($dependencies | Where-Object { $_.id -ne 'multipass' }) }
 if ($script:labMode -eq 'duplicate') { $dependencies += $dependencies[5] }
 if ($script:labMode -eq 'unsupported') { $dependencies[4].status = 'versionUnsupported' }
 if ($script:labMode -eq 'relative') { $dependencies[5].path = 'relative ssh.exe' }
 if ($script:labMode -eq 'control') { $dependencies[4].path += [char]0 }
 $dependencies += [pscustomobject]@{ id = 'ollamaService'; status = 'present' }
 return [pscustomobject]@{ schemaVersion = 1; component = 'windows-native-packages'; componentSucceeded = $script:packagesOk; dependencies = $dependencies; blockers = @('WINDOWS_PACKAGE_RESTART_REQUIRED','private secret must not escape'); restartRequired = $script:restart; operationRetained = $script:retained }
}
$runner = { param($Request)
 $script:events.Add($Request.id)
 if ($Request.executable -cne $script:runtime.nodeExecutable -or $Request.timeoutMs -ne 10000 -or $Request.elevate) { throw 'UNSAFE_RUNTIME_PROBE' }
 if ($Request.id -eq 'handoffNode') { return @{ exitCode = 0; output = 'v26.10.0' } }
 if ($Request.id -eq 'handoffNpm' -and $Request.arguments[0] -ceq $script:runtime.npmCli) { return @{ exitCode = 0; output = $script:npmVersion } }
 throw 'UNEXPECTED_PROCESS'
}
$caller = New-Object 'System.Collections.Generic.Dictionary[string,string]'
$caller.Add('PATH',(Join-Path $base 'prior tools')); $caller.Add('Path',(Join-Path $base 'other tools'))
$caller.Add('TOKEN','synthetic private caller token'); $caller.Add('PYTHON','conflicting python'); $caller.Add('VCINSTALLDIR','conflicting VS')
$caller.Add('dvaia_windows_multipass_executable','conflicting multipass'); $caller.Add('Dvaia_Windows_Ssh_Executable','conflicting ssh')
${steer}
$result = Invoke-DvaiaWindowsDependencies -ExecuteMode $${execute} -RepoRoot ${quote(root)} -UserProfile $base -SystemRoot $base -Bootstrap $bootstrap -Packages $packages -Runner $runner -ProcessEnvironment $caller
$childSummary = $null
if ($result.childEnvironment) { $childSummary = @{ path = $result.childEnvironment['Path']; pathKeys = @($result.childEnvironment.Keys | Where-Object { $_ -ieq 'Path' }); npm = $result.childEnvironment['npm_execpath']; python = $result.childEnvironment['PYTHON']; forcedPython = $result.childEnvironment['NODE_GYP_FORCE_PYTHON']; vs = $result.childEnvironment['npm_package_config_node_gyp_msvs_version']; multipass = $result.childEnvironment['DVAIA_WINDOWS_MULTIPASS_EXECUTABLE']; ssh = $result.childEnvironment['DVAIA_WINDOWS_SSH_EXECUTABLE']; labKeys = @($result.childEnvironment.Keys | Where-Object { $_ -ieq 'DVAIA_WINDOWS_MULTIPASS_EXECUTABLE' -or $_ -ieq 'DVAIA_WINDOWS_SSH_EXECUTABLE' }); secretPreserved = ($result.childEnvironment['TOKEN'] -ceq $caller['TOKEN']); inheritedVsRemoved = (-not $result.childEnvironment.ContainsKey('VCINSTALLDIR')) } }
@{ result = (ConvertTo-DvaiaWindowsDependenciesPublicResult $result); events = @($script:events); child = $childSummary; callerPreserved = ($caller['PYTHON'] -ceq 'conflicting python' -and $caller['VCINSTALLDIR'] -ceq 'conflicting VS' -and $caller['dvaia_windows_multipass_executable'] -ceq 'conflicting multipass' -and $caller['Dvaia_Windows_Ssh_Executable'] -ceq 'conflicting ssh' -and $caller.ContainsKey('PATH') -and $caller.ContainsKey('Path')) } | ConvertTo-Json -Depth 8 -Compress
`;
  const run = spawnSync(interpreter, ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(run.stdout, /private secret|synthetic private caller token/);
  return JSON.parse(run.stdout);
}

test('Plan exits before component import, invocation or any runtime probe', () => {
  assert.match(source, /runtime-version-policy\.sh/);
  const gate = source.indexOf('if (-not $ExecuteMode)');
  assert.ok(gate < source.indexOf(". (Join-Path $PSScriptRoot 'packages.ps1')"));
  assert.ok(gate < source.indexOf('& $Bootstrap'));
  assert.ok(gate < source.indexOf('& $Runner'));
  assert.match(source, /componentSucceeded = \$false; installationBlocked = \$true/);
});

test('coordinator enforces ordered verified runtime and explicit handoff bindings without retries or PATH mutation', () => {
  assert.ok(source.indexOf('& $Bootstrap') < source.indexOf("id = 'handoffNode'"));
  assert.ok(source.indexOf("id = 'handoffNpm'") < source.indexOf('& $Packages'));
  assert.match(source, /executable = \$binding.nodeExecutable; arguments = @\(\$binding.npmCli,'--version'\)/);
  assert.match(source, /\$request.runtime = @\{ nodeExecutable/);
  assert.match(source, /\$stage.restartRequired -or \$stage.operationRetained/);
  assert.match(source, /operationRetained = \$null; \$result.operationUncertain = \$true/);
  assert.match(source, /gitExecutable.*pythonExecutable.*visualStudioInstallation.*ollamaExecutable/);
  assert.match(source, /if \(\$Execute -and -not \$output.componentSucceeded\) \{ exit 1 \}/);
  assert.doesNotMatch(source, /-ResumeRestart|Restart-Computer|SetEnvironmentVariable|Set-ExecutionPolicy|Invoke-WebRequest|Start-Process|\.env|--allow-reboot/);
  for (const wrapper of ['install-windows.ps1','start_all.ps1']) assert.ok(!fs.readFileSync(path.join(root,'scripts/install/Windows',wrapper),'utf8').includes('dependencies.ps1'));
});

test('component data boundary projects only closed statuses and safe codes', () => {
  assert.match(source, /\^WINDOWS_\[A-Z0-9_\]\+\$/);
  assert.match(source, /WINDOWS_DEPENDENCIES_COMPONENT_CONTRACT_DENIED/);
  assert.match(source, /WINDOWS_DEPENDENCIES_RUNTIME_BINDING_DENIED/);
  assert.match(source, /WINDOWS_DEPENDENCIES_PACKAGE_BINDING_DENIED/);
  assert.match(source, /WINDOWS_DEPENDENCIES_OLLAMA_HANDOFF_DENIED/);
});

test('controlled Plan invokes no seam', { skip }, () => {
  const value = fixture('', false);
  assert.deepEqual(value.events, []);
  assert.equal(value.result.nonMutating, true);
  assert.equal(value.result.componentSucceeded, false);
});

test('controlled successful handoff verifies Node/npm before packages and returns all absolute bindings', { skip }, () => {
  const value = fixture();
  assert.deepEqual(value.events, ['bootstrap','handoffNode','handoffNpm','packages']);
  assert.equal(value.result.componentSucceeded, true);
  assert.equal(value.result.installationBlocked, true);
  for (const key of ['nodeExecutable','npmCli','npmExecpath','gitExecutable','pythonExecutable','visualStudioInstallation','ollamaExecutable','multipassExecutable','sshExecutable']) assert.ok(path.isAbsolute(value.result.bindings[key]));
});

test('bootstrap failure or bad npm handoff stops before any package invocation', { skip }, () => {
  for (const steer of ['$script:bootstrapOk = $false', "$script:npmVersion = '11.19.1'", "$script:runtime.npmCli = 'relative.js'"]) {
    const value = fixture(steer);
    assert.equal(value.result.componentSucceeded, false);
    assert.ok(!value.events.includes('packages'));
    assert.equal(value.events.filter(id => id === 'bootstrap').length, 1);
  }
});

test('package restart and uncertainty remain retained without automatic resume/retry', { skip }, () => {
  for (const steer of ['$script:packagesOk = $false; $script:restart = $true; $script:retained = $true', '$script:packagesOk = $false; $script:retained = $true']) {
    const value = fixture(steer);
    assert.equal(value.result.componentSucceeded, false);
    assert.equal(value.result.operationRetained, true);
    assert.equal(value.events.filter(id => id === 'packages').length, 1);
    assert.equal(value.result.bindings, null);
  }
});

test('provider exceptions are sanitized and package binding failure cannot claim completion', { skip }, () => {
  const failed = fixture('$script:throwBootstrap = $true');
  assert.ok(failed.result.blockers.includes('WINDOWS_DEPENDENCIES_FAILED'));
  assert.equal(failed.result.operationUncertain, true);
  assert.equal(failed.result.operationRetained, null);
  const invalid = fixture('$script:badBinding = $true');
  assert.ok(invalid.result.blockers.includes('WINDOWS_DEPENDENCIES_PACKAGE_BINDING_DENIED'));
  assert.equal(invalid.result.componentSucceeded, false);
});


test('child environment is integrated before success and CLI uses explicit public projection', () => {
  assert.match(source, /function New-DvaiaWindowsDependencyEnvironment/);
  assert.ok(source.indexOf('$result.childEnvironment = New-DvaiaWindowsDependencyEnvironment') < source.indexOf('$result.componentSucceeded = $true'));
  assert.match(source, /ConvertTo-DvaiaWindowsDependenciesPublicResult \$output \| ConvertTo-Json/);
  const projection = source.slice(source.indexOf('function ConvertTo-DvaiaWindowsDependenciesPublicResult'),source.indexOf('function Invoke-DvaiaWindowsDependencies'));
  assert.doesNotMatch(projection.match(/foreach \(\$key in @\((.*)\)/)[1], /childEnvironment/);
  assert.match(source, /NODE_GYP_FORCE_PYTHON/);
  assert.match(source, /npm_package_config_node_gyp_msvs_version/);
  assert.match(source, /'VCINSTALLDIR'/);
  assert.doesNotMatch(source, /\$env:[^\n]*=|SetEnvironmentVariable/);
});

test('VS path environment option is supported by both installed locked node-gyp implementations', () => {
  for (const prefix of ['node_modules/node-gyp','node_modules/sqlite3/node_modules/node-gyp']) {
    const config = fs.readFileSync(path.join(root,prefix,'lib/node-gyp.js'),'utf8');
    const finder = fs.readFileSync(path.join(root,prefix,'lib/find-visualstudio.js'),'utf8');
    assert.match(config, /npm_package_config_node_gyp_/);
    assert.match(config, /replaceAll\('_', '-'\)/);
    assert.match(finder, /this.configPath = path.resolve\(this.configMsvsVersion\)/);
  }
});

test('coordinator admits explicit Multipass and OpenSSH bindings and child-only closed environment keys', () => {
  assert.match(source, /id = 'multipass'; key = 'multipassExecutable'/);
  assert.match(source, /id = 'opensshClient'; key = 'sshExecutable'/);
  assert.match(source, /multipassExecutable = \$paths.multipassExecutable; sshExecutable = \$paths.sshExecutable/);
  assert.match(source, /'DVAIA_WINDOWS_MULTIPASS_EXECUTABLE',\$Bindings.multipassExecutable/);
  assert.match(source, /'DVAIA_WINDOWS_SSH_EXECUTABLE',\$Bindings.sshExecutable/);
  assert.match(source, /replace the child's inherited environment \(Clear \+/);
  assert.match(source, /WINDOWS_PROTECTED_LAB_INTEGRATION_PENDING/);
  assert.doesNotMatch(source, /DVAIA_WINDOWS_.*=|BACKEND_UNDECIDED|Docker\/Compose and protected lab backend decision/);
});

test('missing duplicate unsupported relative or control-containing lab handoff bindings deny component completion', { skip }, () => {
  for (const mode of ['missing','duplicate','unsupported','relative','control']) {
    const value = fixture(`$script:labMode = '${mode}'`);
    assert.equal(value.result.componentSucceeded, false);
    assert.equal(value.child, null);
    assert.ok(value.result.blockers.some(code => ['WINDOWS_DEPENDENCIES_PACKAGE_BINDING_DENIED','WINDOWS_DEPENDENCIES_CHILD_BINDING_DENIED'].includes(code)));
  }
});

test('controlled copied child environment preserves secrets and spaces, collapses Path keys and selects admitted Python/VS', { skip }, () => {
  const value = fixture();
  assert.equal(value.result.componentSucceeded, true);
  assert.deepEqual(value.child.pathKeys, ['Path']);
  assert.ok(value.child.path.startsWith(path.dirname(value.result.bindings.nodeExecutable) + ';'));
  for (const key of ['gitExecutable','pythonExecutable','ollamaExecutable']) assert.ok(value.child.path.includes(path.dirname(value.result.bindings[key])));
  assert.ok(value.child.path.includes('prior tools'));
  assert.ok(value.child.path.includes('other tools'));
  assert.equal(value.child.npm,value.result.bindings.npmCli);
  assert.equal(value.child.python,value.result.bindings.pythonExecutable);
  assert.equal(value.child.forcedPython,value.result.bindings.pythonExecutable);
  assert.equal(value.child.vs,value.result.bindings.visualStudioInstallation);
  assert.equal(value.child.multipass,value.result.bindings.multipassExecutable);
  assert.equal(value.child.ssh,value.result.bindings.sshExecutable);
  assert.deepEqual(value.child.labKeys.sort(),['DVAIA_WINDOWS_MULTIPASS_EXECUTABLE','DVAIA_WINDOWS_SSH_EXECUTABLE']);
  assert.equal(value.child.secretPreserved,true);
  assert.equal(value.child.inheritedVsRemoved,true);
  assert.equal(value.callerPreserved,true);
  assert.ok(!Object.hasOwn(value.result,'childEnvironment'));
});

test('pure environment builder rejects missing, relative, control-containing and inconsistent bindings', { skip }, () => {
  const program = `
. ${quote(filename)}
$base = [IO.Path]::GetTempPath()
$valid = @{ nodeExecutable = (Join-Path $base 'Node folder/node.exe'); npmCli = (Join-Path $base 'npm folder/npm-cli.js'); npmExecpath = (Join-Path $base 'npm folder/npm-cli.js'); gitExecutable = (Join-Path $base 'Git folder/git.exe'); pythonExecutable = (Join-Path $base 'Python folder/python.exe'); ollamaExecutable = (Join-Path $base 'Ollama folder/ollama.exe'); visualStudioInstallation = (Join-Path $base 'VS folder'); multipassExecutable = (Join-Path $base 'Multipass folder/multipass.exe'); sshExecutable = (Join-Path $base 'OpenSSH folder/ssh.exe') }
$codes = @()
foreach ($case in @('missing','relative','control','mismatch','type','missingLab','relativeLab','controlLab')) {
 $value = $valid.Clone()
 switch ($case) { 'missing' { $value.Remove('gitExecutable') }; 'relative' { $value.pythonExecutable = 'relative.exe' }; 'control' { $value.ollamaExecutable += [char]0 }; 'mismatch' { $value.npmExecpath = $value.nodeExecutable }; 'type' { $value.nodeExecutable = 42 }; 'missingLab' { $value.Remove('multipassExecutable') }; 'relativeLab' { $value.sshExecutable = 'relative ssh.exe' }; 'controlLab' { $value.multipassExecutable += [char]0 } }
 try { New-DvaiaWindowsDependencyEnvironment -Bindings $value -Environment @{ TOKEN = 'synthetic caller token' } | Out-Null; $codes += 'accepted' } catch { $codes += $_.Exception.Message }
}
$codes | ConvertTo-Json -Compress
`;
  const run = spawnSync(interpreter,['-NoProfile','-NonInteractive','-Command',program],{encoding:'utf8',timeout:10000});
  assert.equal(run.status,0,run.stderr);
  assert.deepEqual(JSON.parse(run.stdout),Array(8).fill('WINDOWS_DEPENDENCIES_CHILD_BINDING_DENIED'));
});
