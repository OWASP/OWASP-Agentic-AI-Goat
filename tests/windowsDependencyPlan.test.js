'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const scriptPath = path.join(root, 'scripts/install/Windows/dependency-plan.ps1');
const source = fs.readFileSync(scriptPath, 'utf8');
const executableSource = source.replace(/<#[\s\S]*?#>/g, '').replace(/^\s*#.*$/gm, '');
const quotePs = value => "'" + value.replaceAll("'", "''") + "'";
// Optional interpreter execution runs only injected probes. No native inventory,
// packages, services, model generation, browser launch or database access occurs.
const interpreter = ['pwsh', 'powershell'].find(command => {
  const result = spawnSync(command, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'], { encoding: 'utf8', timeout: 5000 });
  return result.status === 0 && /^\s*[5-9]\d*\s*$/.test(result.stdout);
});

function controlledPlan(overrides = '', environmentOverrides = '', sdkReady = true) {
  const fixture = `
. ${quotePs(scriptPath)}
$observations = @{
  node = @{ available = $true; exitCode = 0; output = 'v26.10.0' }
  npm = @{ available = $true; exitCode = 0; output = '12.1.0' }
  git = @{ available = $true; exitCode = 0; output = 'git version 2.51.0.windows.1' }
  ollama = @{ available = $true; exitCode = 0; output = 'ollama version is 0.12.0' }
  python = @{ available = $true; exitCode = 0; output = 'Python 3.13.0' }
  cppBuildTools = @{ available = $true; exitCode = 0; output = '17.14.10.0' }
  docker = @{ available = $true; exitCode = 0; output = 'Docker version 28.0.0, build example' }
  compose = @{ available = $true; exitCode = 0; output = '2.38.0' }
  linuxDockerDaemon = @{ available = $true; exitCode = 0; output = 'linux' }
  ollamaModel = @{ available = $true; exitCode = 0; output = "NAME ID SIZE\nllama3.1:8b fixture 4.9GB" }
}
$environment = @{ Windows = $true; Architecture = 'AMD64'; Browser = ${quotePs(scriptPath)}; ExternalPostgres = $false }
${overrides}
${environmentOverrides}
$probe = { param($Name, $Command, $Arguments) $observations[$Name] }
Get-OwaspAiGoatWindowsDependencyPlan -RepoRoot ${quotePs(root)} -Environment $environment -Probe $probe -PathProbe { param($Path) $true } -SdkProbe { param($Path) ${sdkReady ? '$true' : '$false'} } | ConvertTo-Json -Depth 6
`;
  const result = spawnSync(interpreter, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', fixture], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
const states = plan => Object.fromEntries(plan.dependencies.map(item => [item.id, item.status]));

test('inventory bounds pipe draining after process exit', () => {
  assert.match(source, /WaitAll\(\[Threading\.Tasks\.Task\[\]\]@\(\$stdout, \$stderr\), 1000\)/);
  assert.doesNotMatch(source, /\$std(?:out|err)\.Result\b/);
  assert.ok(source.indexOf('::WaitAll') < source.indexOf('$stdout.GetAwaiter().GetResult()'));
});

test('Windows dependency planning uses the shared qualified runtime floor and actual locked native addons', () => {
  const policy = fs.readFileSync(path.join(root, 'scripts/install/runtime-version-policy.sh'), 'utf8');
  assert.match(policy, /^OWASP_AI_GOAT_MINIMUM_NODE_VERSION=26\.10\.0$/m);
  assert.match(policy, /^OWASP_AI_GOAT_MINIMUM_NPM_VERSION=12\.1\.0$/m);
  assert.match(source, /runtime-version-policy\.sh/);
  assert.match(source, /OWASP_AI_GOAT_MINIMUM_NODE_VERSION=\(\\d\+/);
  assert.match(source, /OWASP_AI_GOAT_MINIMUM_NPM_VERSION=\(\\d\+/);
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  for (const name of ['hnswlib-node', 'bcrypt', 'better-sqlite3', 'sqlite3']) {
    assert.ok(lock.packages[`node_modules/${name}`]);
    assert.ok(source.includes(`'${name}'`));
  }
  assert.equal(lock.packages['node_modules/hnswlib-node'].hasInstallScript, true);
  assert.match(source, /Desktop development with C\+\+ workload/);
  assert.match(source, /windowsSdk/);
  assert.match(source, /kernel32\.lib/);
  assert.doesNotMatch(source, /-requires', 'Microsoft\.VisualStudio\.Workload/);
  assert.match(source, /Microsoft\.VisualStudio\.Component\.VC\.Tools\.x86\.x64/);
  assert.doesNotMatch(source, /chocolatey|winget|cmake|make\.exe/i);
});

test('inventory has no install, service, configuration, browser or database mutation path', () => {
  assert.match(source, /^#Requires -Version 5\.1/m);
  assert.doesNotMatch(executableSource, /\b(?:Start-Service|Stop-Service|Set-Service|Install-Module|Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Invoke-WebRequest|Invoke-RestMethod|Set-ExecutionPolicy|Enable-WindowsOptionalFeature|Start-Process)\b/i);
  assert.doesNotMatch(executableSource, /['"](?:install|pull|serve|run|exec|start|create|up|migrate|generate|launch)['"]/i);
  assert.equal((source.match(/Get-Content -LiteralPath/g) || []).length, 2);
  assert.doesNotMatch(executableSource, /['"][^'"]*\.env['"]/);
  assert.match(source, /WaitForExit\(5000\)/);
  assert.match(source, /CommandType Application/);
  assert.match(source, /Microsoft\\\\WindowsApps/);
  assert.match(source, /EnvironmentVariables\['OLLAMA_HOST'\] = 'http:\/\/127\.0\.0\.1:11434'/);
  assert.match(source, /'ollamaModel' 'ollama\.exe' @\('list'\)/);
  assert.match(source, /'linuxDockerDaemon' 'docker\.exe' @\('version', '--format', '\{\{\.Server\.Os\}\}'\)/);
});

test('machine readable plan keeps inventory separate from blocked Windows qualification and raw secrets', () => {
  assert.match(source, /installationBlocked = \$true; nativeQualified = \$false/);
  assert.match(source, /WINDOWS_OWNED_SANDBOX_BACKEND_UNDECIDED/);
  assert.match(source, /schemaVersion = 1; platform = 'windows'; nonMutating = \$true/);
  assert.match(source, /statusMeaning =/);
  assert.match(source, /ExternalPostgres = \[bool\]\$env:PG_ADMIN_DATABASE_URL/);
  const returnedPlan = source.slice(source.indexOf('return [pscustomobject][ordered]@{\n        schemaVersion'));
  assert.doesNotMatch(returnedPlan, /\$env:|\.output|\$Environment|\$RepoRoot/);
  assert.match(source, /ConvertTo-Json -Depth 6/);
  assert.match(source, /\$MyInvocation.InvocationName -ne '\.'/);
});

test('preview names integration blockers without requesting native host qualification', () => {
  assert.doesNotMatch(source, /Obtain native Windows qualification before installation|Wait for the backend decision and Windows authority qualification/);
  assert.match(source, /Installation remains blocked by incomplete Windows installer integration and the pending Docker\/protected sandbox backend decision/);
  assert.match(source, /component validation and installer integration remain separate/);
  assert.match(source, /version candidate.*packages must separately verify x64/);
});

test('Python inventory range agrees with the native package policy instead of the node-gyp discovery floor', () => {
  const packages = fs.readFileSync(path.join(root, 'scripts/install/Windows/packages.ps1'), 'utf8');
  assert.match(packages, /supported = '3\.11 through 3\.14, x64'/);
  const admittedMinors = packages.match(/\$value\.version -match '\^3\\\.\(([^)]+)\)/)[1];
  const inventoryExpression = source.match(/\$Observation\.output -notmatch '(\(\?m\)\^\\s\*Python 3\\\.\([^']+)'/)[1];
  assert.ok(inventoryExpression.includes(`(${admittedMinors})`));
  const inventoryPattern = new RegExp(inventoryExpression.replace('(?m)', ''), 'm');
  for (const version of ['3.11.0', '3.12.10', '3.13.0', '3.14.99']) assert.equal(inventoryPattern.test(`Python ${version}`), true, version);
  for (const version of ['3.6.0', '3.10.99', '3.15.0', '4.0.0', '3.13', '3.13.0rc1']) assert.equal(inventoryPattern.test(`Python ${version}`), false, version);
  assert.match(source, /Get-OwaspAiGoatVersionStatus \$Observation '3\.11\.0'/);
  assert.match(source, /Get-OwaspAiGoatPythonInventoryStatus \$python/);
  assert.doesNotMatch(source, /'3\.6\.0'|detection floor3\.6/);
});

test('controlled Python version boundaries preserve unsupported and missing states', { skip: !interpreter && 'PowerShell unavailable; controlled interpreter not run' }, () => {
  for (const version of ['3.11.0', '3.14.0', '3.10.99', '3.15.0', '4.0.0', '3.13.0rc1']) {
    const plan = controlledPlan(`$observations.python.output = 'Python ${version}'`);
    assert.equal(states(plan).python, ['3.11.0', '3.14.0'].includes(version) ? 'present' : 'versionUnsupported', version);
    assert.equal(plan.installationBlocked, true);
    assert.equal(plan.nativeQualified, false);
  }
  assert.equal(states(controlledPlan('$observations.python.available = $false')).python, 'missing');
});

test('controlled candidate inventory never authorizes installation', { skip: !interpreter && 'PowerShell unavailable; controlled interpreter and native Windows qualification not run' }, () => {
  const plan = controlledPlan();
  assert.equal(plan.installationBlocked, true);
  assert.equal(plan.nativeQualified, false);
  assert.equal(plan.nonMutating, true);
  assert.ok(Object.values(states(plan)).every(status => status === 'present'));
  assert.deepEqual(plan.runtimePolicy, { nodeMinimum: '26.10.0', npmMinimum: '12.1.0' });
});

test('controlled missing capabilities and obsolete versions remain distinct and redact probe output', { skip: !interpreter && 'PowerShell unavailable; controlled interpreter and native Windows qualification not run' }, () => {
  const plan = controlledPlan(`
$observations.node.output = 'v24.15.0'
$observations.npm.output = '12.0.0'
$observations.compose.output = '1.29.2'
$observations.cppBuildTools.output = ''
$observations.ollamaModel.output = 'NAME ID SIZE'
$observations.linuxDockerDaemon.exitCode = 1
$observations.linuxDockerDaemon.output = 'postgresql://private:DO_NOT_RETURN@private-host/db'
`, "$environment.Browser = $null", false);
  const result = states(plan);
  assert.equal(result.node, 'versionUnsupported');
  assert.equal(result.npm, 'versionUnsupported');
  assert.equal(result.compose, 'versionUnsupported');
  for (const id of ['cppBuildTools', 'windowsSdk', 'ollamaModel', 'linuxDockerDaemon', 'browser', 'postgres']) assert.equal(result[id], 'missing');
  assert.ok(!JSON.stringify(plan).includes('DO_NOT_RETURN'));
});

test('controlled external PostgreSQL presence and incompatible configured model do not imply readiness', { skip: !interpreter && 'PowerShell unavailable; controlled interpreter and native Windows qualification not run' }, () => {
  const plan = controlledPlan("$observations.linuxDockerDaemon.output = 'windows'", "$environment.ExternalPostgres = $true; $environment.Model = 'other:7b'");
  assert.equal(states(plan).linuxDockerDaemon, 'versionUnsupported');
  assert.equal(states(plan).postgres, 'present');
  assert.equal(states(plan).ollamaModel, 'versionUnsupported');
  assert.match(plan.qualification, /not service readiness/);
  assert.equal(plan.installationBlocked, true);
});
