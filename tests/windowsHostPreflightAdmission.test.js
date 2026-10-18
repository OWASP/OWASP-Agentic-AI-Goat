'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '..');
const adapter = require('../scripts/lib/windows-host-preflight');
const ps = fs.readFileSync(path.join(root, 'scripts/install/Windows/host-preflight.ps1'), 'utf8');
const remedies = Object.fromEntries([...ps.matchAll(/& \$add '(WINDOWS_HOST_[A-Z0-9_]+)' '([^']+)'/g)].map(match => [match[1], match[2]]));
function dto(supported = true, code = 'WINDOWS_HOST_EDITION_UNSUPPORTED') {
  return { schemaVersion: 1, component: 'windows-hyperv-host-preflight', nonMutating: true,
    hostSupported: supported, minimumBuild: 19045,
    allowedSkus: [4,27,48,49,70,72,84,121,122,125,126,129,130,161,162,164,165],
    capabilityEvidence: 'running-hypervisor', blockers: supported ? [] : [{ code, remedy: remedies[code] }] };
}
const denied = fn => assert.throws(fn, { code: 'WINDOWS_HOST_PREFLIGHT_UNAVAILABLE' });
function observation(output, status = 0) {
  return adapter.createWindowsHostPreflight({ platform: 'win32', systemRoot: 'C:\\Windows', execute(command, args, options) {
    assert.equal(command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.deepEqual(args, ['-NoLogo','-NoProfile','-NonInteractive','-File',path.join(root, 'scripts/install/Windows/host-preflight.ps1')]);
    assert.equal(options.timeout, 60000); assert.equal(options.maxBuffer, 8192);
    assert.deepEqual(options.stdio, ['ignore','pipe','pipe']); assert.equal(options.shell, undefined);
    assert.equal(options.input, undefined); assert.equal(options.env, undefined);
    if (status) throw Object.assign(Error('PRIVATE_DIAGNOSTIC'), { status, stdout: output, stderr: 'PRIVATE_DIAGNOSTIC' });
    return output;
  } }).observe();
}
test('read-only native adapter bounds invocation and freezes the exact approved DTO', () => {
  const result = observation(JSON.stringify(dto()));
  assert.equal(result.hostSupported, true); assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.allowedSkus)); assert.ok(Object.isFrozen(result.blockers));
  assert.deepEqual(adapter.assertWindowsHostSupported(result), result);
});
test('semantic exit1 is an unsupported report, never execution authority; all fixed remedies match PowerShell', () => {
  assert.equal(Object.keys(remedies).length, 11);
  for (const code of Object.keys(remedies)) {
    const value = observation(JSON.stringify(dto(false, code)), 1);
    assert.equal(value.hostSupported, false); assert.ok(Object.isFrozen(value.blockers[0]));
    assert.throws(() => adapter.assertWindowsHostSupported(value), { code: 'WINDOWS_HOST_UNSUPPORTED' });
    assert.ok(!JSON.stringify(value).includes('PRIVATE_DIAGNOSTIC'));
  }
});
test('malformed, oversized, contradictory and future protocol results fail closed without diagnostic leakage', () => {
  for (const [value, status] of [[dto(),1],[dto(false),0],[{...dto(), extra:'PRIVATE_DIAGNOSTIC'},0],
    [{...dto(),allowedSkus:[48]},0],[{...dto(),minimumBuild:1},0],
    [{...dto(),capabilityEvidence:'processor-flags'},0],
    [{...dto(false),blockers:[{code:'WINDOWS_HOST_FUTURE',remedy:'PRIVATE_DIAGNOSTIC'}]},1],
    [{...dto(false),blockers:[dto(false).blockers[0],dto(false).blockers[0]]},1]]) denied(() => observation(JSON.stringify(value),status));
  for (const value of ['not-json', ' '.repeat(8193), JSON.stringify(dto())+'\n'+JSON.stringify(dto())]) denied(() => observation(value));
  denied(() => observation(JSON.stringify(dto(false)),2));
  assert.throws(() => adapter.createWindowsHostPreflight({ platform:'win32',systemRoot:'C:\\Windows',execute(){throw Object.assign(Error('PRIVATE_DIAGNOSTIC'),{code:'ETIMEDOUT',stdout:JSON.stringify(dto())});} }).observe(), error => error.code==='WINDOWS_HOST_PREFLIGHT_UNAVAILABLE' && !error.message.includes('PRIVATE_DIAGNOSTIC'));
});
test('invalid platform and SystemRoot deny before any command launch', () => {
  for (const systemRoot of ['Windows','C:\\Windows\\..\\Other','C:\\Windows\\','\\\\server\\Windows','C:\\Windows.']) denied(() => adapter.createWindowsHostPreflight({ platform:'win32',systemRoot,execute(){assert.fail('must not launch');} }).observe());
  denied(() => adapter.createWindowsHostPreflight({ platform:'darwin',systemRoot:'C:\\Windows',execute(){assert.fail('must not launch');} }).observe());
});
function load(relative, overrides = {}) {
  const filename = path.join(root, relative), realRequire = createRequire(filename), module = { exports:{} };
  const processFixture = { ...process, env:{}, exitCode:0 }, printed=[];
  const wrapped = vm.runInThisContext(`(function(require,module,exports,__filename,__dirname,process,console){${fs.readFileSync(filename,'utf8')}\n})`, { filename });
  wrapped(name => Object.hasOwn(overrides,name) ? overrides[name] : realRequire(name),module,module.exports,filename,path.dirname(filename),processFixture,{log:value=>printed.push(value),error:value=>printed.push(value)});
  return { api:module.exports,processFixture,printed };
}
test('setup rejects unsupported host before root access, managed config, private directories or install work', async () => {
  let reads=0, commands=0;
  const loaded=load('scripts/setup-application.js', {'node:fs/promises':{realpath(){reads++;throw Error('later');}}});
  await assert.rejects(loaded.api.setup({platform:'win32',observeWindowsHost:()=>dto(false),execute(){commands++;},runCommand(){commands++;}}),{code:'WINDOWS_HOST_UNSUPPORTED'});
  assert.equal(reads,0);assert.equal(commands,0);
  assert.equal(loaded.api.setupHostPlan({platform:'win32',observeWindowsHost:()=>dto(false)}).hostSupported,false);
});
test('supported setup continues at the existing root step; POSIX bypasses the Windows observer', async () => {
  let reads=0, observed=0;const later=Object.assign(Error('controlled root step'),{code:'CONTROLLED_ROOT'});
  const loaded=load('scripts/setup-application.js', {'node:fs/promises':{async realpath(){reads++;throw later;}}});
  await assert.rejects(loaded.api.setup({platform:'win32',observeWindowsHost(){observed++;return dto();}}),{code:'CONTROLLED_ROOT'});
  await assert.rejects(loaded.api.setup({platform:'linux',observeWindowsHost(){assert.fail('POSIX observer');}}),{code:'CONTROLLED_ROOT'});
  assert.equal(reads,2);assert.equal(observed,1);
  assert.equal(loaded.api.setupHostPlan({platform:'linux',observeWindowsHost(){assert.fail('POSIX plan observer');}}),null);
});
test('startup execution and plan deny before dotenv/config or data mutations; supported host retains existing flow', async () => {
  let configs=0;const loaded=load('scripts/start-application.js', {'dotenv':{config(){configs++;throw Object.assign(Error('controlled config step'),{code:'CONTROLLED_CONFIG'});}}});
  await assert.rejects(loaded.api.main([],{platform:'win32',observeWindowsHost:()=>dto(false)}),{code:'WINDOWS_HOST_UNSUPPORTED'});
  assert.equal(configs,0);
  await loaded.api.main(['--plan'],{platform:'win32',observeWindowsHost:()=>dto(false)});
  assert.equal(configs,0);assert.equal(loaded.processFixture.exitCode,1);
  assert.equal(JSON.parse(loaded.printed[0]).hostSupported,false);
  await assert.rejects(loaded.api.main([],{platform:'win32',observeWindowsHost:()=>dto()}),{code:'CONTROLLED_CONFIG'});
  await assert.rejects(loaded.api.main([],{platform:'linux',observeWindowsHost(){assert.fail('POSIX observer');}}),{code:'CONTROLLED_CONFIG'});
  assert.equal(configs,2);
});
test('Stop and controlled supervisor helpers have no host-preflight gate; setup CLI plan uses the read-only seam', () => {
  const startup=fs.readFileSync(path.join(root,'scripts/start-application.js'),'utf8');
  assert.doesNotMatch(startup.slice(startup.indexOf('async function stopOwnedChild'),startup.indexOf('async function main')),/windows-host-preflight|observeWindowsHost/);
  const setup=fs.readFileSync(path.join(root,'scripts/setup-application.js'),'utf8');
  assert.match(setup,/args\.includes\('--plan'\)[\s\S]*const host = setupHostPlan\(\)/);
  assert.match(setup,/host && !host\.hostSupported\) process\.exitCode = 1;\s*else \{/);
  const cli=setup.slice(setup.indexOf('if (require.main === module) {'),setup.indexOf('// Explicit candidate seam only;'));
  const owner={},printed=[],runtime={argv:['node','setup','--plan']};
  vm.runInNewContext(cli,{require:{main:owner},module:owner,process:runtime,setupHostPlan:()=>dto(false),console:{log:value=>printed.push(value),error:()=>assert.fail('valid denied observation')},setup:()=>assert.fail('plan must not execute')});
  assert.equal(printed.length,1);assert.equal(JSON.parse(printed[0]).hostSupported,false);assert.equal(runtime.exitCode,1);
});
test('Hyper-V permission and PowerShell module blockers deny setup and startup before later work', async () => {
  for (const code of ['WINDOWS_HOST_HYPERV_PERMISSION_REQUIRED','WINDOWS_HOST_HYPERV_POWERSHELL_REQUIRED']) {
    let reads=0, commands=0;
    const setup=load('scripts/setup-application.js', {'node:fs/promises':{realpath(){reads++;throw Error('later');}}});
    await assert.rejects(setup.api.setup({platform:'win32',observeWindowsHost:()=>dto(false,code),execute(){commands++;},runCommand(){commands++;}}),{code:'WINDOWS_HOST_UNSUPPORTED'});
    const startup=load('scripts/start-application.js', {'dotenv':{config(){reads++;throw Error('later');}}});
    await assert.rejects(startup.api.main([],{platform:'win32',observeWindowsHost:()=>dto(false,code)}),{code:'WINDOWS_HOST_UNSUPPORTED'});
    assert.equal(reads,0);assert.equal(commands,0);
    assert.deepEqual(adapter.assertWindowsHostSupported(dto()).blockers,[]);
  }
});
