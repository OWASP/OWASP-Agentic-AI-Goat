'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), { spawnSync } = require('node:child_process');
const { createWindowsOwnedHyperVObserver } = require('../scripts/lib/windows-owned-hyperv-observer');
const root = path.resolve(__dirname, '..'), helper = path.join(root, 'scripts/install/Windows/owned-hyperv-observer.ps1');
const source = fs.readFileSync(helper,'utf8');
const name = 'dvaia-lab-workspace-123', vmId = '12345678-1234-4321-abcd-123456789abc';
const dto = state => ({version:1,operation:'observeOwnedHyperVVm',name,vmId,state});
const deny = fn => assert.throws(fn,{code:'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED'});
function fixture(response = dto('Off'), overrides = {}) {
  const calls=[];
  return {calls,api:createWindowsOwnedHyperVObserver({platform:'win32',systemRoot:'C:\\Windows',execute(...args){calls.push(args);return typeof response==='string'?response:JSON.stringify(response);},...overrides})};
}
test('explicit owned name produces bounded local read-only PowerShell request and immutable VMId/state', () => {
  for(const state of ['Running','Off','Saved']) {
    const f=fixture(dto(state)),value=f.api.observeOwnedHyperVVm(name);
    assert.deepEqual(value,dto(state));assert.ok(Object.isFrozen(value));
    const [command,args,options]=f.calls[0];
    assert.equal(command,'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.deepEqual(args,['-NoLogo','-NoProfile','-NonInteractive','-File',helper]);
    assert.deepEqual(JSON.parse(options.input),{version:1,operation:'observeOwnedHyperVVm',name});
    assert.ok(Buffer.byteLength(options.input)<1024);assert.equal(options.timeout,30000);assert.equal(options.maxBuffer,4096);
    assert.deepEqual(options.stdio,['pipe','pipe','pipe']);assert.equal(options.shell,undefined);
    assert.equal(options.env,undefined);assert.equal(Object.hasOwn(value,'path'),false);
  }
});
test('foreign, wildcard, command-like and overlong VM names reject before spawning', () => {
  const f=fixture();for(const value of ['',null,[],{},'foreign-vm','DVAIA-LAB-a','dvaia-lab-a*','dvaia-lab-[a]','dvaia-lab-a;Stop-VM','dvaia-lab-a\n','dvaia-lab--','dvaia-lab-'+ 'a'.repeat(48)])deny(()=>f.api.observeOwnedHyperVVm(value));
  assert.equal(f.calls.length,0);
  const longest='dvaia-lab-'+ 'a'.repeat(47);
  assert.deepEqual(fixture({...dto('Off'),name:longest}).api.observeOwnedHyperVVm(longest),{...dto('Off'),name:longest});
});
test('wire protocol denies foreign VMId shape, zero id, extra fields and unstable/unknown states', () => {
  for(const response of [{...dto('Off'),name:'dvaia-lab-other'}, {...dto('Off'),version:2}, {...dto('Off'),vmId:vmId.toUpperCase()},
    {...dto('Off'),vmId:'00000000-0000-0000-0000-000000000000'}, {...dto('Off'),vmId:'not-a-guid'}, {...dto('Off'),vmId:vmId+'\n'},
    {...dto('Off'),diskIdentity:'fabricated'}, dto('Starting'),dto('Unknown'),dto('off'),[],null,
    {version:1,ok:false,code:'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED'},'not-json',' '.repeat(4097)])deny(()=>fixture(response).api.observeOwnedHyperVVm(name));
});
test('native query failure and unavailable platform/SystemRoot remain sanitized unknown, never absence', () => {
  for(const overrides of [{platform:'linux'},{systemRoot:'Windows'},{systemRoot:'C:\\Windows\\..\\Other'},{systemRoot:'\\\\server\\Windows'}]) {
    const f=fixture(dto('Off'),overrides);deny(()=>f.api.observeOwnedHyperVVm(name));assert.equal(f.calls.length,0);
  }
  for(const code of ['ETIMEDOUT','EACCES','ENOENT']) assert.throws(()=>fixture(dto('Off'),{execute(){throw Object.assign(Error('PRIVATE_NATIVE_OUTPUT'),{code,stdout:'PRIVATE_NATIVE_OUTPUT',stderr:'PRIVATE_NATIVE_OUTPUT'});}}).api.observeOwnedHyperVVm(name),error=>error.code==='WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED'&&!error.message.includes('PRIVATE_NATIVE_OUTPUT'));
});
test('native source limits name query to local read-only exact Get-VM and two stable snapshots', () => {
  const executable=source.replace(/<#[\s\S]*?#>/g,'').replace(/^\s*#.*$/gm,'');
  assert.match(source,/Hyper-V\\Get-VM -Name \$ExactName -ErrorAction Stop/);
  assert.match(source,/\$rows\.Count -ne 1/);assert.match(source,/\$vm\.Name -cne \$Name/);
  assert.match(source,/foreach \(\$index in @\(1,2\)\)/);assert.match(source,/\$current\.vmId -cne \$first\.vmId -or \$current\.state -cne \$first\.state/);
  assert.match(source,/\[Guid\]::TryParseExact/);assert.match(source,/\$builder\.Length -ge 1024/);
  assert.doesNotMatch(executable,/\b(?:Start-VM|Stop-VM|Remove-VM|Set-VM|New-VM|Get-VHD|Get-ChildItem|Enable-WindowsOptionalFeature|Invoke-Expression|Start-Process)\b|-ComputerName|-CimSession|-Credential|ReadToEnd|Read-Host/);
  assert.match(source,/'Running','Off','Saved'/);
});
const interpreter=['pwsh','powershell'].find(command=>spawnSync(command,['-NoLogo','-NoProfile','-NonInteractive','-Command','$PSVersionTable.PSVersion.Major'],{encoding:'utf8',timeout:5000}).status===0);
const quote=value=>"'"+value.replaceAll("'","''")+"'";
function controlled(probe,nameArg=name) {
  const command=`. ${quote(helper)}; try { Get-DvaiaOwnedHyperVObservation -Name ${quote(nameArg)} -Probe { param($name) ${probe} } | ConvertTo-Json -Compress } catch { [Console]::Out.WriteLine('DENIED'); exit 7 }`;
  return spawnSync(interpreter,['-NoLogo','-NoProfile','-NonInteractive','-Command',command],{encoding:'utf8',timeout:10000});
}
test('controlled PowerShell snapshots accept stable Off/Saved/Running IDs without any Hyper-V invocation', {skip:!interpreter&&'PowerShell unavailable; native Hyper-V not run'},()=>{
  for(const state of ['Running','Off','Saved']) {
    const value=controlled(`[pscustomobject]@{Name=$name;Id=[Guid]'${vmId.toUpperCase()}';State='${state}'}`);
    assert.equal(value.status,0,value.stderr);assert.deepEqual(JSON.parse(value.stdout),dto(state));
  }
});
test('controlled PowerShell rejects missing/multiple/foreign/transitional/replaced identity observations', {skip:!interpreter&&'PowerShell unavailable; native Hyper-V not run'},()=>{
  const row=`[pscustomobject]@{Name=$name;Id=[Guid]'${vmId}';State='Off'}`;
  for(const probe of ['@()',`${row}; ${row}`,`[pscustomobject]@{Name='dvaia-lab-other';Id=[Guid]'${vmId}';State='Off'}`,`[pscustomobject]@{Name=$name;Id=[Guid]'${vmId}';State='Starting'}`,`if($script:seen){[pscustomobject]@{Name=$name;Id=[Guid]'22345678-1234-4321-abcd-123456789abc';State='Off'}}else{$script:seen=$true;${row}}`,`throw 'PRIVATE_NATIVE_OUTPUT'`]) {
    const value=controlled(probe);assert.equal(value.status,7);assert.equal(value.stdout.trim(),'DENIED');assert.ok(!value.stdout.includes('PRIVATE_NATIVE_OUTPUT'));
  }
});
