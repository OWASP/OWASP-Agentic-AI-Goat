'use strict';
// Controlled command adapters only: no sudo, SSH, Docker, package or service
// operation is executed by these tests.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const system=require('../scripts/install/secureshop-owned-system-provision')._internals;
const combined=require('../scripts/install/secureshop-qualified-system-setup');
const {workspaceId}=require('../scripts/application-data-root');
const root=path.resolve(__dirname,'..'),name='dvaia-mcp-sandbox';
const rendered=require('../scripts/render-mcp-sandbox-apparmor').renderMcpSandboxAppArmor(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/'+name+'.apparmor.in'),'utf8'),name);
const digest=crypto.createHash('sha256').update(rendered).digest('hex');
function fixture(t,platform,state={}) {
 const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'system-profile-control-')));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const authority={version:1,workspaceId:workspaceId(root),host:platform==='linux'?'unix:///var/run/docker.sock':`unix://${home}/.colima/system-test/docker.sock`,daemonId:'owned-daemon',source:'environment-host',platform};
 const events=[],s={exists:false,link:false,trust:true,hash:digest,enforced:false,...state};
 const run=async(file,args,o)=>{
  assert(o.timeoutMs>0&&o.timeoutMs<=30000);assert(o.maxOutputBytes<=1048576);
  let a=args;
  if(file==='docker'){events.push('daemon');assert.deepEqual(a,['--host',authority.host,'info','--format','{{json .ID}}']);return{exitCode:0,stdout:JSON.stringify(s.wrongDaemon?'other-daemon':authority.daemonId)};}
  if(platform==='darwin'){assert(['ssh','scp'].includes(file));assert.deepEqual(args.slice(0,2),['-F',path.join(home,'.colima/_lima/colima-system-test/ssh.config')]);if(file==='scp')return{exitCode:0,stdout:''};assert.equal(args[2],'lima-colima-system-test');
   if(o.stage==='profile-remote-authority'){events.push(o.stage);assert.equal(args[3],require('../scripts/install/mcp-owned-provision')._internals.REMOTE_DAEMON_COMMAND);return{exitCode:s.remoteUnavailable?1:0,stdout:s.remoteMalformed?'invalid':JSON.stringify(s.wrongRemote?'other-daemon':authority.daemonId)};}
   a=args.slice(3);if(a.length===1){const prefix=require('../scripts/install/mcp-owned-provision')._internals.boundRemoteCommand('',authority.daemonId);assert(a[0].startsWith(prefix));if(s.remoteChanged)return{exitCode:1,stdout:''};a=a[0].slice(prefix.length).split(' ');}}
  else assert.equal(file,'sudo');
  if(a[0]==='sudo')a=a.slice(1);if(a[0]==='--non-interactive')a=a.slice(1);
  events.push(o.stage||a[0]);
  if(o.stage==='remote-preflight')return{exitCode:1,stdout:''};
  if(a[0]==='test')return{exitCode:(a[1]==='-L'?s.link:s.exists)?0:1,stdout:''};
  if(a[0]==='stat')return{exitCode:0,stdout:s.trust&&!s.link?'0:0:600:regular file':'1000:1000:644:symbolic link'};
  if(a[0]==='sha256sum')return{exitCode:0,stdout:s.hash+'  /etc/apparmor.d/'+name};
  if(a[0]==='cp'){assert.deepEqual(a.slice(1,4),['--no-clobber','--no-dereference','--']);if(!s.exists&&!s.link){s.exists=true;s.hash=s.raceHash||digest;}return{exitCode:0,stdout:''};}
  if(a[0]==='apparmor_parser'){if(s.parserFailure)return{exitCode:1,stdout:''};if(a[1]==='-r')s.enforced=!s.enforcementFailure;return{exitCode:0,stdout:''};}
  if(a[0]==='cat')return{exitCode:0,stdout:s.enforced?name+' (enforce)\n':''};
  assert(['true','mkdir','chmod','rm'].includes(a[0]),a.join(' '));return{exitCode:0,stdout:''};
 };
 return{root,home,platform,architecture:'arm64',authority,p:{profile:{name,sha256:digest}},environment:{DOCKER_HOST:authority.host},run,events,s};
}
for(const platform of ['linux','darwin']) {
 test(`${platform}: read-only combined preflight plans missing profile; explicit preparation binds daemon, installs, loads, then verifies`,async t=>{
  const f=fixture(t,platform);const before=fs.readdirSync(f.home);
  const plan=await combined.preflight(f);assert.equal(plan.mutating,false);assert.equal(plan.profileVerified,false);assert.equal(plan.profilePreparationRequired,true);assert.deepEqual(fs.readdirSync(f.home),before);assert(!f.events.includes('profile-install'));
  await assert.rejects(system.verifyProfile(f),{code:'SYSTEM_INSTALL_PROFILE_UNAVAILABLE'});
  f.events.length=0;assert.equal((await system.prepareProfile(f)).profileVerified,true);
  assert.equal(f.events[0],'daemon');assert(f.events.indexOf('profile-parse')<f.events.indexOf('profile-install'));assert(f.events.indexOf('profile-install')<f.events.indexOf('profile-load'));assert(f.events.indexOf('profile-published-digest')<f.events.indexOf('profile-load'));
  f.events.length=0;await system.prepareProfile(f);assert(!f.events.includes('profile-install'));assert(!f.events.includes('profile-load'));
 });
 test(`${platform}: identical unloaded profile is loaded without replacement`,async t=>{const f=fixture(t,platform,{exists:true});await system.prepareProfile(f);assert(!f.events.includes('profile-install'));assert(f.events.includes('profile-load'));});
 for(const [label,state]of Object.entries({conflict:{exists:true,hash:'f'.repeat(64)},symlink:{exists:true,link:true},dangling:{link:true},owner:{exists:true,trust:false}}))test(`${platform}: ${label} rejects read-only preflight and preparation before profile mutation`,async t=>{
  const f=fixture(t,platform,state);await assert.rejects(combined.preflight(f),{code:'SYSTEM_INSTALL_PROFILE_CONFLICT'});await assert.rejects(system.prepareProfile(f),{code:'SYSTEM_INSTALL_PROFILE_CONFLICT'});assert(!f.events.some(e=>['profile-install','profile-load','profile-parse'].includes(e)));
 });
 test(`${platform}: daemon change, parser failure, raced bytes and missing enforcement never report readiness`,async t=>{
  for(const state of [{wrongDaemon:true},{parserFailure:true},{raceHash:'f'.repeat(64)},{enforcementFailure:true}]){const f=fixture(t,platform,state);await assert.rejects(system.prepareProfile(f));if(state.wrongDaemon)assert.deepEqual(f.events,['daemon']);if(state.parserFailure||state.raceHash)assert(!f.events.includes('profile-load'));}
 });
}
test('combined setup prepares profile only after bound authority and before private configuration publication',async t=>{
 const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'combined-profile-order-')));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const config=require('../server/services/secureshopQualifiedManagedConfiguration'),file=config.managedPath(root,home);fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});const order=[];
 await assert.rejects(combined.prepare({root,homeDirectory:home,ensureAuthority:async()=>order.push('authority'),prepareProfile:async()=>{order.push('profile');assert(!fs.existsSync(file));throw Error('controlled profile unavailable');},run:async()=>assert.fail('readiness before profile'),activateSystem:async()=>assert.fail('activation before profile')}),/controlled profile unavailable/);
 assert.deepEqual(order,['authority','profile']);assert(!fs.existsSync(file));assert(!fs.existsSync(file+'.setup-lock'));
});
test('wrong selected Colima authority is rejected before any profile command',async t=>{const f=fixture(t,'darwin');f.authority.host='unix:///tmp/unrelated.sock';await assert.rejects(system.verifyProfile(f),{code:'SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT'});assert.deepEqual(f.events,[]);});
test('Colima remote daemon mismatch/unavailable/malformed identity rejects before sudo or profile staging',async t=>{
 for(const state of [{wrongRemote:true},{remoteUnavailable:true},{remoteMalformed:true}]){const f=fixture(t,'darwin',state);await assert.rejects(system.prepareProfile(f),{code:'SYSTEM_INSTALL_PROFILE_AUTHORITY_CONFLICT'});assert.deepEqual(f.events,['daemon','profile-remote-authority']);}
});
test('Colima identity guard is evaluated in the effect shell and cannot use a prior matching read',()=>{
 const {boundRemoteCommand}=require('../scripts/install/mcp-owned-provision')._internals;
 for(const id of ['owned-daemon','other-daemon']){
  // A shell function supplies controlled bytes; no Docker executable runs.
  const source=`docker() { printf '%s' '${JSON.stringify(id)}'; }; `+boundRemoteCommand("printf 'effect-admitted'",'owned-daemon');
  const row=require('node:child_process').spawnSync('/bin/sh',['-c',source],{encoding:'utf8',timeout:2000,maxBuffer:4096});
  assert.equal(row.status,id==='owned-daemon'?0:1);assert.equal(row.stdout,id==='owned-daemon'?'effect-admitted':'');
 }
 assert.throws(()=>boundRemoteCommand('true',"untrusted'$(command)"),{code:'MCP_INSTALL_REMOTE_AUTHORITY_INVALID'});
});
test('actual setup CLI combined and System plans cannot dispatch setup or profile installation',()=>{
 const source=fs.readFileSync(path.join(root,'scripts/setup-application.js'),'utf8');
 const cli=source.slice(source.indexOf('if (require.main === module) {'),source.indexOf('// Explicit candidate seam only;'));
 for(const flags of [['--owned-system'],['--qualified-secureshop','--owned-system'],['--repair','--owned-system']]){
  const owner={},process={argv:['node','setup','--plan',...flags]},messages=[];
  require('node:vm').runInNewContext(cli,{require:{main:owner},module:owner,process,setupHostPlan:()=>null,console:{log:x=>messages.push(x),error:()=>assert.fail('plan rejected')},setup:()=>assert.fail('plan dispatched setup')});
  assert.equal(process.exitCode,undefined);assert(messages.length>0);
 }
});
