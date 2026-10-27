'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {composeOwnedHttpProduction}=require('../server/services/mcp/ownedHttpProduction');
const {plan}=require('../scripts/install/mcp-owned-http');
const config=require('../server/services/mcp/ownedHttpManagedConfiguration');
const crypto=require('node:crypto');
const profileDigest=p=>crypto.createHash('sha256').update(require('../sidecars/sandbox-runner/owned-http/profile').renderOwnedHttpProfile(p.profile)).digest('hex');
const path=require('node:path');
const {collectOwnedServiceBuildContext,_internals:buildContext}=require('../scripts/install/mcp-owned-service-build-context');
const cli={readiness:async()=>({ready:true}),admit:async()=>({}),retire:async()=>{throw Error('must not retire CLI');}};
test('production preserves pre-migration disabled startup and refuses enabled HTTP without migration',async()=>{
 const resourcePool={query:async()=>({rows:[{name:null}]})};
 assert.equal(await composeOwnedHttpProduction({env:{},resourcePool,targets:cli}),cli);
 await assert.rejects(composeOwnedHttpProduction({env:{MCP_OWNED_HTTP_ENABLED:'true'},resourcePool,targets:cli}),{code:'HTTP_LEASE_UNAVAILABLE'});
});
test('missing HTTP config retains durable child cleanup debt',async()=>{
 const scope={targetId:'11111111-1111-4111-8111-111111111111',platformOwnerId:7,platformSessionId:11,generation:0};
 const resourcePool={query:async sql=>sql.includes('to_regclass')?{rows:[{name:'mcp.http_target_leases'}]}:{rows:[{state:'active'}]}};
 const targets=await composeOwnedHttpProduction({env:{},resourcePool,identityPool:{query(){}},targets:cli});
 assert.notEqual(targets,cli);assert.deepEqual(await targets.readiness(),{ready:true});
 // A real repository transaction is intentionally unavailable here; verify a
 // retirement cannot silently call CLI when durable HTTP reconciliation fails.
 await assert.rejects(targets.retire({scope,operationId:'parent'}));
});
test('private service plan uses separate profile and local-only port on mac and Linux',()=>{
 const linux=plan({root:'/tmp/dvaia-owned-plan',home:'/tmp/home',platform:'linux'});
 const mac=plan({root:'/tmp/dvaia-owned-plan',home:'/tmp/home',platform:'darwin',colimaProfile:'colima-owned-test'});
 assert.match(linux.profile,/^dvaia-owned-http-/);assert.equal(mac.profile,linux.profile);
 assert.equal(linux.port,8093);assert.notEqual(linux.destination,'/etc/apparmor.d/dvaia-mcp-sandbox');
 assert.match(mac.dockerHost,/colima\/owned-test\/docker.sock$/);
 const value={version:1,enabled:false,url:'http://127.0.0.1:8093',token:'a'.repeat(64),profile:linux.profile,container:linux.profile,image:'sha256:'+'b'.repeat(64)};
 assert.equal(config.validate(value),value);assert.throws(()=>config.validate({...value,url:'http://public.example:8093'}));
});
test('Windows HTTP plan refuses an unowned guest session',()=>{
 assert.throws(()=>plan({root:path.resolve(__dirname,'..'),platform:'win32',ownedLabSession:{}}),
  {code:'MCP_INSTALL_OWNED_LAB_REQUIRED'});
});
test('HTTP guest build bundle contains exact Docker COPY roots with hashed relative bytes',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os');
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-http-copy-test-'));
 try {
  const base=path.join(root,'sidecars/sandbox-runner'),source=buildContext.sources.http;
  for(const name of source.files){const file=path.join(base,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,name);}
  for(const directory of source.directories){const file=path.join(base,directory,'fixture.txt');await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,directory);}
  const files=await collectOwnedServiceBuildContext({root,service:'http'});
  const names=new Set(files.map(file=>file.path));
  for(const name of ['Dockerfile','owned-http/fixture.txt','policy-render/secureshopPromptPolicyContract.js',
   'policy-render/assets/fixture.txt','labfs/fixture.txt'])assert.ok(names.has('sidecars/sandbox-runner/'+name));
  assert.ok(files.length<128);
  assert.ok(files.every(file=>file.path.startsWith('sidecars/sandbox-runner/')&&
   crypto.createHash('sha256').update(file.bytes).digest('hex')===file.sha256));
  assert.equal(files.some(file=>file.path.includes('/test/')||file.path.includes('node_modules')
   ||file.path.endsWith('/policy-render/native-qualification.js')),false);
 } finally {await fs.rm(root,{recursive:true,force:true});}
});
test('staged Linux provision keeps token private and never enables or migrates',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-http-install-test-'));
 try {
  const root='/tmp/dvaia-http-controlled-root',p=plan({root,home,platform:'linux'}),calls=[];
  const run=async(file,args,options)=>{
   calls.push({file,args,stage:options.stage});let stdout='';
   if(options.stage==='profile-existing-state')return {exitCode:1,stdout:''};
   if(options.stage==='profile-trust')stdout='0:0:600:regular file\n';
   if(options.stage==='profile-published-digest')stdout=profileDigest(p);
   if(options.stage==='profile-verify')stdout=p.profile+' (enforce)\n';
   if(options.stage==='http-image')stdout=JSON.stringify([{Id:'sha256:'+'b'.repeat(64)}]);
   if(options.stage==='http-volume-inspect')stdout=JSON.stringify([{Labels:{'dvaia.http.owner':p.profile}}]);
   return {exitCode:0,stdout};
  };
  const result=await require('../scripts/install/mcp-owned-http').provision({root,home,platform:'linux',commandEnv:{},run,
   serviceFactory:({token})=>{assert.match(token,/^[A-Za-z0-9_-]{43,128}$/);return {readiness:async()=>({ready:true})};}});
  assert.equal(result.activationEnabled,false);assert.equal(result.migrationsApplied,false);
  const saved=config.load({file:p.managedPath});assert.equal(saved.enabled,false);
  const start=calls.find(c=>c.stage==='http-start');assert.ok(start.args.includes('--env-file'));
  assert.equal(start.args.some(arg=>arg.includes(saved.token)),false);
  assert.ok(start.args.includes('127.0.0.1:8093:8091'));
  assert.equal(calls.some(c=>c.args.includes('dvaia-mcp-sandbox')),false);
  assert.equal((await fs.stat(p.managedPath)).mode&0o077,0);
 }finally{await fs.rm(home,{recursive:true,force:true});}
});
test('stopped owned HTTP container restarts by validated full ID and is re-inspected before readiness',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os');
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-http-restart-test-'));
 try{
  const root='/tmp/dvaia-http-restart',p=plan({root,home,platform:'linux'}),image='sha256:'+'b'.repeat(64),token='a'.repeat(64),id='c'.repeat(64),calls=[];
  await fs.mkdir(path.dirname(p.managedPath),{recursive:true});
  await fs.writeFile(p.managedPath,JSON.stringify({version:1,enabled:false,url:'http://127.0.0.1:8093',token,profile:p.profile,container:p.container,image}),{mode:0o600});
  const found={Id:id,Image:image,State:{Running:false},Config:{User:'10001:10001',Labels:{'dvaia.http.owner':p.profile},
   Env:[`MCP_OWNED_HTTP_TOKEN=${token}`,'MCP_OWNED_HTTP_ROOT=/state/targets',`MCP_OWNED_TARGET_APPARMOR_PROFILE=${p.profile}`]},
   HostConfig:{SecurityOpt:[`apparmor=${p.profile}`,'seccomp=unconfined'],PortBindings:{'8091/tcp':[{HostIp:'127.0.0.1',HostPort:'8093'}]}},
   Mounts:[{Type:'volume',Name:p.volume,Destination:'/state'}]};
  const run=async(_file,args,{stage})=>{calls.push({args,stage});let stdout='';
   if(stage==='profile-existing-state')return{exitCode:1,stdout};
   if(stage==='profile-trust')stdout='0:0:600:regular file\n';
   if(stage==='profile-published-digest')stdout=profileDigest(p);
   if(stage==='profile-verify')stdout=p.profile+' (enforce)\n';
   if(stage==='http-image')stdout=JSON.stringify([{Id:image}]);
   if(stage==='http-existing')stdout=id.slice(0,12);
   if(stage==='http-inspect')stdout=JSON.stringify([found]);
   if(stage==='http-reinspect')stdout=JSON.stringify([{...found,State:{Running:true}}]);
   return{exitCode:0,stdout};};
  let ready=false;
  await require('../scripts/install/mcp-owned-http').provision({root,home,platform:'linux',commandEnv:{},run,
   serviceFactory:()=>({readiness:async()=>{ready=true;return{ready:true};}})});
  assert.deepEqual(calls.find(call=>call.stage==='http-restart').args.slice(-2),['start',id]);
  assert.equal(calls.some(call=>call.stage==='http-build'||call.stage==='http-start'),false);
  assert.equal(ready,true);
  const drift=async(_file,args,{stage})=>{
   const result=await run(_file,args,{stage});
   if(stage==='http-reinspect')return{exitCode:0,stdout:JSON.stringify([{...found,Id:'d'.repeat(64),State:{Running:true}}])};
   return result;};
  ready=false;
  await assert.rejects(require('../scripts/install/mcp-owned-http').provision({root,home,platform:'linux',commandEnv:{},run:drift,
   serviceFactory:()=>({readiness:async()=>{ready=true;return{ready:true};}})}),/CONTAINER_CONFLICT/);
  assert.equal(ready,false);
 }finally{await fs.rm(home,{recursive:true,force:true});}
});
test('Windows HTTP startExisting only resumes a pinned retained enabled container',async()=>{
 const root='/tmp/http-existing-only',p=plan({root,home:'/tmp/home',platform:'linux'}),image='sha256:'+'b'.repeat(64),id='c'.repeat(64),token='a'.repeat(64);
 const existing={version:1,enabled:true,url:'http://127.0.0.1:8093',token,profile:p.profile,container:p.container,image};
 const found={Id:id,Image:image,State:{Running:false},Config:{User:'10001:10001',Labels:{'dvaia.http.owner':p.profile},
  Env:[`MCP_OWNED_HTTP_TOKEN=${token}`,'MCP_OWNED_HTTP_ROOT=/state/targets',`MCP_OWNED_TARGET_APPARMOR_PROFILE=${p.profile}`]},
  HostConfig:{SecurityOpt:[`apparmor=${p.profile}`,'seccomp=unconfined'],PortBindings:{'8091/tcp':[{HostIp:'127.0.0.1',HostPort:'8093'}]}},
  Mounts:[{Type:'volume',Name:p.volume,Destination:'/state'}]};
 const calls=[];let drift=false;
 const session={executeDocker:async(args,options)=>{calls.push({args,options});
  if(args[0]==='image')return JSON.stringify([{Id:image}]);
  if(args[0]==='ps')return id.slice(0,12);
  if(args[0]==='inspect')return JSON.stringify([args[1]===id?{...found,Id:drift?'d'.repeat(64):id,State:{Running:true},AppArmorProfile:p.profile}:found]);
  return'';}};
 const options={root,home:'/tmp/home',platform:'win32',ownedLabSession:session,commandEnv:{},
  loadManaged:()=>existing,planService:()=>({...p,platform:'win32'})};
 const result=await require('../scripts/install/mcp-owned-http').startExisting(options);
 assert.equal(result.enabled,true);assert.equal(result.url,existing.url);
 assert.deepEqual(calls.find(call=>call.args[0]==='start').args,['start',id]);
 assert.equal(calls.some(call=>['build','run','volume'].includes(call.args[0])),false);
 drift=true;await assert.rejects(require('../scripts/install/mcp-owned-http').startExisting(options),/CONTAINER_CONFLICT/);
 drift=false;found.State.Running=true;found.AppArmorProfile='unconfined';
 await assert.rejects(require('../scripts/install/mcp-owned-http').startExisting(options),/CONTAINER_CONFLICT/);
 await assert.rejects(require('../scripts/install/mcp-owned-http').startExisting({...options,loadManaged:()=>null}),/CONFIGURATION_REQUIRED/);
});
test('candidate setup hook is default-off before provisioning or reading credentials',async()=>{
 const hook=require('../scripts/setup-application').provisionOwnedHttpCandidateForSetup;
 assert.deepEqual(await hook(),{available:false,candidateOnly:true,activationEnabled:false});
});
test('only exact verified HTTP capability extends tool and objective qualification',()=>{
 const q=require('../server/services/mcp/ownedQualification');
 for(const capability of [undefined,'unverified',q.HTTP_CAPABILITY]){
  const qualification=q.createOwnedQualification(true,{httpCapability:capability});
  assert.equal(qualification.canGrade('mcp_ssrf'),capability===q.HTTP_CAPABILITY);
  assert.equal(q.createOwnedToolAuthorizer(qualification)('fetch_url'),capability===q.HTTP_CAPABILITY);
  assert.equal(q.createOwnedToolAuthorizer(qualification)('install_plugin'),false);
 }
 const actual=q.createOwnedQualification(true,{httpCapability:q.HTTP_CAPABILITY});
 const forged={...actual};assert.equal(q.isProductionQualification(forged),false);assert.equal(q.createOwnedToolAuthorizer(forged)('fetch_url'),false);
});
test('HTTP readiness capability requires manifest and both database ACL checks',async()=>{
 const {createOwnedHttpCompositeTargets}=require('../server/services/mcp/ownedHttpCompositeTargets');
 const {HTTP_CAPABILITY,MANIFEST_SHA256}=require('../server/services/mcp/ownedHttpCapability');
 let manifest=MANIFEST_SHA256,checks=0;
 const target=createOwnedHttpCompositeTargets({cli,http:{readiness:async()=>({ready:true,manifestSha256:manifest})},enabled:true,
  leases:{read(){},checkReadiness:async()=>{checks++;}},receiptRepository:{checkReadiness:async()=>{checks++;}},readMode:async()=>'vuln'});
 assert.equal((await target.readiness()).httpCapability,HTTP_CAPABILITY);assert.equal(checks,2);
 manifest='0'.repeat(64);await assert.rejects(target.readiness(),{code:'HTTP_CHILD_CLEANUP_REQUIRED'});
});
test('supported setup gates CLI before mutation, closes pools and permits explicit retry',async()=>{
 const {provisionOwnedHttpForSetup}=require('../scripts/install/mcp-owned-http-setup');
 const calls=[];let fail=true;
 const args={root:'/tmp/controlled-http-setup',platform:'linux',environment:{},applicationEnvironment:{},
  loadCli:()=>({MCP_OWNED_RESOURCES_ENABLED:'true',MCP_OWNED_TARGET_URL:'http://127.0.0.1:8092',MCP_OWNED_TARGET_TOKEN:'a'.repeat(64)}),
  createCli:()=>({readiness:async()=>{calls.push('cli');return{ready:true};}}),
  createPool:(_env,key)=>({query:async sql=>{calls.push('schema');if(sql.includes('to_regclass'))return{rows:[{name:sql.includes('http_target_leases')?'mcp.http_target_leases':'workshop_conversations.mcp_http_operations'}]};return{rows:[{read:true,insert:true,publish:true,delete:false}]};},end:async()=>calls.push('close:'+key)}),
  provisionService:async()=>{calls.push('provision');return{ok:true,managedPath:'/tmp/controlled-private-http.json'};},
  activate:async()=>{calls.push('activate');if(fail)throw Error('controlled unavailable HTTP');return{activationEnabled:true};}};
 await assert.rejects(provisionOwnedHttpForSetup(args),/controlled unavailable/);assert.equal(calls.filter(x=>x.startsWith('close:')).length,4);
 fail=false;assert.equal((await provisionOwnedHttpForSetup(args)).available,true);assert.equal(calls[0],'cli');assert.ok(calls.indexOf('schema')<calls.indexOf('provision'));
 const before=calls.length;await assert.rejects(provisionOwnedHttpForSetup({...args,loadCli:()=>({MCP_OWNED_RESOURCES_ENABLED:'false'})}),{code:'MCP_HTTP_CLI_REQUIRED'});assert.equal(calls.length,before);
});
