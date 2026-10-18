'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {plan}=require('../scripts/install/mcp-owned-shadow');
const config=require('../server/services/mcp/ownedShadowManagedConfiguration');
const crypto=require('node:crypto');
const path=require('node:path');
const {collectOwnedServiceBuildContext,_internals:buildContext}=require('../scripts/install/mcp-owned-service-build-context');
test('private service plan uses separate profile and local-only port on mac and Linux',()=>{
 const linux=plan({root:'/tmp/dvaia-owned-plan',home:'/tmp/home',platform:'linux'});
 const mac=plan({root:'/tmp/dvaia-owned-plan',home:'/tmp/home',platform:'darwin',colimaProfile:'colima-owned-test'});
 assert.match(linux.profile,/^dvaia-owned-shadow-/);assert.equal(mac.profile,linux.profile);
 assert.equal(linux.port,8094);assert.notEqual(linux.destination,'/etc/apparmor.d/dvaia-mcp-sandbox');
 assert.match(mac.dockerHost,/colima\/owned-test\/docker.sock$/);
 const value={version:1,enabled:false,url:'http://127.0.0.1:8094',token:'a'.repeat(64),profile:linux.profile,container:linux.profile,image:'sha256:'+'b'.repeat(64),runtimeDigest:null};
 assert.equal(config.validate(value),value);assert.throws(()=>config.validate({...value,url:'http://public.example:8094'}));
});
test('Windows shadow plan refuses an unowned guest session',()=>{
 assert.throws(()=>plan({root:path.resolve(__dirname,'..'),platform:'win32',ownedLabSession:{}}),
  {code:'MCP_INSTALL_OWNED_LAB_REQUIRED'});
});
test('shadow guest build bundle retains its Docker COPY closure and relative hashes',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os');
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-shadow-copy-test-'));
 try {
  const base=path.join(root,'sidecars/sandbox-runner'),source=buildContext.sources.shadow;
  for(const name of source.files){const file=path.join(base,name);await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,name);}
  for(const directory of source.directories){const file=path.join(base,directory,'fixture.txt');await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,directory);}
  await fs.writeFile(path.join(base,'owned-shadow/package-lock.json'),'{}');
  const files=await collectOwnedServiceBuildContext({root,service:'shadow'});
  const names=new Set(files.map(file=>file.path));
  for(const name of ['owned-shadow/Dockerfile','owned-shadow/package-lock.json',
   'owned-http/network-manifest.json','protected-operations/operationStore.js','labfs/fixture.txt'])
   assert.ok(names.has('sidecars/sandbox-runner/'+name));
  assert.ok(files.length<128);
  assert.ok(files.every(file=>file.path.startsWith('sidecars/sandbox-runner/')&&
   crypto.createHash('sha256').update(file.bytes).digest('hex')===file.sha256));
  assert.equal(files.some(file=>file.path.includes('/policy-render/')||file.path.includes('/test/')),false);
 } finally {await fs.rm(root,{recursive:true,force:true});}
});
test('staged Linux provision keeps token private and never enables or migrates',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-shadow-install-test-'));
 try {
  const root='/tmp/dvaia-shadow-controlled-root',p=plan({root,home,platform:'linux'}),calls=[];
  const run=async(file,args,options)=>{
   calls.push({file,args,stage:options.stage});let stdout='';
   if(options.stage==='profile-existing-state')return {exitCode:1,stdout:''};
   if(options.stage==='profile-trust')stdout='0:0:600:regular file\n';
   if(options.stage==='profile-verify')stdout=p.profile+' (enforce)\n';
   if(options.stage==='shadow-image')stdout=JSON.stringify([{Id:'sha256:'+'b'.repeat(64)}]);
   if(options.stage==='shadow-volume-inspect')stdout=JSON.stringify([{Labels:{'dvaia.shadow.owner':p.profile}}]);
   return {exitCode:0,stdout};
  };
  const result=await require('../scripts/install/mcp-owned-shadow').provision({root,home,platform:'linux',commandEnv:{},run,
   serviceFactory:({token})=>{assert.match(token,/^[A-Za-z0-9_-]{43,128}$/);return {readiness:async()=>({ready:true})};}});
  assert.equal(result.activationEnabled,false);assert.equal(result.migrationsApplied,false);
  const saved=config.load({file:p.managedPath});assert.equal(saved.enabled,false);
  const start=calls.find(c=>c.stage==='shadow-start');assert.ok(start.args.includes('--env-file'));
  assert.equal(start.args.some(arg=>arg.includes(saved.token)),false);
  assert.ok(start.args.includes('127.0.0.1:8094:8092'));
  assert.equal(calls.some(c=>c.args.includes('dvaia-mcp-sandbox')),false);
  assert.equal((await fs.stat(p.managedPath)).mode&0o077,0);
 }finally{await fs.rm(home,{recursive:true,force:true});}
});

test('enabled private configuration requires immutable runtime pin',()=>{
 const p=plan({root:'/tmp/shadow-pin',home:'/tmp/home',platform:'linux'});
 const value={version:1,enabled:true,url:'http://127.0.0.1:8094',token:'a'.repeat(64),profile:p.profile,container:p.container,image:'sha256:'+'b'.repeat(64),runtimeDigest:null};
 assert.throws(()=>config.validate(value));assert.equal(config.validate({...value,runtimeDigest:'c'.repeat(64)}).enabled,true);
});
test('live shadow readiness checks pinned executable digest before capability grant',async()=>{
 const {createOwnedShadowCompositeTargets}=require('../server/services/mcp/ownedShadowCompositeTargets');
 const {SHADOW_CAPABILITY}=require('../server/services/mcp/ownedQualification');let digest='a'.repeat(64),checks=0;
 const base={admit:async()=>({}),retire:async()=>{},readiness:async()=>({ready:true})};
 const args={base,enabled:true,expectedRuntimeDigest:digest,objectiveQualified:true,readMode:async()=>'vuln',
 shadow:{readiness:async()=>({ready:true,runtimeDigest:digest})},leases:{checkReadiness:async()=>checks++},receiptRepository:{checkReadiness:async()=>checks++}};
 const composite=createOwnedShadowCompositeTargets(args);assert.equal((await composite.readiness()).shadowCapability,SHADOW_CAPABILITY);assert.equal(checks,2);
 digest='b'.repeat(64);await assert.rejects(composite.readiness(),{code:'SHADOW_CHILD_CLEANUP_REQUIRED'});
 assert.equal((await createOwnedShadowCompositeTargets({...args,expectedRuntimeDigest:digest,objectiveQualified:false}).readiness()).shadowObjectiveQualified,false);
});
test('activation checks actual repository exports, applied checksums, and pins runtime for the qualified source release',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-shadow-activation-'));
 try{
  const p=plan({root:'/tmp/shadow-activation',home,platform:'linux'}),file=p.managedPath;
  await fs.mkdir(path.dirname(file),{recursive:true,mode:0o700});
  await fs.writeFile(file,JSON.stringify({version:1,enabled:false,url:'http://127.0.0.1:8094',token:'a'.repeat(64),profile:p.profile,container:p.container,image:'sha256:'+'b'.repeat(64),runtimeDigest:null}),{mode:0o600});
  const pool={query:async(sql,args)=>{
   if(sql.includes('ledger')){const dir=args[0].startsWith('0089')?'identity-migrations':'workshop-migrations/mcp';return{rows:[{checksum:crypto.createHash('sha256').update(await fs.readFile(path.resolve(__dirname,'../db/postgres',dir,args[0]))).digest('hex')}]};}
   if(sql.includes('to_regclass'))return{rows:[{name:sql.includes('shadow_target_leases')?'mcp.shadow_target_leases':'workshop_conversations.mcp_shadow_operations'}]};
   return{rows:[{read:true,insert:true,publish:true,delete:false}]};
  }};
  let digest='c'.repeat(64);const args={file,identityPool:pool,resourcePool:pool,identityMigrationPool:pool,resourceMigrationPool:pool,
   cli:{readiness:async()=>({ready:true,runnerReady:true,isolation:'bwrap-seccomp-v1'})},
   shadow:{readiness:async()=>({ready:true,runtimeDigest:digest,manifestSha256:crypto.createHash('sha256').update(await fs.readFile(path.resolve(__dirname,'../sidecars/sandbox-runner/owned-http/network-manifest.json'))).digest('hex')})}};
  const {activateOwnedShadow}=require('../scripts/install/mcp-owned-shadow-activate');
  assert.equal((await activateOwnedShadow(args)).objectiveRelease,true);assert.equal(config.load({file}).runtimeDigest,digest);
  const before=await fs.readFile(file);await activateOwnedShadow(args);assert.deepEqual(await fs.readFile(file),before);
  digest='d'.repeat(64);await assert.rejects(activateOwnedShadow(args),/RUNTIME_CHANGED/);assert.deepEqual(await fs.readFile(file),before);
 }finally{await fs.rm(home,{recursive:true,force:true});}
});
test('repeat provisioning rejects privileged, host-network and extra-mount drift before service admission',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
 const home=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-shadow-drift-'));
 try{
  const root='/tmp/shadow-drift',p=plan({root,home,platform:'linux'}),image='sha256:'+'b'.repeat(64),token='a'.repeat(64);
  await fs.mkdir(path.dirname(p.managedPath),{recursive:true});await fs.writeFile(p.managedPath,JSON.stringify({version:1,enabled:false,url:'http://127.0.0.1:8094',token,profile:p.profile,container:p.container,image,runtimeDigest:null}),{mode:0o600});
  const baseline={Image:image,Config:{User:'10001:10001',Labels:{'dvaia.shadow.owner':p.profile},Env:[`MCP_OWNED_SHADOW_TOKEN=${token}`,'MCP_OWNED_SHADOW_ROOT=/state/targets',`MCP_OWNED_TARGET_APPARMOR_PROFILE=${p.profile}`]},HostConfig:{Privileged:false,NetworkMode:'default',SecurityOpt:[`apparmor=${p.profile}`,'seccomp=unconfined'],PortBindings:{'8092/tcp':[{HostIp:'127.0.0.1',HostPort:'8094'}]}},Mounts:[{Type:'volume',Name:p.volume,Destination:'/state',RW:true}]};
  for(const mutate of [v=>v.HostConfig.Privileged=true,v=>v.HostConfig.NetworkMode='host',v=>v.Mounts.push({Type:'bind',Destination:'/private'})]){
   const found=structuredClone(baseline);mutate(found);let readinessCalled=false;
   const run=async(_file,_args,{stage})=>{let stdout='';if(stage==='profile-existing-state')return{exitCode:1,stdout};if(stage==='profile-trust')stdout='0:0:600:regular file\n';if(stage==='profile-verify')stdout=p.profile+' (enforce)\n';if(stage==='shadow-image')stdout=JSON.stringify([{Id:image}]);if(stage==='shadow-existing')stdout='owned-id';if(stage==='shadow-inspect')stdout=JSON.stringify([found]);return{exitCode:0,stdout};};
   await assert.rejects(require('../scripts/install/mcp-owned-shadow').provision({root,home,platform:'linux',commandEnv:{},run,serviceFactory:()=>{readinessCalled=true;return{};}}),/CONTAINER_CONFLICT/);assert.equal(readinessCalled,false);
  }
 }finally{await fs.rm(home,{recursive:true,force:true});}
});
test('Windows shadow startExisting only resumes a pinned retained enabled container',async()=>{
 const root='/tmp/shadow-existing-only',p=plan({root,home:'/tmp/home',platform:'linux'}),image='sha256:'+'b'.repeat(64),id='c'.repeat(64),token='a'.repeat(64);
 const existing={version:1,enabled:true,url:'http://127.0.0.1:8094',token,profile:p.profile,container:p.container,image,runtimeDigest:'d'.repeat(64)};
 const found={Id:id,Image:image,State:{Running:false},Config:{User:'10001:10001',Labels:{'dvaia.shadow.owner':p.profile},
  Env:[`MCP_OWNED_SHADOW_TOKEN=${token}`,'MCP_OWNED_SHADOW_ROOT=/state/targets',`MCP_OWNED_TARGET_APPARMOR_PROFILE=${p.profile}`]},
  HostConfig:{SecurityOpt:[`apparmor=${p.profile}`,'seccomp=unconfined'],Privileged:false,NetworkMode:'default',PortBindings:{'8092/tcp':[{HostIp:'127.0.0.1',HostPort:'8094'}]}},
  Mounts:[{Type:'volume',Name:p.volume,Destination:'/state',RW:true}]};
 const calls=[];let drift=false;
 const session={executeDocker:async(args,options)=>{calls.push({args,options});
  if(args[0]==='image')return JSON.stringify([{Id:image}]);
  if(args[0]==='ps')return id.slice(0,12);
  if(args[0]==='inspect')return JSON.stringify([args[1]===id?{...found,Image:drift?'sha256:'+'e'.repeat(64):image,State:{Running:true},AppArmorProfile:p.profile}:found]);
  return'';}};
 const options={root,home:'/tmp/home',platform:'win32',ownedLabSession:session,commandEnv:{},
  loadManaged:()=>existing,planService:()=>({...p,platform:'win32'})};
 const result=await require('../scripts/install/mcp-owned-shadow').startExisting(options);
 assert.equal(result.enabled,true);assert.equal(result.url,existing.url);
 assert.deepEqual(calls.find(call=>call.args[0]==='start').args,['start',id]);
 assert.equal(calls.some(call=>['build','run','volume'].includes(call.args[0])),false);
 drift=true;await assert.rejects(require('../scripts/install/mcp-owned-shadow').startExisting(options),/CONTAINER_CONFLICT/);
 drift=false;found.State.Running=true;found.AppArmorProfile='unconfined';
 await assert.rejects(require('../scripts/install/mcp-owned-shadow').startExisting(options),/CONTAINER_CONFLICT/);
 await assert.rejects(require('../scripts/install/mcp-owned-shadow').startExisting({...options,loadManaged:()=>null}),/CONFIGURATION_REQUIRED/);
});
