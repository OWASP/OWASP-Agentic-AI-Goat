'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const {provision,verifyExisting}=require('../scripts/install/secureshop-owned-listings-provision');
const {sourceManifest,plan}=require('../scripts/install/secureshop-owned-listings');
const managed=require('../server/services/secureshopListingsManagedConfiguration');
const {preflight,setupOwnedListings}=require('../scripts/install/listings-setup');
const {assertActivationReadiness,assertRetainedBindings}=require('../scripts/install/secureshop-owned-listings-activate');
const {workspaceId}=require('../scripts/application-data-root');
const ROOT=path.resolve(__dirname,'..'),IMAGE='sha256:'+'a'.repeat(64),DIGEST='b'.repeat(64),hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(t,realSource=false){
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'listings-install-test-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));const root=realSource?ROOT:path.join(home,'checkout');if(!realSource)fs.mkdirSync(root);
 // Mocked Docker builds copy only synthetic fixture data, never checked-in source.
 if(!realSource)for(const name of Object.keys(sourceManifest(ROOT).files)){const dest=path.join(root,name);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,`synthetic package fixture: ${name} @@SUPERVISOR_PROFILE@@\n`);}
 const id=workspaceId(root),dir=path.join(home,'.owasp-ai-goat',id);fs.mkdirSync(dir,{recursive:true,mode:0o700});
 fs.writeFileSync(path.join(dir,'local-docker.json'),JSON.stringify({version:1,workspaceId:id,host:'unix:///var/run/docker.sock',daemonId:'controlled-daemon',source:'environment-host'}),{mode:0o600});
 const profile='owasp-ai-goat-owned-listings-'+id,profileSha=hash(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',profile));
 const calls=[],envFiles=[],images=new Map(),networks=new Map(),volumes=new Map(),containers=new Map(),controls={badHealth:false,healthCalls:0,healthTransportFailures:0,lostCreate:false,missingCreate:false,badProfile:false,createdForeignNetwork:false,omitStartNetwork:false,lostConnect:false,connectNoEffect:false,nonemptyJournal:false};
 const labels=args=>Object.fromEntries(args.flatMap((v,i)=>v==='--label'?[args[i+1].split('=')]:[]));
 const run=async(file,args,options)=>{calls.push({file,args:[...args]});assert.ok(options.timeoutMs<=300000);assert.ok(options.maxOutputBytes<=1048576);
  if(file==='sudo')return{exitCode:0,stdout:args[1]==='stat'?'0:600:regular file:1\n':args[1]==='sha256sum'?profileSha+' file':controls.badProfile?'':`${profile} (enforce)\n${profile}//bwrap (enforce)\n`};
  assert.equal(file,'docker');assert.deepEqual(args.slice(0,2),['--host','unix:///var/run/docker.sock']);args=args.slice(2);
  if(args[0]==='info')return{exitCode:0,stdout:'"controlled-daemon"'};
  if(args[0]==='ps')return{exitCode:0,stdout:[...containers.values()].map(row=>row.Id).join('\n')};
  if(args[1]==='inspect'){const map=({image:images,network:networks,volume:volumes,container:containers})[args[0]],row=map.get(args[2])||(args[0]==='container'?[...map.values()].find(c=>c.Id===args[2]):null);return row?{exitCode:0,stdout:JSON.stringify([row])}:{exitCode:1,stderr:'No such object'};}
  if(args[0]==='build'){const context=args.at(-1);for(const [name,digest]of Object.entries(sourceManifest(root).files)){assert.equal(hash(fs.readFileSync(path.join(context,name))),digest);assert.equal(fs.statSync(path.join(context,name)).mode&0o777,0o444);assert.equal(fs.statSync(path.dirname(path.join(context,name))).mode&0o777,0o755);}const image={Id:IMAGE,Architecture:'arm64',Os:'linux',Config:{Labels:labels(args),User:'10001:10001',WorkingDir:'/app',Env:['PATH=/usr/bin'],Entrypoint:['node','sidecars/sandbox-runner/owned-listings/manager-entry.js'],Cmd:null}};images.set(args[args.indexOf('--tag')+1],image);images.set(IMAGE,image);return{exitCode:0,stdout:''};}
  if(args[1]==='create'&&['network','volume'].includes(args[0])){({network:networks,volume:volumes})[args[0]].set(args.at(-1),{Id:'d'.repeat(64),Name:args.at(-1),Labels:labels(args),Driver:args[0]==='network'?'bridge':'local',Internal:false,Containers:{},Options:{},Mountpoint:'/var/lib/docker/volumes/'+args.at(-1)});return{exitCode:0,stdout:''};}
  if(args[0]==='create'){assert.equal(managed.load({filePath:path.join(dir,managed.FILE)}).enabled,false);const name=args[args.indexOf('--name')+1],envFile=args[args.indexOf('--env-file')+1];envFiles.push(envFile);assert.equal(fs.statSync(envFile).mode&0o777,0o600);const env=fs.readFileSync(envFile,'utf8').trim().split('\n');assert.ok(!args.join(' ').includes(env.find(v=>v.startsWith('LISTINGS_CONTROL_TOKEN=')).split('=')[1]));if(controls.missingCreate)throw Error();const network=args[args.indexOf('--network')+1],volume=args[args.indexOf('--mount')+1].match(/source=([^,]+)/)[1],port=args[args.indexOf('--publish')+1].split(':')[1];
   containers.set(name,{Id:containers.size?'e'.repeat(64):'c'.repeat(64),Name:'/'+name,Image:IMAGE,Config:{...images.get(IMAGE).Config,Labels:labels(args),Env:['PATH=/usr/bin',...env]},State:{Running:false,Status:'created',StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z'},RestartCount:0,Mounts:[{Type:'volume',Name:volume,Destination:'/journal',RW:true}],HostConfig:{Privileged:false,ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,size=16m'},CapDrop:['ALL'],SecurityOpt:['seccomp=unconfined','apparmor='+profile],NetworkMode:network,PortBindings:{'8095/tcp':[{HostIp:'127.0.0.1',HostPort:port}]}},NetworkSettings:{Networks:controls.createdForeignNetwork?{foreign:{}}:{},Ports:null}});if(controls.lostCreate)throw Error();return{exitCode:0,stdout:''};}
  if(args[0]==='exec'){assert.equal(args[1],'--user');assert.equal(args[2],'10001:10001');assert.equal(args[4],'node');return controls.nonemptyJournal?{exitCode:13,stderr:'journal not empty'}:{exitCode:0,stdout:'EMPTY'};}
  if(args[0]==='stop'){const c=[...containers.values()].find(row=>row.Id===args.at(-1));assert.ok(c);c.State.Running=false;c.State.Status='exited';c.State.FinishedAt='2026-01-01T00:01:00Z';c.NetworkSettings.Networks={};c.NetworkSettings.Ports={};delete networks.get(c.HostConfig.NetworkMode).Containers[c.Id];return{exitCode:0,stdout:c.Id};}
  if(args[0]==='rename'){const c=[...containers.values()].find(row=>row.Id===args[1]);assert.ok(c);containers.delete(c.Name.slice(1));c.Name='/'+args[2];containers.set(args[2],c);return{exitCode:0,stdout:''};}
  if(args[0]==='start'){const c=containers.get(args[1])||[...containers.values()].find(c=>c.Id===args[1]);c.State.Running=true;c.State.Status='running';c.State.StartedAt='2026-01-01T00:00:00Z';if(!controls.omitStartNetwork){c.NetworkSettings.Networks={[c.HostConfig.NetworkMode]:{}};c.NetworkSettings.Ports=c.HostConfig.PortBindings;networks.get(c.HostConfig.NetworkMode).Containers[c.Id]={Name:c.Name.slice(1)};}else c.NetworkSettings.Ports={};return{exitCode:0,stdout:''};}
  if(args[0]==='network'&&args[1]==='connect'){const network=[...networks.values()].find(row=>row.Id===args[2]),c=[...containers.values()].find(row=>row.Id===args[3]);assert.ok(network&&c);if(controls.connectNoEffect)throw Error('connect did not apply');c.NetworkSettings.Networks={[network.Name]:{}};c.NetworkSettings.Ports=c.HostConfig.PortBindings;network.Containers[c.Id]={Name:c.Name.slice(1)};if(controls.lostConnect)throw Error('lost connect acknowledgement');return{exitCode:0,stdout:''};}assert.fail('unexpected operation '+args[0]);
 };
 const fetchImpl=async(url,options)=>{assert.match(url,/^http:\/\/127\.0\.0\.1:(8095|8099|8100)\/manager\/health$/);assert.match(options.headers.authorization,/^Bearer [A-Za-z0-9_-]{64}$/);controls.healthCalls++;if(controls.healthTransportFailures>0){controls.healthTransportFailures--;throw new TypeError('controlled transport unavailable');}return new Response(JSON.stringify({version:1,ready:true,capability:'owned-listings-manager.v1',runtimeDigest:controls.badHealth?'c'.repeat(64):DIGEST,limits:{maxPersistedTargets:200,maxResidentTargets:32,maxConcurrentExecutions:4,maxQueuedExecutions:16}}));};
 const qualifiedSourceSha256=sourceManifest(root).sha256;return{root,home,dir,id,controls,calls,envFiles,containers,images,networks,options:{root,home,platform:'linux',architecture:'arm64',runtimeDigest:DIGEST,qualifiedSourceSha256,run,fetchImpl}};
}
// Exercise the real upgrade phase under explicit controlled maintenance authority.
async function controlledUpgrade(options) {
 const setupModule=require('../scripts/setup-application'),authority=require('../scripts/install/ctf-authority-setup'),original=authority.prepareCtfAuthority;
 authority.prepareCtfAuthority=async({maintenanceScope,environment})=>{require('../scripts/lib/application-maintenance-scope').assertApplicationMaintenanceScope(maintenanceScope,environment);return {state:'active',trafficStarted:false};};
 try{return await setupModule.setup({...options,runDatabasePhase:async(request,dependencies)=>{
  assert.equal(request.kind,'upgrade');const before={...process.env},environment=require('../scripts/install/setup-database-phase').validateRequest(request);Object.assign(process.env,environment);let publish;
  try{return await require('../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment,acquire:async()=>({assertHeld(){},async beginMaintenance(){return Object.freeze({epoch:'1'});},async finishMaintenance(){},async close(){}}),drain:async()=>{},afterDrain:async()=>publish()},scope=>setupModule.executeSetupDatabasePhase(request,scope,{...dependencies,runCommand:options.runCommand,initializeApplication:async({maintenanceScope})=>{assert.equal(maintenanceScope,scope);},deferPublication:callback=>{publish=callback;}}));}
  finally{for(const key of Object.keys(process.env))if(!(key in before))delete process.env[key];Object.assign(process.env,before);}
 }});}finally{authority.prepareCtfAuthority=original;}
}
test('shared manager is privately staged, verified and idempotent without advertising application readiness',async t=>{const f=fixture(t);f.controls.lostCreate=true;const first=await provision(f.options);assert.equal(first.managerReady,true);assert.equal(first.ready,false);assert.equal(first.capabilityAvailable,false);assert.equal(first.activationEnabled,false);assert.equal(f.containers.size,1);const file=path.join(f.dir,managed.FILE),bytes=fs.readFileSync(file);const before=f.calls.length;await provision(f.options);assert.deepEqual(fs.readFileSync(file),bytes);assert.ok(!f.calls.slice(before).some(c=>['create','build','start'].includes(c.args[2])));assert.ok(f.envFiles.every(p=>!fs.existsSync(p)));assert.ok(!JSON.stringify(first).includes(managed.load({filePath:file}).manager.token));});
test('newly created Docker network is empty only before first start; foreign attachment is rejected without replacement',async t=>{const f=fixture(t),file=path.join(f.dir,managed.FILE);f.controls.createdForeignNetwork=true;await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_CONTAINER_CONFLICT'});const before=managed.capture({filePath:file}),container=[...f.containers.values()][0],id=container.Id,token=before.value.manager.token;assert.equal(container.State.Status,'created');assert.equal(container.State.Running,false);assert.deepEqual(Object.keys(container.NetworkSettings.Networks),['foreign']);container.NetworkSettings.Networks={};const result=await provision(f.options);assert.equal(result.managerReady,true);assert.equal(container.Id,id);assert.equal(managed.load({filePath:file}).manager.token,token);assert.equal(managed.load({filePath:file}).enabled,false);assert.deepEqual(Object.keys(container.NetworkSettings.Networks),[container.HostConfig.NetworkMode]);assert.deepEqual(f.calls.filter(c=>c.args[2]==='start').map(c=>c.args[3]),[id]);assert.equal(f.containers.size,1);container.State={Running:false,Status:'created',StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z'};container.NetworkSettings.Networks={};const qualified={runtimeDigest:DIGEST,qualifiedSourceSha256:f.options.qualifiedSourceSha256};await assert.rejects(verifyExisting({...f.options,qualified,qualify:()=>qualified}),{code:'LISTINGS_INSTALL_CONTAINER_CONFLICT'});});
test('installer repairs only the retained running manager with no endpoints or ports',async t=>{const f=fixture(t),file=path.join(f.dir,managed.FILE);f.controls.omitStartNetwork=true;f.controls.connectNoEffect=true;await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_NETWORK_CONNECT_UNCERTAIN'});const before=managed.capture({filePath:file}),container=[...f.containers.values()][0],id=container.Id,token=before.value.manager.token,bridge=f.networks.get(container.HostConfig.NetworkMode);assert.equal(container.State.Running,true);assert.deepEqual(container.NetworkSettings.Networks,{});assert.deepEqual(container.NetworkSettings.Ports,{});assert.deepEqual(bridge.Containers,{});bridge.Containers['f'.repeat(64)]={Name:'foreign'};await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_NETWORK_CONFLICT'});assert.equal(f.calls.filter(c=>c.args[2]==='network'&&c.args[3]==='connect').length,1);bridge.Containers={};f.controls.connectNoEffect=false;f.controls.lostConnect=true;const result=await provision(f.options);assert.equal(result.managerReady,true);assert.equal(container.Id,id);assert.equal(f.containers.size,1);assert.equal(managed.load({filePath:file}).manager.token,token);assert.equal(managed.load({filePath:file}).enabled,false);assert.deepEqual(Object.keys(container.NetworkSettings.Networks),[bridge.Name]);assert.deepEqual(Object.keys(bridge.Containers),[id]);assert.deepEqual(container.NetworkSettings.Ports,container.HostConfig.PortBindings);assert.deepEqual(f.calls.filter(c=>c.args[2]==='network'&&c.args[3]==='connect').map(c=>c.args.slice(4)),[[bridge.Id,id],[bridge.Id,id]]);});
test('disabled 8095 collision retains original, journals interrupted successor, and CAS-retargets only after strict health',async t=>{
 const f=fixture(t),file=path.join(f.dir,managed.FILE),repair={explicitActivation:true,applicationEnvironment:{},assertMaintenance:()=>{},assertUnusedListings:async()=>true,checkListingsPort:async()=>{}};
 f.controls.omitStartNetwork=true;f.controls.connectNoEffect=true;
 await assert.rejects(provision({...f.options,port:8095}),{code:'LISTINGS_INSTALL_NETWORK_CONNECT_UNCERTAIN'});
 const original=[...f.containers.values()][0],originalId=original.Id,originalBytes=fs.readFileSync(file),token=managed.load({filePath:file}).manager.token;
 f.controls.nonemptyJournal=true;
 await assert.rejects(provision({...f.options,...repair}),{code:'LISTINGS_INSTALL_COMMAND_FAILED'});
 assert.equal(original.State.Running,true);assert.deepEqual(fs.readFileSync(file),originalBytes);
 f.controls.nonemptyJournal=false;f.controls.missingCreate=true;
 await assert.rejects(provision({...f.options,...repair}),{code:'LISTINGS_PORT_RECOVERY_UNAVAILABLE'});
 const journal=require('../scripts/install/secureshop-owned-listings-port-recovery')._internals.readJournal(file);
 assert.ok(journal);assert.equal(original.State.Running,false);assert.match(original.Name,/^-?\/owasp-ai-goat-owned-listings-[a-f0-9]{12}-recovery-[a-f0-9]{12}$/);
 assert.deepEqual(Buffer.from(journal.value.managedBytes,'base64'),originalBytes);
 assert.equal(f.containers.size,1);assert.deepEqual(fs.readFileSync(file),originalBytes);
 const lock=file+'.activation.lock';fs.writeFileSync(lock,'0'.repeat(64)+'\n',{mode:0o600});
 await assert.rejects(provision({...f.options,...repair}),{code:'LISTINGS_MANAGED_RETARGET_LOCK_CONFLICT'});
 assert.deepEqual(fs.readFileSync(file),originalBytes);fs.writeFileSync(lock,journal.sha256+'\n',{mode:0o600});
 const companion=lock+'.'+'a'.repeat(24)+'.pending';fs.linkSync(lock,companion);
 assert.equal(fs.statSync(lock).nlink,2);
 f.controls.missingCreate=false;f.controls.omitStartNetwork=false;f.controls.badHealth=true;
 await assert.rejects(provision({...f.options,...repair}),{code:'LISTINGS_PORT_RECOVERY_HEALTH'});
 assert.deepEqual(fs.readFileSync(file),originalBytes);
 f.controls.badHealth=false;
 const result=await provision({...f.options,...repair});assert.equal(result.managerReady,true);
 const next=managed.load({filePath:file}),successor=f.containers.get(next.manager.container);
 assert.equal(next.manager.url,'http://127.0.0.1:8099');assert.equal(next.manager.token,token);assert.equal(next.enabled,false);
 assert.equal(successor.Id,'e'.repeat(64));assert.equal(successor.State.Running,true);assert.equal(original.Id,originalId);
 assert.equal(original.State.Running,false);assert.equal(f.containers.size,2);
 assert.equal(fs.existsSync(lock),false);assert.equal(fs.existsSync(companion),false);
 const before=f.calls.length;await provision({...f.options,...repair});await provision(f.options);
 assert.ok(!f.calls.slice(before).some(c=>['create','stop','rename'].includes(c.args[2])
  ||c.args[2]==='network'&&['create','connect'].includes(c.args[3])));
 assert.equal(managed.load({filePath:file}).enabled,false);
});
test('late work or maintenance loss after successor health keeps recovery disabled and exactly resumable',async t=>{
 for(const denied of ['work','maintenance'])await t.test(denied,async t=>{
  const f=fixture(t),file=path.join(f.dir,managed.FILE);
  f.controls.omitStartNetwork=true;f.controls.connectNoEffect=true;
  await assert.rejects(provision({...f.options,port:8095}),{code:'LISTINGS_INSTALL_NETWORK_CONNECT_UNCERTAIN'});
  const original=[...f.containers.values()][0],originalId=original.Id,originalBytes=fs.readFileSync(file),token=managed.load({filePath:file}).manager.token,volume=original.Mounts[0].Name;
  f.controls.omitStartNetwork=false;f.controls.connectNoEffect=false;
  let successorHealthy=false,deny=true;
  const fetchImpl=async(...args)=>{const response=await f.options.fetchImpl(...args);if(args[0].startsWith('http://127.0.0.1:8099/'))successorHealthy=true;return response;};
  const repair={explicitActivation:true,applicationEnvironment:{},checkListingsPort:async()=>{},fetchImpl,
   assertUnusedListings:async()=>{if(deny&&successorHealthy&&denied==='work')throw Error('controlled late work');return true;},
   assertMaintenance:()=>{if(deny&&successorHealthy&&denied==='maintenance')throw Error('controlled lost maintenance');}};
  await assert.rejects(provision({...f.options,...repair}),error=>{
   assert.equal(error.code,'LISTINGS_PORT_RECOVERY_NO_WORK');
   assert.equal(error.message,'Owned Listings port recovery unavailable; retained resources preserved');
   assert.ok(!JSON.stringify(error).includes('controlled'));
   return true;
  });
  assert.equal(successorHealthy,true);
  const retained=managed.load({filePath:file}),successor=f.containers.get(retained.manager.container);
  assert.deepEqual(fs.readFileSync(file),originalBytes);assert.equal(retained.enabled,false);assert.equal(retained.manager.url,'http://127.0.0.1:8095');assert.equal(retained.manager.token,token);
  assert.equal(f.containers.size,2);assert.equal(original.Id,originalId);assert.equal(original.State.Running,false);assert.ok(successor);assert.equal(successor.State.Running,true);
  assert.deepEqual(original.Mounts.map(row=>row.Name),[volume]);assert.deepEqual(successor.Mounts.map(row=>row.Name),[volume]);
  const successorId=successor.Id;deny=false;
  const result=await provision({...f.options,...repair}),published=managed.load({filePath:file});
  assert.equal(result.managerReady,true);assert.equal(published.enabled,false);assert.equal(published.manager.url,'http://127.0.0.1:8099');assert.equal(published.manager.token,token);
  assert.equal(f.containers.size,2);assert.equal(original.Id,originalId);assert.equal(f.containers.get(published.manager.container).Id,successorId);
  assert.deepEqual(f.containers.get(published.manager.container).Mounts.map(row=>row.Name),[volume]);
 });
});
test('fresh manager selects the first free owned loopback port before staging resources',async t=>{
 const f=fixture(t),foreign={Id:'f'.repeat(64),Name:'/foreign',HostConfig:{PortBindings:{'8094/tcp':[{HostIp:'127.0.0.1',HostPort:'8099'}]}}};
 f.containers.set('foreign',foreign);
 const result=await provision(f.options);assert.equal(result.managerReady,true);
 const value=managed.load({filePath:path.join(f.dir,managed.FILE)});
 assert.equal(value.manager.url,'http://127.0.0.1:8100');
 const owned=f.containers.get(value.manager.container);
 assert.equal(owned.HostConfig.PortBindings['8095/tcp'][0].HostPort,'8100');
 assert.equal(f.containers.get('foreign'),foreign);
});
test('existing-only verifier admits exact manager and never provisions or starts a disabled record',async t=>{
 const f=fixture(t),qualified={runtimeDigest:DIGEST,qualifiedSourceSha256:f.options.qualifiedSourceSha256};await provision(f.options);
 const options={...f.options,qualified,qualify:()=>qualified,configuration:managed.load({filePath:path.join(f.dir,managed.FILE)})};
 const before=f.calls.length,result=await verifyExisting(options);assert.deepEqual(result,{ready:true,enabled:false,containerId:'c'.repeat(64)});
 assert.ok(!f.calls.slice(before).some(c=>['build','create','start'].includes(c.args[2])));
 await assert.rejects(verifyExisting({...options,startStopped:true}),{code:'LISTINGS_INSTALL_NOT_ACTIVE'});
 [...f.containers.values()][0].HostConfig.Privileged=true;
 await assert.rejects(verifyExisting(options),{code:'LISTINGS_INSTALL_CONTAINER_CONFLICT'});
});
test('enabled manager recovers only its retained container ID and detects source or resource drift',async t=>{
 const f=fixture(t),file=path.join(f.dir,managed.FILE),qualified={runtimeDigest:DIGEST,qualifiedSourceSha256:f.options.qualifiedSourceSha256};
 await provision(f.options);await managed.activate({filePath:file,expected:managed.capture({filePath:file}),verify:async()=>true});
 const options={...f.options,qualified,qualify:()=>qualified,configuration:managed.load({filePath:file})};
 const container=[...f.containers.values()][0];container.State={Running:false,Status:'exited'};container.NetworkSettings.Ports=null;
 f.controls.healthTransportFailures=2;
 const before=f.calls.length,healthBefore=f.controls.healthCalls,result=await verifyExisting({...options,startStopped:true});
 assert.deepEqual(result,{ready:true,enabled:true,containerId:'c'.repeat(64)});
 assert.equal(f.controls.healthCalls-healthBefore,4);
 assert.deepEqual(f.calls.slice(before).filter(c=>c.args[2]==='start').map(c=>c.args[3]),['c'.repeat(64)]);
 assert.ok(!f.calls.slice(before).some(c=>['build','create'].includes(c.args[2])));
 container.State={Running:false,Status:'exited'};container.NetworkSettings.Ports=null;f.controls.badHealth=true;
 const identityBefore=f.controls.healthCalls;
 await assert.rejects(verifyExisting({...options,startStopped:true}),{code:'LISTINGS_MANAGER_IDENTITY'});
 assert.equal(f.controls.healthCalls-identityBefore,1);f.controls.badHealth=false;
 f.controls.healthTransportFailures=1;const runningBefore=f.controls.healthCalls;
 await assert.rejects(verifyExisting(options),{name:'TypeError'});
 assert.equal(f.controls.healthCalls-runningBefore,1);
 container.HostConfig.Memory=1024;
 await assert.rejects(verifyExisting(options),{code:'LISTINGS_INSTALL_CONTAINER_CONFLICT'});
});
test('qualified predecessor existing-only verification preserves journal, credentials and exact resource identity',async t=>{
 const f=fixture(t,true),file=path.join(f.dir,managed.FILE),source='cc8faa6a5afd6533eebbe5885d112324da5c4ea04a583c4a6607adf0dcf19a2f',runtime='514a0b7cc6d2eadcc515ce7a96af139f7161f3c3989a271d931c068a18812e13';
 const profile='owasp-ai-goat-owned-listings-'+f.id,network=profile+'-bridge',volume=profile+'-journal';
 const authority=require('../scripts/local-docker-authority').authorityDigest(JSON.parse(fs.readFileSync(path.join(f.dir,'local-docker.json'))));
 const value=managed.validate({version:1,workspaceId:f.id,enabled:false,architecture:'arm64',dockerAuthoritySha256:authority,imageId:IMAGE,sourceManifestSha256:source,runtimeDigest:runtime,
  profile:{name:profile,sha256:hash(fs.readFileSync(path.join(ROOT,'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',profile))},manager:{container:profile,url:'http://127.0.0.1:8099',token:'t'.repeat(64)}});
 managed.stage({filePath:file,value});await managed.activate({filePath:file,expected:managed.capture({filePath:file}),verify:async()=>true});
 const labels={'owasp-ai-goat.listings.workspace':f.id,'owasp-ai-goat.listings.authority':authority,'owasp-ai-goat.listings.source':source,'owasp-ai-goat.listings.runtime':runtime};
 const image={Id:IMAGE,Architecture:'arm64',Os:'linux',Config:{Labels:labels,User:'10001:10001',WorkingDir:'/app',Env:['PATH=/usr/bin'],Entrypoint:['node','sidecars/sandbox-runner/owned-listings/manager-entry.js'],Cmd:null}};
 f.images.set(IMAGE,image);f.networks.set(network,{Id:'d'.repeat(64),Name:network,Labels:labels,Driver:'bridge',Internal:false,Containers:{['c'.repeat(64)]:{}}});
 // The only volume contents are deliberately opaque to verification.
 const volumeRow={Name:volume,Labels:labels,Driver:'local',Options:{},Mountpoint:'/var/lib/docker/volumes/'+volume};
 const ports={'8095/tcp':[{HostIp:'127.0.0.1',HostPort:'8099'}]};
 const container={Id:'c'.repeat(64),Name:'/'+profile,Image:IMAGE,Config:{...image.Config,Env:['PATH=/usr/bin','LISTINGS_MANAGER_ENABLED=true','LISTINGS_PROFILE='+profile,'LISTINGS_PUBLIC_ORIGIN='+value.manager.url,'LISTINGS_CONTROL_TOKEN='+value.manager.token]},State:{Running:false,Status:'exited'},Mounts:[{Type:'volume',Name:volume,Destination:'/journal',RW:true}],HostConfig:{Privileged:false,ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,size=16m'},CapDrop:['ALL'],SecurityOpt:['seccomp=unconfined','apparmor='+profile],NetworkMode:network,PortBindings:ports},NetworkSettings:{Networks:{[network]:{}},Ports:null}};
 f.containers.set(profile,container);
 const run=async(file,args,options)=>args[2]==='volume'&&args[3]==='inspect'?{exitCode:0,stdout:JSON.stringify([volumeRow])}:f.options.run(file,args,options);
 let healthCalls=0;const fetchImpl=async()=>{healthCalls++;return new Response(JSON.stringify({version:1,ready:true,capability:'owned-listings-manager.v1',runtimeDigest:runtime,limits:{maxPersistedTargets:200,maxResidentTargets:32,maxConcurrentExecutions:4,maxQueuedExecutions:16}}));};
 const before=fs.readFileSync(file),configuration=managed.load({filePath:file}),options={...f.options,run,fetchImpl,configuration,startStopped:true};
 assert.deepEqual(require('../server/services/secureshopListingsRuntime').loadConfiguration({root:ROOT,home:f.home}),configuration);
 assert.deepEqual(await verifyExisting(options),{ready:true,enabled:true,containerId:container.Id});
 assert.deepEqual(fs.readFileSync(file),before);assert.equal(healthCalls,2);
 assert.deepEqual(f.calls.filter(c=>c.args[2]==='start').map(c=>c.args[3]),[container.Id]);
 assert.ok(!f.calls.some(c=>['create','build','rm','stop','rename','exec'].includes(c.args[2])));
 image.Config.Labels={...labels,'owasp-ai-goat.listings.source':'0'.repeat(64)};
 await assert.rejects(verifyExisting(options),{code:'LISTINGS_INSTALL_IMAGE_CONFLICT'});image.Config.Labels=labels;
 f.networks.get(network).Containers['f'.repeat(64)]={};
 await assert.rejects(verifyExisting(options),{code:'LISTINGS_INSTALL_NETWORK_FOREIGN_ENDPOINT'});delete f.networks.get(network).Containers['f'.repeat(64)];
 await assert.rejects(verifyExisting({...options,fetchImpl:async()=>new Response(JSON.stringify({version:1,ready:true,capability:'owned-listings-manager.v1',runtimeDigest:DIGEST,limits:{maxPersistedTargets:200,maxResidentTargets:32,maxConcurrentExecutions:4,maxQueuedExecutions:16}}))}),{code:'LISTINGS_MANAGER_IDENTITY'});
 assert.deepEqual(fs.readFileSync(file),before);
});
test('managed activation publishes only after two identity-checked probes and rejects concurrent replacement',async t=>{
 const f=fixture(t),file=path.join(f.dir,managed.FILE);await provision(f.options);const before=managed.capture({filePath:file});
 await assert.rejects(managed.activate({filePath:file,expected:before,verify:async()=>false}),{code:'LISTINGS_MANAGED_ACTIVATION_UNREADY'});
 assert.equal(managed.load({filePath:file}).enabled,false);
 const swapped=path.join(f.dir,'swapped');fs.writeFileSync(swapped,managed.encode(before.value),{mode:0o600});
 await assert.rejects(managed.activate({filePath:file,expected:before,verify:async()=>{fs.renameSync(swapped,file);return true;}}),{code:'LISTINGS_MANAGED_CHANGED'});
 assert.equal(managed.load({filePath:file}).enabled,false);
 const current=managed.capture({filePath:file});let checks=0;
 const enabled=await managed.activate({filePath:file,expected:current,verify:async()=>{checks++;return true;}});
 assert.equal(checks,1);assert.equal(enabled.enabled,true);assert.equal(managed.load({filePath:file}).enabled,true);
 assert.equal(fs.statSync(file).mode&0o777,0o600);assert.equal(fs.existsSync(file+'.activation.lock'),false);
});
test('activation gate requires bound shop and bounded exact runtime schema/history reads',async()=>{
 const env={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SECURESHOP_AGENTS_DATABASE_URL:'postgresql://127.0.0.1/agents_fixture',SECURESHOP_REVIEW_DATABASE_URL:'postgresql://127.0.0.1/review_fixture'};
 await assert.rejects(assertActivationReadiness({applicationEnvironment:{...env,SS_ENABLE:'false'}}),{code:'LISTINGS_ACTIVATION_PREREQUISITES'});
 const closed=[],calls=[];const result=await assertActivationReadiness({applicationEnvironment:env,makePool:options=>{
  assert.match(options.options,/statement_timeout=10000/);return{async query(sql){assert.match(sql,/current_database/);return{rows:[{name:new URL(options.connectionString).pathname.slice(1)}]};},async end(){closed.push(options.connectionString);}};
 },assertSchema:async({agentsPool,reviewPool})=>{assert.ok(agentsPool&&reviewPool);calls.push('schema');},assertHistory:async reviewPool=>{assert.ok(reviewPool);calls.push('history');}});
 assert.equal(result,true);assert.deepEqual(calls,['schema','history']);assert.equal(closed.length,2);
 await assertRetainedBindings({async query(sql,args){assert.match(sql,/owned_listing_admissions/);assert.deepEqual(args,[null]);return{rows:[]};}});
});
test('package drift and unsupported architecture fail before any mutating Docker call',async t=>{const f=fixture(t);await assert.rejects(provision({...f.options,architecture:'x64'}),{code:'LISTINGS_INSTALL_PLATFORM_UNQUALIFIED'});fs.appendFileSync(path.join(f.root,'sidecars/sandbox-runner/owned-listings/manager-entry.js'),'\n');await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_SOURCE_UNQUALIFIED'});assert.equal(f.calls.length,0);});
test('failed health preserves disabled credentials, retry never rotates tokens',async t=>{const f=fixture(t);f.controls.badHealth=true;await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_READINESS_FAILED'});const file=path.join(f.dir,managed.FILE),bytes=fs.readFileSync(file);assert.equal(managed.load({filePath:file}).enabled,false);f.controls.badHealth=false;await provision(f.options);assert.deepEqual(fs.readFileSync(file),bytes);});
test('profile, ambiguous create and unsafe recovered container fail closed',async t=>{const f=fixture(t);f.controls.badProfile=true;await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_PROFILE_CONFLICT'});f.controls.badProfile=false;f.controls.missingCreate=true;await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_CREATE_UNCERTAIN'});f.controls.missingCreate=false;await provision(f.options);[...f.containers.values()][0].HostConfig.Privileged=true;await assert.rejects(provision(f.options),{code:'LISTINGS_INSTALL_CONTAINER_CONFLICT'});});
test('supported setup derives its qualification from checked-in authority and dispatches automatic preparation',async t=>{const f=fixture(t,true),opts={root:ROOT,homeDirectory:f.home,architecture:'arm64',environment:{SS_LISTINGS_QUALIFIED_PACKAGE_PATH:'/ignored/manual-record'}};const verified=preflight(opts);let called=0;const result=await setupOwnedListings({...opts,requested:true,qualification:verified,prepare:async o=>{called++;assert.equal(o.runtimeDigest,verified.runtimeDigest);return{managerReady:true,ready:false,capabilityAvailable:false,activationEnabled:false};}});assert.equal(called,1);assert.equal(result.requested,true);await assert.rejects(setupOwnedListings({...opts,requested:true,qualification:{...verified,runtimeDigest:'0'.repeat(64)},prepare:async()=>assert.fail('changed qualification must not prepare')}),{code:'LISTINGS_INSTALL_QUALIFICATION_CHANGED'});assert.throws(()=>preflight({...opts,architecture:'x64'}),{code:'LISTINGS_INSTALL_PLATFORM_UNQUALIFIED'});});
test('enabled setup replay verifies readiness without preparing or publishing',async t=>{const f=fixture(t,true),file=path.join(f.dir,managed.FILE);await provision(f.options);await managed.activate({filePath:file,expected:managed.capture({filePath:file}),verify:async()=>true});const calls=[];const result=await setupOwnedListings({requested:true,root:f.root,homeDirectory:f.home,architecture:'arm64',environment:{},applicationEnvironment:{},prepare:async()=>assert.fail('enabled replay cannot prepare'),publish:async()=>assert.fail('enabled replay cannot publish'),readiness:async()=>{calls.push('readiness');},verify:async({configuration})=>{assert.equal(configuration.enabled,true);calls.push('verify');return{ready:true,enabled:true,containerId:'c'.repeat(64)};}});assert.deepEqual(calls,['readiness','verify']);assert.equal(result.alreadyEnabled,true);assert.equal(result.restartRequired,false);assert.equal(managed.load({filePath:file}).enabled,true);});
test('activation checks schema before its final resource admission and preserves disabled state on drift',async t=>{const f=fixture(t,true),file=path.join(f.dir,managed.FILE);await provision(f.options);const environment={IDENTITY_DATABASE_URL:'postgresql://runtime@127.0.0.1/identity_fixture',IDENTITY_MIGRATION_DATABASE_URL:'postgresql://migration@127.0.0.1/identity_fixture'};const calls=[];let checks=0;const {withApplicationMaintenanceScope}=require('../scripts/lib/application-maintenance-scope');await assert.rejects(withApplicationMaintenanceScope({environment,acquire:async()=>({assertHeld(){},async beginMaintenance(){return'epoch';},async finishMaintenance(){},async close(){}}),drain:async()=>{}},scope=>setupOwnedListings({requested:true,explicitActivation:true,root:f.root,homeDirectory:f.home,architecture:'arm64',environment:{},applicationEnvironment:environment,maintenanceScope:scope,prepare:async()=>({managerReady:true,ready:false,capabilityAvailable:false,activationEnabled:false}),readiness:async()=>{calls.push('readiness');},verify:async()=>{calls.push('verify');if(++checks===2)throw Object.assign(Error('resource drift'),{code:'LISTINGS_INSTALL_RESOURCE_CHANGED'});return{ready:true,enabled:false,containerId:'c'.repeat(64)};}})),error=>error.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&error.errors.some(cause=>cause.code==='LISTINGS_INSTALL_RESOURCE_CHANGED'));assert.deepEqual(calls,['readiness','verify','readiness','verify']);assert.equal(managed.load({filePath:file}).enabled,false);});
test('managed FIFO is rejected without blocking',async t=>{const f=fixture(t),file=path.join(f.dir,managed.FILE);assert.equal(spawnSync('mkfifo',[file]).status,0);const child=spawnSync(process.execPath,['-e',`try{require(${JSON.stringify(require.resolve('../server/services/secureshopListingsManagedConfiguration'))}).load({filePath:${JSON.stringify(file)}});process.exit(2);}catch(e){process.exit(e.code==='LISTINGS_MANAGED_UNTRUSTED'?0:3);}`],{timeout:2000});assert.equal(child.status,0);});
test('CLI plan and OS plan report preparation only without installation',()=>{
 const quote=value=>"'"+value.replaceAll("'","'\"'\"'")+"'";
 let shell=fs.readFileSync(path.join(ROOT,'scripts/install/bootstrap-unix.sh'),'utf8');
 const rootLine='ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"';
 assert.equal(shell.split(rootLine).length,2,'exact bootstrap root assignment');
 shell=shell.replace(rootLine,'ROOT='+quote(ROOT));
 // Old macOS Bash uses a host temporary file for heredocs; pipe the exact
 // checked-in plan text in memory without changing its contents or dispatcher.
 let plans=0;shell=shell.replace(/cat <<'PLAN'\n([\s\S]*?)\nPLAN/g,(_all,body)=>{plans++;return "printf '%s\\n' "+quote(body)+' | cat';});
 assert.equal(plans,3,'fresh, upgrade and repair plan heredocs retained');
 const osName=process.platform==='darwin'?'Darwin':'Linux';
 for(const [cmd,args,input,title]of [[process.execPath,['scripts/setup-application.js','--plan','--owned-listings']], [process.execPath,['scripts/setup-application.js','--plan','--upgrade','--no-install','--owned-listings','--enable-owned-listings']],['/bin/bash',['-s','--',osName,'--plan','--owned-listings'],shell,'Fresh setup plan'],['/bin/bash',['-s','--',osName,'--plan','--upgrade','--owned-listings'],shell,'Additive upgrade plan'],['/bin/bash',['-s','--',osName,'--plan','--upgrade','--owned-listings','--enable-owned-listings'],shell,'Additive upgrade plan'],['/bin/bash',['-s','--',osName,'--plan','--repair','--owned-listings'],shell,'Existing-install repair plan']]){
  const result=spawnSync(cmd,args,{cwd:ROOT,encoding:'utf8',timeout:5000,...(input?{input}:{})});
  assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/Listings/);assert.match(result.stdout,/private/);if(title)assert.ok(result.stdout.includes(title),`${title} must be selected`);
  if(args.includes('--enable-owned-listings'))assert.match(result.stdout,/activation/i);
 }
 const missingOwned=spawnSync(process.execPath,['scripts/setup-application.js','--plan','--enable-owned-listings'],{cwd:ROOT,encoding:'utf8',timeout:5000});
 assert.equal(missingOwned.status,1);
 assert.match(missingOwned.stderr,/--enable-owned-listings requires --owned-listings/);
 const missingShellOwned=spawnSync('/bin/bash',['-s','--',osName,'--plan','--enable-owned-listings'],{cwd:ROOT,encoding:'utf8',timeout:5000,input:shell});
 assert.equal(missingShellOwned.status,1);
 assert.match(missingShellOwned.stderr,/--enable-owned-listings requires --owned-listings/);
});
test('supported upgrade dispatch preserves private application values on repeat and Listings failure',async t=>{
 const f=fixture(t),{setup,encodeEnv}=require('../scripts/setup-application'),{provisioningPlan}=require('../db/postgres/provision-application');
 const manifest=provisioningPlan(),configuration=Object.fromEntries(manifest.flatMap(r=>[[r.runtimeVariable,`postgresql://${r.runtimeRole}:runtime@127.0.0.1:5432/${r.database}`],[r.migrationVariable,`postgresql://${r.migrationRole}:migration@127.0.0.1:5432/${r.database}`]]));
 fs.writeFileSync(path.join(f.dir,'provisioning.json'),JSON.stringify({version:1,status:'complete',plan:manifest,configuration,created:[]}),{mode:0o600});const envPath=path.join(f.root,'.env');fs.writeFileSync(envPath,"# preserved operator configuration\nJWT_SECRET='unchanged secret'\n"+encodeEnv(configuration),{mode:0o600});
 let calls=0;const options={root:f.root,homeDirectory:f.home,upgrade:true,ownedListings:true,processEnvironment:{},adminUrl:'postgresql://admin:secret@127.0.0.1:5432/postgres',ensureDockerAuthority:async()=>({authority:{version:1,workspaceId:f.id,host:'unix:///var/run/docker.sock',daemonId:'controlled-daemon',source:'environment-host'},persisted:true}),provision:async()=>({status:'existing',plan:manifest,configuration}),provisionDelivery:async()=>({configuration:{CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@127.0.0.1:5432/owasp_ai_goat_ctf'}}),runCommand:async()=>assert.fail('no unrelated initializer or package mutation'),preflightOwnedListings:async()=>({runtimeDigest:DIGEST}),setupOwnedListings:async o=>{calls++;assert.equal(o.requested,true);assert.equal(o.qualification.runtimeDigest,DIGEST);return{requested:true,managerReady:true,ready:false,capabilityAvailable:false,activationEnabled:false};}};
 const first=await controlledUpgrade(options);assert.equal(first.listings.activationEnabled,false);const bytes=fs.readFileSync(envPath),reset=fs.readFileSync(path.join(f.dir,'secureshop-reset-key.json'));await controlledUpgrade(options);assert.equal(calls,2);assert.deepEqual(fs.readFileSync(envPath),bytes);assert.deepEqual(fs.readFileSync(path.join(f.dir,'secureshop-reset-key.json')),reset);
 await controlledUpgrade({...options,enableOwnedListings:true,setupOwnedListings:async o=>{assert.equal(o.explicitActivation,true);assert.ok(o.applicationEnvironment);assert.ok(o.maintenanceScope);return{requested:true,managerReady:true,ready:true,capabilityAvailable:true,activationEnabled:true,restartRequired:true};}});
 assert.deepEqual(fs.readFileSync(envPath),bytes);
 await assert.rejects(controlledUpgrade({...options,setupOwnedListings:async()=>{throw Object.assign(Error('controlled failure'),{code:'LISTINGS_INSTALL_READINESS_FAILED'});}}),error=>error.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&error.errors.some(cause=>cause.code==='LISTINGS_INSTALL_READINESS_FAILED'));assert.deepEqual(fs.readFileSync(envPath),bytes);assert.deepEqual(fs.readFileSync(path.join(f.dir,'secureshop-reset-key.json')),reset);
 const qualified=require('../server/services/secureshopQualifiedManagedConfiguration'),canonicalRoot=fs.realpathSync(f.root),roots=qualified.expectedRoots(canonicalRoot,f.home);
 for(const directory of Object.values(roots))fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const qualifiedValues={SS_ENABLE:'true',...Object.fromEntries(qualified.BOOLEAN_KEYS.map(key=>[key,'false'])),...roots};
 fs.writeFileSync(qualified.managedPath(canonicalRoot,f.home),qualified.KEYS.map(key=>`${key}=${qualifiedValues[key]}`).join('\n')+'\n',{mode:0o600});
 await controlledUpgrade({...options,setupOwnedListings:async o=>{assert.equal(o.applicationEnvironment.SS_ENABLE,'true');assert.equal(o.applicationEnvironment.SS_BOUND_REVIEWS_ENABLED,'false');return{requested:true,managerReady:true,ready:false,capabilityAvailable:false,activationEnabled:false};}});
});
test('checked-in automatic candidate binds exact native-qualified source and denies unqualified architecture',async t=>{
 // Native qualification reads the real package and an exact checked-in copy of its retained record.
 const f=fixture(t,true),candidate=require('../scripts/install/secureshop-owned-listings-qualified-candidate');
 const report=path.join(f.root,'scripts/install/qualification/secureshop-listings-package-2026-10-17.json'),originalReport=fs.readFileSync(report);
 assert.equal(hash(originalReport),'6fbd2ab59428a6507ab80394b43cdc1b4360d06b7919b53d3ad4a3fcdaf0dd03');
 const qualified=candidate.qualifiedPackage({root:f.root,architecture:'arm64'});assert.equal(qualified.qualifiedSourceSha256,f.options.qualifiedSourceSha256);assert.throws(()=>candidate.qualifiedPackage({root:f.root,architecture:'x64'}),{code:'LISTINGS_INSTALL_PLATFORM_UNQUALIFIED'});
 let installed=0,provisioned=0;const result=await candidate.prepare({...f.options,provisionProfile:async({p})=>{installed++;assert.equal(p.profile.name,'owasp-ai-goat-owned-listings-'+f.id);},provision:async o=>{provisioned++;assert.equal(o.runtimeDigest,qualified.runtimeDigest);return{managerReady:true,activationEnabled:false};}});assert.equal(installed,1);assert.equal(provisioned,1);assert.equal(result.activationEnabled,false);
 const target=path.join(f.root,'sidecars/sandbox-runner/owned-listings/manager-entry.js'),originalRead=fs.readFileSync;
 const before=originalRead(target);
 const drift=t.mock.method(fs,'readFileSync',function(file,...args){const bytes=originalRead.call(this,file,...args);return file===target?(Buffer.isBuffer(bytes)?Buffer.concat([bytes,Buffer.from('\n')]):bytes+'\n'):bytes;});
 assert.throws(()=>candidate.qualifiedPackage({root:f.root,architecture:'arm64'}),{code:'LISTINGS_PACKAGE_SOURCE_CHANGED'});
 drift.mock.restore();assert.deepEqual(originalRead(target),before);
 const reportStat=fs.statSync(report);
 const changedReport=t.mock.method(fs,'readFileSync',function(file,...args){const bytes=originalRead.call(this,file,...args);if(typeof file==='number'){const stat=fs.fstatSync(file);if(stat.dev===reportStat.dev&&stat.ino===reportStat.ino)return Buffer.concat([bytes,Buffer.from(' ')]);}return bytes;});
 assert.throws(()=>candidate.qualifiedPackage({root:f.root,architecture:'arm64'}),{code:'LISTINGS_PACKAGE_QUALIFICATION_INVALID'});
 changedReport.mock.restore();assert.deepEqual(originalRead(report),originalReport);
});
test('automatic profile candidate limits destination and quotes the remote helper as one command',async t=>{
 const f=fixture(t),candidate=require('../scripts/install/secureshop-owned-listings-qualified-candidate'),profile='owasp-ai-goat-owned-listings-'+f.id;
 const p={workspaceId:f.id,profile:{name:profile,sha256:hash(fs.readFileSync(path.join(f.root,'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',profile))}};
 let command;await candidate.provisionProfile({p,root:f.root,home:f.home,platform:'darwin',authority:{host:'unix:///Users/owned/.colima/reviewed/docker.sock'},run:async(file,args)=>{command={file,args};return{exitCode:0};}});assert.equal(command.file,'ssh');assert.equal(command.args.length,4);assert.equal(command.args[1],'/Users/owned/.colima/_lima/colima-reviewed/ssh.config');assert.match(command.args[3],/^'sudo' '--non-interactive' 'python3' '-c'/);assert.ok(command.args[3].includes('O_NONBLOCK'));assert.ok(command.args[3].includes('flock'));assert.ok(command.args[3].includes('os.link'));assert.ok(command.args[3].includes('--skip-kernel-load'));
 const py=spawnSync('python3',['-c','import ast,sys; ast.parse(sys.stdin.read())'],{input:candidate._internals.PROFILE_PROGRAM,encoding:'utf8',timeout:3000});assert.equal(py.status,0,py.stderr);
 await assert.rejects(candidate.provisionProfile({p:{...p,profile:{...p.profile,name:'foreign'}},root:f.root,home:f.home,platform:'linux',authority:{host:'unix:///var/run/docker.sock'},run:()=>assert.fail()}),{code:'LISTINGS_PROFILE_INVALID'});
});
test('optional build CA is digest-bound and supplied as a private BuildKit secret',async t=>{const f=fixture(t),file=path.join(f.home,'ca.pem');fs.writeFileSync(file,'owned certificate fixture\n',{mode:0o600});await assert.rejects(provision({...f.options,buildCaFile:file,buildCaSha256:'0'.repeat(64)}),{code:'LISTINGS_INSTALL_BUILD_CA_INVALID'});assert.equal(f.containers.size,0);await provision({...f.options,buildCaFile:file,buildCaSha256:hash(fs.readFileSync(file))});const build=f.calls.find(c=>c.args.includes('build'));assert.ok(build.args.includes('--secret'));const secret=build.args[build.args.indexOf('--secret')+1];assert.match(secret,/^id=npm_ca,src=/);assert.ok(!fs.existsSync(secret.split('src=')[1]));assert.equal(fs.readFileSync(file,'utf8'),'owned certificate fixture\n');});

test('supported preparation binds an explicitly configured CA before provisioning',t=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'listings-ca-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const file=path.join(dir,'ca.pem');fs.writeFileSync(file,'configured CA fixture\n',{mode:0o600});const {configuredBuildCa}=require('../scripts/install/listings-setup');assert.deepEqual(configuredBuildCa({}),{});assert.deepEqual(configuredBuildCa({npm_config_cafile:file}),{buildCaFile:file,buildCaSha256:hash(fs.readFileSync(file))});assert.equal(configuredBuildCa({NODE_EXTRA_CA_CERTS:file}).buildCaFile,file);fs.chmodSync(file,0o666);assert.throws(()=>configuredBuildCa({NODE_EXTRA_CA_CERTS:file}),{code:'LISTINGS_INSTALL_BUILD_CA_INVALID'});fs.chmodSync(file,0o600);const link=path.join(dir,'link');fs.symlinkSync(file,link);assert.throws(()=>configuredBuildCa({npm_config_cafile:link}),{code:'LISTINGS_INSTALL_BUILD_CA_INVALID'});assert.throws(()=>configuredBuildCa({npm_config_cafile:'relative.pem'}),{code:'LISTINGS_INSTALL_BUILD_CA_INVALID'});});

test('v2 candidate report requires explicit unused provenance and owned-process cleanup',()=>{
 const candidate=require('../scripts/install/secureshop-owned-listings-qualified-candidate'),source={sha256:'a'.repeat(64),files:{'a.js':'b'.repeat(64),'b.js':'c'.repeat(64)}};
 const runtime='c'.repeat(64),checks=['real-supplier-prototype-effect','fixed-prototype-no-effect','internal-prototype-route-denial','real-json','internal-ssrf','fixed-denial','real-file-entity','real-http-entity','external-host-denial','restart-no-refetch','timeout-child-cleanup','readonly-write-denial','authenticated-http','retirement-redaction-sibling'];
 const result={status:'passed',modelCalls:0,runtimeDigest:runtime,existingReceipt:false,checks};
 const report={version:2,cohort:'listings-package',status:'passed',error:null,modelCalls:0,candidateOnly:true,sourceCopy:false,frozenHashesVerified:true,frozenFileCount:2,
  source:{package:{sha256:source.sha256,files:{'b.js':'c'.repeat(64),'a.js':'b'.repeat(64)}},drivers:{x:'d'.repeat(64)},node:'e'.repeat(64),docker:'f'.repeat(64),buildx:{path:'/opt/vendor/docker-buildx',sha256:'591a852237e8ed2b8c65f6be8105ef8c2d1ec52edc77c8acf8f263c2240ef4d6'}},
  unusedResources:{remote:'not-used',buildCa:'not-used'},ownedProcesses:{build:{pid:1,pgid:1},fresh:{pid:2,pgid:2},restart:{pid:3,pgid:3}},
  result,restartResult:{...result,existingReceipt:true},reportedCleanup:{containerAbsent:true,volumeAbsent:true,profileAbsent:true,imageAbsent:true,buildPgidAbsent:true,freshPgidAbsent:true,restartPgidAbsent:true,errors:[]}};
 assert.equal(candidate._internals.qualifiedReport(report,source,runtime),true);
 assert.equal(candidate._internals.qualifiedReport({...report,unusedResources:{remote:'not-used'}},source,runtime),false);
 assert.equal(candidate._internals.qualifiedReport({...report,reportedCleanup:{...report.reportedCleanup,freshPgidAbsent:false}},source,runtime),false);
 assert.equal(candidate._internals.qualifiedReport({...report,source:{...report.source,package:{...report.source.package,files:{'a.js':'b'.repeat(64)}}}},source,runtime),false);
 assert.equal(candidate._internals.qualifiedReport({...report,source:{...report.source,package:{...report.source.package,files:{...report.source.package.files,'a.js':'0'.repeat(64)}}}},source,runtime),false);
 assert.equal(candidate._internals.qualifiedReport({...report,source:{...report.source,drivers:{x:'invalid'}}},source,runtime),false);
 assert.equal(candidate._internals.qualifiedReport({...report,source:{...report.source,buildx:{...report.source.buildx,sha256:'0'.repeat(64)}}},source,runtime),false);
 assert.equal(candidate._internals.qualifiedReport({...report,source:{...report.source,buildx:{...report.source.buildx,path:'docker-buildx'}}},source,runtime),false);
 assert.equal(candidate._internals.qualifiedReport({...report,restartResult:{...report.restartResult,existingReceipt:false}},source,runtime),false);
 const legacy={status:'passed',frozenHashesVerified:true,frozenFileCount:2,result:{status:'passed',modelCalls:0,runtimeDigest:runtime},restartResult:{status:'passed',modelCalls:0,runtimeDigest:runtime},reportedCleanup:{containerAbsent:true,volumeAbsent:true,imageAbsent:true,profileAbsent:true,remoteAbsent:true,buildCaAbsent:true,buildPgidAbsent:true,testPgidAbsent:true,errors:[]}};
 assert.equal(candidate._internals.qualifiedReport(legacy,source,runtime),true);
});
