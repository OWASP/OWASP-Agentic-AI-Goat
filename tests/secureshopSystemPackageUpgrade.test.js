'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {provision,startExisting}=require('../scripts/install/secureshop-owned-system-provision');
const {workspaceId}=require('../scripts/application-data-root');
const {sourceManifest}=require('../scripts/install/secureshop-owned-system');
const managed=require('../server/services/secureshopSystemManagedConfiguration');
const {renderMcpSandboxAppArmor}=require('../scripts/render-mcp-sandbox-apparmor');
const ROOT=path.resolve(__dirname,'..'),BASE='sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1',IMAGE='sha256:'+'a'.repeat(64);
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function fixture(t){
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'system-provision-test-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const root=path.join(home,'checkout');fs.mkdirSync(root);
 // Only synthetic package data reaches the mocked Docker build.
 const relative='sidecars/sandbox-runner/owned-system',directory=path.join(root,relative);fs.mkdirSync(directory,{recursive:true});
 const manifest=JSON.parse(fs.readFileSync(path.join(ROOT,relative,'local-package-manifest.json'),'utf8'));
 for(const name of Object.keys(manifest.files)){const bytes=Buffer.from('synthetic controlled package: '+name+'\n');fs.mkdirSync(path.dirname(path.join(directory,name)),{recursive:true});fs.writeFileSync(path.join(directory,name),bytes);manifest.files[name]=hash(bytes);}
 fs.writeFileSync(path.join(directory,'local-package-manifest.json'),JSON.stringify(manifest));
 const apparmor=path.join(root,'sidecars/sandbox-runner/apparmor');fs.mkdirSync(apparmor,{recursive:true});fs.writeFileSync(path.join(apparmor,'owasp-ai-goat-mcp-sandbox.apparmor.in'),'profile @@SUPERVISOR_PROFILE@@ { # synthetic controlled profile\n}\n');
 const id=workspaceId(root),dir=path.join(home,'.owasp-ai-goat',id);fs.mkdirSync(dir,{recursive:true,mode:0o700});
 fs.writeFileSync(path.join(dir,'local-docker.json'),JSON.stringify({version:1,workspaceId:id,host:'unix:///var/run/docker.sock',daemonId:'controlled-daemon',source:'environment-host'}),{mode:0o600});
 const profileSha=hash(renderMcpSandboxAppArmor(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in'),'utf8'),'owasp-ai-goat-mcp-sandbox'));
 const calls=[],envFiles=[],images=new Map([[BASE,{Id:BASE,Architecture:'arm64'}]]),networks=new Map(),volumes=new Map(),containers=new Map();
 let builds=0,serial=0;
 const controls={unknownCreate:false,missingCreate:false,readiness:false,profileSha,profileEnforced:true,buildHook:null};
 const labels=args=>Object.fromEntries(args.flatMap((x,i)=>x==='--label'?[args[i+1].split(/=(.*)/s).slice(0,2)]:[]));
 const inspect=(value,kind)=>value?{exitCode:0,stdout:JSON.stringify([value]),stderr:''}:{exitCode:1,stdout:'',stderr:kind==='volume'?'Error response from daemon: no such volume':'No such object'};
 const run=async(file,args,options)=>{
  calls.push({file,args:[...args],options});controls.hook?.(file,args);assert.ok(options.timeoutMs<=300000);assert.ok(options.maxOutputBytes<=1048576);
  if(file==='sudo'){if(args[1]==='sha256sum')return{exitCode:0,stdout:controls.profileSha+'  /etc/apparmor.d/owasp-ai-goat-mcp-sandbox\n'};return{exitCode:0,stdout:controls.profileEnforced?'owasp-ai-goat-mcp-sandbox (enforce)\n':'owasp-ai-goat-mcp-sandbox (complain)\n'};}
  assert.equal(file,'docker');assert.deepEqual(args.slice(0,2),['--host','unix:///var/run/docker.sock']);args=args.slice(2);
  if(args[0]==='info')return{exitCode:0,stdout:'"controlled-daemon"'};
  if(args[1]==='inspect')return inspect(args[0]==='container'
   ? containers.get(args[2])||[...containers.values()].find(row=>row.Id===args[2])
   : ({image:images,network:networks,volume:volumes}[args[0]]).get(args[2]),args[0]);
  if(args[0]==='build'){
   const context=args.at(-1);assert.ok(context.startsWith(os.tmpdir())||context.startsWith(fs.realpathSync(os.tmpdir())));assert.equal(fs.statSync(context).mode&0o777,0o700);
   const manifest=JSON.parse(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-system/local-package-manifest.json')));
   for(const [name,digest]of Object.entries(manifest.files))assert.equal(hash(fs.readFileSync(path.join(context,name))),digest);
   controls.buildHook?.(context);
   const image={Id:'sha256:'+String(++builds).repeat(64),Architecture:'arm64',Os:'linux',Config:{Labels:labels(args),User:'10001:10001',Env:['PATH=/usr/bin'],Entrypoint:['/usr/local/bin/node','/opt/owasp-ai-goat-owned-system/local-listener-entry.js'],Cmd:null}};
   images.set(args[args.indexOf('-t')+1],image);images.set(image.Id,image);return{exitCode:0,stdout:''};
  }
  if(args[0]==='volume'&&args[1]==='create'){volumes.set(args.at(-1),{Name:args.at(-1),Driver:'local',Options:null,CreatedAt:'2026-10-11',Mountpoint:'/owned/volume',Labels:labels(args)});return{exitCode:0,stdout:''};}
  if(args[0]==='network'&&args[1]==='create'){networks.set(args.at(-1),{Id:'9'.repeat(64),Name:args.at(-1),Driver:'bridge',Internal:false,Labels:labels(args)});return{exitCode:0,stdout:''};}
  if(args[0]==='create'){
   assert.ok(managed.load({filePath:path.join(dir,managed.FILE)}),'disabled staging must precede first container');
   const name=args[args.indexOf('--name')+1],mode=args.at(-1),network=args[args.indexOf('--network')+1],envFile=args[args.indexOf('--env-file')+1];envFiles.push(envFile);assert.equal(fs.statSync(envFile).mode&0o777,0o600);
   const env=fs.readFileSync(envFile,'utf8').trim().split('\n');assert.ok(!args.join(' ').includes(env.find(x=>x.includes('_TOKEN=')).split('=')[1]));
   if(controls.missingCreate)throw Error('controlled uncertain create');
   const port=args[args.indexOf('--publish')+1].split(':')[1];
   let tmpfs={};for(let i=0;i<args.length;i++)if(args[i]==='--tmpfs'){const [mount,...options]=args[i+1].split(':');tmpfs[mount]=options.join(':');}if(mode==='restart')tmpfs=Object.fromEntries(Object.entries(tmpfs).reverse());
   const mountIndex=args.indexOf('--mount'),mount=mountIndex<0?[]:[{Type:'volume',Name:args[mountIndex+1].match(/source=([^,]+)/)[1],Destination:'/var/lib/owasp-ai-goat-owned-restart',RW:true}];
   containers.set(name,{Id:String(++serial).padStart(64,'0'),Name:'/'+name,Image:args.at(-2),Mounts:mount,Config:{Labels:labels(args),User:'10001:10001',Entrypoint:images.get(args.at(-2)).Config.Entrypoint,Cmd:[mode],Env:['PATH=/usr/bin',...env]},State:{Running:false,Status:'created'},HostConfig:{Privileged:false,ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,Tmpfs:tmpfs,Binds:null,Devices:[],DeviceRequests:null,PidMode:'',IpcMode:'private',UsernsMode:'',CapAdd:null,SecurityOpt:['seccomp=unconfined','apparmor=owasp-ai-goat-mcp-sandbox'],NetworkMode:network,PortBindings:{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:port}]}},NetworkSettings:{Networks:{[network]:{}},Ports:null}});
   if(controls.unknownCreate)throw Error('controlled lost create acknowledgment');return{exitCode:0,stdout:'id'};
  }
  if(args[0]==='start'){const c=containers.get(args[1])||[...containers.values()].find(row=>row.Id===args[1]);assert.ok(c);c.State.Running=true;c.State.Status='running';c.NetworkSettings.Ports=c.HostConfig.PortBindings;return{exitCode:0,stdout:''};}
  if(['stop','rename','rm'].includes(args[0])){const id=args[0]==='stop'?args.at(-1):args[1],entry=[...containers.entries()].find(([name,row])=>row.Id===id);assert.ok(entry);const [name,c]=entry;if(args[0]==='stop'){c.State={Running:false,Status:'exited'};c.NetworkSettings.Ports=null;}if(args[0]==='rename'){assert.ok(!containers.has(args[2]));containers.delete(name);c.Name='/'+args[2];containers.set(args[2],c);}if(args[0]==='rm'){assert.equal(c.State.Running,false);containers.delete(name);}return{exitCode:0,stdout:''};}
  assert.fail('unexpected mutating Docker operation: '+args[0]);
 };
 const client=({token})=>({async assertReady(){assert.match(token,/^[A-Za-z0-9_-]{64}$/);if(controls.readiness&&[...containers.values()].some(c=>c.Image==='sha256:'+'2'.repeat(64)))throw Error('controlled private failure');return true;},async health(){assert.match(token,/^[A-Za-z0-9_-]{64}$/);if(controls.readiness&&[...containers.values()].some(c=>c.Image==='sha256:'+'2'.repeat(64)))throw Error('controlled private failure');return{ready:true};},async metrics(){return{ok:true,metricsSource:'owned-system-listener'};}});
 return{root,home,dir,id,calls,envFiles,images,networks,volumes,containers,controls,options:{root,home,platform:'linux',architecture:'arm64',run,probeApplicationPorts:async()=>true,createConfigClient:client,createDiagnosticClient:client,createRestartClient:client,createUploadPreviewClient:client}};
}


const {upgrade}=require('../scripts/install/secureshop-owned-system-upgrade');
const activation=require('../scripts/install/secureshop-owned-system-activate');
async function installed(t){
 const f=fixture(t),result=await provision(f.options);activation.activate({filePath:result.managedPath,expected:activation.capture(result.managedPath)});
 f.file=result.managedPath;f.original=managed.capture({filePath:f.file});f.originalContainers=structuredClone([...f.containers]);
 f.change=()=>{const dir=path.join(f.root,'sidecars/sandbox-runner/owned-system'),file=path.join(dir,'local-package-manifest.json'),m=JSON.parse(fs.readFileSync(file));fs.appendFileSync(path.join(dir,'restart-command-executor.js'),'successor\n');m.files['restart-command-executor.js']=hash(fs.readFileSync(path.join(dir,'restart-command-executor.js')));fs.writeFileSync(file,JSON.stringify(m));};
 f.change();return f;
}
const mutations=f=>f.calls.filter(c=>c.file==='docker'&&['create','build','stop','rename','rm','start'].includes(c.args[2]));

test('explicit upgrade preserves credentials, ports, network and volume; supported startup admits successor',async t=>{
 const f=await installed(t),resourceBytes=JSON.stringify([[...f.networks],[...f.volumes]]),before=f.calls.length;
 const result=await upgrade(f.options),next=managed.load({filePath:f.file});
 assert.equal(result.ready,true);assert.equal(next.enabled,true);assert.equal(next.sourceManifestSha256,sourceManifest(f.root).sha256);
 assert.equal(next.resourceSourceManifestSha256,f.original.value.sourceManifestSha256);assert.notEqual(next.imageId,f.original.value.imageId);
 for(const mode of ['config','diagnostic','restart'])assert.deepEqual(next[mode],f.original.value[mode]);
 assert.equal(JSON.stringify([[...f.networks],[...f.volumes]]),resourceBytes);assert.equal(f.containers.size,3);
 assert.equal(fs.existsSync(f.file+'.upgrade.json'),false);assert.equal(fs.existsSync(f.file+'.activation-lock'),false);
 const receipt=fs.readdirSync(f.dir).find(name=>name.endsWith('.completed.json'));assert.ok(receipt);assert.equal(fs.statSync(path.join(f.dir,receipt)).mode&0o777,0o600);const archived=JSON.parse(fs.readFileSync(path.join(f.dir,receipt)));assert.deepEqual(archived.original,f.original);assert.deepEqual(archived.next,next);
 assert.ok(f.envFiles.every(file=>!fs.existsSync(file)));assert.ok(!JSON.stringify(result).includes(next.config.token));
 assert.ok(f.calls.slice(before).every(c=>!c.args.includes('--volumes')&&!c.args.includes('--force')));
 await startExisting(f.options);await provision({...f.options,reconcileEnabled:true});
 f.change();await upgrade(f.options);assert.equal(managed.load({filePath:f.file}).resourceSourceManifestSha256,f.original.value.sourceManifestSha256);
});

test('normal provision still rejects changed source and upgrade refuses unchanged package',async t=>{
 const f=await installed(t);await assert.rejects(provision({...f.options,reconcileEnabled:true}),{code:'SYSTEM_INSTALL_EXISTING_CONFLICT'});
 await upgrade(f.options);const before=mutations(f).length;await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_SOURCE_UNCHANGED'});assert.equal(mutations(f).length,before);
});

test('readiness failure restores every old container and exact original managed file',async t=>{
 const f=await installed(t);f.controls.readiness=true;await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_READINESS_FAILED'});
 assert.deepEqual(managed.capture({filePath:f.file}),f.original);assert.deepEqual([...f.containers].sort(),f.originalContainers.sort());assert.equal(fs.existsSync(f.file+'.upgrade.json'),false);
 f.controls.readiness=false;await upgrade(f.options);
});

test('rollback preserves originally stopped containers',async t=>{
 const f=await installed(t);for(const c of f.containers.values()){c.State={Running:false,Status:'exited'};c.NetworkSettings.Ports=null;}
 const before=structuredClone([...f.containers]);f.controls.readiness=true;await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_READINESS_FAILED'});assert.deepEqual([...f.containers].sort(),before.sort());
});

test('foreign old container, network, volume and image fail before mutation',async t=>{
 for(const change of [f=>f.containers.values().next().value.Mounts.push({Type:'bind',Source:'/private'}),f=>f.networks.values().next().value.Labels['owasp-ai-goat.system.source']='f'.repeat(64),f=>f.volumes.values().next().value.Driver='nfs',f=>f.images.get(f.original.value.imageId).Config.User='0']){
  const f=await installed(t);change(f);const count=mutations(f).length;await assert.rejects(upgrade(f.options));assert.equal(mutations(f).length,count);assert.deepEqual(managed.capture({filePath:f.file}),f.original);
 }
});

test('source tamper is rejected before Docker mutation',async t=>{
 const f=await installed(t);fs.appendFileSync(path.join(f.root,'sidecars/sandbox-runner/owned-system/executor.js'),'tamper');const count=mutations(f).length;await assert.rejects(upgrade(f.options),{code:'SYSTEM_PACKAGE_SOURCE_CHANGED'});assert.equal(mutations(f).length,count);
});

test('private authority identity replacement during build prevents container mutation',async t=>{
 const f=await installed(t);f.controls.buildHook=()=>{const file=path.join(f.dir,'local-docker.json');fs.writeFileSync(file+'.replacement',fs.readFileSync(file),{mode:0o600});fs.renameSync(file+'.replacement',file);};
 const offset=f.calls.length;await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_AUTHORITY_CHANGED'});assert.ok(f.calls.slice(offset).every(c=>!['stop','rename','create','rm'].includes(c.args[2])));assert.deepEqual(managed.capture({filePath:f.file}),f.original);
});

test('lost create acknowledgement reconciles exact replacement and succeeds',async t=>{
 const f=await installed(t);f.controls.unknownCreate=true;await upgrade(f.options);assert.equal(f.containers.size,3);
});

test('interrupted rollback retains journal, refuses ordinary retry, and explicit recovery restores original IDs',async t=>{
 const f=await installed(t);let broken=false;
 f.controls.hook=(file,args)=>{if(file==='docker'&&args[2]==='rename'){broken=true;throw Error('lost transport');}if(broken&&file==='docker'&&args[2]==='container')throw Error('offline');};
 await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_RECOVERY_REQUIRED'});const journal=f.file+'.upgrade.json';assert.equal(fs.statSync(journal).mode&0o777,0o600);
 f.controls.hook=null;await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_RECOVERY_REQUIRED'});
 const result=await upgrade({...f.options,recover:true});assert.equal(result.recovered,true);assert.deepEqual([...f.containers].sort(),f.originalContainers.sort());assert.deepEqual(managed.capture({filePath:f.file}),f.original);assert.equal(fs.existsSync(journal),false);await upgrade(f.options);
});

test('publication succeeded but cleanup interrupted: recovery keeps successor and removes only old IDs',async t=>{
 const f=await installed(t);let blocked=true;f.controls.hook=(file,args)=>{if(blocked&&file==='docker'&&args[2]==='rm')throw Error('offline');};
 await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_COMMAND_UNCERTAIN'});const successor=managed.capture({filePath:f.file});assert.notEqual(successor.value.imageId,f.original.value.imageId);assert.equal(fs.existsSync(f.file+'.upgrade.json'),true);
 blocked=false;await upgrade({...f.options,recover:true});assert.deepEqual(managed.capture({filePath:f.file}),successor);assert.equal(f.containers.size,3);await startExisting(f.options);
});

test('live activation lock and malformed journal fail closed without mutation',async t=>{
 const f=await installed(t),lock=f.file+'.activation-lock';fs.mkdirSync(lock,{mode:0o700});fs.writeFileSync(path.join(lock,'upgrade-owner.json'),JSON.stringify({pid:process.pid}),{mode:0o600});let before=mutations(f).length;
 await assert.rejects(upgrade({...f.options,recover:true}),{code:'SYSTEM_UPGRADE_LOCKED'});assert.equal(mutations(f).length,before);fs.rmSync(lock,{recursive:true});
 fs.writeFileSync(f.file+'.upgrade.json','{}',{mode:0o600});await assert.rejects(upgrade({...f.options,recover:true}),{code:'SYSTEM_UPGRADE_JOURNAL_INVALID'});assert.equal(mutations(f).length,before);
});

test('resource provenance field is strictly bounded and legacy encoding remains identical',()=>{
 const legacy={version:1,workspaceId:'a'.repeat(12),enabled:false,architecture:'arm64',dockerAuthoritySha256:'b'.repeat(64),imageId:'sha256:'+'c'.repeat(64),sourceManifestSha256:'d'.repeat(64),profile:{name:'owasp-ai-goat-mcp-sandbox',sha256:'e'.repeat(64)}};
 for(const [index,mode]of ['config','diagnostic','restart'].entries())legacy[mode]={container:'owasp-ai-goat-owned-system-'+legacy.workspaceId+'-'+mode,url:'http://127.0.0.1:'+(8090+index),token:String(index).repeat(64)};
 assert.ok(!managed.encode(legacy).includes('resourceSource'));const next={...legacy,resourceSourceManifestSha256:'f'.repeat(64)};assert.deepEqual(JSON.parse(managed.encode(next)),next);
 for(const value of [null,undefined,'',true,'f'.repeat(63)])assert.throws(()=>managed.validate({...legacy,resourceSourceManifestSha256:value}),{code:'SYSTEM_MANAGED_INVALID'});
});


test('stopped-app admission blocks owned launcher and occupied configured ports before mutations',async t=>{
 const f=await installed(t),launcher=path.join(f.dir,'launcher.json');fs.writeFileSync(launcher,'{}',{mode:0o600});let count=mutations(f).length;
 await assert.rejects(upgrade(f.options),{code:'SYSTEM_UPGRADE_APPLICATION_RUNNING'});assert.equal(mutations(f).length,count);fs.unlinkSync(launcher);
 fs.writeFileSync(path.join(f.root,'.env'),'PORT=18181\nOWASP_AI_GOAT_CLIENT_PORT=18182\nSS_AGENT_HOST_PORT=18183\n');
 const probed=[];await assert.rejects(upgrade({...f.options,probeApplicationPorts:async env=>{probed.push(env.PORT);throw Error('occupied');}}),{code:'SYSTEM_UPGRADE_APPLICATION_RUNNING'});assert.deepEqual(probed,['18181']);assert.equal(mutations(f).length,count);
});

test('failed rollback restart retains journal until original running state and readiness are restored',async t=>{
 const f=await installed(t);f.controls.readiness=true;const original=f.options.run;
 await assert.rejects(upgrade({...f.options,run:async(file,args,opts)=>{const r=await original(file,args,opts);if(file==='docker'&&args[2]==='start'){const c=[...f.containers.values()].find(c=>c.Id===args[3]);if(c.Image===f.original.value.imageId){c.State={Running:false,Status:'exited'};c.NetworkSettings.Ports=null;}}return r;}}),{code:'SYSTEM_UPGRADE_RECOVERY_REQUIRED'});
 assert.equal(fs.existsSync(f.file+'.upgrade.json'),true);f.controls.readiness=false;await upgrade({...f.options,recover:true});assert.deepEqual([...f.containers].sort(),f.originalContainers.sort());
});


test('explicit preview upgrade adds exactly one selected mode and preserves prior private identities and state',async t=>{
 const f=await installed(t),resources=JSON.stringify([[...f.networks],[...f.volumes]]);
 const result=await upgrade({...f.options,uploadPreviewPort:8093}),next=managed.load({filePath:f.file});
 assert.equal(result.ready,true);assert.equal(f.containers.size,4);
 for(const mode of ['config','diagnostic','restart'])assert.deepEqual(next[mode],f.original.value[mode]);
 assert.equal(JSON.stringify([[...f.networks],[...f.volumes]]),resources);
 assert.equal(next.uploadPreview.container,`owasp-ai-goat-owned-system-${f.id}-upload-preview`);
 assert.equal(next.uploadPreview.url,'http://127.0.0.1:8093');
 const preview=f.containers.get(next.uploadPreview.container);assert.deepEqual(preview.Config.Cmd,['upload-preview']);
 assert.equal(preview.Mounts.length,0);assert.equal(preview.HostConfig.Tmpfs['/var/lib/owasp-ai-goat-owned-upload-preview'],'rw,nosuid,nodev,size=32m,mode=0700,uid=10001,gid=10001');
 await startExisting(f.options);await provision({...f.options,reconcileEnabled:true,uploadPreviewPort:8093});
 const count=mutations(f).length;await assert.rejects(upgrade({...f.options,uploadPreviewPort:8093}),{code:'SYSTEM_UPGRADE_PREVIEW_ADMISSION_INVALID'});assert.equal(mutations(f).length,count);
});

test('preview upgrade failure removes only the new mode and restores every original ID and bearer',async t=>{
 const f=await installed(t);f.options.createUploadPreviewClient=()=>({assertReady:async()=>{throw Error('controlled preview unavailable');}});
 await assert.rejects(upgrade({...f.options,uploadPreviewPort:8093}),{code:'SYSTEM_UPGRADE_READINESS_FAILED'});
 assert.deepEqual(managed.capture({filePath:f.file}),f.original);
 assert.deepEqual([...f.containers].sort(),f.originalContainers.sort());
 assert.equal(f.containers.size,3);assert.equal(fs.existsSync(f.file+'.upgrade.json'),false);
});

test('preview selection rejects a conflicting port before build and never silently expands a normal upgrade',async t=>{
 const f=await installed(t),count=mutations(f).length;
 await assert.rejects(upgrade({...f.options,uploadPreviewPort:8090}),{code:'SYSTEM_UPGRADE_PREVIEW_ADMISSION_INVALID'});
 assert.equal(mutations(f).length,count);await upgrade(f.options);
 assert.equal(managed.load({filePath:f.file}).uploadPreview,undefined);assert.equal(f.containers.size,3);
});


test('interrupted preview rollback uses retained IDs and removes the new resource on explicit recovery',async t=>{
 const f=await installed(t);f.options.createUploadPreviewClient=()=>({assertReady:async()=>{throw Error('controlled unavailable');}});
 let blocked=false;
 f.controls.hook=(file,args)=>{if(!blocked&&file==='docker'&&args[2]==='rm'){
  const row=[...f.containers.values()].find(value=>value.Id===args[3]);
  if(row?.Config.Cmd[0]==='upload-preview'){blocked=true;throw Error('controlled rollback interruption');}
 }};
 await assert.rejects(upgrade({...f.options,uploadPreviewPort:8093}),{code:'SYSTEM_UPGRADE_RECOVERY_REQUIRED'});
 assert.equal(fs.existsSync(f.file+'.upgrade.json'),true);assert.ok([...f.containers.values()].some(row=>row.Config.Cmd[0]==='upload-preview'));
 f.controls.hook=null;const result=await upgrade({...f.options,recover:true});assert.equal(result.changed,false);
 assert.deepEqual(managed.capture({filePath:f.file}),f.original);assert.deepEqual([...f.containers].sort(),f.originalContainers.sort());
 assert.equal(fs.existsSync(f.file+'.upgrade.json'),false);
});
