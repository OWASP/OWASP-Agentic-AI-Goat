'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const installer=require('../scripts/install/secureshop-owned-policy-renderer');
const managed=require('../server/services/secureshopPolicyRendererManagedConfiguration');
const environment=require('../server/services/secureshopPolicyRendererManagedEnvironment');
const {workspaceId}=require('../scripts/application-data-root');
const contract=require('../server/services/secureshopPromptPolicyContract');
const ROOT=path.resolve(__dirname,'..'),IMAGE='sha256:'+'a'.repeat(64),ID='b'.repeat(64);
function fixture(t){
 const home=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'policy-installer-controlled-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const id=workspaceId(ROOT),directory=path.join(home,'.dvaia',id);fs.mkdirSync(directory,{recursive:true,mode:0o700});
 fs.writeFileSync(path.join(directory,'local-docker.json'),JSON.stringify({version:1,workspaceId:id,host:'unix:///var/run/docker.sock',daemonId:'controlled-policy-daemon',source:'environment-host'}),{mode:0o600});
 const calls=[],state={image:null,network:null,container:null,badHealth:false,badReceipt:false,createLost:false,foreign:false,profile:false,port:false,healthRemaining:0,healthCalls:0,renderCalls:0,onRender:null,daemon:'controlled-policy-daemon',networkMissingError:null};
 const labels=args=>Object.fromEntries(args.flatMap((v,i)=>v==='--label'?[[args[i+1].split('=')[0],args[i+1].slice(args[i+1].indexOf('=')+1)]]:[]));
 const run=async(file,args)=>{
  calls.push({file,args});assert.equal(file,'docker');assert.deepEqual(args.slice(0,2),['--host','unix:///var/run/docker.sock']);args=args.slice(2);
  if(args[0]==='info')return{exitCode:0,stdout:JSON.stringify(args.at(-1).includes('Architecture')?'arm64':state.daemon)};
  if(args[1]==='inspect'){
   const row=state[args[0]==='image'?'image':args[0]==='network'?'network':'container'];
   return row?{exitCode:0,stdout:JSON.stringify([row])}:{exitCode:1,stderr:args[0]==='network'&&state.networkMissingError?state.networkMissingError:'Error: No such object: '+args.at(-1)};
  }
  if(args[0]==='build'){
   assert.equal(args.at(-1),path.join(ROOT,'sidecars/sandbox-runner'));
   state.image={Id:IMAGE,Architecture:'arm64',Os:'linux',Config:{Labels:labels(args),User:'10001:10001',Env:['PATH=/usr/bin','SECURESHOP_POLICY_RENDER_ENABLED=true','SECURESHOP_POLICY_RENDER_MAX_CONCURRENT=1'],Entrypoint:['/usr/local/bin/node','/app/policy-render/listener.js'],Cmd:null}};
  }else if(args[0]==='network'){
   assert.ok(managed.capture({root:ROOT,home},true),'immutable stage precedes network');
   state.network={Name:args.at(-1),Driver:'bridge',Internal:false,Labels:labels(args)};
  }else if(args[0]==='create'){
   assert.ok(managed.capture({root:ROOT,home},true),'immutable stage precedes container');assert.equal(managed.capture({root:ROOT,home}),null);
   assert.ok(!args.includes('--mount')&&!args.includes('--volume')&&!args.includes('--cap-add'));
   const network=args[args.indexOf('--network')+1],port=args[args.indexOf('--publish')+1].split(':')[1];
   state.container={Id:ID,Name:'/'+args[args.indexOf('--name')+1],Image:IMAGE,Mounts:[],RestartCount:0,State:{Running:false,Status:'created',StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z'},
    Config:{...state.image.Config,Labels:labels(args)},HostConfig:{Privileged:false,ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,CapAdd:null,CapDrop:['ALL'],PidMode:'',IpcMode:'private',UsernsMode:'',Binds:null,Devices:[],DeviceRequests:null,Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m'},SecurityOpt:['seccomp=unconfined','apparmor=dvaia-owned-policy-renderer-'+id],NetworkMode:network,PortBindings:{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:port}]}},NetworkSettings:{Networks:{},Ports:null}};
   if(state.foreign)state.container.Config.Labels['dvaia.policy.owner']='foreign';
   if(state.createLost){state.createLost=false;throw Error('controlled lost create acknowledgement');}
  }else if(args[0]==='start'){
   assert.equal(args[1],ID);state.container.State.Running=true;state.container.State.Status='running';state.container.NetworkSettings={Networks:{[state.container.HostConfig.NetworkMode]:{}},Ports:state.container.HostConfig.PortBindings};
  }else assert.fail('unexpected Docker mutation');
  return{exitCode:0,stdout:''};
 };
 const fetchImpl=async(url,options)=>{
  assert.equal(new URL(url).hostname,'127.0.0.1');assert.equal(options.redirect,'error');
  if(url.endsWith('/health')){state.healthCalls++;if(state.healthRemaining-->0)throw Error('controlled delayed bind');return new Response(JSON.stringify({policyRenderer:{enabled:true,available:!state.badHealth,isolation:contract.ISOLATION}}));}
  assert.ok(url.endsWith('/secureshop/policy-render'));state.renderCalls++;state.onRender?.();const request=JSON.parse(options.body),rendered='Returns for SecureShop.';
  return new Response(JSON.stringify({version:1,operationId:request.operationId,requestSha256:contract.requestDigest(request),isolation:state.badReceipt?'unavailable':contract.ISOLATION,rendered,renderedSha256:crypto.createHash('sha256').update(rendered).digest('hex'),exitCode:0,timedOut:false,truncated:false,drained:true}));
 };
 const options={root:ROOT,home,architecture:'arm64',platform:'darwin',environment:{},run,fetchImpl,
  readinessAttempts:3,readinessDelayMs:0,provisionProfile:async()=>{if(state.profile)throw Error('controlled profile conflict');},assertPortAvailable:async()=>{if(state.port)throw Error('controlled port collision');}};
 return{home,id,state,calls,options};
}
test('plan is read-only and unsupported architectures are denied',async t=>{
 const f=fixture(t),execute=async()=>({stdout:'"controlled-policy-daemon"'}),before=fs.readdirSync(managed.paths(f.options).directory);
 const p=await installer.plan({...f.options,execute});assert.equal(p.port,8098);assert.equal(p.mutating,false);assert.deepEqual(fs.readdirSync(managed.paths(f.options).directory),before);assert.equal(f.calls.length,0);
 await assert.rejects(installer.plan({...f.options,architecture:'x64',execute}),{code:'POLICY_RENDER_PLATFORM_UNQUALIFIED'});
});
test('full inert receipt precedes activation and exact repeat preserves private identity',async t=>{
 const f=fixture(t),result=await installer.provision({...f.options,activate:true});assert.equal(result.ready,true);assert.equal(result.enabled,true);
 const p=managed.paths(f.options),before=fs.readFileSync(p.filename),identity=fs.statSync(p.filename).ino,count=f.calls.length;
 await installer.startExisting(f.options);assert.deepEqual(fs.readFileSync(p.filename),before);assert.equal(fs.statSync(p.filename).ino,identity);
 assert.ok(!f.calls.slice(count).some(c=>['build','create','start'].includes(c.args[2])));
 assert.deepEqual(environment.load({home:f.home,environment:{}}),{SS_BOUND_PROMPT_POLICIES_ENABLED:'true',SS_POLICY_RENDERER_BASE_URL:'http://127.0.0.1:8098'});
 assert.deepEqual(environment.load({...f.options,environment:{SS_BOUND_PROMPT_POLICIES_ENABLED:'false'}}),{});
});
test('retained disabled preference remains unchanged without explicit activation request',async t=>{
 const f=fixture(t);await installer.provision(f.options);const before=fs.readFileSync(managed.paths(f.options).filename),count=f.calls.length;
 assert.equal((await installer.provision(f.options)).preservedDisabled,true);assert.deepEqual(fs.readFileSync(managed.paths(f.options).filename),before);
 assert.ok(!f.calls.slice(count).some(c=>['create','start','build'].includes(c.args[2])));
 assert.equal((await installer.provision({...f.options,activate:true})).enabled,true);
});
for(const control of ['badHealth','badReceipt','foreign','profile','port'])test(control+' fails without publishing activation',async t=>{
 const f=fixture(t);f.state[control]=true;await assert.rejects(installer.provision({...f.options,activate:true}));assert.equal(managed.capture(f.options),null);
});
test('lost create acknowledgement resumes original staged owner and activation intent',async t=>{
 const f=fixture(t);f.state.createLost=true;await assert.rejects(installer.provision({...f.options,activate:true}));const saved=managed.capture(f.options,true);
 assert.equal((await installer.provision(f.options)).enabled,true);assert.equal(managed.capture(f.options).value.ownerId,saved.value.ownerId);
 assert.equal(f.calls.filter(c=>c.args[2]==='create').length,1);
});
test('same-byte inode substitution denies private CAS and preserves disabled bytes',async t=>{
 const f=fixture(t);await installer.provision(f.options);const old=managed.capture(f.options),file=old.filename,bytes=fs.readFileSync(file);fs.renameSync(file,file+'.original');fs.writeFileSync(file,bytes,{mode:0o600});
 assert.throws(()=>managed.publish({...f.options,expected:old,expectedStage:managed.capture(f.options,true),value:{...old.value,enabled:true}}),{code:'POLICY_RENDER_MANAGED_INVALID'});assert.deepEqual(fs.readFileSync(file),bytes);
});
test('startup denies image, mount, capability, profile and private container identity drift',async t=>{
 const f=fixture(t);await installer.provision({...f.options,activate:true});const original=structuredClone(f.state.container);
 const mutations=[row=>row.Image='sha256:'+'c'.repeat(64),row=>row.Mounts=[{Type:'bind',Source:'/private',Destination:'/learner'}],row=>row.HostConfig.CapAdd=['SYS_ADMIN'],row=>row.HostConfig.SecurityOpt=['apparmor=unconfined'],row=>row.Id='d'.repeat(64)];
 for(const mutate of mutations){f.state.container=structuredClone(original);mutate(f.state.container);await assert.rejects(installer.startExisting(f.options));}
});
test('empty attachment exception is only exact never-started creation',async t=>{
 const f=fixture(t);await installer.provision({...f.options,activate:true});const p=await installer.plan({...f.options,execute:async()=>({stdout:'"controlled-policy-daemon"'})}),value=managed.capture(f.options).value,image=f.state.image,labels=f.state.container.Config.Labels;
 const row=structuredClone(f.state.container);row.NetworkSettings.Networks={};assert.throws(()=>installer._internals.inspectContainer(row,{p,value,image,labels}));
 row.State={Running:false,Status:'created',StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z'};row.RestartCount=0;installer._internals.inspectContainer(row,{p,value,image,labels});
 for(const invalid of [null,undefined,[]]){row.NetworkSettings.Networks=invalid;assert.throws(()=>installer._internals.inspectContainer(row,{p,value,image,labels}));}
});

test('unsupported absent loader is no-op while explicit activation or retained authority is denied',async t=>{
 const f=fixture(t);assert.deepEqual(environment.load({home:f.home,platform:'win32',environment:{}}),{});
 assert.throws(()=>environment.load({home:f.home,platform:'win32',environment:{SS_BOUND_PROMPT_POLICIES_ENABLED:'true'}}),{code:'POLICY_RENDER_PLATFORM_UNQUALIFIED'});
 await installer.provision({...f.options,activate:true});assert.throws(()=>environment.load({...f.options,platform:'win32'}),{code:'POLICY_RENDER_PLATFORM_UNQUALIFIED'});
});
test('readiness polls health only and never retries an uncertain inert render',async t=>{
 const f=fixture(t);f.state.healthRemaining=2;await installer.provision({...f.options,activate:true});assert.equal(f.state.healthCalls,3);assert.equal(f.state.renderCalls,1);
 const g=fixture(t);g.state.badHealth=true;await assert.rejects(installer.provision({...g.options,activate:true}));assert.equal(g.state.healthCalls,3);assert.equal(g.state.renderCalls,0);assert.equal(managed.capture(g.options),null);
 const h=fixture(t);h.state.badReceipt=true;await assert.rejects(installer.provision({...h.options,activate:true}));assert.equal(h.state.renderCalls,1);assert.equal(managed.capture(h.options),null);
});
test('startup never recreates a missing retained installation stage',async t=>{
 const f=fixture(t);await installer.provision({...f.options,activate:true});const p=managed.paths(f.options),bytes=fs.readFileSync(p.filename),count=f.calls.length;fs.unlinkSync(p.stage);
 await assert.rejects(installer.startExisting(f.options),{code:'POLICY_RENDER_EXISTING_REQUIRED'});assert.equal(fs.existsSync(p.stage),false);assert.deepEqual(fs.readFileSync(p.filename),bytes);assert.ok(!f.calls.slice(count).some(c=>['build','create','start'].includes(c.args[2])));
});
for(const target of ['stage','authority'])test('probe-time '+target+' identity substitution prevents enabled publication',async t=>{
 const f=fixture(t);f.state.onRender=()=>{const p=managed.paths(f.options),file=target==='stage'?p.stage:path.join(p.directory,'local-docker.json'),bytes=fs.readFileSync(file);fs.renameSync(file,file+'.before');fs.writeFileSync(file,bytes,{mode:0o600});};
 await assert.rejects(installer.provision({...f.options,activate:true}));assert.equal(managed.capture(f.options),null);
});

test('an explicit activation request can resume an originally disabled staging operation',async t=>{
 const f=fixture(t);f.state.createLost=true;await assert.rejects(installer.provision(f.options));assert.equal(managed.capture(f.options,true).value.activateRequested,false);
 assert.equal((await installer.provision({...f.options,activate:true})).enabled,true);assert.equal(f.calls.filter(c=>c.args[2]==='create').length,1);
});

test('retained raw false is preserved unless explicit activation replaces it',async t=>{
 const f=fixture(t);await installer.provision({...f.options,activate:true});const before=fs.readFileSync(managed.paths(f.options).filename),count=f.calls.length;
 const disabled={...f.options,environment:{SS_BOUND_PROMPT_POLICIES_ENABLED:'false'}};
 assert.equal((await installer.provision(disabled)).preservedDisabled,true);assert.deepEqual(fs.readFileSync(managed.paths(f.options).filename),before);assert.ok(!f.calls.slice(count).some(c=>['create','start','build'].includes(c.args[2])));
 assert.equal((await installer.provision({...disabled,activate:true})).enabled,true);
});

for(const target of ['daemon','container'])test('probe-time '+target+' drift prevents enabled publication',async t=>{
 const f=fixture(t);f.state.onRender=()=>{if(target==='daemon')f.state.daemon='different-daemon';else f.state.container.HostConfig.CapAdd=['SYS_ADMIN'];};
 await assert.rejects(installer.provision({...f.options,activate:true}));assert.equal(managed.capture(f.options),null);
});

test('pinned build context excludes all unlisted files including descendants of allowed directories',()=>{
 const source=installer.sourceManifest(ROOT);assert.ok(source.files['sidecars/sandbox-runner/policy-render/Dockerfile.dockerignore']);
 const rules=fs.readFileSync(path.join(ROOT,'sidecars/sandbox-runner/policy-render/Dockerfile.dockerignore'),'utf8').split(/\r?\n/).filter(line=>line&&!line.startsWith('#'));
 // Docker evaluates the last matching rule, including matches on parent paths.
 const included=file=>{const parts=file.split('/'),parents=parts.map((_,i)=>parts.slice(0,i+1).join('/'));let excluded=false;
  for(const rule of rules){const allow=rule.startsWith('!'),pattern=(allow?rule.slice(1):rule).replace(/\/$/,'');
   const match=parents.some(name=>pattern==='**'||pattern.endsWith('/**')?pattern==='**'||name.startsWith(pattern.slice(0,-2)):name===pattern);
   if(match)excluded=!allow;
  }return !excluded;};
 for(const file of Object.keys(source.files))assert.equal(included(file.replace('sidecars/sandbox-runner/','')),true,file);
 for(const file of ['index.js','entrypoint.sh','labfs/.env','policy-render/native-qualification.js','policy-render/assets/unknown.js','policy-render/assets/nested/private.json'])assert.equal(included(file),false,file);
});

test('exact native network-not-found permits provisioning under retained staging identity',async t=>{
 const f=fixture(t);f.state.profile=true;await assert.rejects(installer.provision({...f.options,activate:true}));const stage=managed.capture(f.options,true);
 f.state.profile=false;f.state.networkMissingError='Error response from daemon: network dvaia-policy-renderer-'+f.id+'-bridge not found';
 const result=await installer.provision({...f.options,activate:true});assert.equal(result.ready,true);assert.equal(result.enabled,true);assert.equal(managed.capture(f.options).value.ownerId,stage.value.ownerId);assert.equal(managed.capture(f.options).value.imageId,stage.value.imageId);assert.equal(f.calls.filter(c=>c.args[2]==='build').length,1);
});
test('generic or differently named network failures remain closed with bounded stage diagnostics',async t=>{
 for(const message of ['permission denied','Error response from daemon: network foreign-bridge not found','Error response from daemon: network dvaia-policy-renderer-'+workspaceId(ROOT)+'-bridge not found; extra']){
  const f=fixture(t);f.state.networkMissingError=message;await assert.rejects(installer.provision({...f.options,activate:true}),{code:'POLICY_RENDER_COMMAND_FAILED',stage:'docker-network-inspect'});assert.equal(f.state.network,null);assert.equal(f.state.container,null);assert.equal(managed.capture(f.options),null);
 }
});
test('dedicated AppArmor name matches its exact profile admission length',()=>{
 const id=workspaceId(ROOT),name='dvaia-owned-policy-renderer-'+id;assert.equal(name.length,40);assert.ok(installer._internals.profileBytes(ROOT,id).toString().includes(name));
});
