'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const installer=require('../scripts/install/secureshop-owned-listing-template');
const managed=require('../server/services/secureshopListingTemplateManagedConfiguration');
const contract=require('../server/services/secureshopListingTemplateExecutorContract');
const {workspaceId}=require('../scripts/application-data-root');
const ROOT=path.resolve(__dirname,'..'),IMAGE='sha256:'+'a'.repeat(64),ID='b'.repeat(64);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function fixture(t){
 const home=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'listing-template-provision-'));
 t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const id=workspaceId(ROOT),directory=path.join(home,'.owasp-ai-goat',id);
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 fs.writeFileSync(path.join(directory,'local-docker.json'),JSON.stringify({version:1,workspaceId:id,
  host:'unix:///var/run/docker.sock',daemonId:'controlled-template-daemon',source:'environment-host'}),{mode:0o600});
 const calls=[],state={image:null,network:null,container:null,badReceipt:false,foreign:false,onRender:null};
 const labels=args=>Object.fromEntries(args.flatMap((v,i)=>v==='--label'?[[args[i+1].split('=')[0],args[i+1].slice(args[i+1].indexOf('=')+1)]]:[]));
 const run=async(file,args)=>{
  calls.push({file,args});assert.equal(file,'docker');assert.deepEqual(args.slice(0,2),['--host','unix:///var/run/docker.sock']);args=args.slice(2);
  if(args[0]==='info')return {exitCode:0,stdout:JSON.stringify(args.at(-1).includes('Architecture')?'arm64':'controlled-template-daemon')};
  if(args[1]==='inspect'){
   const row=state[args[0]==='image'?'image':args[0]==='network'?'network':'container'];
   return row?{exitCode:0,stdout:JSON.stringify([row])}:{exitCode:1,stderr:'Error: No such object: '+args.at(-1)};
  }
  if(args[0]==='build'){
   state.image={Id:IMAGE,Architecture:'arm64',Os:'linux',Config:{Labels:labels(args),User:'10001:10001',
    Env:['PATH=/usr/bin','SECURESHOP_LISTING_TEMPLATE_ENABLED=true','SECURESHOP_LISTING_TEMPLATE_MAX_CONCURRENT=1'],
    Entrypoint:['/usr/local/bin/node','/app/listing-template/listener.js'],Cmd:null}};
  }else if(args[0]==='network'){
   assert.ok(managed.capture({root:ROOT,home},true));state.network={Id:'c'.repeat(64),Name:args.at(-1),Driver:'bridge',Internal:false,Labels:labels(args),Containers:{}};
  }else if(args[0]==='create'){
   assert.ok(managed.capture({root:ROOT,home},true));
   const network=args[args.indexOf('--network')+1],port=args[args.indexOf('--publish')+1].split(':')[1];
   state.container={Id:ID,Name:'/'+args[args.indexOf('--name')+1],Image:IMAGE,Mounts:[],RestartCount:0,AppArmorProfile:'',
    State:{Running:false,Status:'created',StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z'},
    Config:{...state.image.Config,Labels:labels(args)},
    HostConfig:{Privileged:false,ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,
     CapAdd:null,CapDrop:['ALL'],PidMode:'',IpcMode:'private',UsernsMode:'',Binds:null,Devices:[],DeviceRequests:null,
     Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,mode=1777,size=128m'},
     SecurityOpt:['seccomp=unconfined','apparmor=owasp-ai-goat-owned-listing-template-'+id],NetworkMode:network,
     PortBindings:{'8090/tcp':[{HostIp:'127.0.0.1',HostPort:port}]}},NetworkSettings:{Networks:{},Ports:null}};
   if(state.foreign)state.container.Config.Labels['owasp-ai-goat.listing-template.owner']='foreign';
  }else if(args[0]==='start'){
   assert.equal(args[1],ID);state.container.State={Running:true,Status:'running'};
   state.container.AppArmorProfile='owasp-ai-goat-owned-listing-template-'+id;
   state.container.NetworkSettings={Networks:{[state.container.HostConfig.NetworkMode]:{NetworkID:state.network.Id}},Ports:state.container.HostConfig.PortBindings};
   state.network.Containers={[ID]:{}};
  }else assert.fail('unexpected Docker mutation '+args[0]);
  return {exitCode:0,stdout:''};
 };
 const fetchImpl=async(url,options)=>{
  assert.equal(new URL(url).hostname,'127.0.0.1');assert.equal(options.redirect,'error');
  if(url.endsWith('/health'))return new Response(JSON.stringify({status:'ok',listingTemplate:{enabled:true,available:true,isolation:contract.ISOLATION}}));
  const request=contract.normalizeListingTemplateExecution(JSON.parse(options.body)),rendered='Hello world';
  state.onRender?.();
  return new Response(JSON.stringify({version:1,operationId:request.operationId,productId:request.productId,
   requestSha256:contract.listingTemplateExecutionDigest(request),sourceSha256:request.sourceSha256,
   isolation:contract.ISOLATION,rendered,renderedSha256:sha(rendered),exitCode:0,timedOut:false,truncated:false,
   drained:true,workerAttested:true,commandEffectObserved:state.badReceipt,effectSha256:state.badReceipt?sha('effect'):null}));
 };
 const options={root:ROOT,home,platform:'darwin',architecture:'arm64',environment:{},run,fetchImpl,
  provisionProfile:async()=>{},assertPortAvailable:async()=>{},readinessAttempts:1,readinessDelayMs:0};
 return {home,id,state,calls,options};
}
test('optional setup stages exact bounded container without starting or enabling it',async t=>{
 const f=fixture(t),result=await installer.provision(f.options);
 assert.equal(result.staged,true);assert.equal(result.ready,false);assert.equal(managed.capture(f.options),null);
 assert.equal(managed.capture(f.options,true).value.activateRequested,false);
 assert.equal(f.state.container.State.Status,'created');
 assert.equal(f.calls.filter(c=>c.args[2]==='start').length,0);
});
test('explicit activation and later startup use only the same retained container ID',async t=>{
 const f=fixture(t);await installer.provision(f.options);
 const active=await installer.provision({...f.options,activate:true});assert.equal(active.enabled,true);
 assert.equal(managed.capture(f.options).value.containerId,ID);
 f.state.container.State={Running:false,Status:'exited'};
 f.state.container.AppArmorProfile='';
 f.state.container.NetworkSettings={Networks:{[f.state.container.HostConfig.NetworkMode]:{NetworkID:f.state.network.Id}},Ports:null};
 const before=f.calls.length;
 const restarted=await installer.startExisting(f.options);assert.equal(restarted.containerId,ID);
 assert.deepEqual(f.calls.slice(before).filter(c=>['build','create','start'].includes(c.args[2])).map(c=>c.args.slice(2,4)),[['start',ID]]);
});
test('foreign container label denies activation without enabled publication',async t=>{
 const f=fixture(t);f.state.foreign=true;
 await assert.rejects(installer.provision({...f.options,activate:true}),{code:'LISTING_TEMPLATE_CONTAINER_CONFLICT'});
 assert.equal(managed.capture(f.options),null);
});
test('inert effect denies enabled publication',async t=>{
 const f=fixture(t);f.state.badReceipt=true;
 await assert.rejects(installer.provision({...f.options,activate:true}));
 assert.equal(managed.capture(f.options),null);
});
test('fresh setup picks the first free port only within its distinct allocation range',async t=>{
 const f=fixture(t),probes=[];
 await installer.provision({...f.options,assertPortAvailable:async port=>{
  probes.push(port);if(port===8109)throw Object.assign(Error('controlled occupied'),{code:'EADDRINUSE'});
 }});
 assert.deepEqual(probes,[8109,8110,8110]);
 assert.equal(managed.capture(f.options,true).value.port,8110);
});
test('retained enabled configuration denies unsupported Windows before Docker',async t=>{
 const f=fixture(t);await installer.provision({...f.options,activate:true});
 const before=f.calls.length;
 await assert.rejects(installer.startExisting({...f.options,platform:'win32'}),{code:'LISTING_TEMPLATE_PLATFORM_UNQUALIFIED'});
 assert.equal(f.calls.length,before);
});
test('retained disabled configuration performs no startup mutation',async t=>{
 const f=fixture(t);await installer.provision(f.options);
 const stage=managed.capture(f.options,true),base=Object.fromEntries(Object.entries(stage.value).filter(([key])=>key!=='activateRequested'));
 managed.publish({...f.options,expected:null,expectedStage:stage,value:{...base,containerId:ID,enabled:false}});
 const before=f.calls.length,result=await installer.startExisting(f.options);
 assert.equal(result.preservedDisabled,true);assert.equal(f.calls.length,before);
});
for(const [name,change]of [
 ['image replacement',state=>{state.image.Id='sha256:'+'d'.repeat(64);}],
 ['bridge replacement',state=>{state.network.Id='d'.repeat(64);}],
 ['foreign bridge endpoint',state=>{state.network.Containers['e'.repeat(64)]={};}],
 ['wrong attachment ID',state=>{state.container.NetworkSettings.Networks[state.container.HostConfig.NetworkMode].NetworkID='d'.repeat(64);}],
 ['unconfined running process',state=>{state.container.AppArmorProfile='unconfined';}]
])test('post-health '+name+' denies enabled publication',async t=>{
 const f=fixture(t);f.state.onRender=()=>change(f.state);
 await assert.rejects(installer.provision({...f.options,activate:true}));
 assert.equal(managed.capture(f.options),null);
});
test('profile admission requests base and bwrap enforce with nonblocking exact file read',async t=>{
 const f=fixture(t),name='owasp-ai-goat-owned-listing-template-'+f.id;
 let program='';
 await installer._internals.provisionProfile({p:{profile:name,workspaceId:f.id},authority:{host:'unix:///var/run/docker.sock'},
  root:ROOT,home:f.home,platform:'linux',existingOnly:true,run:async(file,args)=>{
   assert.equal(file,'sudo');assert.equal(args[0],'--non-interactive');program=args[args.indexOf('-c')+1];
   return {exitCode:1};
  }}).then(()=>assert.fail('missing loaded profile must deny'),error=>assert.equal(error.code,'LISTING_TEMPLATE_PROFILE_UNAVAILABLE'));
 assert.match(program,/O_NONBLOCK/);assert.match(program,/\/\/bwrap \(enforce\)/);
 assert.match(program,/st\.st_size==len\(data\)/);
});
