'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{randomUUID}=require('node:crypto');
const managed=require('../server/services/secureshopPricingManagedConfiguration');
const {activationPolicy,preparePricingClient}=require('../server/services/secureshopPricingActivation');
const {workspaceId}=require('../scripts/application-data-root');
const {authorityDigest}=require('../scripts/local-docker-authority');
const env={SS_BOUND_PRICING_ENABLED:'true',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
function fixture(t){const home=fs.mkdtempSync(path.join(os.tmpdir(),'pricing-managed-')),root=path.join(home,'source');t.after(()=>fs.rmSync(home,{recursive:true,force:true}));fs.mkdirSync(root);for(const relative of require('../server/services/secureshopPricingPackage').PRICING_PACKAGE_FILES){const destination=path.join(root,relative);fs.mkdirSync(path.dirname(destination),{recursive:true});fs.writeFileSync(destination,'synthetic controlled Pricing package: '+relative+'\n');}const captured=require('../server/services/secureshopPricingPackage').capturePricingPackage(root);fs.writeFileSync(path.join(root,'sidecars/sandbox-runner/owned-pricing-http/local-package-manifest.json'),JSON.stringify({...captured,qualification:'tasks/sidecar-pricing-package-qualified-2026-09-26.json'}));const id=workspaceId(root),directory=path.join(home,'.dvaia',id);fs.mkdirSync(directory,{recursive:true,mode:0o700});const authority={version:1,workspaceId:id,host:'unix:///tmp/owned-pricing.sock',daemonId:'owned-daemon',source:'environment-host'};
 const config={version:1,enabled:true,workspaceId:id,ownerId:randomUUID(),dockerAuthoritySha256:authorityDigest(authority),containerName:'dvaia-pricing-'+id,containerId:'a'.repeat(64),imageId:'sha256:'+'b'.repeat(64),packageSha256:require('../server/services/secureshopPricingPackage').capturePricingPackage(root).sha256,profile:'dvaia-owned-pricing-http-'+id,port:28093,token:'x'.repeat(43)};
 const filename=path.join(directory,'pricing-managed.json');fs.writeFileSync(filename,JSON.stringify(config),{mode:0o600});fs.writeFileSync(path.join(directory,'local-docker.json'),JSON.stringify(authority),{mode:0o600});t.after(()=>fs.rmSync(home,{recursive:true,force:true}));return{home,root,config,filename};}
test('main Pricing package retains exact checked-in qualification independently of synthetic activation data',()=>{const root=path.resolve(__dirname,'..'),source=require('../scripts/install/secureshop-owned-pricing').qualifiedSource(root),captured=require('../server/services/secureshopPricingPackage').capturePricingPackage(root);assert.equal(source.sha256,captured.sha256);assert.deepEqual(source.files,captured.files);});
test('default disabled is dependency-free and explicit URL/token fallback is refused',async()=>{
 assert.equal(await preparePricingClient({env:{},execute:()=>assert.fail('Docker probe')}),undefined);
 assert.deepEqual(activationPolicy({SS_BOUND_PRICING_ENABLED:'false'}),{requested:false});
 for(const patch of [{SS_ENABLE:'false'},{SS_PRICING_BASE_URL:'http://127.0.0.1:1'},{SS_PRICING_TOKEN:'x'.repeat(43)},{SS_BOUND_PRICING_ENABLED:'yes'}])assert.throws(()=>activationPolicy({...env,...patch}));
});
test('descriptor-bound private workspace record refuses tamper, foreign identity and symlinks',t=>{
 const f=fixture(t);assert.equal(managed.load(f).config.containerId,f.config.containerId);
 assert.throws(()=>managed.validate({...f.config,containerName:'foreign'},{root:f.root}));
 assert.throws(()=>managed.validate({...f.config,extra:'token'},{root:f.root}));
 fs.chmodSync(f.filename,0o644);assert.throws(()=>managed.load(f));fs.chmodSync(f.filename,0o600);
 const saved=f.filename+'.saved';fs.renameSync(f.filename,saved);fs.symlinkSync(saved,f.filename);assert.throws(()=>managed.load(f));
});
test('wrong Docker authority fails before inspection or HTTP and never exposes token',async t=>{
 const f=fixture(t);let calls=0;
 await assert.rejects(preparePricingClient({...f,env,execute:async(_cmd,args)=>{calls++;assert.deepEqual(args.slice(-3),['info','--format','{{json .ID}}']);return{stdout:'"foreign-daemon"'};},fetchImpl:()=>assert.fail('HTTP must not probe')}),error=>error.code==='PRICING_ACTIVATION_UNAVAILABLE'&&!error.message.includes(f.config.token));assert.equal(calls,1);
});
function inspectedResources(c){
 const labels={'dvaia.pricing.owner':c.ownerId,'dvaia.pricing.workspace':c.workspaceId,'dvaia.pricing.package':c.packageSha256};
 const ports={'8093/tcp':[{HostIp:'127.0.0.1',HostPort:String(c.port)}]};
 const network='dvaia-pricing-'+c.workspaceId+'-network';
 return {image:{Id:c.imageId,Architecture:'arm64',Config:{Labels:labels,Entrypoint:['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'],Cmd:null,Env:[]}},container:{Id:c.containerId,Name:'/'+c.containerName,Image:c.imageId,State:{Running:true},Mounts:[],Config:{Labels:labels,Entrypoint:['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'],Cmd:null,User:'10001:10001',Env:['SECURESHOP_PRICING_ENABLED=true','SECURESHOP_PRICING_TOKEN='+c.token,'SECURESHOP_PRICING_PROFILE='+c.profile,'SECURESHOP_PRICING_HOST=0.0.0.0','SECURESHOP_PRICING_PORT=8093']},HostConfig:{Privileged:false,CapDrop:['ALL'],ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,PortBindings:ports,NetworkMode:network,Tmpfs:{'/tmp':'rw,nosuid,nodev,size=134217728'},SecurityOpt:['apparmor='+c.profile,'seccomp=unconfined']},NetworkSettings:{Ports:ports,Networks:{[network]:{}}}},network:{Name:network,Driver:'bridge',Labels:labels}};
}
test('detached pre-start admission requires exact disabled never-started state and owned bridge',async t=>{
 const f=fixture(t),activation=require('../server/services/secureshopPricingActivation');
 fs.writeFileSync(f.filename,JSON.stringify({...f.config,enabled:false}),{mode:0o600});
 const resources=inspectedResources(f.config),c=resources.container;
 resources.network.Labels={...resources.network.Labels};
 c.State={Status:'created',Running:false,StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z'};c.RestartCount=0;c.NetworkSettings.Networks={};c.NetworkSettings.Ports={};
 const execute=async(_command,args)=>({stdout:args.includes('info')?'"owned-daemon"':JSON.stringify([args.includes('image')?resources.image:args.includes('network')?resources.network:c])});
 const options={...f,env,execute,fetchImpl:()=>assert.fail('pre-start must not contact HTTP')};
 assert.equal((await activation.inspectPricingBeforeStart(options)).containerId,f.config.containerId);
 const original=structuredClone(c);
 for(const patch of [{State:{...original.State,Status:'exited'}},{State:{...original.State,Running:true}},{State:{...original.State,StartedAt:'2026-10-09T00:00:00Z'}},{State:{...original.State,FinishedAt:'2026-10-09T00:00:00Z'}},{RestartCount:1},{RestartCount:undefined}]){
  Object.assign(c,structuredClone(original),patch);await assert.rejects(activation.inspectPricingBeforeStart(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});
 }
 Object.assign(c,structuredClone(original));
 for(const networks of [undefined,null,[],{'foreign-network':{}}]){c.NetworkSettings.Networks=networks;await assert.rejects(activation.inspectPricingBeforeStart(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});}
 c.NetworkSettings.Networks={};
 const configuredNetwork=c.HostConfig.NetworkMode;c.HostConfig.NetworkMode='foreign-network';await assert.rejects(activation.inspectPricingBeforeStart(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});c.HostConfig.NetworkMode=configuredNetwork;
 for(const key of ['dvaia.pricing.owner','dvaia.pricing.workspace']){const value=resources.network.Labels[key];resources.network.Labels[key]='foreign';await assert.rejects(activation.inspectPricingBeforeStart(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});resources.network.Labels[key]=value;}
 resources.network.Driver='host';await assert.rejects(activation.inspectPricingBeforeStart(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});resources.network.Driver='bridge';
 await assert.rejects(activation.verifyStagedPricing(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});
 fs.writeFileSync(f.filename,JSON.stringify(f.config),{mode:0o600});
 await assert.rejects(activation.inspectPricingBeforeStart(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});
 await assert.rejects(activation.preparePricingClient(options),{code:'PRICING_ACTIVATION_UNAVAILABLE'});
});
test('controlled exact owned resource inspection precedes readiness; replacement during probe fails closed',async t=>{
 const f=fixture(t),resources=inspectedResources(f.config);let probes=0,replace=false;
 const execute=async(_command,args)=>{
  if(args.includes('info'))return{stdout:'"owned-daemon"'};
  const value=args.includes('image')?resources.image:args.includes('network')?resources.network:resources.container;
  return{stdout:JSON.stringify([value])};
 };
 const fetchImpl=async()=>{probes++;if(replace){const staged=f.filename+'.new';fs.writeFileSync(staged,JSON.stringify(f.config),{mode:0o600});fs.renameSync(staged,f.filename);}return new Response(JSON.stringify({version:require('../sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));};
 assert.ok(await preparePricingClient({...f,env,execute,fetchImpl}));assert.equal(probes,1);
 const fixedPorts=resources.container.HostConfig.PortBindings;resources.container.HostConfig.PortBindings={'8093/tcp':[{HostIp:'127.0.0.1',HostPort:''}]};await assert.rejects(preparePricingClient({...f,env,execute,fetchImpl}),{code:'PRICING_ACTIVATION_UNAVAILABLE'});assert.equal(probes,1);resources.container.HostConfig.PortBindings=fixedPorts;
 resources.container.HostConfig.Privileged=true;await assert.rejects(preparePricingClient({...f,env,execute,fetchImpl}),{code:'PRICING_ACTIVATION_UNAVAILABLE'});assert.equal(probes,1);
 resources.container.HostConfig.Privileged=false;replace=true;await assert.rejects(preparePricingClient({...f,env,execute,fetchImpl}),{code:'PRICING_ACTIVATION_UNAVAILABLE'});assert.equal(probes,2);
});

test('enabled Pricing startup starts only its retained ID and rejects private replacement before start',async t=>{
 const f=fixture(t),{startExisting}=require('../scripts/install/secureshop-owned-pricing-provision');
 const resources=inspectedResources(f.config),commands=[];
 resources.container.State={Running:false,Status:'exited'};
 resources.container.NetworkSettings.Ports=null;
 const run=async(_file,args)=>{
  commands.push([...args]);
  if(args.includes('info'))return{exitCode:0,stdout:'"owned-daemon"'};
  if(args.includes('start')){
   assert.equal(args.at(-1),f.config.containerId);
   resources.container.State={Running:true,Status:'running'};
   resources.container.NetworkSettings.Ports=resources.container.HostConfig.PortBindings;
   return{exitCode:0,stdout:''};
  }
  assert.ok(args.includes('inspect'));
  return{exitCode:0,stdout:JSON.stringify([args.includes('image')?resources.image:args.includes('network')?resources.network:resources.container])};
 };
 const fetchImpl=async()=>new Response(JSON.stringify({version:require('../sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));
 const options={...f,platform:'linux',environment:env,run,fetchImpl,verifyExistingProfile:async()=>{}};
 const before=managed.load(f),result=await startExisting(options);
 assert.equal(result.containerId,f.config.containerId);
 assert.deepEqual(commands.filter(args=>args.includes('start')).map(args=>args.at(-1)),[f.config.containerId]);
 assert.ok(!commands.some(args=>args.includes('build')||args.includes('create')||args.includes('rm')));
 assert.equal(managed.load(f).sha256,before.sha256);
 for(const disabled of [undefined,'false']){
  const inactive={...env};if(disabled===undefined)delete inactive.SS_BOUND_PRICING_ENABLED;else inactive.SS_BOUND_PRICING_ENABLED=disabled;
  const count=commands.length;
  await assert.rejects(startExisting({...options,environment:inactive}),{code:'PRICING_START_ACTIVATION_REQUIRED'});
  assert.equal(commands.length,count,'inactive activation must not inspect or start Docker');
 }
 await assert.rejects(startExisting({...options,fetchImpl:async()=>{
  resources.container.Config.Env.push('FOREIGN=1');
  return new Response(JSON.stringify({version:require('../sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));
 }}),{code:'PRICING_ACTIVATION_UNAVAILABLE'});
 resources.container.Config.Env.pop();
 resources.container.State={Running:false,Status:'paused'};
 const count=commands.length;
 await assert.rejects(startExisting(options),{code:'PRICING_START_CONTAINER_STATE'});
 assert.equal(commands.slice(count).filter(args=>args.includes('start')).length,0);
 resources.container.State={Running:false,Status:'exited'};
 const authority=path.join(path.dirname(f.filename),'local-docker.json'),replacement=authority+'.new';
 const count2=commands.length;
 await assert.rejects(startExisting({...options,run:async(file,args,settings)=>{
  const response=await run(file,args,settings);
  if(args.includes('inspect')&&args.includes(f.config.containerId)){
   fs.writeFileSync(replacement,fs.readFileSync(authority),{mode:0o600});fs.renameSync(replacement,authority);
  }
  return response;
 }}),{code:'PRICING_START_STATE_CHANGED'});
 assert.equal(commands.slice(count2).filter(args=>args.includes('start')).length,0);
});
test('disabled stage validates authority before writing and repeat preserves credentials',t=>{
 const f=fixture(t);fs.unlinkSync(f.filename);const disabled={...f.config,enabled:false};
 assert.throws(()=>managed.stage({...f,value:{...disabled,dockerAuthoritySha256:'f'.repeat(64)}}));assert.equal(fs.existsSync(f.filename),false);
 const first=managed.stage({...f,value:disabled});assert.equal(first.created,true);assert.equal(first.record.config.enabled,false);
 const reordered=Object.fromEntries(Object.entries(disabled).reverse());const repeat=managed.stage({...f,value:reordered});assert.equal(repeat.created,false);assert.equal(repeat.record.sha256,first.record.sha256);assert.equal(repeat.record.identity.ino,first.record.identity.ino);
 assert.throws(()=>managed.stage({...f,value:{...disabled,token:'z'.repeat(43)}}));assert.equal(managed.load(f).sha256,first.record.sha256);
});
test('activation CAS requires captured exact identity and preserves concurrent replacement',t=>{
 const f=fixture(t),original=managed.load(f);assert.throws(()=>managed.compareAndSwap({...f,expected:{...original},enabled:false}));
 const disabled=managed.compareAndSwap({...f,expected:original,enabled:false});assert.equal(disabled.config.enabled,false);assert.equal(disabled.config.token,original.config.token);
 assert.throws(()=>managed.compareAndSwap({...f,expected:original,enabled:true}));
 const replacement=f.filename+'.replace';fs.writeFileSync(replacement,JSON.stringify(disabled.config),{mode:0o600});fs.renameSync(replacement,f.filename);
 assert.throws(()=>managed.compareAndSwap({...f,expected:disabled,enabled:true}));assert.equal(managed.load(f).config.enabled,false);
 assert.equal(fs.existsSync(path.join(path.dirname(f.filename),'.pricing-managed.lock')),false);
});
test('staged readiness never enables configuration until single-use identity-bound activation',async t=>{
 const f=fixture(t),activation=require('../server/services/secureshopPricingActivation');
 fs.writeFileSync(f.filename,JSON.stringify({...f.config,enabled:false}),{mode:0o600});
 const resources=inspectedResources(f.config);const execute=async(_command,args)=>({stdout:args.includes('info')?'"owned-daemon"':JSON.stringify([args.includes('image')?resources.image:args.includes('network')?resources.network:resources.container])});
 const fetchImpl=async()=>{assert.equal(managed.load(f).config.enabled,false);return new Response(JSON.stringify({version:require('../sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));};
 await assert.rejects(activation.preparePricingClient({...f,env,execute,fetchImpl}));
 const proof=await activation.verifyStagedPricing({...f,env,execute,fetchImpl});assert.equal(managed.load(f).config.enabled,false);
 assert.throws(()=>activation.activateStagedPricing({...proof}));const enabled=activation.activateStagedPricing(proof);assert.equal(enabled.config.enabled,true);assert.equal(enabled.config.token,f.config.token);assert.throws(()=>activation.activateStagedPricing(proof));
});
test('cold Pricing base uses only selected daemon, exact digest and arm64; repository mode admits storage before pull',async t=>{
 const {ensureBase,temporaryRoot}=require('../scripts/install/secureshop-owned-pricing-provision')._internals;
 const f=fixture(t),reference='node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
 const digest=reference.replace('node:26.10.0-slim@','node@'),authority={host:'unix:///selected/pricing.sock'};
 let base=null,operations=[],admissions=0;
 const inspect=async(kind,id)=>{assert.equal(kind,'image');assert.equal(id,reference);operations.push('inspect');return base;};
 const docker=async(args,deadline)=>{operations.push(args);assert.deepEqual(args,['image','pull','--platform','linux/arm64',reference]);assert.equal(deadline,300000);base={Architecture:'arm64',Os:'linux',RepoDigests:[digest]};};
 await assert.rejects(ensureBase({inspect,docker,authority,root:f.root,repositoryOnlyStorage:true}),{code:'PRICING_REPOSITORY_STORAGE_UNQUALIFIED'});
 assert.deepEqual(operations,['inspect']);
 operations=[];await ensureBase({inspect,docker,authority,root:f.root,repositoryOnlyStorage:true,admitRepositoryStorage:async details=>{
  admissions++;assert.deepEqual(details,{root:f.root,dockerHost:authority.host,reference,architecture:'arm64'});return true;
 }});
 assert.equal(admissions,1);assert.deepEqual(operations,['inspect',['image','pull','--platform','linux/arm64',reference],'inspect']);
 operations=[];await ensureBase({inspect,docker,authority,root:f.root,repositoryOnlyStorage:true,admitRepositoryStorage:async()=>assert.fail('already present must not re-admit')});
 assert.deepEqual(operations,['inspect']);
 for(const invalid of [{...base,Architecture:'amd64'},{...base,Os:'darwin'},{...base,RepoDigests:['node@sha256:'+'0'.repeat(64)]}]){
  base=invalid;await assert.rejects(ensureBase({inspect,docker,authority,root:f.root}),{code:'PRICING_BASE_UNQUALIFIED'});
 }
 base=null;operations=[];await assert.rejects(ensureBase({inspect,docker:async args=>{operations.push(args);base={Architecture:'arm64',Os:'linux',RepoDigests:['node@sha256:'+'0'.repeat(64)]};},authority,root:f.root}),{code:'PRICING_BASE_UNQUALIFIED'});
 assert.equal(operations.filter(Array.isArray).length,1,'wrong digest after one pull is rejected');
 base=null;operations=[];await assert.rejects(ensureBase({inspect,docker:async args=>{operations.push(args);throw Object.assign(Error('pull failed'),{code:'PRICING_INSTALL_COMMAND_FAILED'});},authority,root:f.root}),{code:'PRICING_INSTALL_COMMAND_FAILED'});
 assert.equal(operations.filter(Array.isArray).length,1,'failed pull never reaches a build');
 fs.mkdirSync(path.join(f.root,'tasks'),{mode:0o700});
 assert.equal(temporaryRoot(f.root,true),path.join(fs.realpathSync(f.root),'tasks','tmp'));
 assert.equal(temporaryRoot(f.root,false),os.tmpdir());
 fs.chmodSync(path.join(f.root,'tasks','tmp'),0o777);assert.throws(()=>temporaryRoot(f.root,true),{code:'PRICING_REPOSITORY_STORAGE_UNQUALIFIED'});
 fs.chmodSync(path.join(f.root,'tasks','tmp'),0o700);
 const moved=path.join(f.root,'tasks','tmp-owned');fs.renameSync(path.join(f.root,'tasks','tmp'),moved);fs.symlinkSync(moved,path.join(f.root,'tasks','tmp'));
 assert.throws(()=>temporaryRoot(f.root,true),{code:'PRICING_REPOSITORY_STORAGE_UNQUALIFIED'});
});
test('private pre-create stage retains exact identity and rejects authority/image/port conflicts',t=>{
 const f=fixture(t),stage=require('../scripts/install/secureshop-owned-pricing-stage');fs.unlinkSync(f.filename);
 const plan={workspaceId:f.config.workspaceId,dockerAuthoritySha256:f.config.dockerAuthoritySha256,source:{sha256:f.config.packageSha256},port:f.config.port};
 const first=stage.prepare({...f,plan,imageId:f.config.imageId});assert.equal(first.created,true);assert.equal(first.value.token.length,43);assert.equal(managed.load(f),null);
 const repeat=stage.prepare({...f,plan,imageId:f.config.imageId});assert.equal(repeat.created,false);assert.deepEqual(repeat.value,first.value);assert.equal(repeat.identity.ino,first.identity.ino);
 for(const change of [{plan:{...plan,port:28094}},{imageId:'sha256:'+'c'.repeat(64)},{plan:{...plan,dockerAuthoritySha256:'f'.repeat(64)}}])assert.throws(()=>stage.prepare({...f,plan,imageId:f.config.imageId,...change}));
 assert.equal(stage.read(f).sha256,first.sha256);
});
test('provision reconciles saved identity without rebuild/create or credential rotation',async t=>{
 const f=fixture(t),{provision}=require('../scripts/install/secureshop-owned-pricing-provision'),resources=inspectedResources(f.config),commands=[];
 
 resources.image.Os='linux';resources.image.Config.User='10001:10001';resources.network.Internal=false;
 const run=async(_file,args)=>{commands.push(args);if(args.includes('info'))return{exitCode:0,stdout:JSON.stringify(args.at(-1).includes('Architecture')?'aarch64':'owned-daemon')};
  assert.ok(args.includes('inspect'),'repeat must not build/create/start');return{exitCode:0,stdout:JSON.stringify([args.includes('image')?resources.image:args.includes('network')?resources.network:resources.container])};};
 const fetchImpl=async()=>new Response(JSON.stringify({version:require('../sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));
 const before=managed.load(f);const result=await provision({...f,platform:'linux',architecture:'arm64',environment:env,run,provisionProfile:async()=>{},fetchImpl});assert.equal(result.ready,true);assert.equal(managed.load(f).sha256,before.sha256);assert.equal(managed.load(f).identity.ino,before.identity.ino);
 const again=await provision({...f,platform:'linux',architecture:'arm64',environment:env,run,provisionProfile:async()=>{},fetchImpl});assert.equal(again.containerId,f.config.containerId);assert.equal(managed.load(f).config.token,f.config.token);
});
test('first provision stages disabled before create, starts checked identity and activates only after readiness',async t=>{
 const f=fixture(t),{provision}=require('../scripts/install/secureshop-owned-pricing-provision');fs.unlinkSync(f.filename);
 let resources=inspectedResources(f.config),baseAvailable=false,pulls=0,imageAvailable=false,builds=0,created=false,network=false,starts=0,creates=0;resources.image.Os='linux';resources.image.Config.User='10001:10001';
 const run=async(_file,args)=>{
  if(args.includes('info'))return{exitCode:0,stdout:JSON.stringify(args.at(-1).includes('Architecture')?'aarch64':'owned-daemon')};
  if(args.includes('pull')){assert.deepEqual(args.slice(-5),['image','pull','--platform','linux/arm64','node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1']);pulls++;baseAvailable=true;return{exitCode:0,stdout:''};}
  if(args.includes('build')){builds++;const context=args.at(-1);for(const relative of require('../server/services/secureshopPricingPackage').PRICING_PACKAGE_FILES)assert.equal(fs.statSync(path.join(context,relative)).mode&0o777,0o444,'runtime source must remain readable after Docker COPY');imageAvailable=true;return{exitCode:0,stdout:''};}
  if(args.includes('create')&&args.includes('network')){network=true;return{exitCode:0,stdout:''};}
  if(args.includes('create')){creates++;assert.equal(managed.load(f),null);const staged=require('../scripts/install/secureshop-owned-pricing-stage').read(f).value;resources=inspectedResources({...f.config,...staged});resources.image.Os='linux';resources.image.Config.User='10001:10001';resources.network.Internal=false;resources.container.State.Running=false;resources.container.NetworkSettings.Ports={};created=true;return{exitCode:0,stdout:f.config.containerId};}
  if(args.includes('start')){starts++;assert.equal(managed.load(f).config.enabled,false);resources.container.State.Running=true;resources.container.NetworkSettings.Ports=resources.container.HostConfig.PortBindings;return{exitCode:0,stdout:''};}
  if(args.includes('inspect')){if(args.includes('image')){if(args.at(-1).startsWith('node:'))return baseAvailable?{exitCode:0,stdout:JSON.stringify([{Architecture:'arm64',Os:'linux',RepoDigests:[args.at(-1).replace('node:26.10.0-slim@','node@')]}])}:{exitCode:1,stderr:'No such image'};if(!imageAvailable)return{exitCode:1,stderr:'No such image'};return{exitCode:0,stdout:JSON.stringify([resources.image])};}if(args.includes('network')){if(!network)return{exitCode:1,stderr:'No such network'};const staged=require('../scripts/install/secureshop-owned-pricing-stage').read(f).value;return{exitCode:0,stdout:JSON.stringify([{...resources.network,Internal:false,Labels:{'dvaia.pricing.owner':staged.ownerId,'dvaia.pricing.workspace':staged.workspaceId,'dvaia.pricing.package':staged.packageSha256}}])};}if(!created)return{exitCode:1,stderr:'No such container'};return{exitCode:0,stdout:JSON.stringify([resources.container])};}
  assert.fail('unexpected command');
 };
 let ready=false;const fetchImpl=async()=>{assert.equal(managed.load(f).config.enabled,false);if(!ready)throw Error('controlled readiness unavailable');return new Response(JSON.stringify({version:require('../sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));};
 const {setupOwnedPricing}=require('../scripts/install/pricing-setup');
 fs.mkdirSync(path.join(f.root,'tasks'),{mode:0o700});
 const repoTmp=path.join(f.root,'tasks','tmp');
 const setup=()=>setupOwnedPricing({requested:true,root:f.root,homeDirectory:f.home,platform:'linux',repositoryOnlyStorage:true,admitRepositoryStorage:async details=>{assert.equal(details.dockerHost,'unix:///tmp/owned-pricing.sock');assert.equal(details.root,f.root);return true;},applicationEnvironment:env,environment:env,provision:input=>provision({...input,architecture:'arm64',run,provisionProfile:async()=>{},fetchImpl})});
 await assert.rejects(setup());assert.deepEqual(fs.readdirSync(repoTmp),[],'failed readiness retires repository-only staging');const stagedBefore=managed.load(f);assert.equal(stagedBefore.config.enabled,false);ready=true;
 const result=await setup();assert.deepEqual(fs.readdirSync(repoTmp),[],'successful setup retires repository-only staging');
 assert.equal(result.activationEnabled,true);assert.equal(pulls,1);assert.equal(managed.load(f).config.token,stagedBefore.config.token);assert.equal(builds,1);assert.equal(creates,1);assert.equal(starts,1);assert.equal(managed.load(f).config.enabled,true);
});
test('expired staged readiness proof cannot activate a disabled record',async t=>{
 const f=fixture(t),activation=require('../server/services/secureshopPricingActivation'),performance=require('node:perf_hooks').performance;
 fs.writeFileSync(f.filename,JSON.stringify({...f.config,enabled:false}),{mode:0o600});const resources=inspectedResources(f.config);
 const execute=async(_c,args)=>({stdout:args.includes('info')?'"owned-daemon"':JSON.stringify([args.includes('image')?resources.image:args.includes('network')?resources.network:resources.container])});
 const fetchImpl=async()=>new Response(JSON.stringify({version:require('../sidecars/sandbox-runner/owned-pricing-http/wire').VERSION,ready:true,isolation:'bwrap-owned-pricing-http-v1',pricingCapability:'secureshop-owned-pricing-http.v1'}));
 let now=100;t.mock.method(performance,'now',()=>now);const proof=await activation.verifyStagedPricing({...f,env,execute,fetchImpl});now=5101;assert.throws(()=>activation.activateStagedPricing(proof));assert.equal(managed.load(f).config.enabled,false);
});
