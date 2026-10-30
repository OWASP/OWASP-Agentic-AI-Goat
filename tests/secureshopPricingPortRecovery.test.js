'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {recoverUnusedPricingPort,neverStarted}=require('../scripts/install/secureshop-owned-pricing-port-recovery');
const managed=require('../server/services/secureshopPricingManagedConfiguration'),stage=require('../scripts/install/secureshop-owned-pricing-stage');
function fixture(t){
 const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'pricing-port-recovery-'))),root=path.join(home,'source');fs.mkdirSync(root);t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 for(const file of require('../server/services/secureshopPricingPackage').PRICING_PACKAGE_FILES){const target=path.join(root,file);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,'controlled Pricing package '+file);}
 const workspaceId=require('../scripts/application-data-root').workspaceId(root),directory=path.join(home,'.owasp-ai-goat',workspaceId);fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const authority={version:1,workspaceId,host:'unix:///tmp/controlled-pricing.sock',daemonId:'controlled-daemon',source:'environment-host'};
 fs.writeFileSync(path.join(directory,'local-docker.json'),JSON.stringify(authority),{mode:0o600});
 const config={version:1,enabled:false,workspaceId,ownerId:crypto.randomUUID(),dockerAuthoritySha256:require('../scripts/local-docker-authority').authorityDigest(authority),containerName:'owasp-ai-goat-pricing-'+workspaceId,containerId:'a'.repeat(64),imageId:'sha256:'+'b'.repeat(64),packageSha256:require('../server/services/secureshopPricingPackage').capturePricingPackage(root).sha256,profile:'owasp-ai-goat-owned-pricing-http-'+workspaceId,port:8093,token:'x'.repeat(43)};
 managed.stage({root,home,value:config});stage.prepare({root,home,plan:{workspaceId,dockerAuthoritySha256:config.dockerAuthoritySha256,source:{sha256:config.packageSha256},port:config.port},imageId:config.imageId});
 const labels={'owasp-ai-goat.pricing.owner':config.ownerId,'owasp-ai-goat.pricing.workspace':workspaceId,'owasp-ai-goat.pricing.package':config.packageSha256},network=config.containerName+'-network',entrypoint=['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'];
 const image={Id:config.imageId,Architecture:'arm64',Config:{Labels:labels,Entrypoint:entrypoint,Cmd:null,Env:[]}};
 let container={Id:config.containerId,Name:'/'+config.containerName,Image:config.imageId,RestartCount:0,State:{Status:'created',Running:false,StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z',ExitCode:128},Mounts:[],Config:{Labels:labels,Entrypoint:entrypoint,Cmd:null,User:'10001:10001',Env:['SECURESHOP_PRICING_ENABLED=true','SECURESHOP_PRICING_TOKEN='+config.token,'SECURESHOP_PRICING_PROFILE='+config.profile,'SECURESHOP_PRICING_HOST=0.0.0.0','SECURESHOP_PRICING_PORT=8093']},HostConfig:{Privileged:false,CapDrop:['ALL'],ReadonlyRootfs:true,Memory:536870912,NanoCpus:1000000000,PidsLimit:128,PortBindings:{'8093/tcp':[{HostIp:'127.0.0.1',HostPort:'8093'}]},NetworkMode:network,Tmpfs:{'/tmp':'rw,nosuid,nodev,size=134217728'},SecurityOpt:['apparmor='+config.profile,'seccomp=unconfined']},NetworkSettings:{Ports:{},Networks:{[network]:{}}}};
 const events=[],control={unused:true,occupied:false,failCreate:false,foreign:false,leaseHeld:false,closes:0};
 const run=async(_file,args)=>{
  assert.equal(control.leaseHeld,true);events.push(args.slice(2));
  if(args.includes('info'))return{exitCode:0,stdout:'"controlled-daemon"'};
  if(args.includes('ps'))return{exitCode:0,stdout:control.foreign?'foreign8096\n':''};
  if(args.includes('rm')){assert.deepEqual(args.slice(-2),['rm',config.containerId]);container=null;return{exitCode:0,stdout:''};}
  if(args.includes('create')){if(control.failCreate)return{exitCode:1,stderr:'controlled create uncertainty'};const labelAt=args.findIndex(a=>a.startsWith('owasp-ai-goat.pricing.retarget='));assert.ok(labelAt>=0);assert.ok(args.includes('127.0.0.1:8096:8093'));const envFile=args[args.indexOf('--env-file')+1];assert.match(fs.readFileSync(envFile,'utf8'),new RegExp(config.token));container=structuredClone(original);container.Id='c'.repeat(64);container.HostConfig.PortBindings['8093/tcp'][0].HostPort='8096';container.Config.Labels['owasp-ai-goat.pricing.retarget']=args[labelAt].split('=')[1];return{exitCode:0,stdout:container.Id};}
  if(args.includes('inspect')){const found=args.includes('image')?image:args.includes('network')?{Name:network,Driver:'bridge',Labels:labels}:container&&[container.Id,config.containerName].includes(args.at(-1))?container:null;return found?{exitCode:0,stdout:JSON.stringify([found])}:{exitCode:1,stderr:'No such container'};}
  assert.fail('unexpected Docker effect');
 };
 const original=structuredClone(container);
 const execute=async(file,args)=>{const result=await run(file,args);if(result.exitCode)throw Error('controlled inspection failed');return result;};
 const options={root,home,environment:{},run,execute,
  acquireLease:async()=>{assert.equal(control.leaseHeld,false);control.leaseHeld=true;return{assertHeld(){assert.equal(control.leaseHeld,true);},assertClean:async()=>{},close:async()=>{control.leaseHeld=false;control.closes++;}};},
  assertUnused:async()=>{assert.equal(control.leaseHeld,true);if(!control.unused)throw Object.assign(Error('prior execution'),{code:'PRICING_PORT_RECOVERY_UNAVAILABLE'});},
  checkPort:async port=>{assert.equal(port,8096);if(control.occupied)throw Object.assign(Error('port occupied'),{code:'PRICING_PORT_RECOVERY_UNAVAILABLE'});}};
 return{...options,options,config,directory,events,control,get container(){return container;}};
}
test('exact never-started collision retarget preserves identity and immutable recovery proof',async t=>{
 const f=fixture(t);assert.equal(await recoverUnusedPricingPort(f.options),true);const after=managed.load(f).config;
 for(const key of Object.keys(f.config).filter(k=>!['port','containerId'].includes(k)))assert.equal(after[key],f.config[key]);
 assert.equal(after.port,8096);assert.equal(after.containerId,'c'.repeat(64));assert.equal(stage.read(f).value.port,8096);
 assert.equal(f.events.filter(a=>a.includes('rm')).length,1);assert.equal(f.events.filter(a=>a.includes('create')).length,1);assert.ok(f.events.every(a=>!a.includes('start')&&!a.includes('stop')));
 const files=['pricing-port-retarget.json','pricing-port-retarget-successor.json','pricing-port-retarget-complete.json'];const bytes=files.map(n=>fs.readFileSync(path.join(f.directory,n)));
 managed.compareAndSwap({...f,expected:managed.load(f),enabled:true});
 f.control.unused=false;assert.equal(await recoverUnusedPricingPort(f.options),false,'completed transition does not relabel subsequent run history');
 assert.equal(managed.load(f).config.enabled,true);
 for(let i=0;i<files.length;i++)assert.deepEqual(fs.readFileSync(path.join(f.directory,files[i])),bytes[i]);assert.equal(f.control.closes,2);assert.equal(fs.existsSync(path.join(f.directory,'.pricing-managed.lock')),false);
});
test('created status alone never proves no execution',()=>{
 const state={State:{Status:'created',Running:false,StartedAt:'0001-01-01T00:00:00Z',FinishedAt:'0001-01-01T00:00:00Z'},RestartCount:0};assert.equal(neverStarted(state),true);
 for(const patch of [{State:{...state.State,StartedAt:'2026-10-09T00:00:00Z'}},{State:{...state.State,FinishedAt:'2026-10-09T00:00:00Z'}},{State:{...state.State,Status:'exited'}},{State:{...state.State,Running:true}},{RestartCount:1},{RestartCount:undefined}])assert.equal(neverStarted({...state,...patch}),false);
});
test('unused SQL guard retains zero-effect cleanup receipts and rejects uncertain readback',async t=>{
 const {assertNoPricingRuns}=require('../scripts/install/secureshop-owned-pricing-port-recovery')._internals;
 let result={rows:[{unused:true}]},closed=0;
 const pg=require('pg'),originalPool=pg.Pool;t.after(()=>{pg.Pool=originalPool;});
 pg.Pool=class {
  constructor(){this.query=async sql=>{
   assert.match(sql,/NOT EXISTS\(SELECT 1 FROM secureshop_agents\.bound_pricing_admissions\)/);
   assert.match(sql,/NOT EXISTS\(SELECT 1 FROM secureshop_agents\.bound_pricing_outcomes\)/);
   assert.match(sql,/WHERE admission_count IS DISTINCT FROM 0 OR outcome_count IS DISTINCT FROM 0/);
   assert.doesNotMatch(sql,/\b(?:DELETE|UPDATE|INSERT)\b/);
   return result;
  };this.end=async()=>{closed++;};}
 };
 const environment={SECURESHOP_AGENTS_MIGRATION_DATABASE_URL:'postgresql://controlled@127.0.0.1:5432/owasp_ai_goat_test_pricing_guard'};
 await assertNoPricingRuns(environment);
 for(const rows of [[{unused:false}],[{unused:null}],[{unused:'true'}],[],[{unused:true},{unused:true}]]){
  result={rows};await assert.rejects(assertNoPricingRuns(environment),{code:'PRICING_PORT_RECOVERY_UNAVAILABLE'});
 }
 assert.equal(closed,6);
});
test('detached never-started collision and successor retain exact owned bridge admission',async t=>{
 const f=fixture(t),run=f.options.run;f.container.NetworkSettings.Networks={};
 f.options.run=async(...args)=>{const result=await run(...args);if(args[1].includes('create'))f.container.NetworkSettings.Networks={};return result;};
 assert.equal(await recoverUnusedPricingPort(f.options),true);assert.equal(managed.load(f).config.port,8096);
 assert.equal(f.events.filter(a=>a.includes('rm')).length,1);assert.equal(f.events.filter(a=>a.includes('create')).length,1);
});
test('active and custom-port configurations are preserved without acquiring recovery authority',async t=>{
 for(const patch of [{enabled:true},{port:28193}]){const f=fixture(t);fs.writeFileSync(managed.paths(f).filename,JSON.stringify({...f.config,...patch}),{mode:0o600});assert.equal(await recoverUnusedPricingPort({...f.options,acquireLease:()=>assert.fail('unrelated configuration')}),false);assert.equal(f.events.length,0);}
});
test('past runs, occupied port, foreign listener and previously started resources deny before retirement',async t=>{
 for(const scenario of ['runs','occupied','foreign','started','restarted','privileged']){const f=fixture(t);
  if(scenario==='runs')f.control.unused=false;if(scenario==='occupied')f.control.occupied=true;if(scenario==='foreign')f.control.foreign=true;if(scenario==='started')f.container.State.StartedAt='2026-10-09T00:00:00Z';if(scenario==='restarted')f.container.RestartCount=1;if(scenario==='privileged')f.container.HostConfig.Privileged=true;
  await assert.rejects(recoverUnusedPricingPort(f.options));assert.equal(f.events.filter(a=>a.includes('rm')||a.includes('create')).length,0,scenario);assert.equal(managed.load(f).config.port,8093);assert.equal(f.control.leaseHeld,false);
 }
});
test('interruption after exact retirement resumes prepared identity without a second retirement',async t=>{
 const f=fixture(t);f.control.failCreate=true;await assert.rejects(recoverUnusedPricingPort(f.options));assert.equal(f.container,null);assert.equal(managed.load(f).config.port,8093);assert.ok(fs.existsSync(path.join(f.directory,'pricing-port-retarget.json')));
 f.control.failCreate=false;assert.equal(await recoverUnusedPricingPort(f.options),true);assert.equal(f.events.filter(a=>a.includes('rm')).length,1);assert.equal(managed.load(f).config.token,f.config.token);
});
test('interrupted multi-file cutover resumes exact successor without new Docker effects',async t=>{
 const f=fixture(t),rename=fs.renameSync;let injected=false;
 t.mock.method(fs,'renameSync',(from,to)=>{if(to===stage.location(f)&&!injected){injected=true;throw Error('controlled stage cutover interruption');}return rename(from,to);});
 await assert.rejects(recoverUnusedPricingPort(f.options));assert.equal(managed.load(f).config.port,8096);assert.equal(stage.read(f).value.port,8093);const effects=f.events.filter(a=>a.includes('rm')||a.includes('create')).length;
 assert.equal(await recoverUnusedPricingPort(f.options),true);assert.equal(stage.read(f).value.port,8096);assert.equal(f.events.filter(a=>a.includes('rm')||a.includes('create')).length,effects);
});
test('lost successor journal commit adopts only the exact digest-labelled inspected candidate',async t=>{
 const f=fixture(t),publish=managed._private.publishImmutable;let injected=false;
 t.mock.method(managed._private,'publishImmutable',(file,bytes)=>{if(file.endsWith('pricing-port-retarget-successor.json')&&!injected){injected=true;throw Error('controlled successor commit loss');}return publish(file,bytes);});
 await assert.rejects(recoverUnusedPricingPort(f.options));assert.equal(f.container.Id,'c'.repeat(64));assert.equal(managed.load(f).config.port,8093);
 const effects=f.events.filter(a=>a.includes('rm')||a.includes('create')).length;
 assert.equal(await recoverUnusedPricingPort(f.options),true);assert.equal(f.events.filter(a=>a.includes('rm')||a.includes('create')).length,effects);
});
test('forged maintenance scope rejects before acquiring another lease or touching resources',async t=>{
 const f=fixture(t);await assert.rejects(recoverUnusedPricingPort({...f.options,maintenanceScope:{assertHeld(){}},acquireLease:()=>assert.fail('must not reacquire')}));assert.equal(f.events.length,0);
});
test('supported setup reuses the authentic completed scope without closing or reacquiring its lease',async t=>{
 const f=fixture(t),environment={IDENTITY_DATABASE_URL:'postgresql://runtime@127.0.0.1:5432/controlled',IDENTITY_MIGRATION_DATABASE_URL:'postgresql://migration@127.0.0.1:5432/controlled'};
 t.mock.method(require('../server/services/applicationMaintenanceInprocessAdmission'),'sourceBinding',()=> 'controlled-source');
 const scopes=require('../scripts/lib/application-maintenance-scope');
 await scopes.withCleanApplicationMaintenanceScope({environment,sourceRoot:f.root,drain:async()=>{},acquire:async()=>{const lease=await f.options.acquireLease();return{...lease,assertProspectiveOriginalComplete:async()=>({sourceManifestSha256:'controlled-source'})};}},async maintenanceScope=>{
  assert.equal(await recoverUnusedPricingPort({...f.options,environment,maintenanceScope,acquireLease:()=>assert.fail('outer scope must be reused')}),true);
  assert.equal(f.control.leaseHeld,true);assert.equal(f.control.closes,0);maintenanceScope.assertHeld();
 });
 assert.equal(f.control.closes,1);assert.equal(f.control.leaseHeld,false);
});
test('foreign stage replacement and symlinked journal cannot authorize a resumed resource',async t=>{
 const f=fixture(t);f.control.failCreate=true;await assert.rejects(recoverUnusedPricingPort(f.options));const baseline=f.events.filter(a=>a.includes('rm')||a.includes('create')).length;
 fs.writeFileSync(stage.location(f),JSON.stringify({...stage.read(f).value,token:'z'.repeat(43)}),{mode:0o600});f.control.failCreate=false;await assert.rejects(recoverUnusedPricingPort(f.options));assert.equal(f.events.filter(a=>a.includes('rm')||a.includes('create')).length,baseline);
 const g=fixture(t);g.control.failCreate=true;await assert.rejects(recoverUnusedPricingPort(g.options));const journal=path.join(g.directory,'pricing-port-retarget.json'),saved=journal+'.saved';fs.renameSync(journal,saved);fs.symlinkSync(saved,journal);await assert.rejects(recoverUnusedPricingPort(g.options));
});
