'use strict';
// Actual disposable Docker provisioning. No installed workspace is admitted.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const net=require('node:net');
const {prepare,provision,_internals}=require('../../scripts/install/secureshop-owned-system-provision');
const managed=require('../../server/services/secureshopSystemManagedConfiguration');
const {workspaceId}=require('../../scripts/application-data-root');
const {writeLocalDockerAuthority}=require('../../scripts/local-docker-authority');
const {createSecureShopSystemDiagnosticClient}=require('../../server/services/secureshopSystemDiagnosticClient');
const root=fs.realpathSync(path.resolve(__dirname,'../..')),out=process.env.SYSTEM_PROVISION_NATIVE_OUT;
assert.equal(process.env.SYSTEM_PROVISION_NATIVE,'1');assert.ok(out&&root===path.join(fs.realpathSync(out),'source'));
const host='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock';
const home='/Users/averma5',id=workspaceId(root),directory=path.join(home,'.owasp-ai-goat',id);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const state={version:1,status:'preparing',workspaceId:id,privateDirectory:directory,containers:[],commands:{},cleanup:{},outerEgressIsolationEstablished:false};
const persist=()=>fs.writeFileSync(path.join(out,'fixture-result.json'),JSON.stringify(state,null,2)+'\n');
const runner=_internals.createRunner({cwd:root,env:process.env});
const run=async(file,args,options)=>{if(file==='docker'){const verb=args[2];state.commands[verb]=(state.commands[verb]||0)+1;persist();}return runner(file,args,options);};
const docker=async args=>{const r=await run('docker',['--host',host,...args],{timeoutMs:35000,maxOutputBytes:1048576});if(r.exitCode)throw Object.assign(Error('Docker operation failed'),{code:'NATIVE_DOCKER_FAILED'});return r.stdout;};
const inspect=async(kind,name)=>JSON.parse(await docker([kind,'inspect',name]))[0];
const freePort=()=>new Promise((resolve,reject)=>{const s=net.createServer();s.on('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
let privateStat;
function identity(){const value=managed.load({filePath:path.join(directory,managed.FILE)});return{image:value.imageId,enabled:value.enabled,configToken:sha(value.config.token),diagnosticToken:sha(value.diagnostic.token),restartToken:sha(value.restart.token),bytes:sha(fs.readFileSync(path.join(directory,managed.FILE)))};}
(async()=>{
 try{
  assert.equal((await docker(['info','--format','{{.Name}}'])).trim(),'colima-owasp-ai-goat-pg-verify');
  fs.mkdirSync(directory,{mode:0o700});privateStat=fs.lstatSync(directory);state.privateIdentity={dev:privateStat.dev,ino:privateStat.ino};persist();
  const daemonId=JSON.parse((await docker(['info','--format','{{json .ID}}'])).trim());
  const authority={version:1,workspaceId:id,host,daemonId,source:'environment-host',platform:'darwin'};
  await writeLocalDockerAuthority({directory,authority});
  const configPort=await freePort();let diagnosticPort=await freePort();while(diagnosticPort===configPort)diagnosticPort=await freePort();let restartPort=await freePort();while(new Set([configPort,diagnosticPort,restartPort]).size!==3)restartPort=await freePort();
  const options={root,home,platform:'darwin',architecture:'arm64',configPort,diagnosticPort,restartPort,run,environment:process.env};
  const execute=async(file,args,o)=>{const r=await run(file,args,{timeoutMs:o.timeout,maxOutputBytes:1048576});assert.equal(r.exitCode,0);return r;};
  const before=fs.readdirSync(directory);const p=await prepare({...options,execute});assert.deepEqual(fs.readdirSync(directory),before);assert.equal(p.mutating,false);assert.equal(p.existing,false);
  state.authoritySha256=p.dockerAuthoritySha256;state.sourceSha256=p.source.sha256;state.imageTag=`owasp-ai-goat-owned-system-${id}:local`;state.network=`owasp-ai-goat-owned-system-${id}-bridge`;state.containers=[p.config.container,p.diagnostic.container,p.restart.container];state.planNonmutating=true;persist();
  const first=await provision(options);assert.equal(first.ready,true);assert.equal(first.activationEnabled,false);
  state.imageId=first.imageId;state.initialIdentity=identity();assert.equal(state.initialIdentity.enabled,false);
  state.containerIds={};for(const name of state.containers)state.containerIds[name]=(await inspect('container',name)).Id;persist();
  const counts={...state.commands};await provision(options);for(const v of ['build','create','start'])assert.equal(state.commands[v],counts[v]);assert.deepEqual(identity(),state.initialIdentity);state.exactRepeat=true;
  for(const name of state.containers)await docker(['stop','--time','25',name]);
  await provision(options);assert.deepEqual(identity(),state.initialIdentity);for(const name of state.containers)assert.equal((await inspect('container',name)).Id,state.containerIds[name]);state.stopRestartSameIdentity=true;persist();
  let probes=0;
  await assert.rejects(provision({...options,createDiagnosticClient:args=>{const real=createSecureShopSystemDiagnosticClient(args);return{assertReady:async()=>{assert.equal(await real.assertReady(),true);probes++;throw Object.assign(Error('Controlled post-readiness rejection'),{code:'CONTROLLED_READINESS_REJECTION'});}};}}),{code:'SYSTEM_INSTALL_READINESS_FAILED'});
  assert.equal(probes,3);assert.deepEqual(identity(),state.initialIdentity);await provision(options);assert.deepEqual(identity(),state.initialIdentity);state.partialFailureRecovery={controlledPostProbeRejection:true,realAuthenticatedProbes:probes,disabledPreserved:true,sameIdentity:true};
  // Select only the newly created authority file by its canonical writer name.
  const authorityPath=fs.readdirSync(directory).find(n=>n!==managed.FILE&&n.endsWith('.json'));
  assert.ok(authorityPath);const file=path.join(directory,authorityPath),original=fs.readFileSync(file);
  const bad={...JSON.parse(original),daemonId:'deliberately-wrong-disposable-daemon-id'};
  fs.writeFileSync(file,JSON.stringify(bad)+'\n',{mode:0o600});
  const mutationCount=JSON.stringify(['build','create','start'].map(k=>state.commands[k]));
  try{await assert.rejects(provision(options));}finally{fs.writeFileSync(file,original,{mode:0o600});}
  assert.equal(JSON.stringify(['build','create','start'].map(k=>state.commands[k])),mutationCount);state.wrongAuthorityDenied=true;
  await provision(options);assert.deepEqual(identity(),state.initialIdentity);state.finalIdentity=identity();
  state.actualContainers=[];for(const name of state.containers){const c=await inspect('container',name);state.actualContainers.push({id:c.Id,name:c.Name,image:c.Image,mounts:c.Mounts.length,user:c.Config.User,readonly:c.HostConfig.ReadonlyRootfs,memory:c.HostConfig.Memory,nanoCpus:c.HostConfig.NanoCpus,pids:c.HostConfig.PidsLimit,tmpfs:c.HostConfig.Tmpfs,securityOpt:c.HostConfig.SecurityOpt,ports:c.NetworkSettings.Ports,environmentValidatedByProductionProvisioner:true});}
  if(process.env.SYSTEM_PROVISION_ACTIVATION==='1'){
   const activation=require('../../scripts/install/secureshop-owned-system-activate');
   const runtime=require('../../server/services/secureshopSystemManagedEnvironment');
   const qualified=require('../../server/services/secureshopQualifiedManagedConfiguration');
   const roots=qualified.expectedRoots(root,home);for(const value of Object.values(roots))fs.mkdirSync(value,{mode:0o700});
   const qualifiedValues={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',SS_PERSONA_INBOX_READY:'true',SS_MCP_TRUST_READY:'true',SS_CONTROLLED_SSRF_READY:'true',...roots};
   fs.writeFileSync(qualified.managedPath(root,home),Object.entries(qualifiedValues).map(([k,v])=>k+'='+v).join('\n')+'\n',{mode:0o600,flag:'wx'});
   const base={PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
   const applicationEnvironment={...base,...qualified.load({root,home})};
   const adapterOptions={enabled:true,root,homeDirectory:home,platform:'darwin',environment:process.env,applicationEnvironment,provision:o=>provision({...o,run})};
   const countsBefore={...state.commands};
   await assert.rejects(activation.setupOwnedSystem({...adapterOptions,architecture:'x64'}),{code:'SYSTEM_INSTALL_PLATFORM_UNQUALIFIED'});
   assert.deepEqual(state.commands,countsBefore);
   await activation.setupOwnedSystem(adapterOptions);
   const enabled=identity();assert.equal(enabled.enabled,true);assert.equal(enabled.configToken,state.initialIdentity.configToken);assert.equal(enabled.diagnosticToken,state.initialIdentity.diagnosticToken);assert.equal(enabled.restartToken,state.initialIdentity.restartToken);assert.equal(enabled.image,state.initialIdentity.image);
   const effective={...base,...runtime.loadWithQualified({root,home,environment:base})};
   assert.equal(effective.SS_ENABLE,'true');assert.equal(effective.SS_BOUND_REVIEWS_ENABLED,'true');await runtime.assertReady({environment:effective});
   let dispatched=0;assert.throws(()=>{runtime.loadWithQualified({root,home,environment:{...base,SS_BOUND_SYSTEM_CONFIG_ENABLED:'false'}});dispatched++;},{code:'SYSTEM_ACTIVATION_ENV_CONFLICT'});assert.equal(dispatched,0);
   const forged={...activation.capture(path.join(directory,managed.FILE)),sha256:'0'.repeat(64)};
   assert.throws(()=>activation.activate({filePath:path.join(directory,managed.FILE),expected:forged}),{code:'SYSTEM_ACTIVATION_CONFLICT'});
   await activation.setupOwnedSystem(adapterOptions);assert.deepEqual(identity(),enabled);
   for(const v of ['build','create','start'])assert.equal(state.commands[v],countsBefore[v]);
   for(const name of state.containers)assert.equal((await inspect('container',name)).Id,state.containerIds[name]);
   state.activationAdapter={enabledRecordPublished:true,sameCredentialAndContainerIdentity:true,exactRepeatNoBuildCreateStart:true,qualifiedOnlyPrerequisites:true,actualParentReadinessPassed:true,conflictPreDispatchConditional:true,unsupportedArchitectureDenied:true,staleCaptureDenied:true,fullSetupCli:false,fullIndex:false};
  }
  state.status='passed';persist();
 }catch(error){
  state.status='failed';state.errorCode=error.code||error.name;state.failureContainers=[];
  for(const name of state.containers){try{const c=await inspect('container',name),hc=c.HostConfig||{},cfg=c.Config||{};state.failureContainers.push({name,id:c.Id,image:c.Image,state:c.State?.Status,mounts:(c.Mounts||[]).map(m=>({type:m.Type,name:m.Name,destination:m.Destination,rw:m.RW})),user:cfg.User,entrypoint:cfg.Entrypoint,cmd:cfg.Cmd,environmentKeys:(cfg.Env||[]).map(v=>String(v).split('=',1)[0]).sort(),labels:cfg.Labels,tmpfs:hc.Tmpfs,readonly:hc.ReadonlyRootfs,memory:hc.Memory,nanoCpus:hc.NanoCpus,pids:hc.PidsLimit,securityOpt:hc.SecurityOpt,networkMode:hc.NetworkMode,networks:Object.keys(c.NetworkSettings?.Networks||{}),portBindings:hc.PortBindings,publishedPorts:c.NetworkSettings?.Ports});}catch{}}
  persist();process.exitCode=1;
 }
 finally{
  // Parent also verifies exact ownership and cleans after interruption.
  state.fixtureTerminal=true;persist();
 }
})().catch(error=>{state.status='failed';state.errorCode=error.code||error.name;persist();process.exitCode=1;});
