'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), path = require('node:path'), crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const vm = require('node:vm');
const adapter = require('./postgres/ownedMcpOriginalBuildAdapter');
const closure = require('./postgres/ownedMcpDependencyClosure');
const bounded = require('./postgres/ownedMcpBoundedBuild');
const replay = require('./postgres/ownedMcpArtifactReplay');
const root = path.resolve(__dirname, '..'), runId = 'd'.repeat(32);
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const metadataPath = path.join(root, 'tasks/qualification/metadata-85b02bf25ca24ad490ae96b973ff16ad/validated-envelope.json');
test('Q05 private pair is distinct and rejects changed plans and forced-closed entry before effects',async()=>{
 const plan=await adapter.originalBuildPlan(root,runId,{consumerMode:'q05-registered-pair'});
 assert.equal(plan.consumerMode,'q05-registered-pair');
 assert.equal(plan.kind,'original-registry-build-q05-registered-pair');
 assert.equal(plan.consumerBinding.profile,'q05-registered-pair');
 assert.equal(plan.consumerBinding.leaseTarget,'q05-registered-pair-total-lease-v1');
 assert.equal(plan.consumerBinding.fixtureMs,480000);
 assert.equal(plan.consumerBinding.modelCalls,12);
 assert.equal(plan.consumerBinding.liveEnabled,true);
 assert.equal(plan.limits.disk,6*1024**3);
 assert.equal(plan.sharedImageLoadAllowed,undefined);
 assert.match(plan.commands.build,/unix:\/\/\$root\/fs\/docker.sock/);
 assert.doesNotMatch(plan.commands.build,/--load|image load|builder prune/);
 const reviewed=adapter.planDigest(plan);
 await assert.rejects(adapter.withPrivateBuiltImage({root,runId,consumerMode:'q05-registered-pair',
  expectedPlanSha256:'0'.repeat(64),workDeadline:performance.now()+600000,
  consumer:()=>{throw Error('must not dispatch');},runner:()=>{throw Error('must not allocate');}}),
  {code:'ORIGINAL_BUILD_PLAN_CHANGED'});
 const old=await adapter.originalBuildPlan(root,runId,{consumerMode:'v39-atomic-pair'});
 assert.equal(old.consumerBinding.profile,'v39-atomic-pair');
 assert.equal(old.consumerBinding.modelCalls,28);
 assert.notEqual(adapter.planDigest(old),reviewed);
 const file=path.join(root,'tests/postgres/ownedMcpOriginalBuildAdapter.js');
 const text=await fs.readFile(file,'utf8'),localRequire=require('node:module').createRequire(file),closed={exports:{}};
 assert.equal(text.split('const Q05_PRIVATE_ENABLED = true;').length,2);
 new Function('require','module','exports','__dirname',text.replace('const Q05_PRIVATE_ENABLED = true;','const Q05_PRIVATE_ENABLED = false;'))(
  id=>{assert.notEqual(id,'node:net');return localRequire(id);},closed,closed.exports,path.dirname(file));
 await assert.rejects(closed.exports._internals.pairEntry(['--q05-pair-run',runId,reviewed,'3']),
  {code:'Q05_PRIVATE_CONSUMER_NOT_ADMITTED'});
 await assert.rejects(adapter._internals.pairEntry(['--q05-pair-run',runId,adapter.planDigest(old),'3','extra']),
  {code:'Q05_PRIVATE_ENTRY_ARGUMENTS'});
});
test('Listings build selects original context and same-lock replay without registry consumer authority',async()=>{
 const plan=await adapter.originalBuildPlan(root,runId,{target:'listings-package'});
 const source=require('../scripts/install/secureshop-owned-listings').sourceManifest(root);
 assert.equal(plan.target,'listings-package');assert.equal(plan.binding.target,'listings-package');
 assert.equal(plan.packageDigest,source.sha256);assert.equal(plan.limits.disk,6*1024**3);
 assert.equal(plan.consumerIntegrationComplete,false);assert.equal(plan.sharedImageLoadAllowed,false);
 assert.equal(plan.buildApproved,false);assert.equal(plan.registryConsumer,undefined);
 assert.deepEqual(plan.imageContract,{entrypoint:['node','sidecars/sandbox-runner/owned-listings/manager-entry.js'],user:'10001:10001',label:'owasp-ai-goat.listings.source',runtimeDigest:require('../scripts/install/secureshop-owned-listings-qualified-candidate').qualifiedPackage({root,architecture:'arm64'}).runtimeDigest});
 assert.match(plan.commands.build,/-f 'sidecars\/sandbox-runner\/owned-listings\/Dockerfile\.candidate'/);
 assert.match(plan.commands.build,/unix:\/\/\$root\/fs\/docker.sock/);
 assert.match(plan.commands.build,/--secret "id=npm_ca/);
 assert.doesNotMatch(plan.commands.build,/--load|image load|builder prune/);
 assert.match(plan.commands.handoff,/target='original-listings-package'/);
 assert.equal(Object.keys(plan.commands).some(n=>n.startsWith('registry')),false);
 for(const name of ['listingsProfileInstall','listingsCreate','listingsFresh','listingsRestart','listingsRetire','listingsProfileRetire']){
   assert.equal(spawnSync('/bin/sh',['-n'],{input:plan.commands[name]}).status,0,name);
 }
 assert.match(plan.commands.listingsCreate,/--network none/);
 assert.match(plan.commands.listingsCreate,/--log-opt max-size=1m --log-opt max-file=1/);
 const creation=plan.commands.listingsCreate.split('\n').find(line=>line.startsWith('docker --host')&&line.includes(' create --cidfile'));
 assert.ok(creation);assert.doesNotMatch(creation,/--publish|\/run\/docker.sock/);
 await adapter._internals.verifyPlanSources(plan);
 for(const [name,hash] of Object.entries(source.files))assert.equal(plan.buildSources[name],hash);
 for(const listingsMode of [undefined,'package','foreign'])await assert.rejects(adapter.withPrivateBuiltImage({root,runId,target:'listings-package',listingsMode,expectedPlanSha256:adapter.planDigest(plan),consumer:()=>{throw Error('must not dispatch');},runner:()=>{throw Error('must not allocate');}}),{code:'LISTINGS_PRIVATE_CONSUMER_NOT_ADMITTED'});
 assert.match(await fs.readFile(path.join(root,'tests/postgres/listings_package_goat_current.py'),'utf8'),/^LIVE_ENABLED = False\b/m);
 for(const options of [{target:'unknown'},{target:'listings-package',consumerMode:'original-service'}])await assert.rejects(adapter.originalBuildPlan(root,runId,options),{code:'ORIGINAL_BUILD_TARGET'});
});
test('actual enabled Listings CLI plans source-only and requires valid plan and inherited authority',async()=>{
 const file=path.join(root,'tests/postgres/ownedMcpOriginalBuildAdapter.js');
 const result=spawnSync(process.execPath,[file,'--listings-manager-plan',runId],
   {cwd:root,encoding:'utf8',timeout:30000,maxBuffer:8*1024**2});
 assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');
 const packet=JSON.parse(result.stdout);
 assert.equal(packet.runId,runId);assert.equal(packet.planSha256,adapter.planDigest(packet.plan));
 assert.equal(packet.plan.listingsConsumer.mode,'manager');assert.equal(packet.plan.listingsLease.browserMs,540000);
 for(const argv of [['--listings-manager-run',runId,packet.planSha256,'999'],
   ['--listings-manager-run',runId,packet.planSha256,'2'],['--listings-manager-plan',runId,'extra']]){
   const denied=spawnSync(process.execPath,[file,...argv],{cwd:root,encoding:'utf8',timeout:5000,maxBuffer:8192});
   assert.equal(denied.status,1);assert.equal(denied.stdout,'');
 }
 const text=await fs.readFile(file,'utf8'),localRequire=require('node:module').createRequire(file),controlled={exports:{}};
 assert.equal(text.split('const LISTINGS_PRIVATE_ENABLED = true;').length,2);
 let authorityRequests=0;
 new Function('require','module','exports','__dirname',text)(id=>id==='node:net'?{Socket:class{
   constructor(options){authorityRequests++;assert.equal(options.fd,999);throw Error('controlled inherited authority required');}
 }}:localRequire(id),controlled,controlled.exports,path.dirname(file));
 await assert.rejects(controlled.exports._internals.listingsEntry(['--listings-manager-run',runId,'0'.repeat(64),'999']),
   {code:'ORIGINAL_BUILD_PLAN_CHANGED'});
 assert.equal(authorityRequests,0);
 await assert.rejects(controlled.exports._internals.listingsEntry(['--listings-manager-run',runId,packet.planSha256,'999']),
   /controlled inherited authority required/);
 assert.equal(authorityRequests,1);
 await assert.rejects(adapter._internals.listingsEntry(['--listings-manager-run',runId,packet.planSha256,'2']),
   {code:'LISTINGS_PRIVATE_ENTRY_ARGUMENTS'});
});
test('V03 Listings source plan uses absolute mapped phases while old live owner stays closed',async()=>{
 const plan=await adapter.originalBuildPlan(root,runId,{target:'listings-package',listingsMode:'v03-manager'});
 assert.equal(plan.consumerMode,'v03-manager');
 assert.equal(plan.consumerIntegrationComplete,false);
 assert.equal(plan.listingsLease.executionApproved,false);
 assert.equal(plan.listingsLease.cohortMs,1200000);
 assert.equal(plan.listingsLease.infrastructureMs,1210000);
 assert.equal(plan.limits.serviceLeaseMs,11096000);
 assert.match(plan.commands.prepare,/guestBootId/);
 assert.match(plan.commands.prepare,/v03-combined-lease\.json/);
 assert.doesNotMatch(plan.commands.prepare,/original-service-phase|claim-build/);
 for(const name of ['namespace','build','handoff','listingsManagerStart','listingsManagerRetire','cleanup']){
  assert.match(plan.commands[name],/v03-listings-phase-/);
  assert.match(plan.commands[name],/\/usr\/bin\/timeout --signal=TERM --kill-after=10/);
 }
 assert.match(plan.commands.serviceLeasecohort,/cohortClaim/);
 for(const name of ['ownedV03ListingsLease.js','ownedV03GuestClock.js','ownedV03PrivateExecutors.js'])
  assert.equal(plan.helperHashes['tests/postgres/'+name],digest(await fs.readFile(path.join(root,'tests/postgres',name))));
 await assert.rejects(adapter.withPrivateBuiltImage({root,runId,target:'listings-package',listingsMode:'v03-manager',
  expectedPlanSha256:adapter.planDigest(plan),consumer:()=>{throw Error('must not run');}}),
  {code:'LISTINGS_PRIVATE_CONSUMER_NOT_ADMITTED'});
});
test('Listings manager phases bind private source, stdin authority and remote retirement before stop',async()=>{
 const plan=await adapter.originalBuildPlan(root,runId,{target:'listings-package',listingsMode:'manager'});
 assert.equal(plan.listingsConsumer.mode,'manager');assert.equal(plan.consumerIntegrationComplete,false);
 assert.deepEqual(plan.listingsLease,{profile:'listings-manager-browser',target:'original-listings-manager-total-lease-v1',totalMs:6680000,startupMs:60000,browserMs:540000,retirementMs:1080000,cleanupMs:2520000});
 assert.equal(plan.limits.consumerWorkMs,600000);
 assert.match(plan.commands.prepare,/original-listings-manager-total-lease-v1/);
 assert.match(plan.commands.listingsManagerStart,/check-startup/);
 assert.match(plan.commands.listingsManagerRetire,/check-retirement/);
 assert.equal(plan.listingsConsumer.name,'owasp-ai-goat-owned-listings-'+require('../scripts/application-data-root').workspaceId(root));
 const resource=await fs.readFile(path.join(root,'tests/postgres/listings_native_resources.py'),'utf8');
 assert.equal(plan.helperHashes['tests/postgres/listings_native_resources.py'],digest(resource));
 const capture=await adapter._internals.captureListings(root);
 capture.workspaceId=require('../scripts/application-data-root').workspaceId(root);
 capture.profileSha256=digest((await fs.readFile(path.join(root,'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'),'utf8')).replaceAll('@@SUPERVISOR_PROFILE@@',plan.listingsConsumer.name));
 for(const operation of ['create','start','channels']){
   const program=adapter._internals.listingsManagerProgram(plan.spec,plan.listingsConsumer.name,'owasp-ai-goat-listings-journal-'+runId,capture,resource,operation);
   const result=spawnSync('/opt/homebrew/bin/python3',['-B','-c','import sys;compile(sys.stdin.read(),"<actual-manager>","exec")'],{input:program,encoding:'utf8'});
   assert.equal(result.status,0,result.stderr);
   if(operation==='create'){
     const invalid=spawnSync('/opt/homebrew/bin/python3',['-B','-c',program],{input:JSON.stringify({origin:'http://127.0.0.1:99999',token:'x'.repeat(48)}),encoding:'utf8'});
     assert.notEqual(invalid.status,0);assert.match(invalid.stderr,/AssertionError/);
   }
 }
 const base={assertOpen(){},assertActive(){},assertRetirementAdmission(){},joinPhase:fn=>fn(),confirmRetired(){},signal:new AbortController().signal,retirementSignal:new AbortController().signal};
 const calls=[];const owner=adapter._internals.listingsLifetime(base,plan,async(name,options)=>{
   let raw='';if(options.input)for await(const chunk of options.input)raw+=chunk;
   calls.push({name,raw});return name==='listingsManagerChannels'?JSON.stringify({version:1,runId,remoteChannelsAbsent:true,channels:[]}):name.includes('Retire')?'absent\n':'controlled';
 });
 await owner.runListingsPhase('listingsProfileInstall');
 assert.throws(()=>owner.runListingsPhase('listingsManagerCreate',{origin:'http://foreign:1234',token:'x'.repeat(48)}),{code:'LISTINGS_MANAGER_INPUT'});
 await owner.runListingsPhase('listingsManagerCreate',{origin:'http://127.0.0.1:1234',token:'x'.repeat(48)});
 await owner.runListingsPhase('listingsManagerStart');
 assert.throws(()=>owner.runListingsPhase('listingsManagerRetire'),{code:'LISTINGS_PHASE_ORDER'});
 assert.throws(()=>owner.runListingsPhase('listingsManagerChannels',{channelIds:[],listenerClosed:false,localChannelsRetired:true}),{code:'LISTINGS_MANAGER_INPUT'});
 await owner.runListingsPhase('listingsManagerChannels',{channelIds:[],listenerClosed:true,localChannelsRetired:true});
 await owner.runListingsPhase('listingsManagerRetire');await owner.runListingsPhase('listingsProfileRetire');owner.confirmRetired();
 assert.deepEqual(calls.map(c=>c.name),['serviceLeasestartup','listingsProfileInstall','listingsManagerCreate','listingsManagerStart','serviceLeasecohort','serviceLeaseretirement','listingsManagerChannels','listingsManagerRetire','listingsProfileRetire']);
 assert.equal(JSON.parse(calls.find(c=>c.name==='listingsManagerCreate').raw).token,'x'.repeat(48));
 assert.doesNotMatch(plan.commands.listingsManagerCreate,/x{48}/);
 const failed=adapter._internals.listingsLifetime(base,plan,async name=>{
   if(name==='listingsManagerStart')throw Error('controlled start failure after create');return 'created';
 });
 await failed.runListingsPhase('listingsProfileInstall');
 await failed.runListingsPhase('listingsManagerCreate',{origin:'http://127.0.0.1:1234',token:'x'.repeat(48)});
 await assert.rejects(failed.runListingsPhase('listingsManagerStart'),/start failure/);
 assert.throws(()=>failed.confirmRetired(),{code:'LISTINGS_RETIREMENT_UNPROVEN'});
 assert.throws(()=>failed.runListingsPhase('listingsManagerRetire'),{code:'LISTINGS_PHASE_ORDER'});
 const debt=adapter._internals.listingsLifetime(base,plan,async name=>name==='listingsManagerChannels'?'{}':'created');
 await debt.runListingsPhase('listingsProfileInstall');await debt.runListingsPhase('listingsManagerCreate',{origin:'http://127.0.0.1:1234',token:'x'.repeat(48)});
 await debt.runListingsPhase('listingsManagerStart');
 await assert.rejects(debt.runListingsPhase('listingsManagerChannels',{channelIds:[],listenerClosed:true,localChannelsRetired:true}),{code:'LISTINGS_RETIREMENT_UNPROVEN'});
 assert.throws(()=>debt.runListingsPhase('listingsManagerRetire'),{code:'LISTINGS_PHASE_ORDER'});
 let hostRequests=0;
 await assert.rejects(adapter.withPrivateBuiltImage({root,runId,target:'listings-package',listingsMode:'manager',expectedPlanSha256:adapter.planDigest(plan),
  consumer:()=>{throw Error('must not dispatch');},runner:()=>{throw Error('must not allocate');},
  verifyHost:async()=>{hostRequests++;throw Error('controlled private host authority required');}}),/controlled private host authority required/);
 assert.equal(hostRequests,1);
});
test('Listings phases join retirement and reject ordering, retry, unjoined work and false absence',async()=>{
 const plan={listingsConsumer:{name:'controlled'}};
 const calls=[],base={assertOpen(){},assertActive(){},assertRetirementAdmission(){},
   joinPhase:fn=>fn(),confirmRetired(){calls.push('confirmed');},signal:new AbortController().signal,retirementSignal:new AbortController().signal};
 const owner=adapter._internals.listingsLifetime(base,plan,async name=>{calls.push(name);return name.includes('Retire')?'absent\n':'controlled';});
 assert.throws(()=>owner.runListingsPhase('listingsCreate'),{code:'LISTINGS_PHASE_ORDER'});
 for(const name of ['listingsProfileInstall','listingsCreate','listingsFresh','listingsRestart'])await owner.runListingsPhase(name);
 assert.throws(()=>owner.confirmRetired(),{code:'LISTINGS_RETIREMENT_UNPROVEN'});
 assert.throws(()=>owner.runListingsPhase('listingsProfileRetire'),{code:'LISTINGS_PHASE_ORDER'});
 await owner.runListingsPhase('listingsRetire');await owner.runListingsPhase('listingsProfileRetire');owner.confirmRetired();
 assert.equal(calls.at(-1),'confirmed');assert.throws(()=>owner.runListingsPhase('listingsRetire'),{code:'LISTINGS_PHASE_ORDER'});
 let release;const pending=adapter._internals.listingsLifetime(base,plan,()=>new Promise(r=>{release=r;}));
 const work=pending.runListingsPhase('listingsProfileInstall');assert.throws(()=>pending.confirmRetired(),{code:'LISTINGS_RETIREMENT_UNPROVEN'});
 assert.throws(()=>pending.runListingsPhase('listingsProfileRetire'),{code:'LISTINGS_PHASE_ORDER'});release('ok');await work;
 const bad=adapter._internals.listingsLifetime(base,plan,async()=> 'not absent');
 await bad.runListingsPhase('listingsProfileInstall');await assert.rejects(bad.runListingsPhase('listingsProfileRetire'),{code:'LISTINGS_RETIREMENT_UNPROVEN'});
 assert.throws(()=>bad.confirmRetired(),{code:'LISTINGS_RETIREMENT_UNPROVEN'});
});
test('actual emitted Listings identity rejects missing CID, wrong owner and wrong image before effects',async()=>{
 const plan=await adapter.originalBuildPlan(root,runId,{target:'listings-package'});
 const command=plan.commands.listingsCreate,start=command.indexOf('\nlistings_identity() {'),end=command.indexOf('\n}\n',start)+3;
 assert.ok(start>0&&end>start);const identity=command.slice(start,end);
 const directory=await fs.mkdtemp(path.join(process.env.TMPDIR,'listings-identity-'));
 try{
   await fs.mkdir(path.join(directory,'fs'));const cid='a'.repeat(64);
   const fake=`docker() { case "$*" in *"index .Config.Labels"*) printf '%s' "$OWNER";; *"{{.Image}}"*) printf '%s' "$IMAGE";; *"image inspect"*) printf '%s' 'sha256:expected';; *) printf '%s' "$CID";; esac; }`;
   const script='set -eu\n'+fake+identity+'\nlistings_identity\nprintf verified';
   const env={PATH:'/usr/bin:/bin',root:directory,nonce:runId,CID:cid,OWNER:runId,IMAGE:'sha256:expected'};
   assert.notEqual(spawnSync('/bin/sh',['-c',script],{env}).status,0);
   await fs.writeFile(path.join(directory,'fs/listings.cid'),cid,{flag:'wx',mode:0o600});
   const ok=spawnSync('/bin/sh',['-c',script],{env,encoding:'utf8'});assert.equal(ok.status,0,ok.stderr);assert.equal(ok.stdout,'verified');
   for(const change of [{OWNER:'foreign'},{CID:'b'.repeat(64)},{IMAGE:'sha256:foreign'}])assert.notEqual(spawnSync('/bin/sh',['-c',script],{env:{...env,...change}}).status,0);
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
test('fixed pair IPC binds one canonical frame and carries no command authority',async()=>{
 const producer=require('./postgres/ownedMcpOriginalServiceProducer');
 const binding={runId,planSha256:'f'.repeat(64)};
 class Socket extends EventEmitter{write(bytes,cb){this.writes??=[];this.writes.push(Buffer.from(bytes));cb();}destroy(){this.emit('close');}}
 const frame=(op,fields={})=>Buffer.from(JSON.stringify({version:1,op,...binding,...fields})+'\n');
 for(const scenario of ['valid','duplicate-key','two','wrong-run','extra','eof','oversize','expired']){
  const socket=new Socket(),channel=producer.pairChannel(socket,binding);
  const reading=channel.read('admit',['remainingMs'],performance.now()+(scenario==='expired'?5:1000));
  if(scenario==='valid')socket.emit('data',frame('admit',{remainingMs:100}));
  if(scenario==='duplicate-key')socket.emit('data',Buffer.from(frame('admit',{remainingMs:100}).toString().replace('"version":1','"version":1,"version":1')));
  if(scenario==='two')socket.emit('data',Buffer.concat([frame('admit',{remainingMs:100}),frame('admit',{remainingMs:100})]));
  if(scenario==='wrong-run')socket.emit('data',frame('admit',{runId:'0'.repeat(32),remainingMs:100}));
  if(scenario==='extra')socket.emit('data',frame('admit',{remainingMs:100,command:'forbidden'}));
  if(scenario==='eof')socket.emit('end');
  if(scenario==='oversize')socket.emit('data',Buffer.alloc(16385,32));
  if(scenario==='valid')assert.equal((await reading).remainingMs,100);else await assert.rejects(reading,/V39_IPC/);
  channel.close();
 }
});
test('pair callback releases only after actual assembly retirement; ordinary failure is not debt',async()=>{
 const producer=require('./postgres/ownedMcpOriginalServiceProducer');
 for(const scenario of ['pass','failed','browser-debt','pg-debt','child-debt','eof']){
  const calls=[],channel={send:async(op,value)=>{calls.push(op);if(op==='window')assert.ok(value.remainingMs<=1000);},
   read:async(op)=>{calls.push(op);if(op==='window')return {};
    if(scenario==='eof')throw Object.assign(Error('EOF'),{code:'V39_IPC_EOF'});
    return {passed:scenario!=='failed',childAbsent:scenario!=='child-debt',browserAbsent:scenario!=='browser-debt',postgresAbsent:scenario!=='pg-debt'};}};
  const operation=producer.pairCohort(channel,{configuration:{controlled:true},deadline:performance.now()+1000});
  if(scenario==='pass')assert.equal((await operation).assemblyRetired,true);
  else await assert.rejects(operation,error=>scenario==='failed'?error.code==='V39_ASSEMBLY_FAILED'&&!error.retirementUnproven:error.retirementUnproven===true);
  assert.deepEqual(calls,['endpoint','window','window','retired']);
 }
});
test('pair CLI validates exact arguments before FD access and forced-closed entry denies all effects',async()=>{
 const file=path.join(root,'tests/postgres/ownedMcpOriginalBuildAdapter.js');
 const text=await fs.readFile(file,'utf8'),localRequire=require('node:module').createRequire(file),closed={exports:{}};
 assert.equal(text.split('const V39_PRIVATE_ENABLED = true;').length,2);
 new Function('require','module','exports','__dirname',text.replace('const V39_PRIVATE_ENABLED = true;','const V39_PRIVATE_ENABLED = false;'))(
  id=>{assert.notEqual(id,'node:net');return localRequire(id);},closed,closed.exports,path.dirname(file));
 await assert.rejects(closed.exports._internals.pairEntry(['--v39-pair-run',runId,'a'.repeat(64),'3']),{code:'V39_PRIVATE_CONSUMER_NOT_ADMITTED'});
 for(const argv of [['--v39-pair-run',runId,'a'.repeat(64),'3','extra'],['--exec','arbitrary'],
  ['--v39-pair-run',runId,'bad','3'],['--v39-pair-run',runId,'a'.repeat(64),'2'],
  ['--v39-pair-run','bad','a'.repeat(64),'3']]){
  await assert.rejects(adapter._internals.pairEntry(argv),/V39_PRIVATE_ENTRY_ARGUMENTS/);
 }
 const actual=spawnSync(process.execPath,[path.join(root,'tests/postgres/ownedMcpOriginalBuildAdapter.js'),
  '--v39-pair-run',runId,'bad','3'],{encoding:'utf8',timeout:5000});
 assert.equal(actual.status,1);assert.equal(actual.stdout,'');assert.equal(actual.stderr,'');
});
test('original service plan is distinct, source-pinned, fixed proxy and admitted only by exact plan and host',async()=>{
 const fixture=await adapter.originalBuildPlan(root,runId);
 const service=await adapter.originalBuildPlan(root,runId,{consumerMode:'original-service'});
 assert.equal(fixture.consumerMode,undefined);assert.equal(fixture.limits.consumerWorkMs,120000);
 assert.equal(service.consumerMode,'original-service');assert.equal(service.limits.consumerWorkMs,1320000);
 assert.equal(service.limits.serviceLeaseMs,7400000);assert.deepEqual(service.buildSources,fixture.buildSources);
 assert.equal(service.guestSource,fixture.guestSource);
 assert.match(service.commands.prepare,/original-service-lease.json/);
 assert.match(service.commands.namespace,/original-service-holder.seconds/);
 assert.match(service.commands.serviceCreate,/--network none/);
 assert.match(service.commands.serviceCreate,/--env-file "\$root\/fs\/service.env"/);
 assert.match(service.commands.serviceCreate,/http-listener.js/);
 assert.doesNotMatch(service.commands.serviceStart,/attach --sig-proxy/);
 assert.match(service.commands.serviceExec,/exec -i "\$registry_cid" node -e/);
 assert.match(service.commands.serviceExec,/check-cohort/);
 assert.match(service.commands.serviceDrain,/check-retirement/);
 assert.match(service.commands.serviceCohortClaim,/check-startup/);
 assert.deepEqual(service.scriptTransport,adapter._internals.PHASE_TRANSPORT);
 for(const [name,script] of Object.entries(service.commands)){
  const transport=adapter._internals.phaseTransport(script);
  assert.ok(transport.decodedBytes<128*1024,name+' exceeds decoded Linux single argument bound');
  assert.ok(transport.commandEnvelopeBytes<64*1024,name+' exceeds escaped transport bound');
  const r=spawnSync('/bin/dash',['-n'],{input:script,encoding:'utf8',timeout:5000,maxBuffer:8192});
  assert.equal(r.status,0,name+':'+r.stderr);
 }
 let effects=0;
 await assert.rejects(adapter.withOriginalRegistryService({root,runId,expectedPlanSha256:adapter.planDigest(fixture),
  consumer(){effects++;},runner(){effects++;},verifyHost(){effects++;}}),{code:'ORIGINAL_BUILD_PLAN_CHANGED'});
 assert.equal(effects,0);
 const denied=Object.assign(Error('controlled host admission denied'),{code:'CONTROLLED_HOST_DENIED'});let hostChecks=0;
 await assert.rejects(adapter.withOriginalRegistryService({root,runId,expectedPlanSha256:adapter.planDigest(service),
  consumer(){effects++;},runner(){effects++;},verifyHost(){hostChecks++;throw denied;}}),error=>error===denied);
 assert.equal(hostChecks,1);assert.equal(effects,0);
 await assert.rejects(adapter.originalBuildPlan(root,runId,{consumerMode:'caller-script'}),/CONSUMER_MODE/);
});
function serviceContainer(plan,handoff,token,running=false){
 const name=plan.registryConsumer.name;
 return {Id:'a'.repeat(64),Image:handoff.imageId,Name:'/'+name,State:{Running:running},
  Config:{Labels:{'owasp-ai-goat.original.registry':handoff.runId},User:'10001:10001',Entrypoint:['node'],Cmd:['sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'],
   Env:['SECURESHOP_MCP_REGISTRY_ENABLED=true','SECURESHOP_MCP_REGISTRY_TOKEN='+token,'SECURESHOP_MCP_REGISTRY_PROFILE='+name,'SECURESHOP_MCP_REGISTRY_HOST=127.0.0.1','SECURESHOP_MCP_REGISTRY_PORT=8094']},
  HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,Privileged:false,CapDrop:['ALL'],Memory:536870912,NanoCpus:1000000000,PidsLimit:128,
   LogConfig:{Type:'none'},RestartPolicy:{Name:'no'},SecurityOpt:['apparmor='+name,'seccomp=unconfined'],Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,size=16m'}},Mounts:[]};
}
test('producer validates actual container shape and rejects changed identity or isolation',()=>{
 const producer=require('./postgres/ownedMcpOriginalServiceProducer');
 const plan={registryConsumer:{name:'owasp-ai-goat-owned-mcp-registry-'+runId.slice(0,12)}};
 const handoff={imageId:'sha256:'+'e'.repeat(64),runId};const token='x'.repeat(43);
 const original=serviceContainer(plan,handoff,token,true),binding={imageId:handoff.imageId,runId,name:plan.registryConsumer.name,token,running:true};
 assert.equal(producer.validateContainer([original],binding),original.Id);
 for(const change of [r=>r.Image='sha256:'+'f'.repeat(64),r=>r.State.Running=false,r=>r.HostConfig.NetworkMode='host',
  r=>r.HostConfig.PortBindings={8094:[{HostPort:'8094'}]},r=>r.Config.Env.push('SECURESHOP_MCP_REGISTRY_OTHER=1'),
  r=>r.Config.Cmd=['caller.js'],r=>r.Config.User='0:0',r=>r.HostConfig.RestartPolicy.Name='always']){
  const changed=structuredClone(original);change(changed);assert.throws(()=>producer.validateContainer([changed],binding));
 }
});
test('controlled actual producer pipeline joins fixed service health, cohort and retirement',async()=>{
 const producer=require('./postgres/ownedMcpOriginalServiceProducer');
 for(const scenario of ['success','bad-inspect','cohort-failure','retirement-failure']){
  const plan={consumerMode:'original-service',spec:{root},registryConsumer:{name:'owasp-ai-goat-owned-mcp-registry-'+runId.slice(0,12)}};
  const handoff={controlled:true,runId,imageId:'sha256:'+'e'.repeat(64)};
  const calls=[],records=[];let token,confirmed=false,retirementEnd,cohortCalls=0;
  const lifetime={signal:new AbortController().signal,retirementSignal:new AbortController().signal,
   assertActive(){},assertOpen(){},assertRetirementAdmission(){},expireWork(){throw Error('unexpected expiry');},beginRetirement(){retirementEnd??=performance.now()+1080000;},
   retirementDeadline(){return retirementEnd;},joinPhase:async fn=>fn(),confirmRetired(){confirmed=true;}};
  const step=async(name,options={})=>{
   calls.push(name);let input='';if(options.input)for await(const part of options.input)input+=part;
   if(name==='serviceCreate'){token=JSON.parse(input).token;return JSON.stringify([serviceContainer(plan,handoff,token)]);}
   if(['serviceStart','serviceInspect'].includes(name)){
    const row=serviceContainer(plan,handoff,token,true);if(scenario==='bad-inspect'&&name==='serviceInspect')row.Image='wrong';return JSON.stringify([row]);
   }
   if(name==='serviceReadiness')return JSON.stringify({ready:true,runtimeDigest:'c'.repeat(64)});
   if(name==='serviceHealth'){
    const q=JSON.parse(input);assert.equal(q.token,token);assert.equal(q.path,'/registration/health');
    return JSON.stringify({status:200,body:{version:1,instanceId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',runtimeDigest:'c'.repeat(64),registrationCapability:'owned-mcp-registration-v1'}});
   }
   if(name==='serviceRetire'&&scenario==='retirement-failure')throw Object.assign(Error('retire failed'),{code:'RETIRE_FAILED'});
   return name.endsWith('Retire')?'absent':'{}';
  };
  const invoke=()=>producer.consume({handoff,lifetime,plan,step,record:r=>records.push(r),
   relayFactory:()=>({listen:async()=>({address:'127.0.0.1',port:23456}),close:async()=>calls.push('relay-close')}),
   cohort:async value=>{cohortCalls++;assert.equal(value.configuration.runtimeDigest,'c'.repeat(64));assert.equal(value.qualificationComplete,false);
    if(scenario==='cohort-failure')throw Object.assign(Error('original failure'),{code:'COHORT_FAILED'});return {originalCriteriaUnchanged:true};}});
  if(scenario==='success'){const result=await invoke();assert.equal(result.cleanupVerified,true);assert.equal(result.qualificationComplete,false);}
  else await assert.rejects(invoke(),e=>{
   assert.equal(producer.isRetiredFailure(e,handoff,plan),scenario==='cohort-failure');
   assert.equal(producer.isRetiredFailure(Object.assign(Error(e.message),e),handoff,plan),false);
   assert.equal(producer.isRetiredFailure(e,{...handoff},plan),false);
   assert.equal(producer.isRetiredFailure(e,handoff,{...plan}),false);
   return scenario!=='retirement-failure'||e.retirementUnproven===true;
  });
  assert.equal(cohortCalls,scenario==='bad-inspect'?0:1);
  assert.equal(confirmed,scenario!=='retirement-failure');
  assert.ok(calls.includes('serviceRetire'));
  if(scenario==='retirement-failure')assert.ok(!calls.includes('serviceProfileRetire'));
  if(scenario==='bad-inspect')assert.ok(!calls.includes('serviceHealth'));
 }
});
function producerControl({scenario='success',hold=()=>{},record=()=>{},inspectCohort=()=>{},mode='original-service',claimRemaining=480000}={}){
 const producer=require('./postgres/ownedMcpOriginalServiceProducer');
 const plan={consumerMode:mode,spec:{root},registryConsumer:{name:'owasp-ai-goat-owned-mcp-registry-'+runId.slice(0,12)}};
 const handoff={controlled:true,runId,imageId:'sha256:'+'e'.repeat(64)};
 const calls=[];let token,dispatch,healthCalls=0,registrations=0,cohortCalls=0;
 const identity={instanceId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',operationId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',requestSha256:'d'.repeat(64)};
 const reply=body=>JSON.stringify({status:200,body});
 const step=async(name,options={})=>{
  calls.push(name);let input='';if(options.input)for await(const part of options.input)input+=part;
  if(name===scenario)await hold();
  if(name==='serviceProfileInstall'&&scenario==='profile-failure')throw Error('profile failed');
  if(name==='serviceCreate'){
   if(scenario==='create-failure')throw Error('create uncertain');
   token=JSON.parse(input).token;return JSON.stringify([serviceContainer(plan,handoff,token)]);
  }
  if(['serviceStart','serviceInspect'].includes(name))return JSON.stringify([serviceContainer(plan,handoff,token,true)]);
  if(name==='serviceReadiness')return JSON.stringify({ready:true,runtimeDigest:'c'.repeat(64)});
  if(name==='serviceHealth'){
   healthCalls++;if(scenario==='health-retry'&&healthCalls===1)return JSON.stringify({status:503,body:{error:'not ready'}});
   if(scenario==='health-failure')return JSON.stringify({status:503,body:{error:'not ready'}});
   const q=JSON.parse(input);
   if(q.path==='/health')return reply({version:1,ready:true,isolation:'owned-mcp-registry-v1',registryCapability:'secureshop-owned-mcp-registry.v1',runtimeDigest:'c'.repeat(64)});
   if(q.path==='/invoke/health')return reply({version:1,instanceId:identity.instanceId,runtimeDigest:'c'.repeat(64)});
   return reply({version:1,instanceId:identity.instanceId,runtimeDigest:'c'.repeat(64),registrationCapability:'owned-mcp-registration-v1'});
  }
  if(name==='serviceCohortClaim'&&mode==='v39-atomic-pair')return JSON.stringify({version:1,target:'v39-atomic-pair-total-lease-v1',runId,phase:'cohort',startedAtMs:1000,deadlineMs:1000+claimRemaining});
  if(name==='serviceExec'){
   const packet=JSON.parse(input);assert.equal(packet.token,token);assert.equal(packet.path,'/registration');registrations++;
   if(scenario==='lost-ack')throw Object.assign(Error('reply lost'),{code:'REPLY_LOST'});
   return reply({version:1,...identity,state:'completed',drained:true});
  }
  if(name==='serviceDrain'){
   const packet=JSON.parse(input);assert.deepEqual(packet.body,identity);assert.equal(packet.path,'/registration/drain');
   return reply({version:1,...identity,state:'completed',drained:true});
  }
  if(name==='serviceRetire'&&scenario==='bad-retirement-proof')return 'unknown';
  return name.endsWith('Retire')?'absent':'{}';
 };
 const run=lifetime=>producer.consume({handoff,lifetime,plan,step,record,
  relayFactory:options=>{dispatch=options.dispatch;return{
   listen:async()=>{if(scenario==='listen-pending')await hold();return {address:'127.0.0.1',port:23456};},
   close:async()=>{calls.push('relay-close');if(scenario==='close-pending')await hold();}};},
  cohort:async value=>{
   inspectCohort(value);
   cohortCalls++;if(scenario==='cohort-pending')await hold();
   if(['registration','lost-ack'].includes(scenario))return dispatch('POST','/secureshop/mcp-registry/registration',identity);
   return {qualificationComplete:false};
  }});
 return {run,calls,handoff,counts:()=>({healthCalls,registrations,cohortCalls})};
}
test('producer preserves actual request identity and recovers lost ACK only with same-ID drain',async()=>{
 for(const scenario of ['registration','lost-ack','health-retry','health-failure','profile-failure','create-failure','bad-retirement-proof']){
  const control=producerControl({scenario});
  const outcome=await adapter._internals.boundedConsumer((_handoff,lifetime)=>control.run(lifetime),control.handoff,
   {milliseconds:2000,retirementMs:1000,phaseJoinMs:0,serviceMode:true});
  if(['registration','health-retry'].includes(scenario))assert.equal(outcome.error,undefined,scenario);
  else assert.ok(outcome.error,scenario);
  if(scenario==='registration'||scenario==='lost-ack')assert.equal(control.counts().registrations,1);
  if(scenario==='lost-ack'){
   assert.equal(outcome.error.code,'REPLY_LOST');assert.equal(outcome.retired,true);
   assert.equal(control.calls.filter(x=>x==='serviceDrain').length,1);
  }
  if(scenario==='health-retry')assert.equal(control.counts().healthCalls,2);
  if(scenario==='health-failure'){assert.equal(control.counts().healthCalls,5);assert.equal(control.counts().cohortCalls,0);}
  if(scenario==='profile-failure')assert.equal(control.calls.includes('serviceCreate'),false);
  if(scenario==='create-failure')assert.equal(control.calls.includes('serviceStart'),false);
  if(scenario==='bad-retirement-proof'){assert.equal(outcome.retired,false);assert.equal(control.calls.includes('serviceProfileRetire'),false);}
 }
});
test('delayed cohort claim consumes the immutable aggregate window, never renews after ACK',async()=>{
 const records=[];let observed;
 const control=producerControl({scenario:'serviceCohortClaim',hold:()=>new Promise(resolve=>setTimeout(resolve,80)),
  record:r=>records.push(r),inspectCohort:value=>{observed=value;}});
 const outcome=await adapter._internals.boundedConsumer((_handoff,lifetime)=>control.run(lifetime),control.handoff,
  {milliseconds:2000,retirementMs:1000,phaseJoinMs:0,serviceMode:true});
 assert.equal(outcome.error,undefined);
 const window=observed.cohortWindow,record=records.find(r=>r.stage==='cohort-window');
 assert.equal(window.deadlineMs-window.startedAtMs,1200000);
 assert.ok(window.callbackEnteredAtMs-window.startedAtMs>=70);
 assert.ok(window.remainingMs<=1199930&&window.remainingMs>0);
 assert.equal(window.remainingMs,window.deadlineMs-window.callbackEnteredAtMs);
 assert.equal(observed.deadline,record.deadlineMs);assert.equal(window.startedAtMs,record.startedAtMs);
 assert.equal(window.admissionIncluded,true);assert.equal(window.renewable,false);
 assert.equal(window.clock,'producer-performance-now-ms');assert.equal(record.clock,window.clock);
});
test('artifact retirement has actual immutable remaining-phase timeout and expiry cannot disable timeout',async()=>{
 const producer=require('./postgres/ownedMcpOriginalServiceProducer');
 const plan=await adapter.originalBuildPlan(root,runId,{consumerMode:'original-service'});
 assert.match(plan.commands.retireArtifacts,/remaining=/);
 assert.match(plan.commands.retireArtifacts,/\/usr\/bin\/timeout --signal=TERM --kill-after=10 "\$remaining"/);
 assert.match(plan.commands.retireArtifacts,/check-settlement/);assert.match(plan.commands.retireArtifacts,/check-cleanup/);
 assert.ok(plan.commands.retireArtifacts.startsWith(producer._internals.PHASE_HEADER));
 const quote=value=>"'"+value.replace(/'/g,"'\\''")+"'";
 assert.ok(plan.commands.retireArtifacts.includes('/bin/sh -c '+quote(producer._internals.PHASE_HEADER).slice(0,-1)));
 const program=producer._internals.REMAINING_PROGRAM;
 const execute=(now,deadline)=>spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',
  'import time,sys,io\ntime.monotonic=lambda:'+now+'\nsys.stdin=io.StringIO('+JSON.stringify(JSON.stringify({deadlineMs:deadline}))+')\n'+program],
  {encoding:'utf8',timeout:5000,maxBuffer:8192});
 const valid=execute(10,10500);assert.equal(valid.status,0);assert.equal(Number(valid.stdout),0.5);
 for(const [now,deadline]of [[10,10000],[11,10500],[10,10000.00000001]]){
  const result=execute(now,deadline);assert.notEqual(result.status,0);assert.equal(result.stdout,'');
 }
});
test('V39 admitted code still requires exact fresh plan, original deadline and actual host authority',async()=>{
 const mode='v39-atomic-pair',plan=await adapter.originalBuildPlan(root,runId,{consumerMode:mode});
 assert.equal(plan.consumerMode,mode);assert.equal(plan.consumerBinding.profile,mode);
 assert.deepEqual([plan.consumerBinding.fixtureMs,plan.consumerBinding.childMs,plan.consumerBinding.parentWorkMs],[240000,480000,960000]);
 assert.deepEqual([plan.consumerBinding.arms,plan.consumerBinding.modelCallsPerArm,plan.consumerBinding.modelCalls],[2,14,28]);
 assert.equal(plan.consumerBinding.liveEnabled,true);assert.equal(plan.consumerBinding.qualificationComplete,false);assert.equal(plan.limits.serviceLeaseMs,4560000);
 assert.equal(plan.consumerBinding.proxySha256,require('./postgres/ownedMcpOriginalService').fixedProxy(mode).sourceSha256);
 for(const phase of ['prepare','namespace','serviceCohortClaim','serviceExec','serviceDrain','cleanup'])
  assert.ok(plan.commands[phase].includes('v39-atomic-pair-total-lease-v1'),phase);
 for(const source of ['ownedMcpOriginalService','ownedMcpOriginalServiceProducer','ownedMcpRegistryService','ownedMcpOriginalServiceLease','ownedMcpOriginalServiceDerivation'])
  assert.match(plan.helperHashes['tests/postgres/'+source+'.js'],/^[a-f0-9]{64}$/);
 assert.equal(plan.helperHashes['tests/postgres/run-owned-mcp-assembly-isolated.py'],digest(await fs.readFile(path.join(root,'tests/postgres/run-owned-mcp-assembly-isolated.py'))));
 const options={root,runId,consumerMode:mode,expectedPlanSha256:adapter.planDigest(plan),
  consumer:()=>assert.fail('consumer'),runner:()=>assert.fail('runner'),verifyHost:()=>assert.fail('host')};
 for(const workDeadline of [undefined,NaN,performance.now()-1,performance.now()+970000])
  await assert.rejects(adapter.withPrivateBuiltImage({...options,workDeadline}),{code:'V39_PRIVATE_DEADLINE'});
 await assert.rejects(adapter.withPrivateBuiltImage({...options,workDeadline:performance.now()+900000,
  expectedPlanSha256:'0'.repeat(64)}),{code:'ORIGINAL_BUILD_PLAN_CHANGED'});
 const denied=Object.assign(Error('controlled host denied'),{code:'CONTROLLED_HOST_DENIED'});let host=0;
 await assert.rejects(adapter.withPrivateBuiltImage({...options,workDeadline:performance.now()+900000,
  verifyHost:()=>{host++;throw denied;}}),error=>error===denied);
 assert.equal(host,1);
});
test('V39 producer charges claim latency and rejects oversized or expired child windows',async()=>{
 for(const remaining of [1000,480001,0]){
  let observed;const control=producerControl({mode:'v39-atomic-pair',claimRemaining:remaining,
   scenario:'serviceCohortClaim',hold:()=>new Promise(resolve=>setTimeout(resolve,20)),inspectCohort:value=>{observed=value;}});
  const outcome=await adapter._internals.boundedConsumer((_handoff,lifetime)=>control.run(lifetime),control.handoff,
   {milliseconds:2000,retirementMs:1000,phaseJoinMs:0,serviceMode:true});
  assert.equal(outcome.retired,true);
  if(remaining===1000){assert.equal(outcome.error,undefined);assert.equal(observed.cohortWindow.budgetMs,1000);
   assert.ok(observed.cohortWindow.remainingMs<=985);assert.equal(control.counts().healthCalls,3);}
  else{assert.equal(outcome.error.code,'V39_SERVICE_COHORT_WINDOW');assert.equal(observed,undefined);}
 }
});
test('lost pair owner retains listener and builder authority rather than deleting underneath external work',async()=>{
 const control=producerControl({mode:'v39-atomic-pair',claimRemaining:1000,
  inspectCohort:()=>{throw Object.assign(Error('owner lost'),{code:'V39_IPC_EOF',retirementUnproven:true});}});
 const outcome=await adapter._internals.boundedConsumer((_handoff,lifetime)=>control.run(lifetime),control.handoff,
  {milliseconds:2000,retirementMs:1000,phaseJoinMs:0,serviceMode:true});
 assert.equal(outcome.retired,false);assert.equal(outcome.error.code,'V39_IPC_EOF');
 assert.equal(control.calls.includes('serviceRetire'),false);
 assert.equal(control.calls.includes('serviceProfileRetire'),false);
});
test('actual timed-shell body initializes its scope and refuses an expired lease before effect',()=>{
 const producer=require('./postgres/ownedMcpOriginalServiceProducer');
 const derive=require('./postgres/ownedMcpOriginalServiceDerivation');
 const emitted=producer.boundedPhase('','printf owned-effect','build');
 const parse=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',
  'import sys,json,shlex; print(json.dumps(shlex.split(sys.stdin.read())[6]))'],
  {input:emitted.slice(emitted.indexOf('/usr/bin/timeout')),encoding:'utf8',timeout:5000,maxBuffer:32768});
 assert.equal(parse.status,0,parse.stderr);
 const body=JSON.parse(parse.stdout),check=derive.leaseCommand('check-build');
 assert.equal(body.split(check).length,2);
 const denied=spawnSync('/bin/sh',['-c',body.replace(check,'false'),'fixed','/controlled','a'.repeat(32)],
  {encoding:'utf8',timeout:5000,maxBuffer:8192});
 assert.notEqual(denied.status,0);assert.equal(denied.stdout,'');
 const admitted=spawnSync('/bin/sh',['-c',body.replace(check,'test "$root" = /controlled && test "$nonce" = '+ 'a'.repeat(32)),
  'fixed','/controlled','a'.repeat(32)],{encoding:'utf8',timeout:5000,maxBuffer:8192});
 assert.equal(admitted.status,0,admitted.stderr);assert.equal(admitted.stdout,'owned-effect');
});
test('pending startup, callback and endpoint operations retain resources past owner expiry',async()=>{
 for(const scenario of ['serviceStart','listen-pending','cohort-pending','close-pending']){
  let release,enteredResolve,work;
  const entered=new Promise(resolve=>{enteredResolve=resolve;});
  const held=new Promise(resolve=>{release=resolve;});
  const control=producerControl({scenario,hold:()=>{enteredResolve();return held;}});
  const parent=new AbortController();
  const result=adapter._internals.boundedConsumer((_handoff,lifetime)=>{
   work=control.run(lifetime);return work;
  },control.handoff,{signal:parent.signal,milliseconds:1000,retirementMs:30,phaseJoinMs:0,serviceMode:true});
  await entered;parent.abort();
  const outcome=await result;
  assert.equal(outcome.retired,false,scenario);assert.ok(outcome.error,scenario);
  assert.equal(control.calls.includes('serviceRetire'),false,scenario);
  release();await assert.rejects(work);
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(control.calls.includes('serviceRetire'),false,scenario+' after late completion');
 }
});
test('original-service callback cannot forge live handoff authority before any journal or phase',async()=>{
 let effects=0;
 await assert.rejects(adapter._internals.originalServiceConsumer({controlled:false}, {},{
  plan:{},step(){effects++;},cohort(){effects++;},charge(){effects++;}}),{code:'ORIGINAL_BUILD_HANDOFF_NOT_LIVE'});
 assert.equal(effects,0);
});
test('actual original twenty-file plan compiles, preserves Dockerfile, and closes egress before build', async () => {
  const plan = await adapter.originalBuildPlan(root, runId);
  assert.equal(plan.buildApproved, false); assert.equal(plan.qualificationComplete, false);
  assert.equal(Object.keys(plan.buildSources).length, 20);
  assert.equal(plan.packageDigest, require('../scripts/install/secureshop-owned-mcp-registry-setup')._internals.packageDigest());
  assert.equal(digest(plan.guestSource), plan.guestSourceSha256);
  new vm.Script(plan.guestSource);
  const bootstrap = plan.guestSource.slice(0, plan.guestSource.indexOf('(async function guestMain'));
  const loaded = new Function('require', bootstrap + ';return {closure:load("ownedMcpDependencyClosure"),metadata:load("ownedPolicySystemMetadata"),replay:load("ownedMcpArtifactReplay")};')(require);
  const emitted = JSON.parse(JSON.parse(await fs.readFile(path.join(path.dirname(metadataPath), 'acquisition-output.json'), 'utf8')).raw);
  assert.equal(loaded.metadata.validateResultEnvelope(JSON.stringify(emitted), emitted.binding).version, 3);
  assert.equal(loaded.closure._internals.npmArtifacts(await fs.readFile(path.join(root, 'sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'))).length, 122);
  assert.equal(loaded.replay.LIMITS.requests, 512);
  assert.equal(loaded.closure.LIMITS.npm, 64 * 1024 ** 2);
  assert.equal(loaded.closure.ORIGINAL_BUILD_LIMITS.npm, 114 * 1024 ** 2);
  assert.equal(plan.limits.artifactBudgetProfile, closure.ORIGINAL_BUILD_PROFILE);
  assert.equal(plan.limits.npmStoredBytes, 114 * 1024 ** 2);
  assert.equal(plan.limits.npmWireBytes, 116 * 1024 ** 2);
  assert.equal(plan.limits.artifactBytes, 192 * 1024 ** 2);
  assert.equal(plan.limits.acquisitionBytes, 261 * 1024 ** 2);
  assert.equal(plan.limits.disk, 6 * 1024 ** 3);
  assert.equal(plan.limits.consumerWorkMs, 120000);
  assert.equal(plan.limits.registryPhaseJoinMs, 360000);
  assert.equal(plan.limits.consumerRetirementMs, 1080000);
  assert.deepEqual(plan.npmUpdatePolicy, replay.NPM_UPDATE_POLICY);
  assert.deepEqual(plan.replayAdmissionPolicy, replay.FIFO_POLICY);
  assert.match(plan.guestSource, /artifacts: plan.artifacts, budgetProfile,/);
  assert.match(plan.guestSource, /,"original-v23-registry"\)\.catch/);
  for (const [name, script] of Object.entries(plan.commands)) {
    const parsed = spawnSync('/bin/sh', ['-n'], { input: script, encoding: 'utf8', timeout: 10000 });
    assert.equal(parsed.status, 0, name + ': ' + parsed.stderr);
    for (const match of script.matchAll(/<<'(OWASP_AI_GOAT_REGISTRY_[A-Z]+)'\n([\s\S]*?)\n\1/g)) {
      const compiled = spawnSync('/opt/homebrew/bin/python3', ['-I', '-S', '-B', '-c', 'import sys;compile(sys.stdin.read(),"<registry-owned>","exec")'], { input: match[2], encoding: 'utf8' });
      assert.equal(compiled.status, 0, name + ': ' + compiled.stderr);
    }
  }
  assert.match(plan.commands.build, /stop_private_relay\nproxy=/);
  assert.match(plan.commands.build, /--secret "id=npm_ca,src=\$root\/fs\/closure\/npm-ca.pem"/);
  assert.match(plan.commands.build, /--pull=false --network=host --platform linux\/arm64/);
  assert.match(plan.commands.build, /Dockerfile\.candidate'/);
  assert.match(plan.commands.startArtifacts, /--log-driver local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false /);
  assert.doesNotMatch(plan.commands.build, /docker\s+(?:load|prune|system)/);
  await adapter._internals.verifyPlanSources(plan);
  const changed = structuredClone(plan); changed.guestSource += '\n';
  await assert.rejects(adapter._internals.verifyPlanSources(changed), { code: 'ORIGINAL_BUILD_SOURCE_CHANGED' });
  const censusBudget = await adapter.originalBuildPlan(root, runId, { budgetProfile: 'default' });
  assert.equal(censusBudget.limits.npmWireBytes, 64 * 1024 ** 2);
  assert.match(censusBudget.guestSource, /,"default"\)\.catch/);
  let called = false;
  await assert.rejects(adapter.withPrivateBuiltImage({ root, runId,
    expectedPlanSha256: adapter.planDigest(censusBudget), consumer() { called = true; },
    runner() { called = true; }, verifyHost() { called = true; } }), { code: 'ORIGINAL_BUILD_PLAN_CHANGED' });
  assert.equal(called, false);
});
test('actual emitted profile heredoc delivers exactly the pinned substituted bytes and digest', async () => {
  const plan = await adapter.originalBuildPlan(root, runId);
  const runtime = require('./postgres/ownedMcpRuntimeQualification')._internals;
  const template = await fs.readFile(path.join(root, runtime.TEMPLATE));
  assert.equal(digest(template), runtime.TEMPLATE_SHA);
  const expected = Buffer.from(template.toString().replaceAll('@@SUPERVISOR_PROFILE@@', plan.registryConsumer.name));
  assert.equal(expected.at(-1), 10);
  const command = plan.commands.registryProfileInstall;
  const offset = command.lastIndexOf(" <<'OWASP_AI_GOAT_ORIGINAL_REGISTRY_PROFILE'\n");
  assert.ok(offset > 0);
  // Execute the exact emitted shell redirection with a harmless stdin→stdout
  // capture. No profile parser, VM, file write or native security effect.
  // macOS /bin/sh uses an out-of-repository heredoc tempfile. zsh's POSIX
  // mode permits an explicitly owned temporary prefix within this wrapper.
  const tempPrefix = path.join(process.env.TMPDIR, 'profile-heredoc-').replace(/'/g, "'\\''");
  const captured = spawnSync('/bin/zsh', ['--emulate', 'sh', '-c', "TMPPREFIX='" + tempPrefix + "'; cat" + command.slice(offset)], { timeout: 10000 });
  assert.equal(captured.status, 0, captured.stderr.toString());
  assert.deepEqual(captured.stdout, expected);
  assert.equal(digest(captured.stdout), digest(expected));
  assert.ok(command.slice(0, offset).endsWith("'" + digest(expected) + "'"));
  assert.notEqual(digest(Buffer.concat([expected, Buffer.from('\n')])), digest(captured.stdout));
});
test('artifact retirement requires successful private listing and exact CID absence, including never-started containers', async () => {
  const plan = await adapter.originalBuildPlan(root, runId);
  const start = plan.commands.retireArtifacts.indexOf('docker --host "unix://$root/fs/docker.sock" stop --time 10');
  assert.ok(start > 0);
  const tail = plan.commands.retireArtifacts.slice(start);
  assert.doesNotMatch(tail, /if docker .*inspect/);
  const cid = 'a'.repeat(64), sibling = 'b'.repeat(64);
  for (const scenario of ['empty', 'sibling', 'created', 'remaining', 'listing-error', 'invalid-list', 'running', 'stop-error', 'remove-error', 'exit-proof-error']) {
    const listing = scenario === 'remaining' ? cid : scenario === 'sibling' ? sibling : scenario === 'invalid-list' ? 'malformed' : '';
    const script = `set -eu
root=/controlled-private-root
cid=${cid}
check_replay_exit() { ${scenario === 'exit-proof-error' ? 'return 44' : 'return 0'}; }
docker() {
 [ "$1" = --host ] && [ "$2" = unix:///controlled-private-root/fs/docker.sock ]
 shift 2
 case "$1" in
 stop) ${scenario === 'stop-error' ? 'return 41' : 'return 0'} ;;
 inspect) printf '%s\\n' '${scenario === 'running' ? 'true' : 'false'}' ;;
 rm) ${scenario === 'remove-error' ? 'return 42' : 'return 0'} ;;
 ps) [ "$*" = 'ps --all --quiet --no-trunc' ]; ${scenario === 'listing-error' ? 'return 43' : `printf '%s\\n' '${listing}'`} ;;
 *) return 99 ;;
 esac
}
${tail}`;
    const result = spawnSync('/bin/sh', ['-c', script], { encoding: 'utf8', timeout: 10000 });
    if (['empty', 'sibling', 'created'].includes(scenario)) { assert.equal(result.status, 0, scenario); assert.equal(result.stdout.trim(), 'absent'); }
    else { assert.notEqual(result.status, 0, scenario); assert.doesNotMatch(result.stdout, /absent/); }
  }
});
function registryRow(nonce = runId) {
  const profile = 'owasp-ai-goat-owned-mcp-registry-' + nonce.slice(0, 12);
  const imageId = 'sha256:' + '1'.repeat(64), cid = 'a'.repeat(64);
  return { Id: cid, Name: '/' + profile, Image: imageId, Mounts: [],
    Config: { Labels: { 'owasp-ai-goat.original.registry': nonce }, User: '10001:10001', OpenStdin: true, Entrypoint: ['node'], Cmd: ['-'], Env: ['SECURESHOP_MCP_REGISTRY_PROFILE=' + profile] },
    HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], CapAdd: [], Memory: 536870912, NanoCpus: 1000000000,
      PidsLimit: 128, LogConfig: { Type: 'none' }, SecurityOpt: ['apparmor=' + profile, 'seccomp=unconfined'], Tmpfs: { '/tmp': 'rw,nosuid,nodev,noexec,size=16m' }, Binds: [], Mounts: [] } };
}
function registryResult() { return JSON.stringify({ status: 'passed', modelCalls: 0, qualificationComplete: false, runtimeDigest: 'b'.repeat(64),
  cases: [...Array(11).fill('controlled-only'), 'immutable assets and all namespace descendants joined'] }); }
test('closed original registry consumer confirms release only after exact runtime teardown; failures preserve debt', async () => {
  const consumer = adapter._internals.originalRegistryConsumer, profile = 'owasp-ai-goat-owned-mcp-registry-' + runId.slice(0, 12);
  const row = registryRow(), imageId = row.Image;
  for (const scenario of ['success', 'identity', 'boundary', 'fixture', 'registryRetire', 'registryProfileRetire']) {
    let confirmed = false; const calls = [], primary = Error('controlled runtime failure');
    const lifetime = { registryName: profile, beginRetirement() {}, confirmRetired() { confirmed = true; }, async runRegistryPhase(name) {
      calls.push(name); if (scenario === name || scenario === 'fixture' && name === 'registryStart') throw primary;
      if (name === 'registryCreate') {
        const value = structuredClone(row); if (scenario === 'identity') value.Image = 'sha256:' + '2'.repeat(64);
        if (scenario === 'boundary') value.HostConfig.Privileged = true; return JSON.stringify([value]);
      }
      if (name === 'registryStart') return registryResult();
      return 'absent\n';
    } };
    const run = consumer({ controlled: true, imageId, runId }, lifetime);
    if (scenario === 'success') { const value = await run; assert.equal(value.controlled, true); assert.equal(value.qualificationComplete, false); }
    else await assert.rejects(run, error => {
      if (scenario === 'fixture') assert.equal(error, primary);
      if (scenario.endsWith('Retire')) assert.equal(error.retirementUnproven, true);
      return true;
    });
    assert.equal(confirmed, !scenario.endsWith('Retire'));
    assert.ok(calls.includes('registryRetire'));
    if (scenario === 'registryRetire') assert.ok(!calls.includes('registryProfileRetire'));
    else assert.equal(calls.at(-1), 'registryProfileRetire');
  }
  await assert.rejects(consumer({ controlled: false }, {}), { code: 'ORIGINAL_BUILD_HANDOFF_NOT_LIVE' });
});
test('derived relay executes exact 192-connect, 116-MiB npm and unchanged aggregate cap without broadening defaults', async () => {
  const identity = { account: 'fixture', uid: 501, gid: 502, python: '/usr/bin/python3.13', pythonSha256: 'a'.repeat(64), setprivSha256: 'b'.repeat(64) };
  const original = await bounded._internals.privateRelayPlan(bounded.specification('/controlled/repo', runId), identity, { transportOnly: true, metadataOnly: true });
  const derived = adapter.derivedRelaySource(original.source, closure.ORIGINAL_BUILD_PROFILE);
  assert.match(original.source, /connections>=32/); assert.doesNotMatch(original.source, /registry\.npmjs\.org/);
  const program = `import sys,json\nscope={'__name__':'controlled'}\nexec(compile(sys.stdin.read(),'<derived>','exec'),scope)\nassert scope['HOSTS']==['registry-1.docker.io','auth.docker.io','deb.debian.org','production.cloudfront.docker.com','registry.npmjs.org']\nfor text in scope['CHILDREN'].values():\n text=text.rsplit('\\nserve(',1)[0]\n child={'__name__':'controlled'};exec(compile(text,'<child>','exec'),child)\n B=child['Budget'];D=child['Denied'];b=B()\n for i in range(192):b.admit()\n try:b.admit();assert False\n except D:pass\n b=B();b.charge('registry.npmjs.org',67108864)\n try:b.charge('registry.npmjs.org',1);assert False\n except D:pass\n b=B();b.charge('deb.debian.org',138412032);b.charge('registry-1.docker.io',134217728);b.charge('auth.docker.io',1048576)\n assert b.total==273678336\n try:b.charge('registry.npmjs.org',1);assert False\n except D:pass\n assert child['authority'](b'CONNECT registry.npmjs.org:443 HTTP/1.1\\r\\nHost: registry.npmjs.org:443\\r\\n\\r\\n')=='registry.npmjs.org'\n for host in ('localhost','registry.npmjs.org.evil','example.com'):\n  try:child['authority'](('CONNECT '+host+':443 HTTP/1.1\\r\\nHost: '+host+':443\\r\\n\\r\\n').encode());assert False\n  except D:pass\n`;
  // Same exact-boundary and +1-byte denial program, with the census-backed
  // derived host cap; the original relay remains unmodified above.
  assert.equal(program.split('67108864').length, 2);
  const result = spawnSync('/opt/homebrew/bin/python3', ['-I', '-S', '-B', '-c', program.replace('67108864', String(116 * 1024 ** 2))], { input: derived, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.throws(() => adapter.derivedRelaySource(derived), { code: 'ORIGINAL_BUILD_SOURCE_SHAPE' });
  assert.throws(() => adapter.derivedRelaySource(original.source, 'unbounded'), { code: 'CLOSURE_BUDGET_PROFILE' });
  const defaultResult = spawnSync('/opt/homebrew/bin/python3', ['-I', '-S', '-B', '-c', program], {
    input: adapter.derivedRelaySource(original.source), encoding: 'utf8', timeout: 10000 });
  assert.equal(defaultResult.status, 0, defaultResult.stderr);
});
test('physical handoff is exact immutable identity data, never a caller-supplied live authority', () => {
  const plan = { runId, spec: { socket: '/private/docker.sock' } };
  const value = { version: 1, target: 'original-v23-registry', runId, privateDockerHost: 'unix:///private/docker.sock',
    namespaceInode: 'net:[123]', filesystemIdentity: { device: 12, inode: 34 },
    daemonProcess: { pid: 20, startTicks: '100', exe: '/usr/bin/dockerd' }, namespaceHolder: { pid: 21, startTicks: '99', exe: '/usr/bin/sleep' } };
  assert.equal(adapter._internals.validatePhysicalHandoff(value, plan), value);
  assert.throws(() => adapter.assertLiveHandoff(value), { code: 'ORIGINAL_BUILD_HANDOFF_NOT_LIVE' });
  for (const change of [x => x.target = 'original-pricing', x => x.daemonProcess.pid = 1,
    x => x.namespaceHolder.pid = 20, x => x.daemonProcess.startTicks = '0', x => x.daemonProcess.exe = '/bin/sh',
    x => x.namespaceInode = 'net:[0]', x => x.filesystemIdentity.inode = 0, x => x.extra = true]) {
    const bad = structuredClone(value); change(bad); assert.throws(() => adapter._internals.validatePhysicalHandoff(bad, plan));
  }
});
test('consumer completion, rejection, cancellation and unresolved teardown stay distinct', async () => {
  const call = adapter._internals.boundedConsumer;
  assert.deepEqual(await call(async (_handoff, lifetime) => { lifetime.confirmRetired(); return 7; }, {}, { milliseconds: 100, graceMs: 10 }), { value: 7, retired: true });
  const primary = Error('original consumer failure');
  const failed = await call(async (_handoff, lifetime) => { lifetime.confirmRetired(); throw primary; }, {}, { milliseconds: 100, graceMs: 10 });
  assert.equal(failed.error, primary); assert.equal(failed.retired, true);
  const retired = await call((_handoff, { signal, confirmRetired }) => new Promise(resolve => signal.addEventListener('abort', () => { confirmRetired(); resolve(); }, { once: true })), {}, { milliseconds: 5, graceMs: 10 });
  assert.equal(retired.error.code, 'ORIGINAL_BUILD_CONSUMER_INTERRUPTED'); assert.equal(retired.retired, true);
  const debt = await call(() => new Promise(() => {}), {}, { milliseconds: 5, graceMs: 5 });
  assert.equal(debt.error.code, 'ORIGINAL_BUILD_CONSUMER_INTERRUPTED'); assert.equal(debt.retired, false);
  const aborted = new AbortController(); aborted.abort(); let invoked = false;
  assert.equal((await call(() => { invoked = true; }, {}, { signal: aborted.signal })).retired, true); assert.equal(invoked, false);
  assert.equal((await call(() => 7, {})).retired, false);
  const explicitDebt = Object.assign(Error('owned resource remains'), { pricingRetirementUnproven: true });
  const rejected = await call((_handoff, lifetime) => { lifetime.confirmRetired(); throw explicitDebt; }, {});
  assert.equal(rejected.error, explicitDebt); assert.equal(rejected.retired, false);
  const wrapped = new AggregateError([Error('original'), new Error('wrapper', { cause: explicitDebt })], 'combined');
  const nested = await call((_handoff, lifetime) => { lifetime.confirmRetired(); throw wrapped; }, {});
  assert.equal(nested.error, wrapped); assert.equal(nested.retired, false);
  const graceError = await call((_handoff, { signal }) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(explicitDebt), { once: true })), {}, { milliseconds: 5, graceMs: 10 });
  assert.equal(graceError.error, explicitDebt); assert.equal(graceError.retired, false);
  let late;
  const noRelease = await call((_handoff, lifetime) => { late = lifetime.confirmRetired; return new Promise(() => {}); }, {}, { milliseconds: 5, graceMs: 5 });
  assert.equal(noRelease.retired, false); assert.throws(late, { code: 'ORIGINAL_BUILD_RETIREMENT_CAPABILITY_CLOSED' });
  await assert.rejects(call(() => {}, {}, { milliseconds: 120001 }));
});
test('closed registry phases cancel outstanding work and revoke all effects and writes after unjoined retirement', async () => {
  for (const slow of ['registryProfileInstall', 'registryStart']) {
    const calls = [], writes = []; let phaseSignal, release, callbackDone, capability;
    const done = new Promise(resolve => { callbackDone = resolve; });
    const plan = { registryConsumer: { name: 'controlled', input: 'controlled' } };
    const outcome = await adapter._internals.boundedConsumer(async (_value, lifetime) => {
      capability = adapter._internals.registryLifetime(lifetime, plan, async (name, options, cleanup) => {
        calls.push(name);
        if (name === slow) { phaseSignal = options.signal; await new Promise(resolve => { release = resolve; }); }
        options.assertOpen(); writes.push(name);
        return 'absent\n';
      });
      try {
        await capability.runRegistryPhase(slow);
        await capability.runRegistryPhase('registryCreate');
      } catch (error) { assert.equal(error.code, 'ORIGINAL_BUILD_RETIREMENT_CAPABILITY_CLOSED'); }
      finally {
        assert.throws(() => capability.runRegistryPhase('registryRetire'), { code: 'ORIGINAL_BUILD_RETIREMENT_CAPABILITY_CLOSED' });
        callbackDone();
      }
    }, {}, { milliseconds: 5, graceMs: 5 });
    assert.equal(outcome.retired, false); assert.equal(phaseSignal.aborted, true);
    release(); await done;
    assert.deepEqual(calls, [slow]); assert.deepEqual(writes, []);
    assert.throws(capability.confirmRetired, { code: 'ORIGINAL_BUILD_RETIREMENT_CAPABILITY_CLOSED' });
  }
});
test('registry work deadline and early primary failure have a separate joined retirement lifetime', async () => {
  for (const scenario of ['early-failure', 'deadline', 'success']) {
    const calls = [], completed = [], primary = Object.assign(Error('first phase failure'), { code: 'CONTROLLED_PRIMARY' });
    const controller = new AbortController(); let releaseCleanup, cleanupStarted, returned = false, cleanupSignal;
    const started = new Promise(resolve => { cleanupStarted = resolve; });
    const plan = { registryConsumer: { name: registryRow().Name.slice(1), input: 'controlled' } };
    const run = adapter._internals.boundedConsumer(async (_value, lifetime) => {
      const capability = adapter._internals.registryLifetime(lifetime, plan, async (name, options, cleanup) => {
        calls.push(name);
        if (name === 'registryProfileInstall' && scenario === 'early-failure') throw primary;
        if (name === 'registryProfileInstall' && scenario === 'deadline') {
          controller.abort();
          // Models the existing failed remote command's uncertainty join, not
          // a shortened production deadline. Its original error survives.
          await new Promise(resolve => setTimeout(resolve, 20)); throw primary;
        }
        if (name === 'registryCreate') return JSON.stringify([registryRow()]);
        if (name === 'registryStart') return registryResult();
        if (cleanup) {
          cleanupSignal = options.signal;
          if (name === (scenario === 'success' ? 'registryRetire' : 'registryProfileRetire')) {
            cleanupStarted(); await new Promise(resolve => { releaseCleanup = resolve; });
          }
        }
        options.assertOpen(); completed.push(name); return 'absent\n';
      });
      return adapter._internals.originalRegistryConsumer({ controlled: true, imageId: registryRow().Image, runId }, capability);
    }, {}, { signal: controller.signal, milliseconds: 30, retirementMs: 1000, phaseJoinMs: 100 }).then(value => { returned = true; return value; });
    await started;
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(returned, false); assert.equal(cleanupSignal.aborted, false);
    releaseCleanup(); const result = await run;
    assert.equal(result.retired, true, scenario);
    if (scenario === 'success') assert.equal(result.value.cleanupVerified, true);
    else assert.equal(result.error, primary);
    assert.equal(completed.at(-1), 'registryProfileRetire');
    if (scenario !== 'success') assert.deepEqual(calls, ['registryProfileInstall', 'registryProfileRetire']);
  }
});
test('registry retirement rejects duplicate or overlapping phases and never confirms unresolved cleanup', async () => {
  const plan = { registryConsumer: { name: 'controlled', input: 'controlled' } };
  let late, release, signal; const calls = [], writes = [];
  const outcome = await adapter._internals.boundedConsumer(async (_value, lifetime) => {
    late = adapter._internals.registryLifetime(lifetime, plan, async (name, options) => {
      calls.push(name); signal = options.signal;
      if (name === 'registryProfileRetire') await new Promise(resolve => { release = resolve; });
      options.assertOpen(); writes.push(name); return 'absent\n';
    });
    await late.runRegistryPhase('registryProfileInstall');
    const cleanup = late.runRegistryPhase('registryProfileRetire');
    assert.throws(() => late.runRegistryPhase('registryProfileRetire'), { code: 'ORIGINAL_BUILD_CONSUMER_PHASE_ORDER' });
    assert.throws(late.confirmRetired, { code: 'ORIGINAL_BUILD_CONSUMER_RETIREMENT_UNPROVEN' });
    await cleanup;
  }, {}, { milliseconds: 100, retirementMs: 20 });
  assert.equal(outcome.retired, false); assert.equal(outcome.error.code, 'ORIGINAL_BUILD_CONSUMER_RETIREMENT_TIMEOUT');
  assert.equal(signal.aborted, true);
  const before = writes.slice(); release(); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(writes, before); assert.deepEqual(calls, ['registryProfileInstall', 'registryProfileRetire']);
  assert.throws(() => late.runRegistryPhase('registryRetire'), { code: 'ORIGINAL_BUILD_RETIREMENT_CAPABILITY_CLOSED' });
  assert.throws(late.confirmRetired, { code: 'ORIGINAL_BUILD_RETIREMENT_CAPABILITY_CLOSED' });
});
test('consumer cannot return across an unawaited actual phase or start cleanup without its remaining join budget', async () => {
  let release, started, returned = false;
  const entered = new Promise(resolve => { started = resolve; });
  const run = adapter._internals.boundedConsumer((_value, lifetime) => {
    lifetime.joinPhase(() => new Promise(resolve => { release = resolve; started(); })).catch(() => {});
    return 'not proof';
  }, {}, { milliseconds: 100, retirementMs: 1000 }).then(value => { returned = true; return value; });
  await entered; await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(returned, false); release(); assert.equal((await run).retired, false);

  const plan = { registryConsumer: { name: 'controlled', input: 'controlled' } };
  const calls = [];
  const result = await adapter._internals.boundedConsumer(async (_value, lifetime) => {
    const capability = adapter._internals.registryLifetime(lifetime, plan, async name => { calls.push(name); return 'absent\n'; });
    await capability.runRegistryPhase('registryProfileInstall');
    await capability.runRegistryPhase('registryProfileRetire');
    assert.throws(() => capability.runRegistryPhase('registryProfileRetire'), { code: 'ORIGINAL_BUILD_CONSUMER_PHASE_ORDER' });
    assert.throws(() => capability.runRegistryPhase('registryCreate'), { code: 'ORIGINAL_BUILD_CONSUMER_INTERRUPTED' });
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.throws(() => capability.runRegistryPhase('registryRetire'), { code: 'ORIGINAL_BUILD_RETIREMENT_BUDGET' });
    capability.confirmRetired();
  }, {}, { milliseconds: 100, retirementMs: 100, phaseJoinMs: 90 });
  assert.equal(result.retired, true);
  assert.deepEqual(calls, ['registryProfileInstall', 'registryProfileRetire']);
});
test('wall-clock jumps cannot extend work or change the monotonic retirement reserve', async () => {
  const originalNow = Date.now;
  try {
    for (const jump of [-86400000, 86400000]) {
      const epoch = originalNow(); Date.now = () => epoch;
      const outcome = await adapter._internals.boundedConsumer(async (_value, lifetime) => {
        Date.now = () => epoch + jump;
        assert.doesNotThrow(lifetime.assertActive);
        lifetime.beginRetirement();
        assert.doesNotThrow(lifetime.assertRetirementAdmission);
        await new Promise(resolve => setTimeout(resolve, 30));
        assert.throws(lifetime.assertRetirementAdmission, { code: 'ORIGINAL_BUILD_RETIREMENT_BUDGET' });
        lifetime.confirmRetired();
      }, {}, { milliseconds: 1000, retirementMs: 200, phaseJoinMs: 190 });
      assert.equal(outcome.retired, true);
      Date.now = () => epoch;
      const expired = await adapter._internals.boundedConsumer(async (_value, lifetime) => {
        Date.now = () => epoch + jump;
        await new Promise(resolve => setTimeout(resolve, 25));
        assert.throws(lifetime.assertActive, { code: 'ORIGINAL_BUILD_CONSUMER_INTERRUPTED' });
        lifetime.confirmRetired();
      }, {}, { milliseconds: 10, retirementMs: 1000 });
      assert.equal(expired.error.code, 'ORIGINAL_BUILD_CONSUMER_INTERRUPTED');
      assert.equal(expired.retired, true);
    }
  } finally { Date.now = originalNow; }
});
test('actual host phase source fences late diagnostics and terminal journals after retirement authority closes', async () => {
  const source = await fs.readFile(path.join(root, 'tests/postgres/ownedMcpOriginalBuildAdapter.js'), 'utf8');
  const start = source.indexOf('  const record = async (name, value, terminal = false, assertOpen = () => {}, io = operation => operation()) => {');
  const end = source.indexOf('  const captureClosure = ', start);
  assert.ok(start > 0 && end > start);
  const writes = []; let open = true, release, dispatched, captured;
  const entered = new Promise(resolve => { dispatched = resolve; });
  const assertOpen = () => { if (!open) throw Object.assign(Error('closed'), { code: 'CONTROLLED_CLOSED' }); };
  const handle = { async writeFile() { writes.push('stderr'); }, async sync() { writes.push('sync'); }, async close() { writes.push('closed'); } };
  const runner = async (_plan, _name, options) => {
    captured = options; await options.diagnosticSink(Buffer.from('first bounded diagnostic'));
    dispatched(); await new Promise(resolve => { release = resolve; }); return 'late output';
  };
  // Evaluate the actual record/step source, not a copied approximation. Its
  // child and filesystem doubles are controlled; no guest or network runs.
  const step = new Function('fs', 'path', 'plan', 'controller', 'verifyPlanSources', 'runner', 'durableJson', 'charge', 'fail', 'sha', 'consumerJournal',
    'let sequence=0; const expectedPlanSha256="controlled";\n' + source.slice(start, end) + '\nreturn step;')(
    { async open() { writes.push('open'); return handle; } }, path, { spec: { artifact: '/controlled' } }, new AbortController(), async () => {}, runner,
    async (_directory, name, _value, guard) => { guard(); writes.push(name); }, () => {}, code => Object.assign(Error(code), { code }), digest,
    adapter._internals.createConsumerJournal());
  const phase = step('registryProfileRetire', { assertOpen }, true);
  await entered;
  open = false; const before = writes.slice();
  await assert.rejects(captured.diagnosticSink(Buffer.from('late')), { code: 'CONTROLLED_CLOSED' });
  release(); await assert.rejects(phase);
  assert.deepEqual(writes, [...before, 'closed']);
  assert.ok(!writes.some(name => name.endsWith('-result.json')));
});
async function closurePacket(binding) {
  // Real retained candidate shape, but deliberately synthetic package byte
  // counters. This tests receipt joins, not signature or download completion.
  const envelope = JSON.parse(JSON.parse(await fs.readFile(path.join(path.dirname(metadataPath), 'acquisition-output.json'), 'utf8')).raw);
  if (binding) { envelope.binding = structuredClone(binding); envelope.candidate.retainedMetadata.binding = structuredClone(binding); }
  const npmLock = await fs.readFile(path.join(root, 'sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'));
  const plan = closure.planArtifacts({ npmLock, stages: envelope.candidate.retainedMetadata.stages });
  const artifacts = plan.artifacts.map(row => ({ ...row, actualBytes: row.bytes ?? 1, file: 'objects/' + closure._internals.objectName(row) }));
  const bytes = { deb: 0, npm: 0, total: 0 }; for (const row of artifacts) { bytes[row.kind] += row.actualBytes; bytes.total += row.actualBytes; }
  const retained = envelope.candidate.retainedMetadata;
  const record = { version: 1, binding: envelope.binding, authenticated: { version: 1, method: 'original-base-apt-closed-replay',
    keyringSha256: envelope.candidate.keyringSha256, installedStatusSha256: envelope.candidate.installedStatusSha256,
    retainedManifestSha256: digest(JSON.stringify(retained)), expandedBytes: 100,
    stages: retained.stages.map(stage => ({ name: stage.name, selectionSha256: digest(stage.selection) })) },
    receipt: { version: 1, budgetProfile: closure.ORIGINAL_BUILD_PROFILE, artifactBytesVerified: true, metadataAuthenticated: false, buildApproved: false, qualificationComplete: false, bytes, artifacts },
    npmSourceWitness: replay.expectedNpmSourceWitness() };
  const raw = JSON.stringify(record), ready = { version: 1, binding: envelope.binding, authority: { host: '127.0.0.1', port: 12345 },
    closureSha256: digest(raw), npmCaSha256: 'a'.repeat(64), artifactBytesVerified: true, metadataAuthenticated: true, buildApproved: false };
  const packet = { 'closure.json': raw, 'ready.json': JSON.stringify(ready),
    'replay-intent.json': JSON.stringify({ version: 1, binding: envelope.binding, npmSourceWitness: replay.expectedNpmSourceWitness(), admissionPolicy: replay.FIFO_POLICY }), 'replay-failure.json': null,
    'replay-terminal.json': JSON.stringify({ version: 1, binding: envelope.binding, firstFailure: null,
    publicationErrors: [], finalizerComplete: true, failure: null, closed: true, active: 0, absenceVerified: true,
    admission: { policy: replay.FIFO_POLICY.id, pending: 0, peakPending: 0 },
    tlsRetirement: { ownerIntents: 0, ownerErrors: 0, firstError: null, pendingHandshakes: 0, establishedSockets: 0, unjoinedTlsSockets: 0, callbackDebt: 0,
      diagnostics: { events: 1, saturated: false, closeRequested: 1, decisions: Object.fromEntries(replay.TLS_DECISIONS.map(key => [key, 0])), firstErrorSocket: null } },
    offlineOnly: true, qualificationComplete: false, requests: 1, connections: 1, bytes: 1,
    npmUpdate: { policy: replay.NPM_UPDATE_POLICY.id, sourceWitness: replay.expectedNpmSourceWitness(), denials: [] } }) };
  return { packet, ready, envelope, npmLock };
}
test('closure evidence binds all original lock paths and both actual stage selections; synthetic flags cannot grant handoff', async () => {
  const fixture = await closurePacket(), { packet, ready, envelope, npmLock } = fixture;
  const check = value => adapter._internals.validateClosureEvidence(value, ready, envelope, npmLock, { terminal: true });
  assert.equal(check(packet).receipt.artifacts.length, 158);
  for (const change of [x => x['closure.json'] += ' ', x => x['ready.json'] = '{}', x => x['replay-terminal.json'] = '{"passed":true}',
    x => { const value = JSON.parse(x['replay-terminal.json']); value.active = 1; x['replay-terminal.json'] = JSON.stringify(value); },
    x => { const value = JSON.parse(x['replay-terminal.json']); value.failure = 'REPLAY_DEADLINE'; x['replay-terminal.json'] = JSON.stringify(value); }]) {
    const bad = structuredClone(packet); change(bad); assert.throws(() => check(bad));
  }
  for (const change of [x => x.receipt.artifacts.pop(), x => x.receipt.artifacts.at(-1).lockPaths.push('node_modules/extra'),
    x => x.receipt.bytes.total++, x => x.authenticated.expandedBytes = 0, x => x.receipt.metadataAuthenticated = true,
    x => delete x.receipt.budgetProfile, x => x.receipt.budgetProfile = 'default']) {
    const bad = structuredClone(packet), record = JSON.parse(bad['closure.json']); change(record);
    bad['closure.json'] = JSON.stringify(record); const alteredReady = { closureSha256: digest(bad['closure.json']) }; bad['ready.json'] = JSON.stringify(alteredReady);
    assert.throws(() => adapter._internals.validateClosureEvidence(bad, alteredReady, envelope, npmLock));
  }
  assert.throws(() => adapter.assertLiveHandoff(check(packet)), { code: 'ORIGINAL_BUILD_HANDOFF_NOT_LIVE' });
  for (const excess of [0, 1]) {
    const capped = structuredClone(packet), record = JSON.parse(capped['closure.json']);
    const npm = record.receipt.artifacts.filter(row => row.kind === 'npm');
    npm[0].actualBytes = 64 * 1024 ** 2;
    npm[1].actualBytes = 50 * 1024 ** 2 - (npm.length - 2) + excess;
    record.receipt.bytes.npm = npm.reduce((sum, row) => sum + row.actualBytes, 0);
    record.receipt.bytes.total = record.receipt.bytes.deb + record.receipt.bytes.npm;
    capped['closure.json'] = JSON.stringify(record);
    const cappedReady = { ...ready, closureSha256: digest(capped['closure.json']) };
    capped['ready.json'] = JSON.stringify(cappedReady);
    const validate = () => adapter._internals.validateClosureEvidence(capped, cappedReady, envelope, npmLock);
    if (excess) assert.throws(validate, { code: 'ORIGINAL_BUILD_CLOSURE_EVIDENCE' });
    else assert.equal(validate().receipt.bytes.npm, 114 * 1024 ** 2);
  }
});
test('actual phase executor gives only Lima the OS account home with MAIN-clean or hostile application HOME', async () => {
  const file = path.join(root, 'tests/postgres/ownedMcpOriginalBuildAdapter.js');
  const text = await fs.readFile(file, 'utf8'), localRequire = require('node:module').createRequire(file);
  const account = require('node:os').userInfo();
  const plan = { commands: { inventory: 'fixed-reviewed-inventory' },
    spec: { root, guest: '/private', runId, lima: '/repo-owned/limactl', limaHome: path.join(root, 'tasks/l') } };
  for (const env of [{ PATH: '/fixed/application/path' }, { HOME: '/hostile/caller/home', SECRET: 'must-not-propagate' }]) {
    const before = { ...env }, module = { exports: {} };
    new Function('require', 'module', 'exports', 'process', text)(localRequire, module, module.exports,
      { env, getuid: () => process.getuid(), geteuid: () => process.geteuid() });
    let invoked;
    const execute = module.exports._internals.createPhaseExecutor({ launch(file, args, options) {
      invoked = { file, args, options };
      const child = new EventEmitter(); Object.assign(child, { pid: undefined, exitCode: null, signalCode: null,
        stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
      queueMicrotask(() => child.emit('close', 0, null)); return child;
    } });
    assert.equal(await execute(plan, 'inventory'), '');
    assert.equal(invoked.file, plan.spec.lima);
    assert.deepEqual(invoked.options.env, { PATH: '/usr/bin:/bin', HOME: account.homedir,
      TMPDIR: path.join(root, 'tasks/tmp'), LIMA_HOME: plan.spec.limaHome });
    assert.deepEqual(invoked.args, ['shell', '--workdir', '/', 'colima-goat-q', 'sudo', '-n', 'timeout',
      '--signal=TERM', '--kill-after=10', '150', '/bin/sh', '-c', adapter._internals.phaseTransport(plan.commands.inventory).command,
      'owned-original-build', plan.spec.guest, runId]);
    assert.deepEqual(env, before); // No application environment mutation or ambient propagation.
  }
});
test('actual phase executor rejects unverified account homes and setuid identity before launch', async () => {
  const file = path.join(root, 'tests/postgres/ownedMcpOriginalBuildAdapter.js');
  const text = await fs.readFile(file, 'utf8'), localRequire = require('node:module').createRequire(file);
  const plan = { commands: { inventory: 'fixed' }, spec: { root } };
  const good = { uid: 501, homedir: '/Users/controlled-account' };
  for (const scenario of [
    { lookup: () => { throw Error('lookup failed with private data'); } },
    ...[undefined, '', 'relative', '/Users/a\0secret', '/Users/a/../b', '/Users//a'].map(homedir => ({ account: { ...good, homedir } })),
    { account: { ...good, uid: 502 } }, { uid: 0, euid: 0, account: { ...good, uid: 0 } },
    { euid: 0 }, { uid: NaN }, { uid: 501.5 }, { uid: undefined }, { euid: undefined },
  ]) {
    const module = { exports: {} }; let launches = 0;
    new Function('require', 'module', 'exports', 'process', text)(
      id => id === 'node:os' ? { userInfo: scenario.lookup || (() => scenario.account || good) } : localRequire(id),
      module, module.exports, { env: { HOME: good.homedir },
        getuid: () => Object.hasOwn(scenario, 'uid') ? scenario.uid : 501,
        geteuid: () => Object.hasOwn(scenario, 'euid') ? scenario.euid : 501 });
    const execute = module.exports._internals.createPhaseExecutor({ launch() { launches++; throw Error('must not launch'); } });
    await assert.rejects(execute(plan, 'inventory'), { code: 'ORIGINAL_BUILD_ACCOUNT_HOME', message: 'ORIGINAL_BUILD_ACCOUNT_HOME' });
    assert.equal(launches, 0);
  }
});
test('phase executor awaits sink failure and remote retirement window; controls cannot dispatch network', async () => {
  let invoked, delayed;
  const child = new EventEmitter(); Object.assign(child, { pid: undefined, exitCode: null, signalCode: null,
    stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  const execute = adapter._internals.createPhaseExecutor({ launch(file, args, options) {
    invoked = { file, args, options }; queueMicrotask(() => { child.stdout.end('controlled'); child.emit('close', 0, null); }); return child;
  }, delay: async ms => { delayed = ms; } });
  const plan = { commands: { retainedExport: 'fixed-reviewed-script' }, spec: { root, guest: '/private', runId, lima: '/repo-owned/limactl', limaHome: '/repo-owned/lima' } };
  const failure = Error('durable sink failed');
  await assert.rejects(execute(plan, 'retainedExport', { sink: async () => { throw failure; } }), failure);
  assert.equal(invoked.file, '/repo-owned/limactl'); assert.equal(delayed, undefined);
  assert.deepEqual(invoked.options.env.PATH, '/usr/bin:/bin');
  assert.ok(invoked.args.includes(adapter._internals.phaseTransport('fixed-reviewed-script').command)); assert.ok(invoked.args.includes('colima-goat-q'));
  await assert.rejects(execute(plan, 'unreviewed'), { code: 'ORIGINAL_BUILD_PHASE' });
});
test('actual host lifecycle retains exact primary failures, rejects terminal replay debt and never brands controlled handoffs', async t => {
  const inventory = JSON.parse(await fs.readFile(path.join(path.dirname(metadataPath), 'inventory-before.json'), 'utf8')).text;
  for (const scenario of ['success', 'registry', 'metadata', 'build', 'semantic-replay', 'journal', 'terminal', 'retirement', 'consumer', 'signal', 'cleanup',
    'pending-write', 'pending-record', 'pending-sync', 'pair-success', 'pair-debt',
    'service-failed-retired', 'service-failed-controlled', 'service-failed-signal', 'service-failed-cleanup', 'service-failed-tampered']) {
    const pair = scenario.startsWith('pair-');
    const serviceFailure=scenario.startsWith('service-failed-'), emulatedLive=serviceFailure&&scenario!=='service-failed-controlled';
    const nonce = crypto.randomBytes(16).toString('hex'), plan = await adapter.originalBuildPlan(root, nonce, pair ? {consumerMode:'v39-atomic-pair'} : serviceFailure?{consumerMode:'original-service'}:{});
    const fixture = await closurePacket(plan.binding), calls = [], original = Object.assign(Error('controlled primary'), { code: 'CONTROLLED_PRIMARY' });
    const artifact = path.join(process.env.TMPDIR, 'adapter-control-' + nonce);
    const mapped = value => typeof value === 'string' && (value === plan.spec.artifact || value.startsWith(plan.spec.artifact + '/'))
      ? artifact + value.slice(plan.spec.artifact.length) : value;
    const localRequire = require('node:module').createRequire(path.join(root, 'tests/postgres/ownedMcpOriginalBuildAdapter.js'));
    const module = { exports: {} };
    const pendingFilesystem = scenario.startsWith('pending-');
    let releaseFilesystem, heldPath, heldClosed;
    const closed = new Promise(resolve => { heldClosed = resolve; });
    const actualSource=await fs.readFile(path.join(root, 'tests/postgres/ownedMcpOriginalBuildAdapter.js'), 'utf8');
    // Execute the actual admitted entry; guest effects remain controlled runner
    // responses and never establish native qualification.
    // Isolated evaluated module only: substitute the physical executor with
    // fixed controlled phase observations, exercising the real provenance mint
    // branch. The normally imported module must reject every resulting error.
    const testSource=emulatedLive?actualSource.replace('const executePhase = createPhaseExecutor();','const executePhase = (...args) => controlledExecute(...args);'):actualSource;
    new Function('require', 'module', 'exports', 'setTimeout', 'controlledExecute', testSource)(
      id => id==='./ownedMcpOriginalServiceProducer'&&(serviceFailure||pair)?{...localRequire(id),consume:args=>localRequire(id).consume({...args,
        relayFactory:()=>({listen:async()=>({address:'127.0.0.1',port:23456}),close:async()=>{}})})}:
      id === 'node:fs' ? {...require('node:fs'),openSync:(value,...args)=>require('node:fs').openSync(mapped(value),...args)} : id === 'node:fs/promises' ? { ...fs,
        realpath:async value=>{const actual=await fs.realpath(mapped(value));return actual===artifact?value:actual;},
        lstat:(value,...args)=>fs.lstat(mapped(value),...args),
        mkdir: (value, ...args) => fs.mkdir(mapped(value), ...args), open: async (value, ...args) => {
        const handle = await fs.open(mapped(value), ...args);
        if (scenario === 'journal' && value.endsWith('-build-stderr.log')) handle.sync = async () => { throw Object.assign(Error('controlled fsync failure'), { code: 'CONTROLLED_SYNC' }); };
        const suffix = scenario === 'pending-record' ? '-registryProfileInstall-intent.json' : '-registryProfileInstall-stderr.log';
        if (pendingFilesystem && value.endsWith(suffix)) {
          heldPath = mapped(value);
          const method = scenario === 'pending-sync' ? 'sync' : 'writeFile';
          const actual = handle[method].bind(handle), actualClose = handle.close.bind(handle);
          // The production call has started and its real filesystem promise
          // remains unresolved across terminal publication. Release later to
          // prove the bytes can arrive late: the receipt MUST report debt.
          handle[method] = async (...input) => { await new Promise(resolve => { releaseFilesystem = resolve; }); return actual(...input); };
          handle.close = async () => { try { return await actualClose(); } finally { heldClosed(); } };
        }
        return handle;
      } } : localRequire(id), module, module.exports,
      // Only the evaluated controlled module's timers are scaled. Production
      // source, plan budgets and remote uncertainty waits remain unchanged.
      (callback, milliseconds, ...args) => setTimeout(callback,
        pendingFilesystem && [120000, adapter._internals.REGISTRY_RETIREMENT_MS].includes(milliseconds) ? 25 : milliseconds, ...args),
      (...args)=>runner(...args));
    const controlledAdapter = module.exports;
    t.after(() => fs.rm(artifact, { recursive: true, force: true }));
    let consumed = false,serviceToken;
    const runner = async (_plan, name, options) => {
      calls.push(name);
      if(scenario==='service-failed-cleanup'&&name==='cleanup')throw Error('controlled cleanup debt');
      await options.diagnosticSink(Buffer.from('controlled ' + name + ' diagnostic\n'));
      if (scenario === name || ['journal', 'semantic-replay'].includes(scenario) && name === 'build' || scenario === 'retirement' && name === 'retireArtifacts') throw original;
      if (name === 'inventory') return inventory;
      if (name === 'inspect') return JSON.stringify({ ID: 'controlled-private-daemon', DockerRootDir: plan.spec.mount + '/data', Driver: 'overlay2', Architecture: 'arm64' });
      if (name === 'metadataFetch') {
        if (scenario === 'metadata') return JSON.stringify({ ...fixture.envelope, version: 2, ok: false, candidate: null, errorCode: 'METADATA_SOURCE_INVALID' });
        return JSON.stringify(fixture.envelope);
      }
      if (name === 'startArtifacts') return JSON.stringify(fixture.ready);
      if (name === 'closureEvidence') {
        const packet = structuredClone(fixture.packet);
        if (calls.includes('retireArtifacts') && scenario === 'terminal') packet['replay-terminal.json'] = '{}';
        if (calls.includes('retireArtifacts') && scenario === 'semantic-replay') {
          const r = JSON.parse(packet['replay-terminal.json']); r.failure = 'REPLAY_TLS';
          r.firstFailure = { version: 1, cause: r.failure, counters: { requests: 1, connections: 1, bytes: 1, active: 1 } };
          packet['replay-terminal.json'] = JSON.stringify(r);
          packet['replay-failure.json'] = JSON.stringify({ binding: plan.binding, ...r.firstFailure });
        }
        return JSON.stringify(packet);
      }
      if (name === 'image') return JSON.stringify([{ Id: 'sha256:' + '1'.repeat(64), Architecture: 'arm64', Os: 'linux',
        Config: { Labels: { 'owasp-ai-goat.registry.package': plan.packageDigest, 'owasp-ai-goat.build-run': nonce } } }]);
      if (name === 'handoff') return JSON.stringify({ version: 1, target: 'original-v23-registry', runId: nonce, privateDockerHost: 'unix://' + plan.spec.socket,
        namespaceInode: 'net:[123]', filesystemIdentity: { device: 12, inode: 34 }, daemonProcess: { pid: 20, startTicks: '100', exe: '/usr/bin/dockerd' },
        namespaceHolder: { pid: 21, startTicks: '99', exe: '/usr/bin/sleep' } });
      if (name === 'evidence') return JSON.stringify({ controlled: true });
      if (name === 'registryCreate') return JSON.stringify([registryRow(nonce)]);
      if (name === 'registryStart') { assert.ok(options.signal); return registryResult(); }
      if (name === 'registryRetire' || name === 'registryProfileRetire') return 'absent\n';
      if (name === 'serviceCreate') {
        let raw='';for await(const part of options.input)raw+=part;serviceToken=JSON.parse(raw).token;
        return JSON.stringify([serviceContainer(plan,{runId:nonce,imageId:'sha256:'+'1'.repeat(64)},serviceToken)]);
      }
      if (['serviceStart','serviceInspect'].includes(name))return JSON.stringify([serviceContainer(plan,{runId:nonce,imageId:'sha256:'+'1'.repeat(64)},serviceToken,true)]);
      if(name==='serviceReadiness')return JSON.stringify({ready:true,runtimeDigest:'c'.repeat(64)});
      if(name==='serviceHealth'){
        let raw='';for await(const part of options.input)raw+=part;const q=JSON.parse(raw);
        const body=q.path==='/health'?{version:1,ready:true,isolation:'owned-mcp-registry-v1',registryCapability:'secureshop-owned-mcp-registry.v1',runtimeDigest:'c'.repeat(64)}:
          {version:1,instanceId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',runtimeDigest:'c'.repeat(64),...(q.path==='/registration/health'?{registrationCapability:'owned-mcp-registration-v1'}:{})};
        return JSON.stringify({status:200,body});
      }
      if(name==='serviceCohortClaim')return JSON.stringify({version:1,target:'v39-atomic-pair-total-lease-v1',runId:nonce,phase:'cohort',startedAtMs:1000,deadlineMs:11000});
      if(name==='serviceRetire'||name==='serviceProfileRetire')return 'absent\n';
      if (name === 'retainedExport') { await options.sink(Buffer.from('controlled archive bytes, not qualification')); return ''; }
      if (name === 'cleanup' || name === 'retireArtifacts') return 'absent\n';
      return '';
    };
    const before = process.listenerCount('SIGTERM');
    const execute = scenario === 'registry' || pendingFilesystem ? controlledAdapter.withOriginalRegistryFixture : controlledAdapter.withPrivateBuiltImage;
    const outerDeadline=performance.now()+60000;
    const claimOptions={root,runId:nonce,expectedPlanSha256:adapter.planDigest(plan),outerDeadline};
    let thrown;
    const work = execute({ ...claimOptions, ...(emulatedLive?{}:{runner}), verifyHost: async () => {},
      ...(serviceFailure?{consumerMode:'original-service'}:{}),
      ...(pair?{consumerMode:'v39-atomic-pair',workDeadline:performance.now()+10000}:{}),
      consumer: async (handoff, lifetime) => {
        if(serviceFailure){consumed=true;if(scenario==='service-failed-signal')process.emit('SIGTERM');throw original;}
        if(pair){
          consumed=true;
          const channel={send:async()=>{},read:async op=>op==='window'?{}:{childAbsent:true,browserAbsent:scenario!=='pair-debt',postgresAbsent:scenario!=='pair-debt',passed:true}};
          return require('./postgres/ownedMcpOriginalServiceProducer').pairCohort(channel,handoff);
        }
        consumed = true; assert.equal(handoff.controlled, true); assert.equal(lifetime.signal.aborted, false);
        assert.ok(Object.isFrozen(handoff.daemonProcess)); assert.ok(Object.isFrozen(handoff.filesystemIdentity));
        assert.ok(calls.indexOf('retireArtifacts') < calls.indexOf('handoff'));
        assert.throws(() => adapter.assertLiveHandoff(handoff), { code: 'ORIGINAL_BUILD_HANDOFF_NOT_LIVE' });
        lifetime.confirmRetired(); // This controlled consumer owns no resources.
        if (scenario === 'consumer') throw original;
        if (scenario === 'signal') process.emit('SIGTERM');
        return 'controlled callback';
      } });
    if (['success', 'registry', 'pair-success'].includes(scenario)) {
      const result = await work.catch(error => { throw Error(JSON.stringify(error.errors?.map(item => ({ code: item.code, message: item.message, stack: item.stack })))); });
      if (scenario === 'registry') {
        assert.equal(result.result.controlled, true); assert.equal(result.result.qualificationComplete, false);
        assert.ok(calls.indexOf('registryStart') < calls.indexOf('registryRetire'));
        assert.ok(calls.indexOf('registryProfileRetire') < calls.indexOf('stop'));
      } else if(pair){assert.equal(result.result.value.assemblyRetired,true);assert.ok(calls.indexOf('serviceProfileRetire')<calls.indexOf('stop'));}
      else assert.equal(result.result, 'controlled callback');
      assert.equal(result.receipt.cleanupVerified, true);
    }
    else await assert.rejects(work, error => {
      thrown=error;
      assert.ok(error instanceof AggregateError);
      if (['build', 'semantic-replay', 'consumer', 'retirement'].includes(scenario)) assert.ok(error.errors.includes(original));
      if (scenario === 'journal') {
        const combined = error.errors.find(item => item instanceof AggregateError);
        assert.ok(combined.errors.includes(original)); assert.ok(combined.errors.some(item => item.code === 'CONTROLLED_SYNC'));
      }
      return true;
    });
    assert.equal(process.listenerCount('SIGTERM'), before);
    const receipt = JSON.parse(await fs.readFile(path.join(artifact, 'result.json'), 'utf8'));
    assert.equal(receipt.controlled, !emulatedLive); assert.equal(receipt.qualificationComplete, false);
    if(serviceFailure){
      await assert.rejects(adapter.claimFailedRetirement(thrown,original,claimOptions),{code:'ORIGINAL_BUILD_FAILED_RETIREMENT_REQUIRED'});
      const claim=(error=thrown,failure=original,opts=claimOptions)=>controlledAdapter.claimFailedRetirement(error,failure,opts);
      if(scenario==='service-failed-tampered'){
        const file=path.join(artifact,'result.json'),raw=await fs.readFile(file,'utf8');
        await fs.writeFile(file,raw.replace('CONTROLLED_PRIMARY','CONTROLLED_CHANGED'));
        await assert.rejects(claim(),{code:'ORIGINAL_BUILD_FAILED_RETIREMENT_CHANGED'});
      }else if(scenario==='service-failed-retired'){
        assert.equal(receipt.error,'CONTROLLED_PRIMARY');assert.equal(receipt.cleanupVerified,true);
        for(const options of [{...claimOptions,runId:'0'.repeat(32)},{...claimOptions,expectedPlanSha256:'0'.repeat(64)},
          {...claimOptions,outerDeadline:outerDeadline+1},{...claimOptions,outerDeadline:performance.now()-1}])await assert.rejects(claim(thrown,original,options));
        await assert.rejects(claim(Object.assign(Error('forged'),{cleanupVerified:true,receipt}),original));
        await assert.rejects(claim(thrown,Error('same text')));
        const proof=await claim();assert.equal(proof.cleanupVerified,true);
        assert.equal(proof.sourceSha256,adapter.sourceBindingDigest(plan));
        assert.equal(proof.producerReceipt.sha256,digest(await fs.readFile(path.join(artifact,'result.json'))));
        assert.equal(proof.runId,nonce);assert(Object.isFrozen(proof));await assert.rejects(claim());
      }else await assert.rejects(claim());
    }
    if (pendingFilesystem) {
      assert.equal(receipt.cleanupVerified, false);
      assert.equal(receipt.consumerJournal.sealed, false);
      assert.equal(receipt.consumerJournal.pendingOperations, 1);
      assert.ok(receipt.cleanupErrors.includes('ORIGINAL_BUILD_CONSUMER_JOURNAL_UNJOINED'));
      assert.ok(receipt.cleanupErrors.includes('ORIGINAL_BUILD_CONSUMER_RETIREMENT_UNPROVEN'));
      assert.ok(!calls.includes('stop') && !calls.includes('cleanup'));
      assert.equal(typeof releaseFilesystem, 'function');
      const terminalBytes = await fs.readFile(path.join(artifact, 'result.json'));
      const names = await fs.readdir(artifact), heldBefore = await fs.readFile(heldPath);
      releaseFilesystem(); await closed; await new Promise(resolve => setImmediate(resolve));
      const heldAfter = await fs.readFile(heldPath);
      if (scenario !== 'pending-sync') { assert.equal(heldBefore.length, 0); assert.ok(heldAfter.length > 0); }
      assert.deepEqual(await fs.readFile(path.join(artifact, 'result.json')), terminalBytes);
      assert.deepEqual(await fs.readdir(artifact), names);
      assert.ok(!calls.includes('registryProfileRetire'));
    } else assert.deepEqual(receipt.consumerJournal, { sealed: true, pendingOperations: 0 });
    if (scenario === 'semantic-replay') { assert.equal(receipt.cleanupVerified, true); assert.equal(receipt.error, 'CONTROLLED_PRIMARY'); assert.ok(calls.includes('cleanup')); }
    assert.equal(consumed, serviceFailure||['success', 'consumer', 'signal', 'cleanup','pair-success','pair-debt'].includes(scenario));
    if(scenario==='pair-debt'){
      assert.equal(receipt.cleanupVerified,false);assert.ok(receipt.cleanupErrors.includes('ORIGINAL_BUILD_CONSUMER_RETIREMENT_UNPROVEN'));
      assert.ok(!calls.includes('serviceRetire')&&!calls.includes('stop')&&!calls.includes('cleanup'));
    }
    if (scenario === 'retirement') { assert.equal(receipt.cleanupVerified, false); assert.ok(!calls.includes('stop')); assert.ok(!calls.includes('cleanup')); }
    if (scenario === 'terminal') assert.equal(receipt.buildCompleted, false);
    const logs = (await fs.readdir(artifact)).filter(name => name.endsWith('-stderr.log'));
    assert.ok(logs.length > 0); assert.match(await fs.readFile(path.join(artifact, logs[0]), 'utf8'), /^controlled inventory diagnostic/);
    if (scenario === 'success') {
      const archive = JSON.parse(await fs.readFile(path.join(artifact, 'metadata-archive.json'), 'utf8'));
      assert.equal(archive.sha256, digest(await fs.readFile(path.join(artifact, archive.file))));
      assert.equal(JSON.parse(await fs.readFile(path.join(artifact, 'image-handoff.json'), 'utf8')).handoff.controlled, true);
    }
  }
});
test('serialized guest enforces ordering and joins replay on APT/publication failure (controlled dependencies, no signature claim)', async () => {
  for (const scenario of ['success', 'retained-read', 'npm-source-mismatch', 'apt-failure', 'apt-close-failure', 'acquisition-failure', 'publication-failure', 'replay-listen-failure', 'replay-listen-publication-debt']) {
    const fixture = await closurePacket(), { envelope, npmLock } = fixture, files = new Map(), services = [], commands = [], timers = new Set();
    const keyring = Buffer.from('controlled keyring, not a signing authority'), status = Buffer.from('controlled base status'), index = Buffer.from('controlled expanded index');
    const c = envelope.candidate;
    c.keyringSha256 = digest(keyring); c.installedStatusSha256 = digest(status);
    c.indices = [{ name: 'controlled_Packages.lz4', bytes: index.length, sha256: digest(index) }]; c.releaseFreshness = [];
    c.retainedMetadata.objects = [['keyring', keyring], ['installed-status', status], ['upstream', index]].map(([kind, bytes]) => ({ kind,
      url: kind === 'upstream' ? 'http://deb.debian.org/debian/dists/trixie/main/binary-arm64/Packages.xz' : null,
      file: 'objects/' + digest(bytes), sha256: digest(bytes), bytes: bytes.length }));
    for (const bytes of [keyring, status, index]) files.set('/metadata-retained/objects/' + digest(bytes), bytes);
    files.set('/metadata-retained/result.json', Buffer.from(JSON.stringify(envelope)));
    files.set('/metadata-retained/manifest.json', Buffer.from(JSON.stringify(c.retainedMetadata)));
    files.set(c.keyringPath, keyring); files.set('/var/lib/dpkg/status', status); files.set('/metadata/lists/controlled_Packages.lz4', index);
    for (const file of envelope.sourceSnapshot.files) files.set(file.path, Buffer.from(file.text));
    for (const file of Object.keys(replay.NPM_UPDATE_POLICY.sources)) files.set('/usr/local/lib/node_modules/npm/' + file, Buffer.from('controlled source read'));
    const fakeFs = {
      realpath: async value => value, mkdir: async () => {},
      link: async (from, to) => { assert.ok(files.has(from)); assert.ok(!files.has(to)); files.set(to, files.get(from)); },
      unlink: async name => { files.delete(name); }, readFile: async name => {
        assert.ok(files.has(name), name); return files.get(name);
      }, writeFile: async (name, bytes) => { files.set(name, Buffer.from(bytes)); },
      open: async (name, flags) => {
        if (scenario === 'retained-read' && name === '/metadata-retained/result.json') throw Object.assign(Error('read denied'), { code: 'EACCES' });
        if (scenario === 'publication-failure' && name === '/closure/npm-ca.pem.partial') throw Object.assign(Error('disk full'), { code: 'ENOSPC' });
        return { close: async () => {}, sync: async () => {
          if (scenario === 'replay-listen-publication-debt' && name === '/closure' && files.has('/closure/replay-terminal.json')) throw Object.assign(Error('directory fsync failed'), { code: 'EIO' });
        }, writeFile: async bytes => { files.set(name, Buffer.from(bytes)); },
          readFile: async () => files.get(name), stat: async () => ({ isFile: () => true, nlink: 1, uid: 0,
            mode: name.startsWith('/usr/local/lib/node_modules/npm/') ? 0o644 : 0o444, size: files.get(name)?.length, mtimeMs: 1, ctimeMs: 1 }) };
      }
    };
    const processDouble = new EventEmitter(); Object.assign(processDouble, { env: { OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS: '100', OWASP_AI_GOAT_ARTIFACT_PROXY_PORT: '12345' },
      hrtime: { bigint: () => 0n }, stderr: { write() {} }, kill() { throw Error('Unexpected real process authority'); } });
    const spawnDouble = (file, args) => {
      commands.push({ file, args }); const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
      queueMicrotask(() => {
        let text = '';
        if (file === '/usr/bin/apt-get' && args.includes('install')) {
          const packages = args.slice(args.indexOf('install') + 1), stage = c.retainedMetadata.stages.find(row => JSON.stringify(row.packages) === JSON.stringify(packages));
          assert.ok(stage); text = args.includes('--simulate') ? stage.simulation : stage.selection;
        } else if (file === '/usr/bin/apt-cache') {
          const row = c.retainedMetadata.stages.flatMap(stage => stage.selected).find(row => `${row.name}=${row.version}` === args.at(-1));
          assert.ok(row); text = `Package: ${row.name}\nVersion: ${row.version}\nArchitecture: ${row.architecture}\nFilename: ${row.filename}\nSHA256: ${row.sha256}\nSize: ${row.bytes}\n`;
        } else if (file === '/usr/lib/apt/apt-helper') text = 'controlled expansion';
        child.stdout.end(text); child.stderr.end(); child.emit('close', scenario.startsWith('apt-') && args.includes('update') ? 100 : 0, null);
      }); return child;
    };
    let acquired = false;
    const metadata = require('./postgres/ownedPolicySystemMetadata');
    const dependencies = {
      ownedPolicySystemMetadata: { ...metadata, validateResultEnvelope: () => envelope, validateRetainedMetadata: () => c.retainedMetadata },
      ownedMcpDependencyClosure: { ...closure, acquireArtifacts: async options => {
        assert.equal(options.budgetProfile, closure.ORIGINAL_BUILD_PROFILE);
        assert.ok(commands.some(row => row.file === '/usr/bin/apt-cache')); assert.equal(services[0].closed, true); acquired = true;
        if (scenario === 'acquisition-failure') throw Object.assign(Error('controlled reset'), { code: 'ECONNRESET', closureTransport: 'body',
          closureArtifact: { index: 51, kind: 'npm', algorithm: 'sha512', digest: 'a'.repeat(128), stage: 'body' } });
        return JSON.parse(fixture.packet['closure.json']).receipt;
      }, artifactReader: () => async () => { throw Error('No real replay request authorized in this control'); } },
      ownedMcpArtifactReplay: { NPM_UPDATE_POLICY: replay.NPM_UPDATE_POLICY, FIFO_POLICY: replay.FIFO_POLICY,
        // The separate replay controls validate actual retained source hashes;
        // this controlled seam proves guest placement and bounded file reads.
        verifyNpmUpdateSources: async read => {
          assert.equal(commands.length, 0); assert.equal(acquired, false);
          for (const file of Object.keys(replay.NPM_UPDATE_POLICY.sources)) assert.equal((await read('/usr/local/lib/node_modules/npm/' + file)).toString(), 'controlled source read');
          if (scenario === 'npm-source-mismatch') throw Object.assign(Error('source mismatch'), { code: 'REPLAY_NPM_SOURCE' });
          return replay.expectedNpmSourceWitness();
        }, createReplayBudget: () => ({}), replayCertificate: () => ({ key: Buffer.from('controlled'), cert: Buffer.from('controlled') }),
        createReplay: options => {
          if (services.length === 1) { assert.equal(options.npmUpdatePolicy, replay.NPM_UPDATE_POLICY.id); assert.deepEqual(options.npmSourceWitness, replay.expectedNpmSourceWitness()); assert.equal(options.admissionPolicy, replay.FIFO_POLICY.id); }
          else assert.equal(options.npmUpdatePolicy, undefined);
          let first = null, notify; const service = { closed: false,
          firstFailure: new Promise(resolve => { notify = resolve; }), failureRecord: () => first,
          state: () => ({ failure: first?.cause || null }), listen: async () => {
            if (services.length === 2 && scenario.startsWith('replay-listen-')) {
              first = { version: 1, cause: 'REPLAY_LISTEN', counters: { requests: 0, connections: 0, bytes: 0, active: 0 } };
              notify(first); throw Object.assign(Error('listen failed'), { code: 'REPLAY_LISTEN' });
            }
            return { host: '127.0.0.1', port: 12346 };
          }, close: async () => {
          service.closed = true;
          if (scenario === 'apt-close-failure') throw Object.assign(Error('controlled close rejection'), { code: 'CONTROLLED_CLOSE' });
          return { firstFailure: first, failure: first?.cause || null, absenceVerified: true, active: 0, closed: true, offlineOnly: true, qualificationComplete: false };
        } }; services.push(service); return service; } }
    };
    const requireDouble = id => id === 'node:fs/promises' ? fakeFs : id === 'node:child_process' ? { spawn: spawnDouble } : require(id);
    const invoke = new Function('require', 'process', 'load', 'binding', 'lock', 'setTimeout', 'clearTimeout',
      'const createReplayFinalizer=' + adapter._internals.createReplayFinalizer.toString() + ';return (' + adapter._internals.guestMain.toString() + ')(load,binding,lock,"original-v23-registry");');
    const work = invoke(requireDouble, processDouble, name => dependencies[name], envelope.binding, npmLock.toString('base64'),
      callback => { const token = { callback }; timers.add(token); return token; }, token => timers.delete(token));
    if (scenario === 'success') {
      await work; assert.equal(acquired, true); assert.ok(files.has('/closure/ready.json'));
      assert.equal(services[1].closed, false); processDouble.emit('SIGTERM');
      await new Promise(resolve => setImmediate(resolve)); assert.equal(services[1].closed, true); assert.ok(files.has('/closure/replay-terminal.json'));
    } else {
      await assert.rejects(work, error => {
        assert.equal(error.code, { 'retained-read': 'EACCES', 'npm-source-mismatch': 'REPLAY_NPM_SOURCE', 'apt-failure': 'ORIGINAL_BUILD_APT_FAILED', 'apt-close-failure': 'ORIGINAL_BUILD_APT_FAILED', 'acquisition-failure': 'ECONNRESET', 'publication-failure': 'ENOSPC', 'replay-listen-failure': 'REPLAY_LISTEN', 'replay-listen-publication-debt': 'REPLAY_LISTEN' }[scenario]);
        if (scenario === 'apt-close-failure') assert.ok(error.cleanupErrors.includes('CONTROLLED_CLOSE'));
        assert.equal(error.diagnostic.guestStage, { 'retained-read': 'retained-input', 'npm-source-mismatch': 'npm-policy-source', 'apt-failure': 'apt-authentication', 'apt-close-failure': 'apt-authentication', 'acquisition-failure': 'artifact-acquisition', 'publication-failure': 'publication', 'replay-listen-failure': 'frozen-replay', 'replay-listen-publication-debt': 'frozen-replay' }[scenario]);
        if (['acquisition-failure', 'publication-failure'].includes(scenario) || scenario.startsWith('replay-listen-')) {
          assert.deepEqual(error.diagnostic.authenticationWitness.binding, envelope.binding);
          assert.equal(error.diagnostic.authenticationWitness.method, 'original-base-apt-closed-replay');
          assert.equal(error.diagnostic.authenticationWitness.retainedManifestSha256, digest(files.get('/metadata-retained/manifest.json')));
        } else assert.equal(error.diagnostic.authenticationWitness, null);
        if (scenario === 'acquisition-failure') { assert.equal(error.diagnostic.transport, 'body'); assert.equal(error.diagnostic.artifact.index, 51); }
        assert.ok(Buffer.byteLength(JSON.stringify(error.diagnostic)) < 4096);
        return true;
      });
      assert.ok(services.every(service => service.closed)); assert.ok(!files.has('/closure/ready.json'));
      assert.equal(acquired, ['acquisition-failure', 'publication-failure'].includes(scenario) || scenario.startsWith('replay-listen-'));
      if (scenario.startsWith('replay-listen-')) {
        assert.ok(files.has('/closure/replay-failure.json')); assert.ok(files.has('/closure/replay-terminal.json'));
        assert.equal(processDouble.exitCode, scenario === 'replay-listen-publication-debt' ? 2 : 1);
      }
      assert.equal(processDouble.listenerCount('SIGTERM'), 0); assert.equal(processDouble.listenerCount('SIGINT'), 0);
    }
    assert.equal(timers.size, 0);
  }
});
test('replay failure automatically persists first cause and terminal without SIGTERM; racing retirement joins once', async () => {
  const binding = { runId }, events = [], records = new Map(); let notify, first = null, release, closeCalls = 0, report;
  const writeBarrier = new Promise(resolve => { release = resolve; });
  const service = { firstFailure: new Promise(resolve => { notify = resolve; }), failureRecord: () => first,
    state: () => ({ failure: first?.cause || null }), close: async () => {
      events.push('close'); closeCalls++;
      return { requests: 5, connections: 5, bytes: 10, active: 0, closed: true, absenceVerified: true,
        failure: first?.cause || null, firstFailure: first, offlineOnly: true, qualificationComplete: false };
    } };
  const finish = adapter._internals.createReplayFinalizer(service, async (name, bytes) => {
    events.push(name); if (name === 'replay-failure.json') await writeBarrier;
    assert.ok(!records.has(name)); records.set(name, JSON.parse(bytes));
  }, binding, result => { report = result; });
  first = Object.freeze({ version: 1, cause: 'REPLAY_REQUEST_LIMIT', counters: Object.freeze({ requests: 5, connections: 5, bytes: 10, active: 5 }) });
  notify(first); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(events, ['replay-failure.json']); assert.equal(closeCalls, 0);
  const signalRace = finish(); assert.equal(finish(), signalRace);
  release(); const result = await signalRace;
  assert.equal(closeCalls, 1); assert.equal(result, report); assert.equal(result.absenceVerified, true);
  assert.equal(result.failure, 'REPLAY_REQUEST_LIMIT');
  assert.deepEqual(events, ['replay-failure.json', 'close', 'replay-terminal.json']);
  assert.deepEqual(records.get('replay-failure.json'), { binding, ...first });
  assert.deepEqual(records.get('replay-terminal.json').firstFailure, first);
});
test('replay finalizer publication errors and unjoined work stay explicit debt with original cause', async () => {
  for (const scenario of ['first-write', 'terminal-write-after-visible', 'close-rejects', 'unjoined']) {
    const first = { version: 1, cause: 'REPLAY_TLS', counters: { requests: 0, connections: 1, bytes: 0, active: 0 } };
    const records = new Map(); let closed = 0;
    const service = { firstFailure: Promise.resolve(first), failureRecord: () => first,
      state: () => ({ failure: first.cause }), close: async () => {
        closed++; if (scenario === 'close-rejects') throw Error('private failure text');
        return { failure: first.cause, firstFailure: first, closed: true, active: 0, absenceVerified: scenario !== 'unjoined' };
      } };
    const finish = adapter._internals.createReplayFinalizer(service, async (name, bytes) => {
      if (name === 'replay-failure.json' && scenario === 'first-write') throw Error('disk failed');
      records.set(name, JSON.parse(bytes));
      if (name === 'replay-terminal.json' && scenario === 'terminal-write-after-visible') throw Error('directory fsync failed');
    }, { runId }, () => {});
    const result = await finish(); assert.equal(closed, 1); assert.equal(result.failure, 'REPLAY_TLS');
    assert.equal(result.absenceVerified, false); assert.doesNotMatch(JSON.stringify(result), /private|disk failed|directory fsync/);
    if (scenario !== 'unjoined') assert.ok(result.publicationErrors.length);
    if (scenario === 'terminal-write-after-visible') {
      assert.deepEqual(records.get('replay-terminal.json').publicationErrors, []);
      assert.deepEqual(result.publicationErrors, ['ORIGINAL_BUILD_REPLAY_TERMINAL_PUBLICATION']);
    }
  }
});
test('bounded finalizer deadline reports debt and does not publish a late terminal', async () => {
  let fire, resolveClose, clears = 0; const writes = [];
  const create = new Function('setTimeout', 'clearTimeout', 'return (' + adapter._internals.createReplayFinalizer.toString() + ');')(
    (callback, delay) => { assert.equal(delay, 5000); fire = callback; return 1; }, () => { clears++; });
  const service = { firstFailure: new Promise(() => {}), failureRecord: () => null, state: () => ({ failure: null }),
    close: () => new Promise(resolve => { resolveClose = resolve; }) };
  const finish = create(service, async name => { writes.push(name); }, { runId }, () => {});
  const pending = finish(); await new Promise(resolve => setImmediate(resolve)); fire();
  const result = await pending;
  assert.equal(result.absenceVerified, false); assert.equal(result.finalizerComplete, false);
  assert.deepEqual(result.publicationErrors, ['ORIGINAL_BUILD_REPLAY_FINALIZER_TIMEOUT']); assert.equal(clears, 1);
  resolveClose({ failure: null, absenceVerified: true }); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(writes, []); assert.equal(finish(), pending);
});
test('failed replay can prove retirement but never successful build; missing or contradictory records remain debt', async () => {
  const { packet, ready, envelope, npmLock } = await closurePacket();
  const terminal = JSON.parse(packet['replay-terminal.json']);
  terminal.failure = 'REPLAY_REQUEST_LIMIT'; terminal.requests = 5; terminal.connections = 5;
  terminal.firstFailure = { version: 1, cause: terminal.failure, counters: { requests: 5, connections: 5, bytes: 1, active: 5 } };
  packet['replay-terminal.json'] = JSON.stringify(terminal);
  packet['replay-failure.json'] = JSON.stringify({ binding: envelope.binding, ...terminal.firstFailure });
  const validate = (value, allowFailedReplay = true) => adapter._internals.validateClosureEvidence(value, ready, envelope, npmLock, { terminal: true, allowFailedReplay });
  assert.ok(validate(packet)); assert.throws(() => validate(packet, false), { code: 'ORIGINAL_BUILD_REPLAY_FAILED' });
  for (const change of [x => x['replay-failure.json'] = null, x => x['replay-intent.json'] = null,
    x => x['replay-terminal.json'] = null,
    x => { const r = JSON.parse(x['replay-terminal.json']); r.publicationErrors = ['ORIGINAL_BUILD_REPLAY_FAILURE_PUBLICATION']; x['replay-terminal.json'] = JSON.stringify(r); },
    x => { const r = JSON.parse(x['replay-terminal.json']); r.firstFailure.cause = 'secret'; x['replay-terminal.json'] = JSON.stringify(r); }]) {
    const bad = structuredClone(packet); change(bad); assert.throws(() => validate(bad));
  }
});
test('unlisted first-request identity is required, bounded and joined through failure and terminal records', async () => {
  const replay = require('./postgres/ownedMcpArtifactReplay');
  const { packet, ready, envelope, npmLock } = await closurePacket();
  const terminal = JSON.parse(packet['replay-terminal.json']);
  terminal.failure = 'CLOSURE_UNLISTED_URL'; terminal.requests = 1; terminal.connections = 1;
  const diagnosticUrls = JSON.parse(packet['closure.json']).receipt.artifacts.flatMap(row => row.urls);
  const declaredNpm = diagnosticUrls.find(url => url.startsWith('https://registry.npmjs.org/'));
  const packageUrl = declaredNpm.slice(0, declaredNpm.indexOf('/-/'));
  terminal.firstFailure = { version: 1, cause: terminal.failure, counters: { requests: 1, connections: 1, bytes: 1, active: 1 },
    request: replay._internals.requestIdentity(packageUrl, diagnosticUrls) };
  const update = value => {
    const copy = structuredClone(packet); copy['replay-terminal.json'] = JSON.stringify(value);
    copy['replay-failure.json'] = JSON.stringify({ binding: envelope.binding, ...value.firstFailure }); return copy;
  };
  const validate = value => adapter._internals.validateClosureEvidence(value, ready, envelope, npmLock, { terminal: true, allowFailedReplay: true });
  assert.ok(validate(update(terminal)));
  for (const edit of [x => delete x.firstFailure.request, x => x.firstFailure.request.path = '/different',
    x => x.firstFailure.request.urlSha256 = '0'.repeat(64), x => x.firstFailure.request.pathBytes = 4097,
    x => x.firstFailure.request.host = 'private.example', x => x.firstFailure.request.headers = { secret: 'value' },
    x => { x.failure = x.firstFailure.cause = 'REPLAY_TLS'; }]) {
    const bad = structuredClone(terminal); edit(bad); assert.throws(() => validate(update(bad)), { code: 'ORIGINAL_BUILD_REPLAY_TERMINAL' });
  }
  const mismatched = update(terminal), failed = JSON.parse(mismatched['replay-failure.json']);
  failed.request = replay._internals.requestIdentity('https://registry.npmjs.org/other');
  mismatched['replay-failure.json'] = JSON.stringify(failed); assert.throws(() => validate(mismatched));
  const fallback = structuredClone(terminal);
  fallback.firstFailure.request = replay._internals.requestIdentity('https://registry.npmjs.org/arbitrary/private/path');
  assert.equal(fallback.firstFailure.request.path, null); assert.ok(validate(update(fallback)));
  const forged = structuredClone(terminal);
  forged.firstFailure.request = structuredClone(replay._internals.requestIdentity('https://registry.npmjs.org/unknown-secret-name'));
  forged.firstFailure.request.path = '/unknown-secret-name';
  assert.throws(() => validate(update(forged)), { code: 'ORIGINAL_BUILD_REPLAY_TERMINAL' });
});
test('terminal policy binds actual source witness and one denial without pretending to serve metadata', async () => {
  const { packet, ready, envelope, npmLock } = await closurePacket();
  const terminal = JSON.parse(packet['replay-terminal.json']);
  terminal.npmUpdate.denials = [{ version: 1, sequence: 1, requestOrdinal: 1, method: 'GET',
    url: replay.NPM_UPDATE_POLICY.url, decision: 'local-deny', status: 403, bodyBytes: 0 }];
  const validate = value => adapter._internals.validateClosureEvidence(value, ready, envelope, npmLock, { terminal: true });
  const update = value => ({ ...packet, 'replay-terminal.json': JSON.stringify(value) });
  assert.ok(validate(update(terminal)));
  for (const edit of [x => delete x.tlsRetirement, x => x.tlsRetirement.pendingHandshakes = 1,
    x => x.tlsRetirement.unjoinedTlsSockets = 1, x => x.tlsRetirement.callbackDebt = 1,
    x => delete x.tlsRetirement.diagnostics, x => x.tlsRetirement.diagnostics.events = 4097,
    x => x.tlsRetirement.diagnostics.closeRequested = 0, x => x.tlsRetirement.diagnostics.decisions['owner-branded'] = 1,
    x => x.tlsRetirement.establishedSockets = 1, x => x.tlsRetirement.ownerIntents = 1,
    x => x.tlsRetirement.firstError = { code: 'ECONNRESET', phase: 'owner-retiring', ownerError: true },
    x => delete x.admission, x => x.admission.policy = 'strict', x => x.admission.pending = 1,
    x => x.admission.peakPending = 12, x => x.admission.peakPending = -1, x => x.admission.extra = true,
    x => delete x.npmUpdate, x => x.npmUpdate.policy = 'strict', x => x.npmUpdate.sourceWitness.npmVersion = '11.16.0',
    x => x.npmUpdate.sourceWitness.sources['lib/cli/update-notifier.js'] = '0'.repeat(64),
    x => x.npmUpdate.denials.push(x.npmUpdate.denials[0]), x => x.npmUpdate.denials[0].status = 200,
    x => x.npmUpdate.denials[0].bodyBytes = 1, x => x.npmUpdate.denials[0].requestOrdinal = 2,
    x => x.npmUpdate.denials[0].url += '?extra', x => x.npmUpdate.denials[0].method = 'HEAD']) {
    const bad = structuredClone(terminal); edit(bad); assert.throws(() => validate(update(bad)), { code: 'ORIGINAL_BUILD_REPLAY_TERMINAL' });
  }
  const intent = JSON.parse(packet['replay-intent.json']); delete intent.npmSourceWitness;
  assert.throws(() => validate({ ...update(terminal), 'replay-intent.json': JSON.stringify(intent) }));
});
test('actual emitted build readiness binds selected target and rejects foreign or unsafe evidence', async t => {
  const directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'build-ready-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  // Preserve real type/mode/size/link checks; only the local UID is controlled.
  const prefix = 'import os\noriginal=os.fstat\nclass S:\n def __init__(self,s):self.s=s;self.st_uid=0\n def __getattr__(self,k):return getattr(self.s,k)\nos.fstat=lambda fd:S(original(fd))\n';
  const closureBytes = Buffer.from('controlled exact closure bytes\n'), caBytes = Buffer.from('controlled exact CA bytes\n');
  for (const target of ['v23-registry', 'listings-package']) {
    const plan = await adapter.originalBuildPlan(root, runId, target === 'listings-package'
      ? { target, listingsMode: 'manager' } : {});
    // Decode the manager lease shell's POSIX-quoted body without executing it.
    const command = target === 'listings-package' ? plan.commands.build.replaceAll("'\\''", "'") : plan.commands.build;
    const programs = [...command.matchAll(/<<'OWASP_AI_GOAT_CLOSURE_READY'\n([\s\S]*?)\nOWASP_AI_GOAT_CLOSURE_READY/g)];
    assert.equal(programs.length, 1);
    const script = programs[0][1];
    for (const fault of ['none', 'cross-target', 'run', 'base', 'binding-extra', 'closure-hash', 'ca-hash',
      'mode', 'symlink', 'hardlink', 'uid', 'host', 'port', 'port-bool', 'metadata', 'approved', 'ready-extra']) {
      const location = path.join(directory, target + '-' + fault);
      await fs.mkdir(location, { mode: 0o700 });
      const ready = { version: 1, binding: { ...plan.binding }, authority: { host: '127.0.0.1', port: 12345 },
        closureSha256: digest(closureBytes), npmCaSha256: digest(caBytes),
        artifactBytesVerified: true, metadataAuthenticated: true, buildApproved: false };
      if (fault === 'cross-target') ready.binding.target = target === 'v23-registry' ? 'listings-package' : 'v23-registry';
      if (fault === 'run') ready.binding.runId = '0'.repeat(32);
      if (fault === 'base') ready.binding.base = 'sha256:' + '0'.repeat(64);
      if (fault === 'binding-extra') ready.binding.extra = true;
      if (fault === 'host') ready.authority.host = '192.0.2.1';
      if (fault === 'port') ready.authority.port = 65536;
      if (fault === 'port-bool') ready.authority.port = true;
      if (fault === 'metadata') ready.metadataAuthenticated = false;
      if (fault === 'approved') ready.buildApproved = true;
      if (fault === 'ready-extra') ready.extra = true;
      await fs.writeFile(path.join(location, 'closure.json'), fault === 'closure-hash' ? Buffer.from('changed') : closureBytes, { flag: 'wx', mode: 0o400 });
      await fs.writeFile(path.join(location, 'npm-ca.pem'), fault === 'ca-hash' ? Buffer.from('changed') : caBytes, { flag: 'wx', mode: 0o400 });
      const file = path.join(location, 'ready.json');
      await fs.writeFile(file, JSON.stringify(ready), { flag: 'wx', mode: fault === 'mode' ? 0o600 : 0o400 });
      if (fault === 'symlink') { await fs.rename(file, file + '.target'); await fs.symlink(file + '.target', file); }
      if (fault === 'hardlink') await fs.link(file, file + '.linked');
      const controlledPrefix = fault === 'uid' ? prefix.replace('self.st_uid=0', 'self.st_uid=12345') : prefix;
      const result = spawnSync(process.env.PYTHON || 'python3',
        ['-I', '-S', '-B', '-c', controlledPrefix + script, location, runId],
        { cwd: root, encoding: 'utf8', timeout: 10000, maxBuffer: 16384,
          env: { ...process.env, TMPDIR: path.join(root, 'tasks/tmp'), PYTHONDONTWRITEBYTECODE: '1' } });
      assert.ifError(result.error);
      assert.equal(result.signal, null, target + ':' + fault + ':unexpected signal');
      assert.equal(result.status, fault === 'none' ? 0 : 1, target + ':' + fault + ':' + result.stderr);
      if (fault === 'none') assert.equal(result.stderr, '');
      else if (fault === 'symlink') assert.match(result.stderr, /\nOSError: \[Errno (?:40|62)\]/);
      else assert.match(result.stderr, /\nAssertionError(?:\n|:|$)/);
      assert.equal(result.stdout, fault === 'none' ? '12345\n' : '', target + ':' + fault);
      if (target === 'listings-package' && fault === 'none') {
        const currentTarget = "'target':\"listings-package\"";
        assert.equal(script.split(currentTarget).length, 2);
        // Reproduce the old defect only in memory against the same valid files.
        const baseline = spawnSync(process.env.PYTHON || 'python3',
          ['-I', '-S', '-B', '-c', prefix + script.replace(currentTarget, "'target':'v23-registry'"), location, runId],
          { cwd: root, encoding: 'utf8', timeout: 10000, maxBuffer: 16384,
            env: { ...process.env, TMPDIR: path.join(root, 'tasks/tmp'), PYTHONDONTWRITEBYTECODE: '1' } });
        assert.ifError(baseline.error); assert.equal(baseline.signal, null);
        assert.equal(baseline.status, 1); assert.equal(baseline.stdout, '');
        assert.match(baseline.stderr, /\nAssertionError(?:\n|:|$)/);
      }
    }
  }
});
test('actual emitted owner exit gate rejects post-link publication debt even when terminal bytes look clean', async t => {
  const plan = await adapter.originalBuildPlan(root, runId);
  const script = /<<'OWASP_AI_GOAT_REPLAY_EXIT'\n([\s\S]*?)\nOWASP_AI_GOAT_REPLAY_EXIT/.exec(plan.commands.retireArtifacts)[1];
  const directory = await fs.mkdtemp(path.join(process.env.TMPDIR, 'replay-exit-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  // Host controlled fixture only: preserve real file mode/type/link/size/time
  // checks, substitute uid0 for the local test user's file. No guest authority.
  const prefix = `import os\noriginal=os.fstat\nclass S:\n def __init__(self,s):self.s=s;self.st_uid=0\n def __getattr__(self,k):return getattr(self.s,k)\nos.fstat=lambda fd:S(original(fd))\n`;
  const { packet } = await closurePacket();
  for (const [name, failure, exit, edit] of [
    ['clean', null, '0', () => {}], ['failed', 'REPLAY_TLS', '1', () => {}],
    ['clean-wrong-exit', null, '1', () => {}], ['failed-publication-debt', 'REPLAY_TLS', '2', () => {}],
    ['killed', null, '137', () => {}], ['incomplete', null, '0', r => { r.finalizerComplete = false; }],
    ['publication', 'REPLAY_TLS', '1', r => { r.publicationErrors = ['ORIGINAL_BUILD_REPLAY_TERMINAL_PUBLICATION']; }],
    ['unjoined', null, '0', r => { r.absenceVerified = false; }]]) {
    const target = path.join(directory, name); await fs.mkdir(target, { mode: 0o700 });
    const record = JSON.parse(packet['replay-terminal.json']); record.binding.runId = runId; record.failure = failure; edit(record);
    await fs.writeFile(path.join(target, 'replay-terminal.json'), JSON.stringify(record), { flag: 'wx', mode: 0o400 });
    const result = spawnSync('/opt/homebrew/bin/python3', ['-I', '-S', '-B', '-c', prefix + script, target, runId, exit], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status === 0, ['clean', 'failed'].includes(name), name);
  }
  const catchSource = plan.guestSource.slice(plan.guestSource.lastIndexOf('.catch(error=>')) + ');';
  for (const [initial, cleanupErrors, expected] of [[2, [], 2], [0, ['debt'], 2], [0, [], 1]]) {
    const processDouble = { exitCode: initial, stderr: { write() {} } };
    // Execute the exact generated outer rejection handler, not a copied rule.
    const execute = new Function('process', 'error', 'return Promise.reject(error)' + catchSource.slice(0, -2));
    await execute(processDouble, { code: 'ORIGINAL_BUILD_REPLAY_FAILED', cleanupErrors });
    assert.equal(processDouble.exitCode, expected);
  }
});
