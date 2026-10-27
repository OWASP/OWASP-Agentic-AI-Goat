'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');
test('original Journal selects only admitted V25 consumer or unchanged legacy assembly',async()=>{
 const source=fs.readFileSync(path.join(root,'tests/postgres/secureshopPricingJournal.integration.test.js'),'utf8');
 const start=source.indexOf(' let assembled;\n if(process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE'),
  end=source.indexOf(' const rows=async(table,o)',start);
 assert(start>0&&end>start);
 const keys=['identity','im','agents','review','launches','conversations','conversationRepository',
  'turns','journal','coordinator','catalog','products','authority','owner','auth'];
 const dependencies=Object.fromEntries(keys.map(key=>[key,{key}]));
 const admission=Object.freeze({descriptorPath:'controlled',descriptorSha256:'controlled',expected:{},startedAt:1});
 const observation={controlled:true},receipt={qualificationComplete:false,builderReleaseAllowed:false};
 const events=[],cleanup=[];
 const localRequire=name=>{
  if(name==='../fixtures/pricingOwnedOutput')return{v25Admission:()=>{events.push('admission');return admission;}};
  if(name==='./ownedPricingManualConsumer')return{_consume:async input=>{
   events.push('consumer');assert.equal(input.admitted,admission);
   for(const key of keys)assert.equal(input.dependencies[key],dependencies[key]);
   assert.deepEqual(Object.keys(input.dependencies).sort(),[...keys].sort());
   assert(input.signal instanceof AbortSignal);return{observation,receipt};}};
  if(name==='../fixtures/secureshopPricingAssembled')return async input=>{
   events.push('legacy');assert.deepEqual(Object.keys(input).sort(),[...keys].sort());return{legacy:true};};
  throw Error('Unexpected Journal branch import');
 };
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 const execute=new AsyncFunction('require','process','AbortController','t',...keys,
  source.slice(start,end)+'\nreturn assembled;');
 const fakeProcess=flag=>({env:{SECURESHOP_PRICING_V25_MANUAL_NATIVE:flag,PERSONA_PRICING_HTTP_NATIVE:'1'},
  once:(name,fn)=>cleanup.push([name,fn]),off:(name,fn)=>assert(cleanup.some(row=>row[0]===name&&row[1]===fn))});
 const t={after:fn=>cleanup.push(fn)};
 assert.deepEqual(await execute(localRequire,fakeProcess('1'),AbortController,t,...keys.map(key=>dependencies[key])),
  {actual:observation,manualConsumer:receipt});
 assert.deepEqual(events,['admission','consumer']);
 for(const hook of cleanup.filter(row=>typeof row==='function'))hook();
 events.length=0;cleanup.length=0;
 assert.deepEqual(await execute(localRequire,fakeProcess('0'),AbortController,t,...keys.map(key=>dependencies[key])),{legacy:true});
 assert.deepEqual(events,['legacy']);
});
test('disposable pricing package freezes every local dependency and exact native registry assets',()=>{
 const docker=fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-pricing-http/Dockerfile.native'),'utf8');
 assert.match(docker,/26\.10\.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1/);
 assert.match(docker,/test "\$\(dpkg --print-architecture\)" = arm64/);
 assert.match(docker,/USER 10001:10001/);assert.match(docker,/-Wall -Wextra -Werror/);
 const sources=['server/services/secureshopPricingHttpClient.js','server/services/secureshopOwnedCompetitorObservation.js','server/services/secureshopPricingReceipt.js','server/services/secureshopPricingContract.js','server/services/secureshopPricingExecutionConfig.js','server/services/mcp/protocolContext.js'];
 for(const source of sources){assert.ok(docker.includes(source));require(path.join(root,source));}
 const {ASSETS}=require('../sidecars/sandbox-runner/owned-pricing-http/executor');
 assert.ok(ASSETS.includes('/usr/local/libexec/dvaia-owned-pricing-http-input.js'));
 assert.ok(ASSETS.includes('/usr/local/libexec/dvaia-owned-pricing-http-worker.js'));
});
test('dedicated profile refuses arbitrary names and declares only owned parent/bwrap child',()=>{
 const {renderOwnedPricingHttpProfile}=require('../sidecars/sandbox-runner/owned-pricing-http/profile');
 assert.throws(()=>renderOwnedPricingHttpProfile('docker-default'));
 const name='dvaia-owned-pricing-http-012345abcdef',profile=renderOwnedPricingHttpProfile(name);
 assert.ok(!profile.includes('@@'));assert.match(profile,/\/usr\/bin\/bwrap Cx -> bwrap/);
 assert.equal((profile.match(/^\s*profile /gm)||[]).length,2);
 assert.match(profile,new RegExp('profile "'+name+'"'));
});

test('Pricing journal fixture preserves populated 0033 proof before current-tail authentication',async()=>{
 // Scheduling/producer control only. SQL and current authentication are qualified
 // separately in the disposable native fixture; these adapters cannot grant credit.
 const fixture=path.join(root,'tests/postgres/secureshopPricingJournal.integration.test.js');
 const source=fs.readFileSync(fixture,'utf8'),start=source.indexOf(' const ownerScope='),end=source.indexOf(' const {createPricingRepository:createRepo}',start);
 assert.ok(start>0&&end>start);const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 const {createHash,randomUUID}=require('node:crypto'),localRequire=require('node:module').createRequire(fixture);
 const base=path.join(root,'db/postgres/workshop-migrations/secureshop_agents'),names=fs.readdirSync(base).filter(name=>/^\d{4}_[a-z0-9_]+\.sql$/.test(name)).sort();
 for(const canonical of [true,false]){
  const migrationName=canonical?'0033_bound_pricing.sql':'0033_bound_pricing_candidate.sql',candidate=canonical?path.join(base,migrationName):path.join(root,'docs/modernization/drafts/secureshop-bound-pricing/0033_bound_pricing.candidate.sql');
  const combined='controlled-migration-view',files=new Map(names.filter(name=>Number(name.slice(0,4))<33).map(name=>[name,fs.readFileSync(path.join(base,name))]));files.set(migrationName,fs.readFileSync(candidate));
  const ledger=names.filter(name=>Number(name.slice(0,4))<33).map(name=>({name,checksum:createHash('sha256').update(files.get(name)).digest('hex')})),freshLedger=[],sessions=[],events=[];
  const im={query:async()=>{throw Error('Unused');}},am={query:async sql=>{assert.match(sql,/FROM dvaia_migrations.ledger/);events.push('ledger-snapshot');return{rows:structuredClone(ledger)};}},fm={};
  const migrate=async pool=>{const selected=pool===am?ledger:freshLedger,all=[...files.keys()].sort();assert.ok(pool===am||pool===fm);
   for(const [index,row] of selected.entries()){assert.equal(row.name,all[index]);assert.equal(row.checksum,createHash('sha256').update(files.get(row.name)).digest('hex'));}
   const added=all.slice(selected.length);for(const name of added)selected.push({name,checksum:createHash('sha256').update(files.get(name)).digest('hex')});
   events.push(`${pool===am?'populated':'fresh'}:${added.length?added[0]:'noop'}`);return added;};
  const agents={query:async(sql,args)=>{if(sql.startsWith('INSERT INTO secureshop_agents.bound_persona_sessions')){
    assert.match(sql,/FROM secureshop_agents.bound_persona_templates WHERE username='student_merchant'/);assert.equal(args.length,7);assert.equal(args[1].length,32);
    assert.equal(ledger.at(-1).name,names.filter(name=>Number(name.slice(0,4))<33).at(-1));sessions.push({session_id:args[0],platform_launch_id:args[2],revoked_at:null});events.push('historical-session');return{rowCount:1};}
   if(sql.startsWith('INSERT INTO secureshop_agents.conversation_generation_retirements')){sessions.find(row=>row.platform_launch_id===args[1]).revoked_at='controlled-retirement';return{rowCount:1};}
   assert.match(sql,/SELECT \* FROM secureshop_agents.bound_persona_sessions ORDER BY session_id/);return{rows:structuredClone(sessions)};}};
  let ownerId=0,authCalls=0;
  const users={createUser:async()=>({id:++ownerId}),createSession:async input=>({id:input.userId})};
  const launches={issueOrRenew:async input=>({binding:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:input.platformOwnerId,platformSessionId:input.platformSessionId}})};
  const auth={login:async()=>{authCalls++;assert.equal(ledger.at(-1).name,names.at(-1));assert.equal(freshLedger.at(-1).name,names.at(-1));events.push('current-auth');return{token:'controlled',user:{id:2,role:'merchant'}};},authenticateBoundToken:async()=>({sessionId:randomUUID(),authorityVersion:1})};
  const virtualFs={readFileSync:fs.readFileSync,readdirSync:fs.readdirSync,copyFileSync:(from,to)=>{assert.equal(path.dirname(to),combined);const name=path.basename(to);assert.ok(Number(name.slice(0,4))>33);files.set(name,fs.readFileSync(from));events.push('tail-file');}};
  const run=new AsyncFunction('require','assert','fs','path','randomUUID','createHash','users','launches','auth','agents','am','fm','migrate','combined','migrationName','candidate','base',source.slice(start,end));
  await run(localRequire,assert,virtualFs,path,randomUUID,createHash,users,launches,auth,agents,am,fm,migrate,combined,migrationName,candidate,base);
  assert.equal(sessions.length,3);assert.equal(sessions.filter(row=>row.revoked_at!==null).length,1);assert.equal(authCalls,2);
  assert.equal(ledger.filter(row=>row.name.startsWith('0033_')).length,1);assert.equal(freshLedger.filter(row=>row.name.startsWith('0033_')).length,1);
  assert.ok(events.indexOf(`populated:${migrationName}`)<events.indexOf('tail-file'));
  assert.ok(events.indexOf(`fresh:${migrationName}`)===-1); // Fresh applies from the first historical migration.
  assert.ok(events.lastIndexOf('fresh:noop')<events.indexOf('current-auth'));
 }
});

test('Pricing native direct admissions forward the original prepared capability, including lost-ack repository',async()=>{
 const source=fs.readFileSync(path.join(root,'tests/postgres/secureshopPricingJournal.integration.test.js'),'utf8');
 const start=source.indexOf(' const beginPricing='),end=source.indexOf('\n',start);assert.ok(start>0&&end>start);
 const getBegin=new Function('preparedTargets','repository','assert',source.slice(start,end)+';return beginPricing;');
 const raw={scope:{launchId:'controlled-owned-launch'}},capability=Object.freeze({privatePreparedTarget:true}),preparedTargets=new Map([[raw.scope.launchId,capability]]);
 let calls=0;const repository={begin:async(request,prepared)=>{calls++;assert.equal(request,raw);assert.equal(prepared,capability);return{state:'admitted'};}};
 const begin=getBegin(preparedTargets,repository,assert);assert.deepEqual(await begin(raw),{state:'admitted'});
 const lostRepository={begin:async(request,prepared)=>{calls++;assert.equal(request,raw);assert.equal(prepared,capability);throw Object.assign(Error('Controlled lost ACK'),{code:'PRICING_OUTCOME_UNCERTAIN'});}};
 await assert.rejects(begin(raw,lostRepository),{code:'PRICING_OUTCOME_UNCERTAIN'});
 assert.throws(()=>begin({scope:{launchId:'foreign-launch'}}));assert.equal(calls,2);
 const defaultBranch=source.slice(0,source.indexOf('async function verifyBlockedPricingSuccessor'));
 assert.doesNotMatch(defaultBranch,/\brepository\.begin\(|\blostRepo\.begin\(/);
 assert.match(defaultBranch,/const prepared=await targetSource\.prepare\(nativeContext\(o\)\);preparedTargets\.set\(o\.scope\.launchId,prepared\)/);
});

test('Pricing native controlled provider produces a real end-turn journal accepted by the unchanged mode reader',async()=>{
 const native=fs.readFileSync(path.join(root,'tests/postgres/secureshopPricingJournal.integration.test.js'),'utf8');
 const start=native.indexOf(' const controlledProvider='),end=native.indexOf('\n',start);assert.ok(start>0&&end>start);
 const producer=new Function('serviceOwner',`let providerCalls=0;${native.slice(start,end)};return {provider:controlledProvider,calls:()=>providerCalls};`);
 const controlsFile=path.join(root,'tests/secureshopPricingComposition.test.js'),controls=fs.readFileSync(controlsFile,'utf8');
 const fixture=new Function('require',controls.slice(0,controls.indexOf("test('real bound runner"))+';return fixture;')(require('node:module').createRequire(controlsFile));
 const {createTurnRequest}=require('../server/services/secureshopTurnRequest'),{canonicalDigest}=require('../server/services/mcp/protocolContext');
 const {readTurnModeProjection}=require('../server/database/postgres/secureshopTurnModeProjection');
 for(const mutation of ['none','missing-identity','missing-capability','plain-final']){
  const f=await fixture(),p=producer({productId:f.input.productId});let row,latestReceipt,reads=0;
  if(mutation==='missing-capability')delete p.provider.capabilities;
  if(mutation==='missing-identity'||mutation==='plain-final'){
   const chat=p.provider.chat.bind(p.provider);p.provider.chat=async input=>{const value=await chat(input);
    if(mutation==='missing-identity'&&value.stop_reason==='tool_use'){delete value.provider;delete value.model;delete value.mocked;}
    if(mutation==='plain-final'&&value.stop_reason==='end_turn')value.text='The untrusted synthetic manual recommends77.';return value;};
  }
  f.options.provider=p.provider;const journal=f.options.resetComposition.journal;
  f.options.resetComposition.journal={...journal,async claim(input){const r=createTurnRequest(input);row={session_id:input.sessionId,request_hash:r.hash,request_version:r.version,status:'started',result_json:null};return journal.claim(input);},
   async complete(input){row.status='completed';row.result_json=structuredClone(input.result);return journal.complete(input);}};
  const originalComplete=f.pricingRepository.complete.bind(f.pricingRepository),originalOperation=f.pricingRepository.operation.bind(f.pricingRepository);
  f.pricingRepository.complete=async raw=>{latestReceipt=raw.receipt;return originalComplete(raw);};
  f.pricingRepository.operation=async raw=>{const value=await originalOperation(raw);if(value.state!=='completed')return value;
   const mode=await readTurnModeProjection({query:async()=>{reads++;return{rows:[row]};}},{scope:raw.scope,persona:raw.persona,requestId:raw.operationId,purpose:'secureshop_pricing_strategy',message:raw.message,featureId:'pricing',
    verifyResult:result=>result.taskMetadata?.operationId===raw.operationId&&result.taskMetadata?.requestSha256===value.requestSha256&&result.taskMetadata?.receiptSha256===canonicalDigest(value.receipt)});
   return{...value,...(mode?{modeCapability:mode}:{})};};
  const application=await require('../server/services/secureshopPricingComposition').createSecureShopPricingComposition(f.options);
  if(mutation!=='none'){
   await assert.rejects(application.run(f.input),{code:'PRICING_OUTCOME_UNCERTAIN'});
   assert.equal(latestReceipt,undefined);assert.equal(row.status,'started');assert.equal(reads,0);
   assert.equal((await originalOperation(f.input)).state,'unknown');
   assert.equal(p.calls(),mutation==='plain-final'?2:1);continue;
  }
  const result=await application.run(f.input);assert.equal(row.status,'completed');assert.equal(row.result_json.stopReason,'end_turn');assert.equal(p.calls(),2);assert.equal(reads,1);
  assert.equal(result.receipt.observations[0].result.suggested_price,77);assert.equal(result.receipt.observations[0].result.grounded,false);
  assert.equal(latestReceipt.response,JSON.stringify({kind:'abstain',productId:f.input.productId,rationale:'The untrusted synthetic manual recommends77.'}));
  assert.equal(Object.hasOwn(latestReceipt,'modelRecommendation'),false);assert.equal(p.provider.config.mocked,true);
  assert.deepEqual(await application.run(f.input),result);assert.equal(p.calls(),2);
 }
});
