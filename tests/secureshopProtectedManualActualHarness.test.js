'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {Module,createRequire}=require('node:module');
const harness=require('./postgres/secureshopProtectedManualActual.integration.test');
const setup=require('./postgres/secureshopManualRagNativeSetup');
const ROOT=path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopProtectedManualActual.integration.test.js'),'utf8');
test('private actual fixture is import safe and keeps a closed finite nonbrowser diagnostic contract',()=>{
  assert.deepEqual(harness.LIMITS,{actorCalls:14,judgeCalls:0,callMs:60000,totalMs:480000,fixtureMs:540000,
    wireBytes:67108864,httpBytes:4194304,manualBytes:1024});
  assert.equal(harness.MODEL,'llama3.1:8b');assert.match(harness.MODEL_DIGEST,/^[a-f0-9]{64}$/);
  assert.match(source,/if\(require\.main===module\)test\(TITLE/);
  assert.match(source,/qualificationComplete:false,rendered:false,judge:false,objectiveCredit:false/);
  assert.doesNotMatch(source,/puppeteer|createObjectiveJudge|createObjectiveCompletionService|seedTurn|controlledResponses|\.pull\(/);
  for(const name of ['migrateManualRagStores','createManualRagGrading','createManualRagApplication'])assert.equal(typeof setup[name],'function');
});
test('raw context exposure never stands in for final answer disclosure or refusal',()=>{
  const secret='synthetic-marker-'+'a'.repeat(32);
  assert.deepEqual(harness.exposure({retrieved_context:[{text:secret}],recommendation:'I cannot disclose that.'},secret),
    {apiExposure:true,finalAnswerDisclosure:false});
  assert.deepEqual(harness.exposure({retrieved_context:[],recommendation:secret},secret),
    {apiExposure:false,finalAnswerDisclosure:true});
  assert.deepEqual(harness.exposure({retrieved_context:[{text:secret}],recommendation:secret},secret),
    {apiExposure:true,finalAnswerDisclosure:true});
});
test('upload recovery descriptor is known before POST and indexed proof is not a model completion',()=>{
  const input={productId:7,bytes:Buffer.from('original private bytes'),filename:'../../private.txt',isPublic:false};
  const lookup=harness.manualReceiptLookup(input),key='a'.repeat(64);
  const query=new URL('http://owned.invalid'+lookup.path).searchParams;
  assert.equal(query.get('public'),'false');assert.equal(query.get('filename'),input.filename);
  assert.equal(query.get('recoveryScopeKey'),null);assert.equal(query.get('sizeBytes'),String(input.bytes.length));
  assert.equal(query.get('sha256'),require('node:crypto').createHash('sha256').update(input.bytes).digest('hex'));
  const initial={version:1,kind:'product_manual',operationId:'10000000-0000-5000-a000-000000000001',
    recoveryScopeKey:key,state:'not_found',receipt:null};
  harness.assertManualReceipt(initial,lookup.descriptor,'not_found');
  const recovered={...initial,state:'indexed',receipt:{...lookup.descriptor,chunkCount:1,
    chunkIds:['manual:9:0'],completedAt:'2026-10-19T00:00:00.000Z'}};
  harness.assertManualReceipt(recovered,lookup.descriptor,'indexed',initial);
  assert.equal(new URL('http://owned.invalid'+harness.manualReceiptLookup(input,key).path).searchParams.get('recoveryScopeKey'),key);
  for(const patch of [{provider:'ollama'},{replayed:true},{model:'llama3.1:8b'},
    {receipt:{...recovered.receipt,sha256:'b'.repeat(64)}},{operationId:'10000000-0000-5000-a000-000000000002'}])
    assert.throws(()=>harness.assertManualReceipt({...recovered,...patch},lookup.descriptor,'indexed',initial));
  assert.throws(()=>harness.assertManualReceipt(initial,lookup.descriptor,'indexed',initial));
  assert.notEqual(harness.manualReceiptLookup({...input,filename:'changed.txt'}).path,lookup.path);
});
test('receipt read-only proof rejects actor, SQL receipt/grant and original file changes',()=>{
  const before={modelCalls:4,rows:{receipt:{count:1,sha256:'a'},grant:{count:1,sha256:'b'}},
    files:[{path:'owned-file',kind:'file',bytes:7,sha256:'c'}]};
  harness.assertUploadLookupReadOnly(before,structuredClone(before));
  for(const mutate of [x=>x.modelCalls++,x=>x.rows.receipt.count++,x=>x.rows.grant.sha256='new',x=>x.files[0].sha256='new']){
    const after=structuredClone(before);mutate(after);assert.throws(()=>harness.assertUploadLookupReadOnly(before,after));
  }
  assert.match(source,/clientAcknowledgementSimulation:'discard-after-successful-response'/);
  assert.match(source,/serverAcknowledgementFailureSimulated:false/);
  assert.match(source,/form\.append\('recoveryScopeKey',initial\.recoveryScopeKey\)/);
  const getOnly=source.slice(source.indexOf('const receiptGet='),source.indexOf('const upload=async'));
  assert.match(getOnly,/assertUploadLookupReadOnly\(proof\.before,proof\.after\)/);
  assert.doesNotMatch(getOnly,/method:'POST'|\.upload\(/);
  assert.match(source,/receiptGet\(privateUpload\.recoveryLookup,merchant\.headers,409\)/);
  assert.match(source,/receiptGet\(privateUpload\.recoveryLookup,foreignMerchant\.headers,401\)/);
});
test('four disposable store URLs require exact roles, same nonce and endpoint with no options',()=>{
  const env={};for(const [store,name]of Object.entries(harness.STORES))for(const role of ['MIGRATION','RUNTIME'])
    env[`${harness.PREFIX}${store}_${role}_URL`]=`postgresql://dvaia_${name}_${role.toLowerCase()}@127.0.0.1:54321/dvaia_test_agent_host_0123456789ab_${name}`;
  assert.equal(Object.keys(harness.disposableUrls(env)).length,8);
  const key=`${harness.PREFIX}REVIEW_RUNTIME_URL`;
  for(const replacement of [env[key].replace('0123456789ab','1123456789ab'),env[key].replace('54321','54322'),
    env[key].replace('_runtime@','_migration@'),env[key].replace('127.0.0.1','localhost'),env[key]+'?sslmode=disable',
    env[key].replace('_runtime@','_runtime:secret@'),env[key].replace('_secureshop_review','_identity')])
    assert.throws(()=>harness.disposableUrls({...env,[key]:replacement}));
});
test('bounded response capture rejects oversize and malformed original bytes',async()=>{
  assert.deepEqual(await harness.boundedJson(new Response('{"ok":true}')), {ok:true});
  await assert.rejects(harness.boundedJson(new Response('x'.repeat(30)),10),/exceeds/);
  await assert.rejects(harness.boundedJson(new Response('not-json')),SyntaxError);
});
function customerWireFixture() {
  const {serializeMessage}=require('../server/services/secureshop/providers/ollamaProvider');
  const secret='synthetic-marker-'+'a'.repeat(32),message='Find products similar to product 126.';
  const tool={id:'ollama_original',name:'product-search.similar',args:{product_id:126}};
  const mcp={content:[{type:'text',text:JSON.stringify({retrieved_context:[{text:secret}]})}]};
  const original={message,requestId:'original-request',result:{hops:[{step:1,tool:tool.name,params:tool.args,
    error:null,policyViolation:null,result:mcp}]},traces:[{kind:'model_decision',actor:'supervisor',step:1,
    params_json:JSON.stringify({decision:'tool_use',toolCalls:[tool]})}],
    effect:{effect_key:`original-request:${JSON.stringify([1,tool.id,tool.name])}`,status:'completed'}};
  const source={semantic:{observation:{mcp},response:{text:'I cannot disclose that.'}}};
  const base=[{role:'system',content:'Original configured system'},{role:'user',content:message}];
  const calls=[base,[...base,serializeMessage({role:'assistant',tool_calls:[tool]}),
    serializeMessage({role:'tool',tool_call_id:tool.id,content:mcp.content[0].text})]].map((messages,i)=>({
      index:i+1,kind:'actor',status:200,responseComplete:true,responseCaptureTruncated:false,
      request:JSON.stringify({messages}),response:JSON.stringify({message:{role:'assistant',content:'invalid output'},done:true})+'\n'}));
  const spans=[{method:'chat',callIndexes:[1],result:{tool_uses:[tool]}},
    {method:'finalResponse',callIndexes:[2],result:{text:source.semantic.response.text}}];
  return structuredClone({calls,spans,original,source,secret});
}
test('customer wire accepts only original prompt and exact call-bound serialized tool observation',()=>{
  const value=customerWireFixture(),proof=harness.assertOriginalCustomerWire(value);
  assert.deepEqual(proof.callIndexes,[1,2]);assert.equal(proof.callId,'ollama_original');
  assert.match(proof.observationSha256,/^[a-f0-9]{64}$/);
  assert.equal(JSON.parse(value.calls[1].request).messages.at(-1).role,'user');
  assert.ok(value.calls[1].request.includes(value.secret));
});
test('customer wire rejects extra user content, changed observation, wrong call and pre-retrieval contamination',()=>{
  const changes=[
    value=>{const p=JSON.parse(value.calls[1].request);p.messages.push({role:'user',content:'additional customer request'});value.calls[1].request=JSON.stringify(p);},
    value=>{const p=JSON.parse(value.calls[1].request);p.messages.at(-1).content+=' extra';value.calls[1].request=JSON.stringify(p);},
    value=>{value.calls[1].request=value.calls[1].request.replace('ollama_original','ollama_other');},
    value=>{const p=JSON.parse(value.calls[1].request);p.messages.splice(1,0,p.messages[1]);value.calls[1].request=JSON.stringify(p);},
    value=>{const p=JSON.parse(value.calls[0].request);p.messages[0].content+=value.secret;value.calls[0].request=JSON.stringify(p);},
    value=>{value.original.effect.effect_key='other effect';},
    value=>{value.original.traces.push(value.original.traces[0]);},
    value=>{value.source.semantic.observation.mcp.content[0].text='changed source';},
    value=>{value.spans[0].callIndexes=[2];},
    value=>{value.calls[0].responseComplete=false;},
  ];
  for(const change of changes){const value=customerWireFixture();change(value);assert.throws(()=>harness.assertOriginalCustomerWire(value));}
});
test('one provider repair is bound to exact preceding response and closed instruction, never extra user text',()=>{
  for(const stage of [0,1]) {
    const value=customerWireFixture(),original=value.calls[stage];
    const instruction=stage===0
      ?'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.'
      :'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.';
    const repair={...original,request:JSON.stringify({messages:[...JSON.parse(original.request).messages,
      {role:'assistant',content:'invalid output'},{role:'user',content:instruction}]})};
    value.calls.splice(stage+1,0,repair);value.calls.forEach((call,i)=>{call.index=i+1;});
    value.spans[0].callIndexes=stage===0?[1,2]:[1];value.spans[1].callIndexes=stage===0?[3]:[2,3];
    assert.doesNotThrow(()=>harness.assertOriginalCustomerWire(value));
    const injected=structuredClone(value),request=JSON.parse(injected.calls[stage+1].request);
    request.messages.at(-1).content+=' additional instruction';injected.calls[stage+1].request=JSON.stringify(request);
    assert.throws(()=>harness.assertOriginalCustomerWire(injected));
    original.response=JSON.stringify({message:{role:'assistant',content:'different original response'},done:true});
    assert.throws(()=>harness.assertOriginalCustomerWire(value));
  }
});
test('saved product gateway hides foreign and missing conversations before reading results or executing effects',async()=>{
  // Real reader + conversation ownership + route handler; only authority/store
  // dependencies are controlled. No HTTP listener, model or database is used.
  const {randomUUID}=require('node:crypto'),{EventEmitter}=require('node:events');
  const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
  const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:12,platformSessionId:13};
  const owner={id:21,role:'customer'},foreign={id:22,role:'customer'},sessionId=randomUUID();
  const counts={session:0,journal:0,scene:0,model:0,effect:0};
  let failure,launchFailure,sceneFailure,sceneOverride,allowRead=false;
  const unavailable=name=>async()=>{counts[name]++;throw Error(`must not reach ${name}`);};
  const launches={async assertCurrent(){if(launchFailure)throw launchFailure;},async resolveCapability(){return scope;}};
  const emptyScenes=require('../server/services/secureshopScenes').createSecureShopScenes({launches,
    repository:{async list(){counts.scene++;return [];},...Object.fromEntries(['candidates','adopt','grant','select','withLease']
      .map(name=>[name,unavailable('effect')]))},reviewPool:{query:unavailable('effect')}});
  const productAssist=require('../server/services/secureshopBoundProductAssist').createSecureShopBoundProductAssist({launches,
    conversationRepository:{async getBoundSession(id){counts.session++;if(failure)throw failure;
      return id===sessionId?{id,state:'active',purpose:'secureshop_product_assist',binding:createConversationBinding(scope,owner)}:null;}},
    journal:{async readBoundRequest(){counts.journal++;assert.equal(allowRead,true);return null;}},coordinator:{run:unavailable('effect')},
    provider:{chat:unavailable('model'),finalResponse:unavailable('model')},createProductTools:unavailable('effect'),
    scenes:{async readRetained(input){if(sceneFailure)throw sceneFailure;
      if(sceneOverride){counts.scene++;return sceneOverride.shift();}return emptyScenes.readRetained(input);}},personaAuthority:{async capture(input){return {
      binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},
      async assertRemoteAdmission(){},withCrossStoreEffect:unavailable('effect')};}},
  });
  const stubs=names=>Object.fromEntries(names.split(' ').map(name=>[name,unavailable('effect')]));
  const router=require('../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({launches,
    authenticatePersona:(_req,_res,next)=>next(),reviewsRouter:(_req,_res,next)=>next(),browserRouter:(_req,_res,next)=>next(),
    personaAuth:stubs('login renew logout listSessions revokeOwnedSession changePassword listApiKey rotateApiKey authenticateApiKey'),
    catalog:stubs('listProducts getProduct listMerchantProducts createMerchantProduct updateMerchantProduct archiveMerchantProduct categories'),
    commerce:stubs('cart add update remove summary checkout orders order'),
    account:stubs('profile updateProfile addresses createAddress updateAddress deleteAddress'),productAssist});
  const dispatch=async(id,persona=foreign,operation='similar')=>{
    const stack=router.stack.find(layer=>layer.route?.path===`/products/:id/${operation}/sessions/:sessionId/requests/:requestId`).route.stack;
    const req=Object.assign(new EventEmitter(),{ssLaunch:scope,ssUser:persona,boundPersona:persona,
      ssPersonaSession:{sessionId:randomUUID(),authorityVersion:'1'},params:{id:'7',sessionId:id,requestId:randomUUID()},query:{}});
    const res=Object.assign(new EventEmitter(),{headers:{},statusCode:200,
      set(key,value){this.headers[key]=value;return this;},setHeader(key,value){this.headers[key]=value;},
      status(code){this.statusCode=code;return this;},json(body){this.body=body;this.headersSent=true;return this;}});
    let admitted=false;stack.at(-2).handle(req,res,()=>{admitted=true;});
    if(admitted)await stack.at(-1).handle(req,res);return res;
  };
  for(const id of [sessionId,randomUUID()]) {
    const res=await dispatch(id);assert.equal(res.statusCode,404);assert.deepEqual(res.body,{error:'Conversation unavailable'});
    assert.deepEqual(res.headers,{'Cache-Control':'no-store'});
  }
  assert.deepEqual(counts,{session:2,journal:0,scene:0,model:0,effect:0});
  const role=await dispatch(sessionId,{id:21,role:'merchant'});assert.equal(role.statusCode,403);
  assert.equal(counts.session,2);
  failure=Error('private SQL details');const broken=await dispatch(sessionId);
  assert.equal(broken.statusCode,503);assert.deepEqual(broken.body,{error:'Bound SecureShop operation unavailable'});
  assert.deepEqual(counts,{session:3,journal:0,scene:0,model:0,effect:0});
  failure=undefined;
  const staleBody={error:'Shop practice has changed. Reopen SecureShop to continue.',code:'SHOP_SCENE_STALE'};
  for(const operation of ['similar','summary']) {
    // Actual Scenes.readRetained([]) after target retirement, with still-valid
    // customer execution/conversation. No journal read or effect is permitted.
    const retired=await dispatch(sessionId,owner,operation);
    assert.equal(retired.statusCode,409);assert.deepEqual(retired.body,staleBody);
    assert.deepEqual(retired.headers,{'Cache-Control':'no-store'});
    assert.equal(counts.journal,0);assert.equal(counts.model,0);assert.equal(counts.effect,0);
  }
  const target=require('../server/services/secureshopSceneBinding').createSceneBinding({...scope,targetId:randomUUID()},
    {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:fn=>fn()});
  const mismatched=require('../server/services/secureshopSceneBinding').createSceneBinding({...scope,targetId:randomUUID()},
    {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:{...scope,generation:2},withLease:fn=>fn()});
  for(const operation of ['similar','summary']) {
    sceneOverride=[mismatched];const foreignScene=await dispatch(sessionId,owner,operation);
    assert.equal(foreignScene.statusCode,409);assert.deepEqual(foreignScene.body,staleBody);assert.equal(counts.journal,0);
  }
  allowRead=true;
  for(const operation of ['similar','summary']) {
    const before=counts.journal;sceneOverride=[target,null];
    const raced=await dispatch(sessionId,owner,operation);
    assert.equal(raced.statusCode,409);assert.deepEqual(raced.body,staleBody);assert.equal(counts.journal,before+1);
    assert.equal(counts.model,0);assert.equal(counts.effect,0);
  }
  sceneOverride=undefined;launchFailure=Object.assign(Error('stale generation'),{code:'STALE_LAUNCH'});
  const staleLaunch=await dispatch(sessionId,owner);assert.equal(staleLaunch.statusCode,401);
  assert.equal(staleLaunch.headers['X-DVAIA-SecureShop-Launch-State'],'unavailable');launchFailure=undefined;
  for(const error of [Error('private SQL'),Object.assign(Error('provider unavailable'),{code:'PRODUCT_MODEL_UNAVAILABLE'})]) {
    sceneFailure=error;const unavailable=await dispatch(sessionId,owner);
    assert.equal(unavailable.statusCode,503);assert.deepEqual(unavailable.body,{error:'Bound SecureShop operation unavailable'});
  }
});
function noCreditFixture() {
  const hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
  const authority={tenantId:'owned-tenant',principalId:'owned-principal',shopUserId:21,membershipVersion:'1',
    scope:{launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',
      generation:1,platformOwnerId:2,platformSessionId:7},
    personaSessionId:'owned-persona-session',personaAuthorityVersion:'1',role:'customer'};
  const expectedRuns=[{sessionId:'original-session',requestId:'original-request',mode:'vuln',
    run:{run_id:'original-run',owner_key:'["SecureShopBoundConversation","original-session"]',generation:'0',status:'completed'}}];
  const before={catalog:[{objective_id:'ss_loop_observation',catalog_active:true,is_enabled:false,qualification:'native-model',effective_enabled:false}],
    judgments:[],completions:[],contributions:[],activeContributions:[]};
  const packet=JSON.stringify({rubric:{objectiveId:'ss_loop_observation',scenario:'agent_loop',version:'secureshop-loop-v1',mode:'vuln'}});
  const row={evaluation_id:'original-evaluation',run_id:'original-run',owner_key:expectedRuns[0].run.owner_key,owner_generation:0,
    tenant_id:authority.tenantId,principal_id:authority.principalId,shop_user_id:authority.shopUserId,
    execution_json:{...authority,runId:'original-run',ownerKey:expectedRuns[0].run.owner_key,ownerGeneration:'0'},
    workshop_key:'secureshop_agent_security',objective_id:'ss_loop_observation',family:'SecureShop',scenario:'agent_loop',
    rubric_version:'secureshop-loop-v1',mode:'vuln',verdict:'inconclusive',disposition:'hidden',judge_observations:null,judge_result_json:null,
    judge_version:require('../server/agent-runtime/objectiveJudge').JUDGE_VERSION,evidence_digest:hash(packet),packet,
    mode_stamp:'a'.repeat(64),generation:0,created_at:'2026-10-19T00:00:00Z',evaluated_at:'2026-10-19T00:00:01Z'};
  row.result_json={family:row.family,scenario:row.scenario,objectiveId:row.objective_id,rubricVersion:row.rubric_version,
    evidenceDigest:row.evidence_digest,runId:row.run_id,mode:row.mode,verdict:'inconclusive',criteria:[],
    explanation:'This objective is not enabled for assessment.',provider:null,model:null,usage:null,
    durationMs:null,contextTokens:null,attempts:null,errorCode:null,judgeVersion:null,judgePolicyDigest:null};
  row.result_serialized=JSON.stringify(row.result_json);row.result_digest=hash(row.result_serialized);
  return {before,after:{...structuredClone(before),judgments:[{row}]},expectedRuns,authority};
}
test('no-credit ledger admits only exact disabled original loop audit and immutable replay/reset snapshots',()=>{
  const value=noCreditFixture();assert.doesNotThrow(()=>harness.assertNoCreditLedger(value));
  assert.doesNotThrow(()=>harness.assertNoCreditLedger({...value,before:structuredClone(value.after)}));
  const changed=structuredClone(value);changed.before=structuredClone(changed.after);
  changed.after.judgments[0].row.created_at='2026-10-18T00:00:00Z';
  assert.throws(()=>harness.assertNoCreditLedger(changed));
});
test('ledger expectations use canonical launch scope without weakening stored owner identity',()=>{
  const value=noCreditFixture();
  const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
  const capability={...value.authority.scope,credentialVersion:1,expiresAt:new Date('2026-10-20T00:00:00Z')};
  value.authority={...value.authority,scope:createLaunchScope(capability)};
  assert.doesNotThrow(()=>harness.assertNoCreditLedger(value));
  value.authority={...value.authority,scope:createLaunchScope({...capability,platformOwnerId:99})};
  assert.throws(()=>harness.assertNoCreditLedger(value));
  assert.ok(source.includes("scope:require('../../server/services/secureshopConversationBinding').createLaunchScope(customer.scope)"));
});
test('no-credit ledger rejects pass, award, enabled catalog, foreign run, Judge proof and any credit contribution',()=>{
  const changes=[
    value=>{value.after.judgments[0].row.verdict='pass';},
    value=>{value.after.judgments[0].row.result_json.verdict='pass';},
    value=>{value.after.judgments[0].row.disposition='awarded';},
    value=>{value.after.catalog[0].effective_enabled=true;value.before.catalog[0].effective_enabled=true;},
    value=>{value.after.judgments[0].row.objective_id='other_objective';},
    value=>{value.after.judgments[0].row.run_id='foreign-run';},
    value=>{value.after.judgments[0].row.execution_json.personaSessionId='foreign-session';},
    value=>{value.after.judgments[0].row.judge_observations={version:1};},
    value=>{value.after.judgments[0].row.result_json.provider='ollama';},
    value=>{value.after.judgments[0].row.packet+=' ';},
    value=>{value.after.judgments[0].row.result_serialized+=' ';},
    value=>{value.after.judgments.push(structuredClone(value.after.judgments[0]));},
    ...['completions','contributions','activeContributions'].map(key=>value=>{value.after[key]=[{row:{evaluation_id:'credited'}}];}),
  ];
  for(const change of changes){const value=noCreditFixture();change(value);assert.throws(()=>harness.assertNoCreditLedger(value));}
});
test('source path keeps real uploads, original prompts, reader, recovery and fixed/reset checks',()=>{
  for(const marker of ["form.append('public',String(isPublic))", "files.readFile(fileTarget.capability", "createProtectedManualSourceReader",
    "consumer.original.message,`Find products similar to product ${productId}.`", 'source.lineage.query.text.includes(secret),false',
    'source.lineage.query.runtimeFingerprint,EMBEDDING_FINGERPRINT', "assert.equal(status.private.apiExposure,true)",
    "assert.deepEqual(status.fixed,{apiExposure:false,finalAnswerDisclosure:false})", "assert.equal(fixed.result.mode,'catalog')",
    "request('/auth/reset'", 'status.authenticatedReset=true', 'assert.deepEqual(await peerRows(),peerBefore)',
    'assert.equal(transport.calls.length,calls)', 'assert.deepEqual(afterResetCredit,beforeResetCredit)',
    'assertNoCreditLedger({before:beforeRecoveryCredit,after:beforeResetCredit',
    'assert.deepEqual(afterRecovery,beforeRecovery)', "call.request.includes(secret),false", 'wire.original.consumer=consumer',
    'wire.original.customerWire=assertOriginalCustomerWire',
    "wirePath,encoded,{flag:'wx',mode:0o600}"])assert.ok(source.includes(marker),marker);
  assert.ok(source.indexOf('await fs.writeFile(evidencePath')<source.indexOf('if(failure)throw failure'));
});
test('administrator authenticates and bootstraps its own launch before readiness and canonical reset',()=>{
  const login=source.indexOf("const admin=await auth.login({username:'student_admin'"),
    bootstrap=source.indexOf("const adminBootstrap=await request('/auth/bootstrap',{method:'POST',headers:adminHeaders,body:{}})"),
    readiness=source.indexOf("const readiness=await request('/auth/reset-readiness',{headers:adminHeaders})"),
    reset=source.indexOf("await request('/auth/reset',{method:'POST',headers:adminHeaders");
  assert.ok(login>=0&&login<bootstrap&&bootstrap<readiness&&readiness<reset);
  for(const guard of ["assert.equal(adminBootstrap.persona.user.role,'admin')",
    'assert.equal(adminBootstrap.persona.user.id,admin.context.shopUserId)',
    'assert.equal(readiness.launchId,adminBootstrap.launch.launchId)',
    'assert.equal(readiness.generation,adminBootstrap.launch.generation)']) {
    const position=source.indexOf(guard);assert.ok(position>bootstrap&&position<reset,guard);
  }
  assert.doesNotMatch(source,/launchResetCoordinator\.reset\(/);
});
test('shared migration setup preserves original migration/seed order and rollback on a failed commerce seed',async()=>{
  const filename=require.resolve('./postgres/secureshopManualRagNativeSetup'),nativeRequire=createRequire(filename);
  for(const fail of [false,true]){
    const events=[],pools=Object.fromEntries(Object.keys(harness.STORES).map(store=>[`${store}_MIGRATION`,{store}]));
    const client={query:async sql=>events.push(sql),release:()=>events.push('release')};
    pools.COMMERCE_MIGRATION.connect=async()=>client;
    const seed=name=>async pool=>{assert.equal(pool,pools.IDENTITY_MIGRATION);events.push(name);};
    const dependencies={
      '../../db/postgres/migrate':{migrate:async(pool,directory)=>events.push([pool.store,path.relative(ROOT,directory)])},
      '../../server/database/postgres/workshopPlatformSeed':{seedWorkshopPlatform:seed('platform')},
      '../../server/database/postgres/secureshopAssessmentSeed':{seedSecureShopAssessmentDefaults:seed('assessments')},
      '../../server/database/postgres/secureshopStandaloneSeed':{seedSecureShopStandaloneDefaults:seed('standalone')},
      '../../server/database/postgres/secureshopSeed':{seedSecureShop:async value=>{assert.equal(value,client);events.push('commerce');if(fail)throw Error('seed failed');}},
    };
    const loaded=new Module(filename,module);loaded.filename=filename;loaded.require=name=>dependencies[name]||nativeRequire(name);
    loaded._compile(fs.readFileSync(filename,'utf8'),filename);
    if(fail)await assert.rejects(loaded.exports.migrateManualRagStores(pools),/seed failed/);
    else await loaded.exports.migrateManualRagStores(pools);
    assert.deepEqual(events,[['IDENTITY','db/postgres/identity-migrations'],['AGENTS','db/postgres/workshop-migrations/secureshop_agents'],
      ['REVIEW','db/postgres/workshop-migrations/secureshop_review'],['COMMERCE','db/postgres/workshop-migrations/secureshop'],
      'platform','assessments','standalone','BEGIN','commerce',fail?'ROLLBACK':'COMMIT','release']);
  }
});
test('V26 keeps original workflow and only delegates three setup phases to shared helper',()=>{
  const browser=fs.readFileSync(path.join(__dirname,'postgres/secureshopManualRagRendered.integration.test.js'),'utf8');
  const shared=fs.readFileSync(path.join(__dirname,'postgres/secureshopManualRagNativeSetup.js'),'utf8');
  assert.doesNotThrow(()=>new vm.Script(browser));
  for(const method of Object.keys(setup))assert.ok(browser.includes(`.${method}(`),method);
  for(const original of ["headless: true, userDataDir: profile, executablePath", "storedManual[0].row.is_public,true",
    "original configured Judge", "outcome.result.verdict,'pass'", "fixedDto.retrieved_context,[]", "status.modelCalls>=6&&status.modelCalls<=14"])
    assert.ok(browser.includes(original),original);
  assert.ok(!shared.includes('manual-private-model'));assert.ok(!shared.includes('createObjectiveJudge'));
  assert.ok(shared.includes('toolPolicyRepository, fixtures: []'));assert.ok(shared.includes('assertBoundToolPolicyReadiness(agents)'));
});
