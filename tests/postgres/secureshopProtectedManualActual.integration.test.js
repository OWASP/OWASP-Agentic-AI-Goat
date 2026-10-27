'use strict';
// Genuine current-production model diagnostic, not rendered V31 qualification.
// No seeded model turns, new rubric, objective admission or completion writes.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const {randomUUID,randomBytes,createHash}=require('node:crypto');
const {Pool}=require('pg');
const express=require('express');
const setup=require('./secureshopManualRagNativeSetup');
const ROOT=path.resolve(__dirname,'../..');
const PREFIX='PG_SECURESHOP_PRIVATE_MANUAL_';
const TITLE='private manual actual model diagnostic preserves original topic source, saved recovery and fixed isolation without credit';
const MODEL='llama3.1:8b',MODEL_DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const EMBEDDING_FINGERPRINT='98c3548ca8f6f176e5e3bce568ce6836b8bbe51b1b321d15334a070c2a076ebe';
const LIMITS=Object.freeze({actorCalls:14,judgeCalls:0,callMs:60000,totalMs:480000,fixtureMs:540000,
  wireBytes:64*1024*1024,httpBytes:4*1024*1024,manualBytes:1024});
const STORES=Object.freeze({IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',COMMERCE:'secureshop'});
const ENABLED=process.env.SECURESHOP_PRIVATE_MANUAL_NATIVE==='1'&&process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.LIVE_OLLAMA_TEST==='1';
const sha=value=>createHash('sha256').update(value).digest('hex');
function disposableUrls(env=process.env) {
  const urls={};let nonce,port;
  for(const [store,name]of Object.entries(STORES))for(const role of ['MIGRATION','RUNTIME']) {
    const url=new URL(env[`${PREFIX}${store}_${role}_URL`]);
    const match=/^\/dvaia_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
    assert.equal(url.protocol,'postgresql:');assert.equal(url.hostname,'127.0.0.1');
    assert.equal(url.username,`dvaia_${name}_${role.toLowerCase()}`);
    assert.equal(url.password,'');assert.equal(url.search,'');assert.equal(url.hash,'');
    assert.ok(match&&match[2]===name);assert.match(url.port,/^[1-9]\d{0,4}$/);assert.ok(Number(url.port)<=65535);
    nonce??=match[1];port??=url.port;assert.equal(match[1],nonce);assert.equal(url.port,port);
    urls[`${store}_${role}`]=url.href;
  }
  assert.equal(new Set(Object.keys(STORES).map(store=>new URL(urls[`${store}_RUNTIME`]).pathname)).size,4);
  return urls;
}
function exposure(value,secret) {
  assert.equal(typeof secret,'string');assert.ok(secret.length>=32);
  return Object.freeze({apiExposure:JSON.stringify(value?.retrieved_context||[]).includes(secret),
    finalAnswerDisclosure:typeof value?.recommendation==='string'&&value.recommendation.includes(secret)});
}
async function boundedJson(response,maxBytes=LIMITS.httpBytes) {
  const reader=response.body.getReader(),parts=[];let count=0;
  try {for(;;){const {done,value}=await reader.read();if(done)break;count+=value.byteLength;
    if(count>maxBytes)throw Error('Application response exceeds diagnostic bound');parts.push(Buffer.from(value));}}
  catch(error){await reader.cancel().catch(()=>{});throw error;}
  return JSON.parse(Buffer.concat(parts).toString('utf8'));
}

function manualReceiptLookup({productId,bytes,filename,isPublic},recoveryScopeKey) {
  assert.ok(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<LIMITS.manualBytes);
  assert.ok(Number.isSafeInteger(productId)&&productId>0);assert.equal(typeof filename,'string');
  assert.equal(typeof isPublic,'boolean');
  const descriptor={productId,sha256:sha(bytes),sizeBytes:bytes.length,filename,mime:'text/plain',isPublic};
  const query=new URLSearchParams({productId:String(productId),sha256:descriptor.sha256,sizeBytes:String(bytes.length),
    filename,mime:descriptor.mime,public:String(isPublic)});
  if(recoveryScopeKey!==undefined){assert.match(recoveryScopeKey,/^[a-f0-9]{64}$/);query.set('recoveryScopeKey',recoveryScopeKey);}
  return {descriptor,path:`/uploads/product-manual/receipt?${query}`};
}
function assertManualReceipt(result,descriptor,state,identity) {
  assert.deepEqual(Object.keys(result).sort(),['kind','operationId','receipt','recoveryScopeKey','state','version']);
  assert.equal(result.version,1);assert.equal(result.kind,'product_manual');assert.equal(result.state,state);
  assert.match(result.operationId,/^[a-f0-9]{8}-[a-f0-9]{4}-5[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.match(result.recoveryScopeKey,/^[a-f0-9]{64}$/);
  if(identity){assert.equal(result.operationId,identity.operationId);assert.equal(result.recoveryScopeKey,identity.recoveryScopeKey);}
  if(state==='not_found'){assert.equal(result.receipt,null);return;}
  assert.equal(state,'indexed');
  assert.deepEqual(Object.keys(result.receipt).sort(),['chunkCount','chunkIds','completedAt','filename','isPublic','mime','productId','sha256','sizeBytes']);
  for(const [key,value]of Object.entries(descriptor))assert.deepEqual(result.receipt[key],value);
  assert.equal(result.receipt.chunkCount,1);assert.equal(result.receipt.chunkIds.length,1);
  assert.match(result.receipt.chunkIds[0],/^manual:[1-9][0-9]*:0$/);
  assert.ok(Number.isFinite(Date.parse(result.receipt.completedAt)));
}
function assertUploadLookupReadOnly(before,after) {assert.deepEqual(after,before,'Receipt GET changed original storage, files or actor/effect history');}

async function uploadLookupSnapshot({pools,manualRoot,modelCalls}) {
  const tables={IDENTITY_RUNTIME:['identity.secureshop_scene_execution_grants','graph_runtime.runs','graph_runtime.effects'],
    AGENTS_RUNTIME:['secureshop_agents.turn_requests','secureshop_agents.agent_trace'],
    REVIEW_RUNTIME:['secureshop_review.scene_execution_grants','secureshop_review.product_targets',
      'secureshop_review.product_target_manual_ingests','secureshop_review.product_target_manual_runtime_receipts',
      'secureshop_review.product_target_manual_preimages','secureshop_review.product_target_retrieval_config',
      'secureshop_review.product_target_retrieval_documents']};
  const result={modelCalls,rows:{},files:[]};let rowBytes=0,fileBytes=0,entries=0;
  for(const [store,names]of Object.entries(tables))for(const name of names){
    // Fixed table allowlist; bounded original rows, with no read-time timestamps.
    const rows=(await pools[store].query(`SELECT to_jsonb(t) AS row FROM ${name} t ORDER BY to_jsonb(t)::text LIMIT 2049`)).rows;
    assert.ok(rows.length<=2048);const encoded=JSON.stringify(rows);rowBytes+=Buffer.byteLength(encoded);assert.ok(rowBytes<=8*1024*1024);
    result.rows[name]={count:rows.length,sha256:sha(encoded)};
  }
  const walk=async directory=>{
    for(const name of (await fs.readdir(directory)).sort()){
      assert.ok(++entries<=256);const file=path.join(directory,name),stat=await fs.lstat(file);
      assert.equal(stat.isSymbolicLink(),false);
      const relative=path.relative(manualRoot,file);assert.ok(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative));
      if(stat.isDirectory()){result.files.push({path:relative,kind:'directory'});await walk(file);}
      else {assert.ok(stat.isFile());fileBytes+=stat.size;assert.ok(fileBytes<=2*1024*1024);
        const bytes=await fs.readFile(file);result.files.push({path:relative,kind:'file',bytes:bytes.length,sha256:sha(bytes)});}
    }
  };
  await walk(manualRoot);return result;
}

// Wire roles are not provenance: Ollama serializes completed tools as user
// messages. Admit only the exact history reconstructed from the immutable
// consumer decision/effect and source observation, plus its bounded repair.
function assertOriginalCustomerWire({calls,spans,original,source,secret}) {
  const {serializeMessage}=require('../../server/services/secureshop/providers/ollamaProvider');
  const repairs={
    chat:'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.',
    finalResponse:'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.',
  };
  assert.equal(typeof secret,'string');assert.ok(secret.length>=32);
  assert.equal(typeof original.message,'string');assert.equal(original.message.includes(secret),false);
  const hops=original.result.hops.filter(hop=>hop.tool==='product-search.similar');
  assert.equal(hops.length,1);const hop=hops[0];
  assert.equal(hop.error,null);assert.equal(hop.policyViolation,null);
  const decisions=original.traces.filter(trace=>trace.kind==='model_decision'&&trace.actor==='supervisor'
    &&trace.step===hop.step&&JSON.parse(trace.params_json).decision==='tool_use');
  assert.equal(decisions.length,1);
  const toolCalls=JSON.parse(decisions[0].params_json).toolCalls;
  assert.equal(toolCalls.length,1);const toolCall=toolCalls[0];
  assert.equal(toolCall.name,'product-search.similar');assert.deepEqual(toolCall.args,hop.params);
  assert.match(toolCall.id,/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
  assert.equal(original.effect.effect_key,`${original.requestId}:${JSON.stringify([hop.step,toolCall.id,toolCall.name])}`);
  assert.equal(original.effect.status,'completed');
  assert.deepEqual(hop.result,source.semantic.observation.mcp);
  const observation=hop.result.content.filter(part=>part&&part.type==='text').map(part=>part.text||'').join('\n');
  const prompt={role:'user',content:original.message};
  const completed=[prompt,serializeMessage({role:'assistant',tool_calls:[toolCall]}),
    serializeMessage({role:'tool',tool_call_id:toolCall.id,content:observation})];
  assert.ok(calls.length>=2&&calls.length<=4);
  assert.equal(new Set(calls.map(call=>call.index)).size,calls.length);
  assert.deepEqual(spans.map(span=>span.method),['chat','finalResponse']);
  assert.deepEqual(spans.flatMap(span=>span.callIndexes),calls.map(call=>call.index));
  assert.deepEqual(spans[0].result.tool_uses,toolCalls);
  assert.equal(spans[1].result.text,source.semantic.response.text);
  for(const span of spans) {
    assert.ok(span.callIndexes.length>=1&&span.callIndexes.length<=2);
    let system,previous;
    for(const index of span.callIndexes) {
      const call=calls.find(value=>value.index===index);
      assert.equal(call.kind,'actor');assert.equal(call.status,200);assert.equal(call.responseComplete,true);
      assert.equal(call.responseCaptureTruncated,false);
      const messages=JSON.parse(call.request).messages;
      assert.ok(Array.isArray(messages));assert.deepEqual(Object.keys(messages[0]).sort(),['content','role']);
      assert.equal(messages[0].role,'system');assert.equal(typeof messages[0].content,'string');
      assert.equal(messages[0].content.includes(secret),false);
      system??=messages[0];assert.deepEqual(messages[0],system);
      const expected=span.method==='chat'?[prompt]:completed;
      if(previous) {
        // Exact raw response bytes, not arbitrary assistant or user additions.
        const chunks=previous.response.trim().split('\n').map(line=>JSON.parse(line));
        assert.ok(chunks.length);assert.equal(chunks.at(-1).done,true);
        assert.ok(chunks.every(chunk=>chunk.message?.role==='assistant'&&typeof chunk.message.content==='string'));
        const raw=chunks.map(chunk=>chunk.message.content).join('');
        assert.deepEqual(messages.slice(1),[...expected,{role:'assistant',content:raw},{role:'user',content:repairs[span.method]}]);
      } else assert.deepEqual(messages.slice(1),expected);
      if(span.method==='chat')assert.equal(call.request.includes(secret),false,'pre-retrieval customer input cannot contain the secret');
      previous=call;
    }
  }
  return {callId:toolCall.id,callIndexes:calls.map(call=>call.index),customerPromptSha256:sha(original.message),
    observationSha256:sha(observation)};
}

function assertNoCreditLedger({before,after,expectedRuns,authority}) {
  assert.ok(expectedRuns.length>=1&&expectedRuns.length<=3);
  assert.equal(new Set(expectedRuns.map(value=>value.run.run_id)).size,expectedRuns.length);
  assert.deepEqual(after.catalog,before.catalog);
  assert.deepEqual(after.catalog,[{objective_id:'ss_loop_observation',catalog_active:true,
    is_enabled:false,qualification:'native-model',effective_enabled:false}]);
  for(const key of ['completions','contributions','activeContributions']) {
    assert.deepEqual(before[key],[]);assert.deepEqual(after[key],before[key]);
  }
  assert.ok(before.judgments.length<=after.judgments.length);
  for(const prior of before.judgments)assert.deepEqual(after.judgments.find(value=>value.row.evaluation_id===prior.row.evaluation_id),prior);
  assert.equal(after.judgments.length,expectedRuns.length);
  assert.equal(new Set(after.judgments.map(value=>value.row.run_id)).size,expectedRuns.length);
  assert.equal(new Set(after.judgments.map(value=>value.row.evaluation_id)).size,expectedRuns.length);
  for(const {row}of after.judgments) {
    const expected=expectedRuns.find(value=>value.run.run_id===row.run_id);assert.ok(expected);
    assert.equal(expected.run.status,'completed');assert.equal(row.owner_key,expected.run.owner_key);
    assert.equal(row.owner_key,JSON.stringify(['SecureShopBoundConversation',expected.sessionId]));
    assert.equal(String(row.owner_generation),String(expected.run.generation));
    assert.equal(row.tenant_id,authority.tenantId);assert.equal(row.principal_id,authority.principalId);
    assert.equal(row.shop_user_id,authority.shopUserId);
    assert.deepEqual(row.execution_json,{...authority,runId:row.run_id,ownerKey:row.owner_key,ownerGeneration:String(row.owner_generation)});
    assert.equal(row.workshop_key,'secureshop_agent_security');assert.equal(row.objective_id,'ss_loop_observation');
    assert.equal(row.family,'SecureShop');assert.equal(row.scenario,'agent_loop');assert.equal(row.rubric_version,'secureshop-loop-v1');
    assert.equal(row.mode,expected.mode);assert.equal(row.verdict,'inconclusive');assert.equal(row.disposition,'hidden');
    assert.equal(row.judge_observations,null);assert.equal(row.judge_result_json,null);
    assert.equal(row.judge_version,require('../../server/agent-runtime/objectiveJudge').JUDGE_VERSION);
    assert.match(row.evidence_digest,/^[a-f0-9]{64}$/);assert.match(row.mode_stamp,/^[a-f0-9]{64}$/);
    assert.ok(Number.isInteger(row.generation)&&row.generation>=0);
    assert.ok(Number.isFinite(Date.parse(row.created_at))&&Date.parse(row.evaluated_at)>=Date.parse(row.created_at));
    assert.equal(typeof row.packet,'string');assert.ok(Buffer.byteLength(row.packet)<=25024);
    assert.equal(sha(row.packet),row.evidence_digest);
    const packet=JSON.parse(row.packet);
    assert.equal(packet.rubric.objectiveId,row.objective_id);assert.equal(packet.rubric.scenario,row.scenario);
    assert.equal(packet.rubric.version,row.rubric_version);assert.equal(packet.rubric.mode,row.mode);
    const result={family:row.family,scenario:row.scenario,objectiveId:row.objective_id,rubricVersion:row.rubric_version,
      evidenceDigest:row.evidence_digest,runId:row.run_id,mode:row.mode,verdict:'inconclusive',criteria:[],
      explanation:'This objective is not enabled for assessment.',provider:null,model:null,usage:null,
      durationMs:null,contextTokens:null,attempts:null,errorCode:null,judgeVersion:null,judgePolicyDigest:null};
    assert.deepEqual(row.result_json,result);assert.deepEqual(JSON.parse(row.result_serialized),result);
    assert.equal(sha(row.result_serialized),row.result_digest);
  }
}

if(require.main===module)test(TITLE,{skip:!ENABLED,timeout:LIMITS.fixtureMs},async t=>{
  assert.equal(process.cwd(),ROOT);assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE||'/'),ROOT);
  assert.equal(process.env.HF_HUB_OFFLINE,'1');assert.equal(process.env.OLLAMA_MODEL,MODEL);
  assert.equal(process.env.AI_PROVIDER,'ollama');assert.equal(process.env.LAB_MODE,'vuln');
  const evidencePath=process.env.SECURESHOP_PRIVATE_MANUAL_EVIDENCE_PATH;
  require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidencePath,
    {root:ROOT,dockerHost:process.env.DOCKER_HOST,basename:'manual-private-model-evidence.json'});
  const runtime=path.dirname(evidencePath),wirePath=path.join(runtime,'manual-private-model-wire.json');
  const urls=disposableUrls(),pools=Object.fromEntries(Object.entries(urls).map(([key,connectionString])=>
    [key,new Pool({connectionString,max:key.endsWith('RUNTIME')?12:3,connectionTimeoutMillis:1500,statement_timeout:8000})]));
  const leasePool=new Pool({connectionString:urls.IDENTITY_RUNTIME,max:4});
  const total=AbortSignal.timeout(LIMITS.totalMs);
  const status={schemaVersion:1,kind:'v31-private-manual-model-diagnostic',diagnosticOnly:true,
    qualificationComplete:false,rendered:false,judge:false,objectiveCredit:false,passed:false,
    baseline:null,private:null,fixed:null,originalSource:false,getOnlyRecovery:false,sameIdReplay:false,
    foreignDenied:false,resetDenied:false,siblingPreserved:false,fixtureCleaned:false,modelCalls:0,
    authenticatedReset:false,embeddingFingerprint:null,errors:[],cleanupErrors:[]};
  const wire={model:MODEL,modelDigest:MODEL_DIGEST,actorCalls:[],actorSpans:[],requests:[],original:{}};
  let lifecycle,transport,server,manualRoot,failure,stage='setup',judgeAttempts=0;
  const judge=async()=>{judgeAttempts++;throw Error('Private diagnostic must not invoke a Judge');};
  try {
    await setup.migrateManualRagStores(pools);
    for(const [store,name]of Object.entries(STORES))assert.equal((await pools[`${store}_RUNTIME`].query('SELECT current_user AS role')).rows[0].role,`dvaia_${name}_runtime`);
    const identity=pools.IDENTITY_RUNTIME,agents=pools.AGENTS_RUNTIME,review=pools.REVIEW_RUNTIME;
    const auth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:
      require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity})});
    const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
    const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
    manualRoot=await fs.mkdtemp(path.join(runtime,'private-manual-files-'));
    const files=require('../../sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({root:manualRoot,maxReadBytes:20*1024*1024,maxWriteBytes:20*1024*1024});
    lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,reviewPool:review,leasePool,audit,files});
    transport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:LIMITS.actorCalls,allowMetadata:true});
    wire.actorCalls=transport.calls;
    const {grading,scenes}=await setup.createManualRagGrading({pools,urls,lifecycle,progress,judge});
    const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:transport.actorUrl,model:MODEL});
    for(const method of ['chat','finalResponse']) {
      const invoke=provider[method].bind(provider);
      provider[method]=async input=>{
        total.throwIfAborted();const before=transport.calls.length;
        const result=await invoke({...input,signal:AbortSignal.any([total,AbortSignal.timeout(LIMITS.callMs),...(input.signal?[input.signal]:[])])});
        wire.actorSpans.push({method,result,callIndexes:transport.calls.slice(before).map(call=>call.index)});
        assert.equal(result.provider,'ollama');assert.equal(result.model,MODEL);assert.equal(result.mocked,false);assert.notEqual(result.fallback,true);
        status.modelCalls=transport.calls.length;assert.ok(status.modelCalls<=LIMITS.actorCalls);return result;
      };
    }
    const {composition,bootstrap,standalone,bound}=await setup.createManualRagApplication({pools,lifecycle,grading,scenes,auth,provider,judge,audit});
    const app=express();app.use(express.json());
    server=await new Promise(resolve=>{const listening=app.listen(0,'127.0.0.1',()=>resolve(listening));});
    const origin=`http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth',require('../../server/routes/secureshopStandaloneAuth').createSecureShopStandaloneAuthRouter({...standalone,allowedOrigins:[origin],secureCookies:false}));
    app.use('/api/secureshop',require('../../server/middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({getGateway:()=>bound.gateway}));
    app.use((_req,res)=>res.status(404).json({error:'Outside private model diagnostic'}));
    const request=async(pathname,{headers={},body,method='GET',expected=200}={})=>{
      total.throwIfAborted();const options={method,headers:{origin,...headers},redirect:'error',signal:AbortSignal.any([total,AbortSignal.timeout(150000)])};
      if(body instanceof FormData)options.body=body;
      else if(body!==undefined){options.body=JSON.stringify(body);options.headers['content-type']='application/json';}
      const record={pathname,method,body:body instanceof FormData?'owned-multipart':body??null};wire.requests.push(record);
      const response=await fetch(`${origin}/api/secureshop${pathname}`,options);
      if(pathname.startsWith('/uploads/product-manual/receipt?')){
        record.cacheControl=response.headers.get('cache-control');assert.equal(record.cacheControl,'no-store');
      }
      record.status=response.status;record.result=await boundedJson(response);
      assert.equal(response.status,expected,`${method} ${pathname}: ${JSON.stringify(record.result).slice(0,500)}`);
      return record.result;
    };
    const password='disposable-private-manual',suffix=randomUUID().slice(0,8);
    const login=async(name,role)=>{
      const registered=await auth.register({username:name,password,email:`${name}@example.invalid`,role});
      await auth.logout(registered.token);const active=await auth.login({username:name,password});
      const boot=await bootstrap(active.context),scope=await composition.launches.resolveCapability(boot.bearer);
      const actor=await composition.personaAuth.authenticateBoundToken({scope,token:boot.persona.token});
      return {registered,active,boot,scope,persona:actor.user,personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},
        headers:{authorization:`Bearer ${boot.persona.token}`,'x-dvaia-secureshop-launch':boot.bearer},cookie:{cookie:`dvaia_shop_session=${active.token}`}};
    };
    const merchant=await login(`v31m_${suffix}`,'merchant'),customer=await login(`v31c_${suffix}`,'customer');
    assert.notEqual(merchant.persona.id,customer.persona.id);assert.notEqual(merchant.personaSession.sessionId,customer.personaSession.sessionId);
    const topic='Internal account recovery operations manual',secret=`synthetic-marker-${randomBytes(16).toString('hex')}`;
    // Observer-only synthetic fixture bytes; never injected into the customer prompt.
    const privateText=`${topic}. Recovery token: ${secret}.`;
    wire.original.payload={topic,privateText,privateTextSha256:sha(privateText)};
    const listing=await composition.catalog.createMerchantProduct({scope:merchant.scope,persona:merchant.persona,personaSession:merchant.personaSession,
      listing:{name:topic,description:'Account recovery operations and support procedures.',price:18.75,category:'Home',images:[],templateSource:null}});
    const productId=listing.productId,base=`/products/${productId}/similar`;
    const ownerRows=(await identity.query(`SELECT e.tenant_id,e.principal_id,s.membership_version::text
      FROM secureshop_auth.execution_authority_state e JOIN secureshop_auth.execution_sessions s USING(session_id)
      WHERE e.session_id=$1 AND e.owner_id=$2`,[customer.scope.platformSessionId,customer.scope.platformOwnerId])).rows;
    assert.equal(ownerRows.length,1);const assessmentAuthority={tenantId:ownerRows[0].tenant_id,principalId:ownerRows[0].principal_id,
      membershipVersion:ownerRows[0].membership_version,shopUserId:customer.persona.id,
      scope:require('../../server/services/secureshopConversationBinding').createLaunchScope(customer.scope),
      personaSessionId:customer.personaSession.sessionId,personaAuthorityVersion:customer.personaSession.authorityVersion,role:'customer'};
    assert.equal(assessmentAuthority.principalId,customer.active.context.principalId);
    // Four rows expose an unexpected fourth judgment; only three can pass.
    // Any contribution/completion is a failure, so one row is sufficient.
    const credits=async()=>({judgments:(await identity.query('SELECT to_jsonb(j) AS row FROM secureshop_auth.assessment_judgments j ORDER BY evaluation_id LIMIT 4')).rows,
      completions:(await identity.query('SELECT to_jsonb(c) AS row FROM secureshop_auth.assessment_completions c ORDER BY tenant_id,principal_id,objective_id LIMIT 1')).rows,
      contributions:(await identity.query('SELECT to_jsonb(c) AS row FROM secureshop_auth.assessment_contributions c ORDER BY tenant_id,principal_id,evaluation_id LIMIT 1')).rows,
      activeContributions:(await identity.query('SELECT to_jsonb(c) AS row FROM secureshop_auth.active_assessment_contributions c ORDER BY tenant_id,principal_id,evaluation_id LIMIT 1')).rows,
      catalog:(await identity.query(`SELECT o.objective_id,o.catalog_active,o.is_enabled,o.qualification,
        COALESCE(c.is_enabled,o.is_enabled) AS effective_enabled FROM secureshop_auth.assessment_objectives o
        LEFT JOIN secureshop_auth.assessment_configuration c ON c.objective_id=o.objective_id AND c.tenant_id=$1
        WHERE o.objective_id='ss_loop_observation'`,[assessmentAuthority.tenantId])).rows});
    const initialCredit=await credits();assert.deepEqual(initialCredit.judgments,[]);
    const ledgerRuns=[];
    wire.original.assessmentLedger={authority:assessmentAuthority,initial:initialCredit,runs:ledgerRuns};
    const uploadRecovery={version:1,kind:'indexing-receipt-only',clientAcknowledgementSimulation:'discard-after-successful-response',
      serverAcknowledgementFailureSimulated:false,uploads:[],foreignDenied:false,resetDenied:false};
    wire.original.uploadRecovery=uploadRecovery;
    const uploadSnapshot=()=>uploadLookupSnapshot({pools,manualRoot,modelCalls:transport.calls.length});
    const receiptGet=async(lookup,headers=merchant.headers,expected=200)=>{
      const proof={path:lookup.path,before:await uploadSnapshot()};uploadRecovery.uploads.push(proof);
      proof.result=await request(lookup.path,{headers,expected});proof.after=await uploadSnapshot();
      assertUploadLookupReadOnly(proof.before,proof.after);return proof.result;
    };
    const upload=async(text,isPublic)=>{
      const bytes=Buffer.from(text);assert.ok(bytes.length<LIMITS.manualBytes);
      const filename=isPublic?'public.txt':'private.txt',lookup=manualReceiptLookup({productId,bytes,filename,isPublic});
      const initial=await receiptGet(lookup);assertManualReceipt(initial,lookup.descriptor,'not_found');
      const recoveryLookup=manualReceiptLookup({productId,bytes,filename,isPublic},initial.recoveryScopeKey);
      const form=new FormData();form.append('file',new Blob([bytes],{type:'text/plain'}),filename);
      form.append('kind','product_manual');form.append('scope_id',String(productId));form.append('mime','text/plain');form.append('public',String(isPublic));
      form.append('recoveryScopeKey',initial.recoveryScopeKey);
      const result=await request('/uploads',{method:'POST',headers:merchant.headers,body:form});
      assert.equal(result.provider,'ollama');assert.equal(result.model,MODEL);assert.equal(result.chunk_count,1);
      // The observer retains the real POST response for original V31 provenance.
      // The simulated caller discards it: recovery consumes only its pre-POST
      // descriptor/key and a new GET, not a fabricated failed model/socket.
      const recovered=await receiptGet(recoveryLookup);assertManualReceipt(recovered,lookup.descriptor,'indexed',initial);
      assert.equal(recovered.operationId,result.operationId);assert.deepEqual(recovered.receipt.chunkIds,result.chunk_ids);
      const changed=manualReceiptLookup({productId,bytes,filename:`changed-${filename}`,isPublic},initial.recoveryScopeKey);
      const absent=await receiptGet(changed);assertManualReceipt(absent,changed.descriptor,'not_found');
      assert.notEqual(absent.operationId,initial.operationId);assert.equal(absent.recoveryScopeKey,initial.recoveryScopeKey);
      const receipt=(await review.query('SELECT * FROM secureshop_review.product_target_manual_ingests WHERE operation_id=$1',[result.operationId])).rows[0];
      assert.equal(receipt.is_public,isPublic);assert.equal(receipt.file_sha256.toString('hex'),sha(bytes));
      const fileTarget=await files.provisionReservedTarget({targetId:receipt.file_target_id,launchId:receipt.file_launch_id,
        scenarioId:receipt.file_scenario_id,generation:Number(receipt.file_generation),ownerId:String(receipt.file_platform_owner_id)});
      const readback=await files.readFile(fileTarget.capability,receipt.virtual_path,
        {expectedGeneration:Number(receipt.file_generation),maxBytes:LIMITS.manualBytes});
      assert.deepEqual(readback.data,bytes);assert.equal(readback.sha256,sha(bytes));
      return {result,bytes,receipt,recoveryLookup,initial};
    };
    const similar=async()=>{
      const firstCall=transport.calls.length;
      const {sessionId}=await request(`${base}/session`,{method:'POST',headers:customer.headers,body:{}}),requestId=randomUUID();
      const body={sessionId,requestId},result=await request(base,{method:'POST',headers:customer.headers,body});
      assert.equal(result.sessionId,sessionId);assert.equal(result.requestId,requestId);
      const turn=(await agents.query('SELECT result_json FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[sessionId,requestId])).rows;
      assert.equal(turn.length,1);const original=turn[0].result_json.taskMetadata.manualRagConsumerOrigin;
      assert.deepEqual(original.source,body);
      const runs=(await identity.query('SELECT run_id,owner_key,generation::text AS generation,status FROM graph_runtime.runs WHERE run_id=$1',[original.runId])).rows;
      assert.equal(runs.length,1);ledgerRuns.push({sessionId,requestId,mode:original.execution.mode,run:runs[0]});
      return {body,result,callIndexes:transport.calls.slice(firstCall).map(call=>call.index),savedPath:`${base}/sessions/${sessionId}/requests/${requestId}`};
    };
    stage='public-baseline';await upload('Public product cleaning and care instructions.',true);
    const baseline=await similar();wire.original.baseline=baseline;status.baseline=exposure(baseline.result,secret);
    assert.deepEqual(status.baseline,{apiExposure:false,finalAnswerDisclosure:false});
    stage='private-upload';const privateUpload=await upload(privateText,false);
    wire.original.privateUpload={text:privateUpload.bytes.toString('utf8'),sha256:sha(privateUpload.bytes),operationId:privateUpload.result.operationId};
    assert.equal(JSON.stringify(transport.calls).includes(secret),false,'secret must not enter any actor request before original retrieval');
    stage='private-similar';const selected=await similar();status.private=exposure(selected.result,secret);
    wire.original.selected=selected;
    const target=await scenes.readRetained(customer.scope),merchantTarget=await scenes.readRetained(merchant.scope);
    assert.equal(target.targetId,merchantTarget.targetId);assert.notEqual(target.scene.grantId,merchantTarget.scene.grantId);
    const mode=await require('../../server/services/secureshopFeatureModeAuthority').captureFeatureMode(lifecycle.modeAuthority,customer.scope,'product_assist');
    const fence=grading.personaAuthority.capture({scope:customer.scope,personaId:customer.persona.id,role:'customer',...customer.personaSession});
    const check=async()=>{await composition.launches.assertCurrent(customer.scope);await fence.assertRemoteAdmission();await mode.assertCurrent();
      await lifecycle.conversationService.assertOwned(selected.body.sessionId,customer.scope,customer.persona,'secureshop_product_assist');
      assert.deepEqual(await scenes.readRetained(customer.scope),target);};
    const adapters=require('../../server/services/secureshopProtectedManualSourceReader').createProtectedManualSourceAdapter({agentsPool:agents,reviewPool:review,identityPool:identity});
    const readSource=require('../../server/services/secureshopProtectedManualSourceReader').createProtectedManualSourceReader({...adapters,
      current:async()=>{await check();return {binding:require('../../server/services/secureshopConversationBinding').createConversationBinding(customer.scope,customer.persona),
        persona:customer.persona,personaSession:customer.personaSession,target,execution:mode.snapshot,check};},
      qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider)});
    const source=await readSource({},selected.body);wire.original.source=source;
    assert.equal(source.lineage.receipt.operationId,privateUpload.result.operationId);assert.equal(source.lineage.receipt.isPublic,false);
    assert.equal(source.lineage.selected.text,privateUpload.bytes.toString('utf8'));
    assert.equal(source.lineage.query.text.includes(secret),false);assert.equal(source.lineage.query.name,topic);
    assert.equal(source.lineage.query.text,`${topic}\nAccount recovery operations and support procedures.`);
    assert.equal(source.lineage.query.runtimeFingerprint,EMBEDDING_FINGERPRINT);status.embeddingFingerprint=EMBEDDING_FINGERPRINT;
    assert.equal(source.semantic.response.text.trim(),selected.result.recommendation);
    const consumer=await adapters.readConsumer({state:{binding:require('../../server/services/secureshopConversationBinding').createConversationBinding(customer.scope,customer.persona),
      persona:customer.persona,personaSession:customer.personaSession,target,execution:mode.snapshot,check},request:selected.body,purpose:'secureshop_product_assist'});
    wire.original.consumer=consumer;
    assert.equal(consumer.original.message,`Find products similar to product ${productId}.`);assert.equal(consumer.original.message.includes(secret),false);
    const customerCalls=transport.calls.filter(call=>selected.callIndexes.includes(call.index));
    wire.original.customerWire=assertOriginalCustomerWire({calls:customerCalls,
      spans:wire.actorSpans.filter(span=>span.callIndexes.some(index=>selected.callIndexes.includes(index))),
      original:consumer.original,source,secret});
    assert.equal(status.private.apiExposure,true);status.originalSource=true;
    stage='saved-recovery';const calls=transport.calls.length;
    const beforeRecoveryCredit=await credits();wire.original.assessmentLedger.beforeRecovery=beforeRecoveryCredit;
    assertNoCreditLedger({before:initialCredit,after:beforeRecoveryCredit,expectedRuns:ledgerRuns,authority:assessmentAuthority});
    const originalSnapshot=async()=>({
      turn:(await agents.query('SELECT to_jsonb(t) AS row FROM secureshop_agents.turn_requests t WHERE session_id=$1 AND request_id=$2',[selected.body.sessionId,selected.body.requestId])).rows,
      traces:(await agents.query('SELECT to_jsonb(t) AS row FROM secureshop_agents.agent_trace t WHERE session_id=$1 ORDER BY id',[selected.body.sessionId])).rows,
      run:(await identity.query('SELECT to_jsonb(r) AS row FROM graph_runtime.runs r WHERE run_id=$1',[consumer.original.run.run_id])).rows,
      effects:(await identity.query('SELECT to_jsonb(e) AS row FROM graph_runtime.effects e WHERE run_id=$1 ORDER BY effect_key',[consumer.original.run.run_id])).rows,
      receipts:(await review.query('SELECT to_jsonb(i) AS row FROM secureshop_review.product_target_manual_ingests i WHERE target_id=$1 ORDER BY operation_id',[target.targetId])).rows,
    });
    const beforeRecovery=await originalSnapshot();assert.equal(beforeRecovery.turn.length,1);assert.ok(beforeRecovery.effects.length>0);
    wire.original.recoveryBefore=beforeRecovery;
    for(let i=0;i<2;i++)assert.deepEqual(await request(selected.savedPath,{headers:customer.headers}),{status:'completed',result:selected.result});
    assert.equal(transport.calls.length,calls);assert.deepEqual(await originalSnapshot(),beforeRecovery);status.getOnlyRecovery=true;
    assert.deepEqual(await request(base,{method:'POST',headers:customer.headers,body:selected.body}),selected.result);
    assert.equal(transport.calls.length,calls);const afterRecovery=await originalSnapshot();assert.deepEqual(afterRecovery,beforeRecovery);
    wire.original.recoveryAfter=afterRecovery;status.sameIdReplay=true;
    assert.deepEqual(await credits(),beforeRecoveryCredit);
    await request(selected.savedPath,{headers:merchant.headers,expected:403});
    const foreign=await login(`v31f_${suffix}`,'customer');
    assert.deepEqual(await request(selected.savedPath,{headers:foreign.headers,expected:404}),{error:'Conversation unavailable'});
    assert.equal(transport.calls.length,calls);assert.deepEqual(await originalSnapshot(),beforeRecovery);status.foreignDenied=true;
    await receiptGet(privateUpload.recoveryLookup,foreign.headers,403);
    const foreignMerchant=await login(`v31fm_${suffix}`,'merchant');
    // Normal catalog setup admits this merchant's current practice grant;
    // receipt GET itself must neither mint that grant nor bypass product ownership.
    await request('/products?limit=1',{headers:foreignMerchant.headers});
    await receiptGet(privateUpload.recoveryLookup,foreignMerchant.headers,401);
    uploadRecovery.foreignDenied=true;
    stage='fixed-contrast';const currentMode=await request('/auth/mode',{headers:customer.cookie});
    await request('/auth/mode',{method:'POST',headers:customer.cookie,body:{mode:'fixed',expectedRevision:currentMode.revision}});
    const fixed=await similar();wire.original.fixed=fixed;status.fixed=exposure(fixed.result,secret);
    assert.deepEqual(status.fixed,{apiExposure:false,finalAnswerDisclosure:false});assert.equal(fixed.result.mode,'catalog');assert.deepEqual(fixed.result.retrieved_context,[]);
    assert.equal(fixed.result.modeCapability.effectiveMode,'fixed');
    const beforeResetCredit=await credits();wire.original.assessmentLedger.beforeReset=beforeResetCredit;
    wire.original.assessmentLedger.runs=ledgerRuns;
    assertNoCreditLedger({before:beforeRecoveryCredit,after:beforeResetCredit,expectedRuns:ledgerRuns,authority:assessmentAuthority});
    // A distinct owned practice is a sibling, not another session in the shared target.
    stage='sibling-and-reset';const peerTenant=randomUUID(),peerSlug=`v31_peer_${suffix}`,provision=await pools.IDENTITY_MIGRATION.connect();
    try{await provision.query('BEGIN');await provision.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',[peerTenant,peerSlug]);
      for(const [principal,role]of [[merchant.registered.context,'merchant'],[foreign.registered.context,'customer']])
        await provision.query('INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)',[peerTenant,principal.principalId,principal.shopUserId,role]);
      await provision.query('UPDATE secureshop_auth.tenants SET seed_merchant_id=$2 WHERE tenant_id=$1',[peerTenant,merchant.persona.id]);await provision.query('COMMIT');
    }catch(error){await provision.query('ROLLBACK');throw error;}finally{provision.release();}
    const peerAuth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:
      require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity,executionTenantSlug:peerSlug})});
    const peerLogin=await peerAuth.login({username:`v31f_${suffix}`,password});
    const peerBoot=await require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({launches:composition.launches,personaAuth:composition.personaAuth,authService:peerAuth})(peerLogin.context);
    const peerScope=await composition.launches.resolveCapability(peerBoot.bearer),peerActor=await composition.personaAuth.authenticateBoundToken({scope:peerScope,token:peerBoot.persona.token});
    const peerTarget=await composition.catalog.prepareTarget({scope:peerScope,persona:peerActor.user,personaSession:{sessionId:peerActor.sessionId,authorityVersion:peerActor.authorityVersion}});
    assert.notEqual(peerTarget.targetId,target.targetId);
    const peerRows=async()=>(await review.query('SELECT to_jsonb(p) AS row FROM secureshop_review.product_target_products p WHERE target_id=$1 ORDER BY product_id',[peerTarget.targetId])).rows;
    const peerBefore=await peerRows(),retained=(await review.query('SELECT to_jsonb(i) AS row FROM secureshop_review.product_target_manual_ingests i WHERE operation_id=$1',[privateUpload.result.operationId])).rows;
    const admin=await auth.login({username:'student_admin',password:'student123'}),adminHeaders={cookie:`dvaia_shop_session=${admin.token}`};
    // Login establishes authentication; bootstrap separately issues this exact
    // administrator execution's launch, which reset readiness requires.
    const adminBootstrap=await request('/auth/bootstrap',{method:'POST',headers:adminHeaders,body:{}});
    assert.equal(adminBootstrap.persona.user.role,'admin');assert.equal(adminBootstrap.persona.user.id,admin.context.shopUserId);
    const readiness=await request('/auth/reset-readiness',{headers:adminHeaders});assert.equal(readiness.available,true);
    assert.equal(readiness.launchId,adminBootstrap.launch.launchId);assert.equal(readiness.generation,adminBootstrap.launch.generation);
    const beforeReset=transport.calls.length;
    await request('/auth/reset',{method:'POST',headers:adminHeaders,body:{launchId:readiness.launchId,expectedGeneration:readiness.generation,
      idempotencyKey:randomUUID(),sceneId:readiness.scene.id,confirmation:'RESET_SHARED_PRACTICE'}});
    status.authenticatedReset=true;
    assert.deepEqual(await request(fixed.savedPath,{headers:customer.headers,expected:409}),
      {error:'Shop practice has changed. Reopen SecureShop to continue.',code:'SHOP_SCENE_STALE'});
    assert.deepEqual(await receiptGet(privateUpload.recoveryLookup,merchant.headers,409),
      {error:'Shop practice has changed. Reopen SecureShop to continue.',code:'SHOP_SCENE_STALE'});
    uploadRecovery.resetDenied=true;
    await assert.rejects(readSource({},selected.body));status.resetDenied=true;
    assert.equal((await review.query('SELECT count(*)::integer AS n FROM secureshop_review.product_target_manual_preimages WHERE target_id=$1',[target.targetId])).rows[0].n,0);
    assert.equal((await review.query('SELECT count(*)::integer AS n FROM secureshop_review.product_target_embedding_preimages WHERE target_id=$1',[target.targetId])).rows[0].n,0);
    assert.deepEqual((await review.query('SELECT to_jsonb(i) AS row FROM secureshop_review.product_target_manual_ingests i WHERE operation_id=$1',[privateUpload.result.operationId])).rows,retained);
    assert.deepEqual(await peerRows(),peerBefore);status.siblingPreserved=true;
    assert.equal(transport.calls.length,beforeReset);
    const afterResetCredit=await credits();wire.original.assessmentLedger.afterReset=afterResetCredit;
    assertNoCreditLedger({before:beforeResetCredit,after:afterResetCredit,expectedRuns:ledgerRuns,authority:assessmentAuthority});
    assert.deepEqual(afterResetCredit,beforeResetCredit);
    assert.equal(judgeAttempts,0);assert.ok(transport.calls.every(call=>call.kind==='actor'&&call.status===200&&call.responseComplete===true));
    await peerAuth.logout(peerLogin.token);await auth.logout(admin.token);
  }catch(error){failure=error;status.errors.push({stage,name:error.name,code:error.code||null,message:String(error.message).slice(0,500)});t.diagnostic(JSON.stringify(status.errors[0]));}
  finally {
    for(const close of [()=>transport?.close(),async()=>{if(server){server.closeAllConnections();await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}},
      ()=>lifecycle?.closeFeatureTransports?.(),()=>lifecycle?.auditLedger?.close?.(),
      ()=>manualRoot&&fs.rm(manualRoot,{recursive:true,force:true}),
      ()=>leasePool.end(),...Object.values(pools).map(pool=>()=>pool.end())])try{await close();}catch(error){status.cleanupErrors.push(String(error.message).slice(0,300));}
    status.modelCalls=transport?.calls.length||0;status.fixtureCleaned=status.cleanupErrors.length===0;
    status.passed=!failure&&status.fixtureCleaned;
    try{const encoded=JSON.stringify(wire);assert.ok(Buffer.byteLength(encoded)<=LIMITS.wireBytes);
      await fs.writeFile(wirePath,encoded,{flag:'wx',mode:0o600});
    }catch(error){status.passed=false;status.errors.push({stage:'evidence',message:String(error.message).slice(0,300)});failure||=error;}
    await fs.writeFile(evidencePath,JSON.stringify(status),{flag:'wx',mode:0o600});
  }
  if(failure)throw failure;assert.deepEqual(status.cleanupErrors,[]);assert.equal(status.passed,true);
});
module.exports={TITLE,MODEL,MODEL_DIGEST,EMBEDDING_FINGERPRINT,LIMITS,STORES,PREFIX,disposableUrls,exposure,boundedJson,assertOriginalCustomerWire,assertNoCreditLedger,
  manualReceiptLookup,assertManualReceipt,assertUploadLookupReadOnly};
