'use strict';
// Actual original moderation and durable recovery; no browser, Judge or lesson credit.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {Pool}=require('pg'),express=require('express');
const setup=require('./secureshopManualRagNativeSetup');
const ROOT=path.resolve(__dirname,'../..');
const PREFIX='PG_SECURESHOP_REVIEW_RECOVERY_';
const TITLE='actual review moderation scoped recovery is read-only and preserves owner mode reset and sibling boundaries';
const MODEL='llama3.1:8b',MODEL_DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const LIMITS=Object.freeze({actorCalls:8,judgeCalls:0,callMs:60000,totalMs:360000,fixtureMs:420000,wireBytes:64*1024*1024,httpBytes:1024*1024});
const STORES=Object.freeze({IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',COMMERCE:'secureshop'});
const FLAGS=Object.freeze(['isolatedStores','standaloneReady','preflightReadOnly','originalModelEffect','getOnlyRecovery',
  'sameIdReplay','foreignDenied','revokedDenied','fixedScopeDenied','authenticatedReset','resetDenied','siblingPreserved','noCredit','fixtureCleaned']);
const sha=value=>createHash('sha256').update(value).digest('hex');
function disposableUrls(env=process.env){
  const urls={};let nonce,port;
  for(const [store,name]of Object.entries(STORES))for(const role of ['MIGRATION','RUNTIME']){
    const url=new URL(env[`${PREFIX}${store}_${role}_URL`]);
    const match=/^\/dvaia_test_agent_host_([a-f0-9]{12})_(identity|secureshop_agents|secureshop_review|secureshop)$/.exec(url.pathname);
    assert.equal(url.protocol,'postgresql:');assert.equal(url.hostname,'127.0.0.1');assert.equal(url.username,`dvaia_${name}_${role.toLowerCase()}`);
    assert.equal(url.password,'');assert.equal(url.search,'');assert.equal(url.hash,'');assert.ok(match&&match[2]===name);
    assert.match(url.port,/^[1-9]\d{0,4}$/);assert.ok(Number(url.port)<=65535);
    nonce??=match[1];port??=url.port;assert.equal(match[1],nonce);assert.equal(url.port,port);urls[`${store}_${role}`]=url.href;
  }
  assert.equal(new Set(Object.values(urls)).size,8);return urls;
}
function receiptPath(requestId,key,limit=1){
  assert.match(requestId,/^[a-f0-9-]{36}$/);assert.ok(Number.isInteger(limit)&&limit>=1&&limit<=100);
  if(key!==undefined)assert.match(key,/^[a-f0-9]{64}$/);
  return `/merchant/reviews/moderation/${requestId}?limit=${limit}${key===undefined?'':`&recoveryScopeKey=${key}`}`;
}
function assertReceipt(value,{requestId,key,state,projection}){
  assert.deepEqual(Object.keys(value).sort(),['recoveryScopeKey','requestId','requestedLimit','result','state','version']);
  assert.equal(value.version,1);assert.equal(value.requestId,requestId);assert.equal(value.requestedLimit,1);
  assert.match(value.recoveryScopeKey,/^[a-f0-9]{64}$/);if(key)assert.equal(value.recoveryScopeKey,key);
  assert.equal(value.state,state);assert.deepEqual(value.result,state==='completed'?projection:null);
}
async function boundedJson(response){
  const reader=response.body.getReader(),parts=[];let size=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;assert.ok(size<=LIMITS.httpBytes);parts.push(Buffer.from(value));}}
  catch(error){await reader.cancel().catch(()=>{});throw error;}
  return JSON.parse(Buffer.concat(parts).toString('utf8'));
}
// Recovery GET preserves the selected business, retained-scope, journal,
// graph-effect/owner and assessment state below. Authentication last_seen_at
// telemetry is deliberately outside this claim; production auth is unchanged.
// Fixed table names never come from HTTP. Existing row timestamps are hashed.
const SNAPSHOT_TABLES=Object.freeze({
  IDENTITY_RUNTIME:['identity.secureshop_scenes','identity.secureshop_scene_principals','identity.secureshop_scene_execution_grants',
    'identity.secureshop_scene_review_targets','identity.secureshop_target_reservations','secureshop_auth.tenant_modes','graph_runtime.owners','graph_runtime.runs','graph_runtime.effects',
    'secureshop_auth.assessment_judgments','secureshop_auth.assessment_completions',
    'secureshop_auth.assessment_contributions','secureshop_auth.active_assessment_contributions','secureshop_auth.assessment_retries',
    'secureshop_auth.assessment_scene_bindings','secureshop_auth.assessment_scene_cleanup_history'],
  AGENTS_RUNTIME:['secureshop_agents.turn_requests','secureshop_agents.agent_trace','secureshop_agents.agent_sessions'],
  REVIEW_RUNTIME:['secureshop_review.scene_execution_grants','secureshop_review.product_targets','secureshop_review.product_target_products','secureshop_review.review_targets',
    'secureshop_review.scene_review_targets','secureshop_review.reviews','secureshop_review.bound_audit_events'],
});
async function snapshot(pools,calls){
  const result={modelCalls:calls.length,rows:{}};let bytes=0;
  for(const [store,tables]of Object.entries(SNAPSHOT_TABLES))for(const table of tables){
    const rows=(await pools[store].query(`SELECT to_jsonb(t) AS row FROM ${table} t ORDER BY to_jsonb(t)::text LIMIT 2049`)).rows;
    assert.ok(rows.length<=2048);const json=JSON.stringify(rows);bytes+=Buffer.byteLength(json);assert.ok(bytes<=12*1024*1024);
    result.rows[table]={count:rows.length,sha256:sha(json)};
  }
  return result;
}
function assertReadOnly(before,after){
  const tables=Object.values(SNAPSHOT_TABLES).flat().sort();
  for(const value of [before,after]){
    assert.ok(value&&Object.getPrototypeOf(value)===Object.prototype);
    assert.deepEqual(Object.keys(value).sort(),['modelCalls','rows']);
    assert.ok(Number.isInteger(value.modelCalls)&&value.modelCalls>=0&&value.modelCalls<=LIMITS.actorCalls);
    assert.ok(value.rows&&Object.getPrototypeOf(value.rows)===Object.prototype);
    assert.deepEqual(Object.keys(value.rows).sort(),tables,'Recovery snapshot must include every declared base table');
    for(const row of Object.values(value.rows)){
      assert.ok(row&&Object.getPrototypeOf(row)===Object.prototype);assert.deepEqual(Object.keys(row).sort(),['count','sha256']);
      assert.ok(Number.isInteger(row.count)&&row.count>=0&&row.count<=2048);assert.equal(typeof row.sha256,'string');assert.match(row.sha256,/^[a-f0-9]{64}$/);
    }
  }
  assert.deepEqual(after,before,'Recovery changed original business, journal, effect, assessment or model state');
}
const RUBRICS=Object.freeze({ss_loop_observation:['agent_loop','secureshop-loop-v1'],
  ss_content_persist:['indirect_content','secureshop-review-content-v2'],ss_content_followed:['indirect_content','secureshop-review-content-v4']});
function assertNoCredit({before,after,original,authority}){
  const session=original.session;
  assert.equal(session.authority_mode,'launch_bound');assert.equal(session.role,'merchant');assert.equal(Number(session.user_id),authority.shopUserId);
  for(const [stored,scope]of [['platform_launch_id','launchId'],['platform_scenario_id','scenarioId'],
    ['platform_launch_generation','generation'],['original_platform_owner_id','platformOwnerId'],['original_platform_session_id','platformSessionId']])
    assert.equal(String(session[stored]),String(authority.scope[scope]));
  assert.deepEqual(after.catalog,before.catalog);assert.equal(after.catalog.length,3);
  for(const row of after.catalog){assert.ok(Object.hasOwn(RUBRICS,row.objective_id));assert.equal(row.catalog_active,true);
    assert.equal(row.is_enabled,false);assert.equal(row.effective_enabled,false);assert.equal(row.qualification,'native-model');}
  for(const key of ['completions','contributions','activeContributions']){assert.deepEqual(before[key],[]);assert.deepEqual(after[key],[]);}
  assert.ok(after.judgments.length>=1&&after.judgments.length<=3);
  assert.equal(new Set(after.judgments.map(({row})=>row.objective_id)).size,after.judgments.length);
  for(const prior of before.judgments)assert.deepEqual(after.judgments.find(({row})=>row.evaluation_id===prior.row.evaluation_id),prior);
  for(const {row}of after.judgments){
    assert.ok(Object.hasOwn(RUBRICS,row.objective_id));assert.equal(row.run_id,original.run.run_id);
    assert.equal(row.owner_key,original.run.owner_key);assert.equal(row.owner_key,JSON.stringify(['SecureShopBoundConversation',original.turn.session_id]));
    assert.equal(String(row.owner_generation),String(original.run.generation));
    assert.equal(row.tenant_id,authority.tenantId);assert.equal(row.principal_id,authority.principalId);assert.equal(row.shop_user_id,authority.shopUserId);
    assert.deepEqual(row.execution_json,{...authority,runId:row.run_id,ownerKey:row.owner_key,ownerGeneration:String(row.owner_generation)});
    assert.equal(row.family,'SecureShop');assert.equal(row.workshop_key,'secureshop_agent_security');assert.equal(row.mode,'vuln');
    assert.deepEqual([row.scenario,row.rubric_version],RUBRICS[row.objective_id]);
    assert.equal(row.verdict,'inconclusive');assert.equal(row.disposition,'hidden');assert.equal(row.judge_observations,null);assert.equal(row.judge_result_json,null);
    assert.ok(Buffer.byteLength(row.packet)<=25024);assert.equal(sha(row.packet),row.evidence_digest);
    const packet=JSON.parse(row.packet);assert.equal(packet.rubric.objectiveId,row.objective_id);assert.equal(packet.rubric.version,row.rubric_version);
    const result={family:row.family,scenario:row.scenario,objectiveId:row.objective_id,rubricVersion:row.rubric_version,
      evidenceDigest:row.evidence_digest,runId:row.run_id,mode:'vuln',verdict:'inconclusive',criteria:[],
      explanation:'This objective is not enabled for assessment.',provider:null,model:null,usage:null,
      durationMs:null,contextTokens:null,attempts:null,errorCode:null,judgeVersion:null,judgePolicyDigest:null};
    assert.deepEqual(row.result_json,result);assert.deepEqual(JSON.parse(row.result_serialized),result);assert.equal(sha(row.result_serialized),row.result_digest);
  }
}
function assertOriginal({original,calls,spans,submission}){
  const {serializeMessage}=require('../../server/services/secureshop/providers/ollamaProvider');
  const run=original.turn.result_json;
  assert.equal(original.turn.status,'completed');assert.equal(original.session.conversation_purpose,'review_moderation');
  assert.equal(original.session.id,original.turn.session_id);assert.equal(original.run.status,'completed');
  assert.equal(run.taskMetadata.reviewBatch.runId,original.run.run_id);assert.equal(run.taskMetadata.reviewBatch.requested,1);
  assert.equal(run.taskMetadata.reviewBatch.complete,true);assert.equal(run.taskMetadata.reviewBatch.considered,1);
  assert.equal(run.taskMetadata.reviewRecovery.requestId,original.turn.request_id);
  const decisions=original.traces.filter(row=>row.kind==='model_decision'&&row.actor==='supervisor');
  assert.equal(decisions.length,spans.length);assert.ok(spans.length>=2&&spans.length<=LIMITS.actorCalls);
  assert.deepEqual(spans.flatMap(span=>span.callIndexes),calls.map(call=>call.index));
  const repairs={chat:'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.',
    finalResponse:'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.'};
  const history=[];let originalPrompt;
  for(let index=0;index<spans.length;index++){
    const span=spans[index],trace=decisions[index],meta=JSON.parse(trace.result_json);
    assert.equal(trace.provider,'ollama');assert.equal(meta.model,MODEL);assert.equal(meta.mocked,false);assert.notEqual(meta.fallback,true);
    assert.equal(span.result.provider,'ollama');assert.equal(span.result.model,MODEL);assert.equal(span.result.mocked,false);assert.notEqual(span.result.fallback,true);
    assert.equal(span.input.messages[0].role,'user');originalPrompt??=span.input.messages[0];assert.deepEqual(span.input.messages[0],originalPrompt);
    assert.deepEqual(span.input.messages.slice(1),history);
    if(span.result.stop_reason==='tool_use')assert.deepEqual(JSON.parse(trace.params_json).toolCalls,
      span.result.tool_uses.map(call=>({id:call.id,name:call.name,args:call.args})));
    else assert.equal(meta.text,span.result.text);
    let previous;
    assert.ok(span.callIndexes.length>=1&&span.callIndexes.length<=2);
    for(const callId of span.callIndexes){
      const call=calls.find(value=>value.index===callId);assert.ok(call);assert.equal(call.kind,'actor');assert.equal(call.status,200);
      assert.equal(call.responseComplete,true);assert.equal(call.responseCaptureTruncated,false);
      assert.equal(sha(call.request),call.requestSha256);assert.equal(sha(call.response),call.responseSha256);
      assert.equal(Buffer.byteLength(call.request),call.requestBytes);assert.equal(Buffer.byteLength(call.response),call.responseBytes);
      const request=JSON.parse(call.request);assert.equal(request.model,MODEL);assert.equal(request.messages[0].role,'system');
      const expected=span.input.messages.map(serializeMessage);
      if(previous){const chunks=previous.response.trim().split('\n').map(line=>JSON.parse(line));assert.equal(chunks.at(-1).done,true);
        expected.push({role:'assistant',content:chunks.map(chunk=>chunk.message.content).join('')},{role:'user',content:repairs[span.method]});}
      assert.deepEqual(request.messages.slice(1),expected);previous=call;
    }
    const responseChunks=previous.response.trim().split('\n').map(line=>JSON.parse(line));assert.equal(responseChunks.at(-1).done,true);
    const parsed=JSON.parse(responseChunks.map(chunk=>chunk.message?.content||'').join(''));
    if(span.result.stop_reason==='tool_use')assert.deepEqual(parsed.tool_calls,span.result.tool_uses.map(call=>{
      const [agent,tool]=call.name.split('.');return {agent,tool,args:call.args};}));
    else assert.equal(span.method==='finalResponse'?parsed.answer:parsed.reply,span.result.text);
    if(span.result.stop_reason==='tool_use'){
      const tools=span.result.tool_uses;history.push({role:'assistant',content:'',tool_calls:tools.map(call=>({id:call.id,type:'function',function:{name:call.name,arguments:JSON.stringify(call.args||{})}}))});
      for(const call of tools){
        const hop=run.hops.find(hop=>hop.step===trace.step&&hop.tool===call.name&&JSON.stringify(hop.params)===JSON.stringify(call.args));assert.ok(hop);
        assert.equal(hop.error,null);assert.notEqual(hop.result?.isError,true);
        const effect=original.effects.find(effect=>effect.effect_key===`${original.turn.request_id}:${JSON.stringify([trace.step,call.id,call.name])}`);
        assert.ok(effect);assert.equal(effect.run_id,original.run.run_id);assert.equal(effect.status,'completed');
        assert.equal(effect.owner_key,original.run.owner_key);assert.equal(String(effect.generation),String(original.run.generation));
        const outputs=original.traces.filter(row=>row.step===trace.step&&row.kind==='local_tool_result'&&`${row.agent_ns}.${row.tool_name}`===call.name);
        assert.equal(outputs.length,1);assert.deepEqual(JSON.parse(outputs[0].result_json),hop.result);
        history.push({role:'tool',tool_call_id:call.id,content:hop.result.content.filter(part=>part.type==='text').map(part=>part.text||'').join('\n')});
      }
    }
  }
  assert.equal(originalPrompt.content,'Moderate up to 1 pending reviews according to the review moderation policy. Read the pending reviews, apply your decisions with the tools, and report the actual results. Stop when there are no pending reviews or you have considered 1 reviews.');
  const reads=run.hops.filter(hop=>hop.tool==='review-moderator.moderate_pending');assert.equal(reads.length,1);
  const read=JSON.parse(reads[0].result.content[0].text);assert.equal(read.ok,true);assert.equal(read.reviews.length,1);
  assert.equal(read.reviews[0].id,submission.review_id);assert.equal(read.reviews[0].body,submission.body);
  const changes=run.hops.filter(hop=>['review-moderator.approve','review-moderator.reject'].includes(hop.tool));assert.equal(changes.length,1);
  const changed=JSON.parse(changes[0].result.content[0].text);assert.equal(changed.ok,true);assert.equal(changed.applied,true);
  assert.equal(changed.review.id,submission.review_id);assert.equal(changed.review.moderator_kind,'auto');
  assert.equal(original.review.status,changed.review.status);assert.equal(original.review.body,submission.body);
  assert.equal(original.review.source_kind,'learner');assert.equal(original.review.source_version,1);
  const bodyDigest=Buffer.isBuffer(original.review.body_sha256)?original.review.body_sha256:Buffer.from(original.review.body_sha256.data);
  assert.equal(bodyDigest.length,32);assert.equal(bodyDigest.toString('hex'),sha(submission.body));
  assert.ok(Number.isFinite(Date.parse(original.review.created_at))&&Date.parse(original.review.created_at)<=Date.parse(original.run.started_at));
  assert.equal(run.hops.length,2);assert.equal(original.effects.length,run.hops.length);
}
function assertEvidence(wire,status){
  assert.equal(status.schemaVersion,1);assert.equal(status.kind,'review-moderation-recovery-actual');assert.equal(status.passed,true);
  for(const key of ['qualificationComplete','rendered','objectiveCredit','fixedModelEffectProved','serverAcknowledgementFailureSimulated'])assert.equal(status[key],false);
  assert.equal(status.clientAcknowledgementSimulation,'discard-after-successful-response');
  for(const flag of FLAGS)assert.equal(status[flag],true);assert.deepEqual(status.errors,[]);assert.deepEqual(status.cleanupErrors,[]);
  assert.equal(status.judgeCalls,0);assert.equal(status.modelCalls,wire.actorCalls.length);assert.ok(status.modelCalls>=2&&status.modelCalls<=8);
  assert.equal(wire.model,MODEL);assert.equal(wire.modelDigest,MODEL_DIGEST);
  assertOriginal({original:wire.original,calls:wire.actorCalls,spans:wire.actorSpans,submission:wire.submission});
  const requestId=wire.original.turn.request_id,key=wire.original.turn.result_json.taskMetadata.reviewRecovery.recoveryScopeKey;
  require('../../server/services/secureshopReviewModerationRecovery').assertReviewRecoveryResult(wire.original.turn.result_json,
    {requestId,requestedLimit:1,recoveryScopeKey:key});
  assert.deepEqual(wire.postProjection,require('../../server/services/secureshopReviewRunProjection').projectBoundReviewModeration(wire.original.turn.result_json));
  const posts=wire.requests.filter(row=>row.pathname==='/merchant/reviews/moderate-all');assert.equal(posts.length,2);
  for(const row of posts){assert.equal(row.method,'POST');assert.equal(row.status,200);assert.deepEqual(row.body,{request_id:requestId,limit:1,recoveryScopeKey:key});}
  assert.deepEqual(posts[0].result,wire.postProjection);assert.deepEqual(posts[1].result,{...wire.postProjection,replayed:true});
  const labels=['preflight','recovery-0','recovery-1','same-id-post-replay','customer-denied','foreign-key-denied',
    'foreign-not-found','old-mode-key-denied','fixed-preflight','revoked-persona-denied','reset-denied'];
  assert.deepEqual(wire.checks.map(row=>row.label),labels);
  for(const row of wire.checks)assertReadOnly(row.before,row.after);
  const checks=Object.fromEntries(wire.checks.map(row=>[row.label,row]));
  assertReceipt(checks.preflight.result,{requestId,key,state:'not_found'});
  for(const label of ['recovery-0','recovery-1'])assertReceipt(checks[label].result,{requestId,key,state:'completed',projection:wire.postProjection});
  assertReceipt(checks['foreign-not-found'].result,{requestId,state:'not_found'});assert.notEqual(checks['foreign-not-found'].result.recoveryScopeKey,key);
  for(const [label,code]of [['customer-denied',403],['foreign-key-denied',409],['old-mode-key-denied',409],['revoked-persona-denied',401],['reset-denied',409]]){
    assert.equal(checks[label].status,code);assert.equal(checks[label].cacheControl,'no-store');
  }
  for(const row of wire.requests.filter(row=>row.pathname.startsWith('/merchant/reviews/moderation/')))assert.equal(row.cacheControl,'no-store');
  const fixed=checks['fixed-preflight'].result;assertReceipt(fixed,{requestId:fixed.requestId,state:'not_found'});assert.notEqual(fixed.recoveryScopeKey,key);
  assert.deepEqual(wire.siblingAfter,wire.siblingBefore);assert.equal(wire.siblingBefore.length,1);
  assertNoCredit({before:wire.ledger.initial,after:wire.ledger.afterOriginal,original:wire.original,authority:wire.ledger.authority});
  assert.deepEqual(wire.ledger.beforeReset,wire.ledger.afterOriginal);assert.deepEqual(wire.ledger.afterReset,wire.ledger.beforeReset);
}

const ENABLED=process.env.SECURESHOP_REVIEW_RECOVERY_NATIVE==='1'&&process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.LIVE_OLLAMA_TEST==='1';
if(require.main===module)test(TITLE,{skip:!ENABLED,timeout:LIMITS.fixtureMs},async t=>{
  assert.equal(process.cwd(),ROOT);assert.equal(path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE||'/'),ROOT);
  assert.equal(process.env.OLLAMA_MODEL,MODEL);assert.equal(process.env.AI_PROVIDER,'ollama');assert.equal(process.env.LAB_MODE,'vuln');
  const evidencePath=process.env.SECURESHOP_REVIEW_RECOVERY_EVIDENCE_PATH;
  require('../fixtures/secureshopNativeEvidencePath').assertNativeEvidencePath(evidencePath,{root:ROOT,dockerHost:process.env.DOCKER_HOST,basename:'review-moderation-recovery-evidence.json'});
  const wirePath=path.join(path.dirname(evidencePath),'review-moderation-recovery-wire.json');
  const urls=disposableUrls(),pools=Object.fromEntries(Object.entries(urls).map(([key,connectionString])=>[key,new Pool({connectionString,max:key.endsWith('RUNTIME')?12:3,connectionTimeoutMillis:1500,statement_timeout:8000})]));
  const leasePool=new Pool({connectionString:urls.IDENTITY_RUNTIME,max:4});
  const status={schemaVersion:1,kind:'review-moderation-recovery-actual',qualificationComplete:false,rendered:false,objectiveCredit:false,
    fixedModelEffectProved:false,clientAcknowledgementSimulation:'discard-after-successful-response',serverAcknowledgementFailureSimulated:false,
    passed:false,modelCalls:0,judgeCalls:0,...Object.fromEntries(FLAGS.map(flag=>[flag,false])),errors:[],cleanupErrors:[]};
  const wire={model:MODEL,modelDigest:MODEL_DIGEST,actorCalls:[],actorSpans:[],requests:[],checks:[],original:null,ledger:{}};
  const total=AbortSignal.timeout(LIMITS.totalMs);let lifecycle,transport,server,fileRoot,failure,stage='setup',judgeCalls=0;
  const judge=async()=>{judgeCalls++;throw Error('Review recovery cannot invoke a Judge');};
  try{
    await setup.migrateManualRagStores(pools);
    for(const [store,name]of Object.entries(STORES))assert.equal((await pools[`${store}_RUNTIME`].query('SELECT current_user AS role')).rows[0].role,`dvaia_${name}_runtime`);
    status.isolatedStores=true;
    const identity=pools.IDENTITY_RUNTIME,agents=pools.AGENTS_RUNTIME,review=pools.REVIEW_RUNTIME;
    const auth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity})});
    const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
    const audit=require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
    // The shared composition has lazy file-summary dependencies. Give them a
    // private empty root rather than allowing default-path storage; no file tool
    // belongs to this fixture's review graph.
    fileRoot=await fs.mkdtemp(path.join(path.dirname(evidencePath),'review-recovery-files-'));
    const files=require('../../sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({root:fileRoot,maxReadBytes:1024,maxWriteBytes:1024});
    lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({identityPool:identity,agentsPool:agents,reviewPool:review,leasePool,audit,files});
    transport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:LIMITS.actorCalls,allowMetadata:true});wire.actorCalls=transport.calls;
    const {grading,scenes}=await setup.createManualRagGrading({pools,urls,lifecycle,progress,judge});
    const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:transport.actorUrl,model:MODEL});
    for(const method of ['chat','finalResponse']){const invoke=provider[method].bind(provider);provider[method]=async input=>{
      total.throwIfAborted();const span={method,input:{messages:structuredClone(input.messages)},callIndexes:[]};wire.actorSpans.push(span);const before=transport.calls.length;
      try{return span.result=await invoke({...input,signal:AbortSignal.any([total,AbortSignal.timeout(LIMITS.callMs),...(input.signal?[input.signal]:[])])});}
      finally{span.callIndexes=transport.calls.slice(before).map(call=>call.index);}
    };}
    const {composition,bootstrap,standalone,bound}=await setup.createManualRagApplication({pools,lifecycle,grading,scenes,auth,provider,judge,audit});status.standaloneReady=true;
    const app=express();app.use(express.json());server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
    const origin=`http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth',require('../../server/routes/secureshopStandaloneAuth').createSecureShopStandaloneAuthRouter({...standalone,allowedOrigins:[origin],secureCookies:false}));
    app.use('/api/secureshop',require('../../server/middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({getGateway:()=>bound.gateway}));
    app.use((_req,res)=>res.status(404).json({error:'Outside review recovery fixture'}));
    const request=async(pathname,{headers={},method='GET',body,expected=200}={})=>{
      total.throwIfAborted();const record={pathname,method,body:body??null};wire.requests.push(record);
      const response=await fetch(`${origin}/api/secureshop${pathname}`,{method,headers:{origin,...headers,...(body===undefined?{}:{'content-type':'application/json'})},
        ...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'error',signal:total});
      record.status=response.status;record.cacheControl=response.headers.get('cache-control');record.result=await boundedJson(response);
      if(pathname.startsWith('/merchant/reviews/moderation/'))assert.equal(record.cacheControl,'no-store');
      assert.equal(record.status,expected,`${method} ${pathname}: ${JSON.stringify(record.result).slice(0,300)}`);return record.result;
    };
    const password='owned-review-recovery',suffix=randomUUID().slice(0,8);
    const login=async(name,role)=>{const registered=await auth.register({username:name,password,email:`${name}@example.invalid`,role});await auth.logout(registered.token);
      const active=await auth.login({username:name,password}),boot=await bootstrap(active.context),scope=await composition.launches.resolveCapability(boot.bearer);
      const actor=await composition.personaAuth.authenticateBoundToken({scope,token:boot.persona.token});return {registered,active,boot,scope,persona:actor.user,
        personaSession:{sessionId:actor.sessionId,authorityVersion:actor.authorityVersion},headers:{authorization:`Bearer ${boot.persona.token}`,'x-dvaia-secureshop-launch':boot.bearer},cookie:{cookie:`dvaia_shop_session=${active.token}`}};};
    const merchant=await login(`q05m_${suffix}`,'merchant'),customer=await login(`q05c_${suffix}`,'customer'),foreign=await login(`q05f_${suffix}`,'merchant');
    const listing=await composition.catalog.createMerchantProduct({scope:merchant.scope,persona:merchant.persona,personaSession:merchant.personaSession,
      listing:{name:'Owned recovery headphones',description:'Wireless headphones for everyday listening.',price:21.25,category:'Electronics',images:[],templateSource:null}});
    const body='The product arrived on time and works well. The controls are easy to use.';
    const submitted=await request(`/products/${listing.productId}/reviews`,{method:'POST',headers:customer.headers,body:{submission_id:randomUUID(),author_id:customer.persona.id,body,rating:4}});
    wire.submission={...submitted,body};await request('/merchant/reviews?page=1&per_page=25',{headers:merchant.headers});
    await request('/merchant/reviews?page=1&per_page=25',{headers:foreign.headers});
    const requestId=randomUUID(),readOnly=async(label,pathname,headers=merchant.headers,expected=200)=>{
      assert.deepEqual(await fs.readdir(fileRoot),[]);
      const proof={label,before:await snapshot(pools,transport.calls)};wire.checks.push(proof);
      proof.result=await request(pathname,{headers,expected});proof.status=wire.requests.at(-1).status;proof.cacheControl=wire.requests.at(-1).cacheControl;
      proof.after=await snapshot(pools,transport.calls);assertReadOnly(proof.before,proof.after);assert.deepEqual(await fs.readdir(fileRoot),[]);return proof.result;
    };
    stage='preflight';const initial=await readOnly('preflight',receiptPath(requestId));assertReceipt(initial,{requestId,state:'not_found'});status.preflightReadOnly=true;
    const key=initial.recoveryScopeKey,savedPath=receiptPath(requestId,key);
    const owner=(await identity.query('SELECT e.tenant_id,e.principal_id,s.membership_version::text FROM secureshop_auth.execution_authority_state e JOIN secureshop_auth.execution_sessions s USING(session_id) WHERE e.session_id=$1 AND e.owner_id=$2',[merchant.scope.platformSessionId,merchant.scope.platformOwnerId])).rows[0];assert.ok(owner);
    const authority={tenantId:owner.tenant_id,principalId:owner.principal_id,membershipVersion:owner.membership_version,shopUserId:merchant.persona.id,
      scope:require('../../server/services/secureshopConversationBinding').createLaunchScope(merchant.scope),personaSessionId:merchant.personaSession.sessionId,personaAuthorityVersion:merchant.personaSession.authorityVersion,role:'merchant'};
    const credits=async()=>({judgments:(await identity.query('SELECT to_jsonb(j) AS row FROM secureshop_auth.assessment_judgments j ORDER BY evaluation_id LIMIT 4')).rows,
      completions:(await identity.query('SELECT to_jsonb(c) AS row FROM secureshop_auth.assessment_completions c LIMIT 1')).rows,
      contributions:(await identity.query('SELECT to_jsonb(c) AS row FROM secureshop_auth.assessment_contributions c LIMIT 1')).rows,
      activeContributions:(await identity.query('SELECT to_jsonb(c) AS row FROM secureshop_auth.active_assessment_contributions c LIMIT 1')).rows,
      catalog:(await identity.query('SELECT o.objective_id,o.catalog_active,o.is_enabled,o.qualification,COALESCE(c.is_enabled,o.is_enabled) AS effective_enabled FROM secureshop_auth.assessment_objectives o LEFT JOIN secureshop_auth.assessment_configuration c ON c.objective_id=o.objective_id AND c.tenant_id=$1 WHERE o.objective_id=ANY($2::text[]) ORDER BY o.objective_id',[owner.tenant_id,Object.keys(RUBRICS)])).rows});
    wire.ledger.authority=authority;wire.ledger.initial=await credits();assert.deepEqual(wire.ledger.initial.judgments,[]);
    stage='original-moderation';const postBody={request_id:requestId,limit:1,recoveryScopeKey:key};
    // Observer retains successful response; simulated caller discards it. This
    // is not a dropped socket, failed final response or a mutation retry.
    const projection=await request('/merchant/reviews/moderate-all',{method:'POST',headers:merchant.headers,body:postBody});wire.postProjection=projection;
    const turns=(await agents.query('SELECT * FROM secureshop_agents.turn_requests WHERE request_id=$1',[requestId])).rows;assert.equal(turns.length,1);const turn=turns[0];
    const runId=turn.result_json.taskMetadata.reviewBatch.runId;
    wire.original={turn,session:(await agents.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[turn.session_id])).rows[0],
      run:(await identity.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1',[runId])).rows[0],
      effects:(await identity.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1 ORDER BY effect_key',[runId])).rows,
      traces:(await agents.query('SELECT * FROM secureshop_agents.agent_trace WHERE session_id=$1 ORDER BY id',[turn.session_id])).rows,
      review:(await review.query('SELECT * FROM secureshop_review.reviews WHERE id=$1',[submitted.review_id])).rows[0]};
    wire.ledger.afterOriginal=await credits();
    assertOriginal({original:wire.original,calls:transport.calls,spans:wire.actorSpans,submission:wire.submission});status.originalModelEffect=true;
    assertNoCredit({before:wire.ledger.initial,after:wire.ledger.afterOriginal,original:wire.original,authority});
    stage='saved-recovery';for(let n=0;n<2;n++)assertReceipt(await readOnly(`recovery-${n}`,savedPath),{requestId,key,state:'completed',projection});status.getOnlyRecovery=true;
    const replay={label:'same-id-post-replay',before:await snapshot(pools,transport.calls)};wire.checks.push(replay);
    replay.result=await request('/merchant/reviews/moderate-all',{method:'POST',headers:merchant.headers,body:postBody});replay.after=await snapshot(pools,transport.calls);
    assert.deepEqual(replay.result,{...projection,replayed:true});assertReadOnly(replay.before,replay.after);status.sameIdReplay=true;
    stage='foreign';await readOnly('customer-denied',savedPath,customer.headers,403);
    await readOnly('foreign-key-denied',savedPath,foreign.headers,409);
    assertReceipt(await readOnly('foreign-not-found',receiptPath(requestId),foreign.headers),{requestId,state:'not_found'});status.foreignDenied=true;
    stage='fixed-scope';const mode=await request('/auth/mode',{headers:merchant.cookie});
    await request('/auth/mode',{method:'POST',headers:merchant.cookie,body:{mode:'fixed',expectedRevision:mode.revision}});
    const changed={error:'Review moderation scope changed. Reopen SecureShop to continue.'};
    assert.deepEqual(await readOnly('old-mode-key-denied',savedPath,merchant.headers,409),changed);
    const fixedId=randomUUID(),fixed=await readOnly('fixed-preflight',receiptPath(fixedId));assertReceipt(fixed,{requestId:fixedId,state:'not_found'});assert.notEqual(fixed.recoveryScopeKey,key);status.fixedScopeDenied=true;
    stage='revocation';await composition.personaAuth.logout({scope:foreign.scope,token:foreign.boot.persona.token});
    await readOnly('revoked-persona-denied',savedPath,foreign.headers,401);status.revokedDenied=true;
    stage='sibling';const peerTenant=randomUUID(),peerSlug=`q05peer_${suffix}`,provision=await pools.IDENTITY_MIGRATION.connect();
    try{await provision.query('BEGIN');await provision.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',[peerTenant,peerSlug]);
      for(const [principal,role]of [[merchant.registered.context,'merchant'],[customer.registered.context,'customer']])await provision.query('INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,$4)',[peerTenant,principal.principalId,principal.shopUserId,role]);
      await provision.query('UPDATE secureshop_auth.tenants SET seed_merchant_id=$2 WHERE tenant_id=$1',[peerTenant,merchant.persona.id]);await provision.query('COMMIT');}
    catch(error){await provision.query('ROLLBACK');throw error;}finally{provision.release();}
    const peerAuth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity,executionTenantSlug:peerSlug})});
    const peerLogin=await peerAuth.login({username:`q05c_${suffix}`,password});
    const peerBoot=await require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({launches:composition.launches,personaAuth:composition.personaAuth,authService:peerAuth})(peerLogin.context);
    const peerHeaders={authorization:`Bearer ${peerBoot.persona.token}`,'x-dvaia-secureshop-launch':peerBoot.bearer};
    const peerProducts=await request('/products?limit=1',{headers:peerHeaders});assert.ok(peerProducts.products.length);
    const peerReview=await request(`/products/${peerProducts.products[0].id}/reviews`,{headers:peerHeaders,method:'POST',body:{submission_id:randomUUID(),author_id:customer.persona.id,body:'Sibling product works well.',rating:4}});
    const peerRows=async()=>(await review.query('SELECT to_jsonb(r) AS row FROM secureshop_review.reviews r WHERE id=$1',[peerReview.review_id])).rows;
    wire.siblingBefore=await peerRows();assert.equal(wire.siblingBefore.length,1);
    stage='authenticated-reset';const admin=await auth.login({username:'student_admin',password:'student123'}),adminHeaders={cookie:`dvaia_shop_session=${admin.token}`};
    const boot=await request('/auth/bootstrap',{method:'POST',headers:adminHeaders,body:{}}),ready=await request('/auth/reset-readiness',{headers:adminHeaders});
    assert.equal(ready.available,true);assert.equal(ready.launchId,boot.launch.launchId);assert.equal(ready.generation,boot.launch.generation);
    wire.ledger.beforeReset=await credits();assert.deepEqual(wire.ledger.beforeReset,wire.ledger.afterOriginal);
    await request('/auth/reset',{method:'POST',headers:adminHeaders,body:{launchId:ready.launchId,expectedGeneration:ready.generation,idempotencyKey:randomUUID(),sceneId:ready.scene.id,confirmation:'RESET_SHARED_PRACTICE'}});status.authenticatedReset=true;
    assert.deepEqual(await readOnly('reset-denied',receiptPath(fixedId,fixed.recoveryScopeKey),merchant.headers,409),changed);status.resetDenied=true;
    wire.siblingAfter=await peerRows();assert.deepEqual(wire.siblingAfter,wire.siblingBefore);status.siblingPreserved=true;
    wire.ledger.afterReset=await credits();assert.deepEqual(wire.ledger.afterReset,wire.ledger.beforeReset);
    assertNoCredit({before:wire.ledger.initial,after:wire.ledger.afterReset,original:wire.original,authority});status.noCredit=true;
    assert.equal(judgeCalls,0);assert.ok(transport.calls.length>=2&&transport.calls.length<=LIMITS.actorCalls);
    await peerAuth.logout(peerLogin.token);await auth.logout(admin.token);
  }catch(error){failure=error;status.errors.push({stage,name:error.name,code:error.code||null,message:String(error.message).slice(0,500)});t.diagnostic(JSON.stringify(status.errors[0]));}
  finally{
    for(const close of [()=>transport?.close(),async()=>{if(server){server.closeAllConnections();await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}},
      ()=>lifecycle?.closeFeatureTransports?.(),()=>lifecycle?.auditLedger?.close?.(),async()=>{
        if(fileRoot){assert.equal(await fs.realpath(fileRoot),fileRoot);assert.equal(path.dirname(fileRoot),path.dirname(evidencePath));
          assert.match(path.basename(fileRoot),/^review-recovery-files-[A-Za-z0-9]+$/);assert.deepEqual(await fs.readdir(fileRoot),[]);await fs.rmdir(fileRoot);}
      },()=>leasePool.end(),...Object.values(pools).map(pool=>()=>pool.end())])
      try{await close();}catch(error){status.cleanupErrors.push(String(error.message).slice(0,300));}
    status.modelCalls=transport?.calls.length||0;status.judgeCalls=judgeCalls;status.fixtureCleaned=status.cleanupErrors.length===0;
    status.passed=!failure&&FLAGS.every(flag=>status[flag]);
    if(status.passed)try{assertEvidence(wire,status);}catch(error){failure=error;status.passed=false;status.errors.push({stage:'evidence-contract',message:String(error.message).slice(0,300)});}
    try{const encoded=JSON.stringify(wire);assert.ok(Buffer.byteLength(encoded)<=LIMITS.wireBytes);await fs.writeFile(wirePath,encoded,{flag:'wx',mode:0o600});status.wireSha256=sha(encoded);}
    catch(error){status.passed=false;failure||=error;status.errors.push({stage:'evidence',message:String(error.message).slice(0,300)});}
    await fs.writeFile(evidencePath,JSON.stringify(status),{flag:'wx',mode:0o600});
  }
  if(failure)throw failure;assert.equal(status.passed,true);
});
module.exports={TITLE,MODEL,MODEL_DIGEST,LIMITS,STORES,PREFIX,FLAGS,SNAPSHOT_TABLES,disposableUrls,receiptPath,assertReceipt,snapshot,assertReadOnly,assertNoCredit,assertOriginal,assertEvidence};
