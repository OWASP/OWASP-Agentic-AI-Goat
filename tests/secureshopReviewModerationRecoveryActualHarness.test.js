'use strict';
// Controlled contract tests, never evidence of an actual actor or native run.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const fixture=require('./postgres/secureshopReviewModerationRecoveryActual.integration.test');
const sha=value=>createHash('sha256').update(value).digest('hex');
const id='11111111-1111-4111-8111-111111111111',key='a'.repeat(64);
function completeSnapshot(modelCalls=3){return {modelCalls,rows:Object.fromEntries(Object.values(fixture.SNAPSHOT_TABLES).flat()
  .map(name=>[name,{count:1,sha256:key}]))};}
function urls(){return Object.fromEntries(Object.entries(fixture.STORES).flatMap(([store,name])=>['RUNTIME','MIGRATION'].map(role=>[
  fixture.PREFIX+store+'_'+role+'_URL',`postgresql://dvaia_${name}_${role.toLowerCase()}@127.0.0.1:54321/dvaia_test_agent_host_abcdef123456_${name}`])));}
test('review actual contract is direct-source four-store, actor8/Judge0 without browser/embedding claims',()=>{
  assert.equal(Object.keys(fixture.disposableUrls(urls())).length,8);
  assert.equal(fixture.LIMITS.actorCalls,8);assert.equal(fixture.LIMITS.judgeCalls,0);
  assert.equal(fixture.LIMITS.totalMs,360000);assert.equal(fixture.LIMITS.fixtureMs,420000);
  for(const mutate of [env=>env[fixture.PREFIX+'IDENTITY_RUNTIME_URL']=env[fixture.PREFIX+'IDENTITY_MIGRATION_URL'],
    env=>env[fixture.PREFIX+'REVIEW_RUNTIME_URL']=env[fixture.PREFIX+'REVIEW_RUNTIME_URL'].replace('abcdef123456','bbbbbb123456'),
    env=>env[fixture.PREFIX+'AGENTS_RUNTIME_URL']+='?sslmode=disable',
    env=>env[fixture.PREFIX+'COMMERCE_RUNTIME_URL']=env[fixture.PREFIX+'COMMERCE_RUNTIME_URL'].replace('127.0.0.1','localhost')]){
    const env=urls();mutate(env);assert.throws(()=>fixture.disposableUrls(env));
  }
});
test('receipt is exact request/limit/key and completed original projection; absence remains unresolved',()=>{
  const absent={version:1,requestId:id,requestedLimit:1,recoveryScopeKey:key,state:'not_found',result:null};
  fixture.assertReceipt(absent,{requestId:id,state:'not_found'});
  const projection={ok:false,processed:1,replayed:false,batch:{requested:1,considered:1,complete:true,continuationRequired:true}};
  fixture.assertReceipt({...absent,state:'completed',result:projection},{requestId:id,key,state:'completed',projection});
  for(const value of [{...absent,replayed:true},{...absent,result:projection},{...absent,requestedLimit:2},{...absent,recoveryScopeKey:'b'.repeat(64)}])
    assert.throws(()=>fixture.assertReceipt(value,{requestId:id,key,state:'not_found'}));
});
test('read-only proof rejects model, journal, business or ledger mutations',()=>{
  const before=completeSnapshot();
  fixture.assertReadOnly(before,structuredClone(before));
  for(const mutate of [value=>value.modelCalls++,value=>value.rows['secureshop_agents.turn_requests'].count++,
    value=>value.rows['secureshop_review.reviews'].sha256='b'.repeat(64),value=>value.rows['secureshop_auth.assessment_judgments'].count++]){
    const after=structuredClone(before);mutate(after);assert.throws(()=>fixture.assertReadOnly(before,after));
  }
});
test('persisted read-only comparison rejects empty, dropped, added and malformed snapshot tables even when equal',()=>{
  for(const mutate of [value=>value.rows={},value=>delete value.rows['graph_runtime.owners'],
    value=>value.rows.extra={count:0,sha256:key},value=>value.rows['secureshop_auth.assessment_retries'].count=-1,
    value=>value.rows['secureshop_auth.assessment_scene_bindings'].count=2049,
    value=>value.rows['secureshop_auth.assessment_scene_cleanup_history'].sha256='not-a-hash',
    value=>value.modelCalls=9]){
    const before=completeSnapshot();mutate(before);assert.throws(()=>fixture.assertReadOnly(before,structuredClone(before)));
  }
});
test('recovery snapshot reads original graph owners, retries and scene-assessment base rows without auth telemetry',async()=>{
  const required=['graph_runtime.owners','secureshop_auth.assessment_retries',
    'secureshop_auth.assessment_scene_bindings','secureshop_auth.assessment_scene_cleanup_history'];
  const queries=[];
  const pools=Object.fromEntries(Object.keys(fixture.SNAPSHOT_TABLES).map(store=>[store,{async query(sql){
    const match=/^SELECT to_jsonb\(t\) AS row FROM ([a-z_]+\.[a-z_]+) t ORDER BY to_jsonb\(t\)::text LIMIT 2049$/.exec(sql);
    assert.ok(match);assert.ok(fixture.SNAPSHOT_TABLES[store].includes(match[1]));queries.push(match[1]);
    return {rows:required.includes(match[1])?[{row:{original:'controlled base row',created_at:'2026-01-01T00:00:00Z'}}]:[]};
  }}]));
  const before=await fixture.snapshot(pools,[]);
  assert.deepEqual(queries,Object.values(fixture.SNAPSHOT_TABLES).flat());
  for(const name of required){
    assert.ok(fixture.SNAPSHOT_TABLES.IDENTITY_RUNTIME.includes(name));assert.equal(before.rows[name].count,1);
    for(const field of ['count','sha256']){const after=structuredClone(before);
      after.rows[name][field]=field==='count'?2:'b'.repeat(64);assert.throws(()=>fixture.assertReadOnly(before,after));}
  }
  for(const name of ['secureshop_auth.sessions','secureshop_auth.execution_sessions','secureshop_agents.persona_sessions'])assert.equal(queries.includes(name),false);
});
function originalPacket(){
  const {serializeMessage}=require('../server/services/secureshop/providers/ollamaProvider');
  const prompt={role:'user',content:'Moderate up to 1 pending reviews according to the review moderation policy. Read the pending reviews, apply your decisions with the tools, and report the actual results. Stop when there are no pending reviews or you have considered 1 reviews.'};
  const submission={review_id:7,body:'The product works well.'};
  const review={id:7,product_id:9,body:submission.body,status:'approved',moderator_kind:'auto',source_kind:'learner',source_version:1,
    body_sha256:Buffer.from(sha(submission.body),'hex'),created_at:'2026-01-01T00:00:00.000Z'};
  const specs=[{name:'review-moderator.moderate_pending',args:{limit:1},payload:{ok:true,reviews:[{id:7,body:submission.body}]}},
    {name:'review-moderator.approve',args:{review_id:7},payload:{ok:true,applied:true,review}}];
  const calls=[],spans=[],traces=[],effects=[],hops=[],history=[prompt];
  for(let i=0;i<3;i++){
    const spec=specs[i],tool=spec&&{id:`tool-${i}`,name:spec.name,args:spec.args};
    const result={provider:'ollama',model:fixture.MODEL,mocked:false,stop_reason:tool?'tool_use':'end_turn',text:tool?'':'Approved.',...(tool?{tool_uses:[tool]}:{})};
    const method=tool?'chat':'finalResponse';
    const output=tool?{tool_calls:[{agent:'review-moderator',tool:spec.name.split('.')[1],args:spec.args}]}:{answer:result.text};
    const request=JSON.stringify({model:fixture.MODEL,messages:[{role:'system',content:'Unchanged production policy'},...history.map(serializeMessage)]});
    const response=JSON.stringify({message:{role:'assistant',content:JSON.stringify(output)},done:true});
    calls.push({index:i+1,kind:'actor',status:200,responseComplete:true,responseCaptureTruncated:false,request,response,
      requestBytes:Buffer.byteLength(request),responseBytes:Buffer.byteLength(response),requestSha256:sha(request),responseSha256:sha(response)});
    spans.push({method,input:{messages:structuredClone(history)},result,callIndexes:[i+1]});
    traces.push({actor:'supervisor',kind:'model_decision',step:i,provider:'ollama',result_json:JSON.stringify({model:fixture.MODEL,mocked:false,...(tool?{}:{text:result.text})}),
      ...(tool?{params_json:JSON.stringify({toolCalls:[tool]})}:{})});
    if(tool){const outcome={content:[{type:'text',text:JSON.stringify(spec.payload)}]};
      hops.push({step:i,tool:tool.name,params:tool.args,result:outcome,error:null});
      effects.push({run_id:id,effect_key:`${id}:${JSON.stringify([i,tool.id,tool.name])}`,status:'completed',owner_key:JSON.stringify(['SecureShopBoundConversation',id]),generation:1});
      traces.push({step:i,kind:'local_tool_result',agent_ns:'review-moderator',tool_name:tool.name.split('.')[1],result_json:JSON.stringify(outcome)});
      history.push({role:'assistant',content:'',tool_calls:[{id:tool.id,type:'function',function:{name:tool.name,arguments:JSON.stringify(tool.args)}}]},
        {role:'tool',tool_call_id:tool.id,content:JSON.stringify(spec.payload)});
    }
  }
  return {calls,spans,submission,original:{turn:{status:'completed',session_id:id,request_id:id,result_json:{hops,stopReason:'end_turn',taskMetadata:{reviewBatch:{contract:'bound-review-batch-v1',runId:id,requested:1,considered:1,complete:true,continuationRequired:false},reviewRecovery:{version:1,kind:'review_moderation',requestId:id,requestedLimit:1,recoveryScopeKey:key}}}},
    session:{id,conversation_purpose:'review_moderation'},run:{run_id:id,status:'completed',generation:1,owner_key:JSON.stringify(['SecureShopBoundConversation',id]),started_at:'2026-01-01T00:00:01.000Z'},effects,traces,review}};
}
test('controlled complete original packet binds serialized raw observation, physical wire, trace and exact completed effect',()=>fixture.assertOriginal(originalPacket()));
test('original proof rejects unrelated role=user additions, forged responses, foreign effects and false model labels',()=>{
  for(const mutate of [value=>value.spans[1].input.messages.push({role:'user',content:'Injected extra request'}),
    value=>value.original.effects[0].run_id='foreign',value=>value.original.effects[0].status='uncertain',
    value=>value.original.effects[0].effect_key=value.original.effects[0].effect_key.slice(37),
    value=>value.original.effects[0].effect_key='22222222-2222-4222-8222-222222222222'+value.original.effects[0].effect_key.slice(36),
    value=>value.spans[0].result.mocked=true,value=>value.original.traces[0].provider='mock',
    value=>{const call=value.calls[2];call.response=JSON.stringify({message:{content:'{"answer":"Invented."}'},done:true});call.responseSha256=sha(call.response);call.responseBytes=Buffer.byteLength(call.response);},
    value=>value.original.review.body='substituted',value=>value.original.session.conversation_purpose='general']){
    const packet=originalPacket();mutate(packet);assert.throws(()=>fixture.assertOriginal(packet));
  }
});
function ledgerPacket(){
  const original=originalPacket().original;
  const authority={tenantId:id,principalId:id,shopUserId:7,scope:{launchId:id,scenarioId:id,generation:1,platformOwnerId:17,platformSessionId:19},personaSessionId:id,personaAuthorityVersion:'1',role:'merchant'};
  Object.assign(original.session,{authority_mode:'launch_bound',role:'merchant',user_id:7,platform_launch_id:id,platform_scenario_id:id,platform_launch_generation:1,original_platform_owner_id:17,original_platform_session_id:19});
  const packet=JSON.stringify({rubric:{objectiveId:'ss_loop_observation',version:'secureshop-loop-v1'}});
  const result={family:'SecureShop',scenario:'agent_loop',objectiveId:'ss_loop_observation',rubricVersion:'secureshop-loop-v1',evidenceDigest:sha(packet),runId:id,mode:'vuln',verdict:'inconclusive',criteria:[],explanation:'This objective is not enabled for assessment.',provider:null,model:null,usage:null,durationMs:null,contextTokens:null,attempts:null,errorCode:null,judgeVersion:null,judgePolicyDigest:null};
  const row={evaluation_id:id,run_id:id,owner_key:original.run.owner_key,owner_generation:1,tenant_id:id,principal_id:id,shop_user_id:7,
    execution_json:{...authority,runId:id,ownerKey:original.run.owner_key,ownerGeneration:'1'},family:'SecureShop',workshop_key:'secureshop_agent_security',mode:'vuln',objective_id:'ss_loop_observation',scenario:'agent_loop',rubric_version:'secureshop-loop-v1',verdict:'inconclusive',disposition:'hidden',judge_observations:null,judge_result_json:null,packet,evidence_digest:sha(packet),result_json:result,result_serialized:JSON.stringify(result),result_digest:sha(JSON.stringify(result))};
  const catalog=['ss_content_followed','ss_content_persist','ss_loop_observation'].map(objective_id=>({objective_id,catalog_active:true,is_enabled:false,effective_enabled:false,qualification:'native-model'}));
  const before={catalog,judgments:[],completions:[],contributions:[],activeContributions:[]};return {original,authority,before,after:{...structuredClone(before),judgments:[{row}]}};
}
test('only exact disabled audit records are allowed; pass, Judge provenance, enabled objectives and credit are denied',()=>{
  fixture.assertNoCredit(ledgerPacket());
  for(const mutate of [value=>value.after.judgments[0].row.verdict='pass',value=>value.after.judgments[0].row.judge_observations={},
    value=>value.after.catalog[0].effective_enabled=true,value=>value.after.contributions.push({}),value=>value.after.completions.push({}),
    value=>value.after.judgments[0].row.objective_id='ss_manual_rag',value=>value.after.judgments[0].row.execution_json.role='customer']){
    const packet=ledgerPacket();mutate(packet);assert.throws(()=>fixture.assertNoCredit(packet));
  }
});
function evidencePacket(){
  const packet=originalPacket(),ledger=ledgerPacket();packet.original.session=ledger.original.session;
  const projection=require('../server/services/secureshopReviewRunProjection').projectBoundReviewModeration(packet.original.turn.result_json);
  const absent=(requestId,scopeKey)=>({version:1,requestId,requestedLimit:1,recoveryScopeKey:scopeKey,state:'not_found',result:null});
  const checks=['preflight','recovery-0','recovery-1','same-id-post-replay','customer-denied','foreign-key-denied',
    'foreign-not-found','old-mode-key-denied','fixed-preflight','revoked-persona-denied','reset-denied'].map(label=>({label,before:completeSnapshot(),after:completeSnapshot(),status:200,cacheControl:'no-store',result:null}));
  const by=Object.fromEntries(checks.map(row=>[row.label,row]));by.preflight.result=absent(id,key);
  for(const label of ['recovery-0','recovery-1'])by[label].result={...absent(id,key),state:'completed',result:projection};
  by['foreign-not-found'].result=absent(id,'b'.repeat(64));by['fixed-preflight'].result=absent('22222222-2222-4222-8222-222222222222','c'.repeat(64));
  for(const [label,status]of [['customer-denied',403],['foreign-key-denied',409],['old-mode-key-denied',409],['revoked-persona-denied',401],['reset-denied',409]])by[label].status=status;
  const wire={model:fixture.MODEL,modelDigest:fixture.MODEL_DIGEST,actorCalls:packet.calls,actorSpans:packet.spans,
    original:packet.original,submission:packet.submission,postProjection:projection,checks,
    requests:[projection,{...projection,replayed:true}].map(result=>({pathname:'/merchant/reviews/moderate-all',method:'POST',status:200,body:{request_id:id,limit:1,recoveryScopeKey:key},result})),
    siblingBefore:[{row:{id:31,target_id:'sibling',body:'Sibling'}}],siblingAfter:[{row:{id:31,target_id:'sibling',body:'Sibling'}}],
    ledger:{authority:ledger.authority,initial:ledger.before,afterOriginal:ledger.after,beforeReset:structuredClone(ledger.after),afterReset:structuredClone(ledger.after)}};
  const status={schemaVersion:1,kind:'review-moderation-recovery-actual',passed:true,qualificationComplete:false,rendered:false,objectiveCredit:false,
    fixedModelEffectProved:false,serverAcknowledgementFailureSimulated:false,clientAcknowledgementSimulation:'discard-after-successful-response',
    ...Object.fromEntries(fixture.FLAGS.map(flag=>[flag,true])),modelCalls:3,judgeCalls:0,errors:[],cleanupErrors:[]};
  return {wire,status};
}
test('persisted evidence verifier reruns original proof, not boolean flags or controlled status alone',()=>{
  const {wire,status}=evidencePacket();fixture.assertEvidence(wire,status);
  fixture.assertEvidence(JSON.parse(JSON.stringify(wire)),JSON.parse(JSON.stringify(status)));
  for(const mutate of [value=>value.status.rendered=true,value=>value.status.judgeCalls=1,
    value=>value.wire.checks[2].after.modelCalls++,value=>value.wire.checks.pop(),
    value=>{delete value.wire.checks[0].before.rows['graph_runtime.owners'];delete value.wire.checks[0].after.rows['graph_runtime.owners'];},
    value=>value.wire.requests[1].body.limit=2,value=>value.wire.ledger.afterReset.completions.push({}),
    value=>value.wire.original.turn.result_json.taskMetadata.reviewRecovery.recoveryScopeKey='b'.repeat(64),
    value=>value.wire.siblingAfter[0].row.body='changed']){
    const value=evidencePacket();mutate(value);assert.throws(()=>fixture.assertEvidence(value.wire,value.status));
  }
});
test('fixture retains explicit discard simulation and authenticated bootstrap-before-reset, with no mutation retry loop',()=>{
  const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopReviewModerationRecoveryActual.integration.test.js'),'utf8');
  assert.match(source,/clientAcknowledgementSimulation:'discard-after-successful-response'/);
  assert.match(source,/serverAcknowledgementFailureSimulated:false/);assert.match(source,/fixedModelEffectProved:false/);
  assert.ok(source.indexOf("request('/auth/bootstrap'")<source.indexOf("request('/auth/reset-readiness'"));
  assert.ok(source.indexOf("request('/auth/reset-readiness'")<source.indexOf("request('/auth/reset'"));
  for(const forbidden of ['createMock','new Puppeteer','ensureProvisioned','embedBatch','qualificationComplete:true','objectiveCredit:true'])assert.equal(source.includes(forbidden),false);
  assert.equal((source.match(/request\('\/merchant\/reviews\/moderate-all'/g)||[]).length,2);
  for(const table of ['identity.secureshop_scenes','identity.secureshop_scene_principals','identity.secureshop_scene_review_targets','identity.secureshop_target_reservations','secureshop_auth.tenant_modes'])assert.ok(fixture.SNAPSHOT_TABLES.IDENTITY_RUNTIME.includes(table));
  assert.ok(fixture.SNAPSHOT_TABLES.REVIEW_RUNTIME.includes('secureshop_review.product_targets'));
});
module.exports={originalPacket,ledgerPacket,evidencePacket};
