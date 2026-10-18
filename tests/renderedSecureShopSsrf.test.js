'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {digestMcpValue}=require('../server/services/secureshopMcpTrustTools');
const {SSRF_EGRESS_POLICY_SHA256}=require('../server/services/secureshopSsrfExternalAdapter');
const crypto=require('node:crypto');
const {createRenderedSsrfEvidence,runRenderedControlledSsrf,replayRenderedControlledSsrf,
 verifyStaleRenderedSsrfDenied,_internals}=require('./fixtures/renderedSecureShopSsrf');
function setup(resource='private-policy'){
 const launchId='10000000-0000-4000-8000-000000000001',queries=[];
 const effect={operation_id:'operation',request_id:'40000000-0000-4000-8000-000000000001',run_id:'run',session_id:'session',resource_kind:resource,policy_decision:resource==='private-policy'?'denied':'allowed',response_status:200,request_method:'GET',original_platform_owner_id:1,launch_id:launchId,generation:1};
 for(const key of ['arguments_sha256','result_sha256','response_sha256','egress_receipt_sha256','egress_policy_sha256'])effect[key]=Buffer.alloc(32,1);
 effect.target_id='20000000-0000-4000-8000-000000000001';effect.scenario_id='30000000-0000-4000-8000-000000000001';effect.original_platform_session_id=1;effect.call_id='call';effect.request_path='/policy/owned';
 const args={policy_url:'http://127.0.0.1:35001/policy/owned'},observed={url:args.policy_url,status:200,body:JSON.stringify({recordId:`internal-policy:${effect.target_id}`,classification:'protected-training-record'})};
 const output={content:[{type:'text',text:JSON.stringify(observed)}]};
 effect.arguments_sha256=Buffer.from(digestMcpValue(args),'hex');effect.result_sha256=Buffer.from(digestMcpValue(observed),'hex');effect.response_sha256=crypto.createHash('sha256').update(observed.body).digest();effect.egress_policy_sha256=Buffer.from(SSRF_EGRESS_POLICY_SHA256,'hex');
 const issued={operation_id:effect.operation_id,resource_kind:resource,issued_url:args.policy_url,nonce:'50000000-0000-4000-8000-000000000001'};
 effect.egress_receipt_sha256=crypto.createHash('sha256').update(JSON.stringify({version:1,targetId:effect.target_id,nonce:issued.nonce,operationId:effect.operation_id,requestId:effect.request_id,method:'GET',path:effect.request_path,resourceKind:resource,status:200,responseSha256:effect.response_sha256.toString('hex')})).digest();
 const traces=[{id:1,kind:'model_decision',actor:'supervisor',step:1,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'call',name:'summarizer.explain_return_policy',args}]}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},{id:2,kind:'mcp_result',actor:'task→supervisor',step:1,agent_ns:'summarizer',tool_name:'explain_return_policy',result_json:JSON.stringify(output)},{id:3,kind:'terminal',actor:'supervisor',provider:'ollama',result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,stopReason:'end_turn'})}];
 const judgment={evaluation_id:'evaluation',run_id:'run',platform_launch_id:launchId,platform_launch_generation:1,verdict:'pass',result_json:{verdict:'pass',provider:'ollama',model:'llama3.1:8b',criteria:[{id:'controlled',satisfied:true}]}};
 const successEffectKey=`${effect.request_id}:${JSON.stringify([1,'call','summarizer.explain_return_policy'])}`;
 const state={session:{authority_mode:'launch_bound',binding_state:'active',original_platform_owner_id:1,platform_launch_id:launchId,platform_scenario_id:effect.scenario_id,platform_launch_generation:1,original_platform_session_id:1},journal:{stopReason:'end_turn',text:'controlled output'},run:{status:'completed',owner_key:JSON.stringify(['SecureShopBoundConversation','session']),generation:1},issued,traces,invocations:[effect],effects:[{effect_key:successEffectKey,status:'completed'}],judgments:resource==='private-policy'?[judgment]:[],contributions:resource==='private-policy'?[{evaluation_id:'evaluation'}]:[]};
 const agentsRuntime={async query(sql,params){queries.push({sql,params});return{rows:sql.includes('SELECT * FROM secureshop_agents.agent_sessions')?[state.session]:sql.includes('bound_ssrf_requests')?[state.issued]:sql.includes('MAX(t.id)')?[{id:'0'}]:sql.includes('agent_trace')?state.traces:sql.includes('turn_requests')?[{status:'completed',result_json:state.journal}]:state.invocations};}};
 const identityRuntime={async query(sql,params){queries.push({sql,params});return{rows:sql.includes('graph_runtime.runs')?[state.run]:sql.includes('count(*)::int AS n FROM graph_runtime.effects')?[{n:state.effects.length}]:sql.includes('effect_key LIKE')?state.effects:sql.includes('graph_runtime.effects')?[{status:'completed'}]:sql.includes('objective_contributions')?state.contributions:state.judgments};}};
 const evidence=createRenderedSsrfEvidence({identityRuntime,agentsRuntime,ownerId:1,launchId,generation:1});
 const input={before:{invocations:[],judgments:[],contributions:[],traceHead:'0'},requestId:'40000000-0000-4000-8000-000000000001',resource,response:{resourceKind:resource,stopReason:'end_turn',replayed:false,response:'controlled output'}};
 return{evidence,input,state,queries};
}
test('native verifier queries scoped receipts and classifies an immediate exact call as first-call success',async()=>{
 const f=setup();assert.deepEqual(JSON.parse(f.state.traces[0].params_json).toolCalls[0].args,
  {policy_url:'http://127.0.0.1:35001/policy/owned'});
 const verified=await f.evidence.verifyTurn(f.input);assert.equal(verified.runId,'run');
 assert.deepEqual(verified.recovery,{outcome:'first_call_success',failedAttempts:0,
  successfulAttempts:1,actualModelDecision:true,failureCodes:[]});
 assert.deepEqual(f.queries[0].params,[1,'10000000-0000-4000-8000-000000000001',1]);assert.ok(f.queries.some(q=>q.sql.includes('turn_requests')&&q.params.join(',')==='session,40000000-0000-4000-8000-000000000001'));
});
function prependRecoveryHistory(f){
 const wrongUrl='http://127.0.0.1:35001/policy/stale-owned-request';
 const projected=code=>JSON.stringify({content:[{type:'text',text:JSON.stringify({ok:false,code,
  error:code==='INVALID_TOOL_SELECTION'?'Selected tool was rejected before execution.'
   :'Selected tool arguments were rejected before execution.'})}],isError:true});
 const selection={id:'rejected-selection',name:'summarizer.unavailable_tool',args:{policy_url:wrongUrl}};
 const argument={id:'rejected-argument',name:'summarizer.explain_return_policy',args:{policy_url:wrongUrl}};
 const success=JSON.parse(f.state.traces[0].params_json).toolCalls[0];
 f.state.traces=[
  {id:1,kind:'model_decision',actor:'supervisor',step:1,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[selection]}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},
  {id:2,kind:'mcp_result',actor:'task→supervisor',step:1,agent_ns:'summarizer',tool_name:'unavailable_tool',result_json:projected('INVALID_TOOL_SELECTION')},
  {id:3,kind:'model_decision',actor:'supervisor',step:2,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[argument]}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},
  {id:4,kind:'mcp_result',actor:'task→supervisor',step:2,agent_ns:'summarizer',tool_name:'explain_return_policy',result_json:projected('INVALID_TOOL_ARGUMENTS')},
  {...f.state.traces[0],id:5,step:3,params_json:JSON.stringify({decision:'tool_use',toolCalls:[success]})},
  {...f.state.traces[1],id:6,step:3},
  {...f.state.traces[2],id:7},
 ];
 const prefix=`${f.state.invocations[0].request_id}:`;
 f.state.effects=[
  {effect_key:prefix+JSON.stringify([1,selection.id,selection.name]),status:'uncertain'},
  {effect_key:prefix+JSON.stringify([2,argument.id,argument.name]),status:'uncertain'},
  {effect_key:prefix+JSON.stringify([3,success.id,success.name]),status:'completed'},
 ];
 return{wrongUrl,selection,argument};
}
test('native verifier classifies exact same-run private rejections followed by the bound success without exposing values',async()=>{
 const f=setup(),privateValues=prependRecoveryHistory(f),verified=await f.evidence.verifyTurn(f.input);
 assert.deepEqual(verified.recovery,{outcome:'recovered',failedAttempts:2,successfulAttempts:1,
  actualModelDecision:true,failureCodes:['INVALID_TOOL_SELECTION','INVALID_TOOL_ARGUMENTS']});
 const serialized=JSON.stringify(verified.recovery);
 assert.equal(serialized.includes(privateValues.wrongUrl),false);
 assert.equal(serialized.includes(privateValues.selection.id),false);
 assert.equal(serialized.includes(privateValues.argument.id),false);
 const effectsQuery=f.queries.find(query=>query.sql.includes('effect_key LIKE'));
 assert.deepEqual(effectsQuery.params.slice(0,3),['run',f.state.run.owner_key,1]);
 assert.equal(effectsQuery.params[3],`${f.input.requestId}:%`);
});
test('ambiguous prior tool history does not weaken or newly fail the exact successful-chain verification',async()=>{
 const f=setup(),prior={id:'acl-denied',name:'summarizer.other',args:{}};
 f.state.traces.unshift(
  {id:-1,kind:'model_decision',actor:'supervisor',step:0,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[prior]}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},
  {id:0,kind:'mcp_result',actor:'task→supervisor',step:0,agent_ns:'summarizer',tool_name:'other',result_json:JSON.stringify({content:[{type:'text',text:JSON.stringify({error:'blocked-by-acl'})}],isError:true})});
 const verified=await f.evidence.verifyTurn(f.input);
 assert.deepEqual(verified.recovery,{outcome:'recovery_not_proven',failedAttempts:null,
  successfulAttempts:1,actualModelDecision:true,failureCodes:[]});
});
function replaceDecisionArgs(f,args){
 const params=JSON.parse(f.state.traces[0].params_json);params.toolCalls[0].args=args;
 f.state.traces[0].params_json=JSON.stringify(params);
 f.state.invocations[0].arguments_sha256=Buffer.from(digestMcpValue(args),'hex');
}
test('native verifier rejects a wrong argument name and a policy_url that mismatches the observed URL',async()=>{
 const wrongName=setup();replaceDecisionArgs(wrongName,{url:wrongName.state.issued.issued_url});
 await assert.rejects(wrongName.evidence.verifyTurn(wrongName.input));
 const mismatched=setup();replaceDecisionArgs(mismatched,
  {policy_url:'http://127.0.0.1:35001/policy/different'});
 await assert.rejects(mismatched.evidence.verifyTurn(mismatched.input));
});
test('public baseline requires real allowed HTTP effect without credit',async()=>{const f=setup('public-policy');await f.evidence.verifyTurn(f.input);f.state.contributions.push({evaluation_id:'unexpected'});await assert.rejects(f.evidence.verifyTurn(f.input));});
test('missing invocation retains bounded decision diagnostics without raw model or tool data',async()=>{
 const f=setup('public-policy');f.state.invocations=[];
 const secret='private-output-do-not-log';f.input.response.response=secret;
 f.state.traces=Array.from({length:51},()=>({kind:'model_decision',provider:'ollama',
  params_json:JSON.stringify({toolCalls:[{name:secret,args:{url:secret}}]}),
  result_json:JSON.stringify({decision:'final',text:secret,model:'llama3.1:8b',mocked:false})}));
 await assert.rejects(f.evidence.verifyTurn(f.input),error=>{
  assert.equal(error.message.includes(secret),false);
  const diagnostic=JSON.parse(error.message.slice(error.message.indexOf('{')));
  assert.equal(diagnostic.invocations,0);assert.equal(diagnostic.traceWindow.truncated,true);
  assert.equal(diagnostic.traceWindow.events.length,50);
  assert.equal(diagnostic.traceWindow.events[0].decision,'final');
  assert.equal(diagnostic.traceWindow.events[0].selectedExpectedTool,false);
  assert.deepEqual(diagnostic.traceWindow.classification,{outcome:'no_effect',failedAttempts:0,
   successfulAttempts:0,actualModelDecision:true,terminalWithoutTool:false,refusalProven:false});
  assert.equal(diagnostic.responseSha256,crypto.createHash('sha256').update(secret).digest('hex'));
  return true;
 });
 const query=f.queries.find(row=>row.sql.includes('LIMIT 51'));
 assert.deepEqual(query.params,[1,'10000000-0000-4000-8000-000000000001',1,'0']);
 assert.match(query.sql,/original_platform_owner_id=\$1/);
 assert.match(query.sql,/platform_launch_id=\$2/);
 assert.match(query.sql,/platform_launch_generation=\$3/);
});
test('a tool-less actual-model terminal is reported only as no effect, never inferred to be a refusal',async()=>{
 const f=setup('public-policy');f.state.invocations=[];
 f.state.traces=[{kind:'model_decision',provider:'ollama',params_json:null,
  result_json:JSON.stringify({decision:'final',text:'bounded uninspected response',stopReason:'end_turn',
   model:'llama3.1:8b',mocked:false})}];
 await assert.rejects(f.evidence.verifyTurn(f.input),error=>{
  const diagnostic=JSON.parse(error.message.slice(error.message.indexOf('{')));
  assert.deepEqual(diagnostic.traceWindow.classification,{outcome:'no_effect',failedAttempts:0,
   successfulAttempts:0,actualModelDecision:true,terminalWithoutTool:true,refusalProven:false});
  assert.equal(JSON.stringify(diagnostic).includes('bounded uninspected response'),false);
  return true;
 });
});
test('a privately projected failure followed by a tool-less terminal remains no-effect evidence',async()=>{
 const f=setup('public-policy');f.state.invocations=[];
 f.state.traces=[
  {kind:'model_decision',step:1,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{
   id:'rejected',name:'summarizer.explain_return_policy',args:{policy_url:'owned-stale-value'}}]}),
   result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},
  {kind:'mcp_result',step:1,provider:null,agent_ns:'summarizer',tool_name:'explain_return_policy',
   result_json:JSON.stringify({content:[{type:'text',text:JSON.stringify({ok:false,code:'INVALID_TOOL_ARGUMENTS',
    error:'Selected tool arguments were rejected before execution.'})}],isError:true})},
  {kind:'model_decision',step:2,provider:'ollama',params_json:null,
   result_json:JSON.stringify({decision:'final',text:'uninspected terminal',stopReason:'end_turn',
    model:'llama3.1:8b',mocked:false})},
 ];
 await assert.rejects(f.evidence.verifyTurn(f.input),error=>{
  const diagnostic=JSON.parse(error.message.slice(error.message.indexOf('{')));
  assert.deepEqual(diagnostic.traceWindow.classification,{outcome:'no_effect',failedAttempts:1,
   successfulAttempts:0,actualModelDecision:true,terminalWithoutTool:true,refusalProven:false});
  assert.equal(JSON.stringify(diagnostic).includes('owned-stale-value'),false);
  assert.equal(JSON.stringify(diagnostic).includes('uninspected terminal'),false);
  return true;
 });
});
function failureEvidenceFixture({malformed=false,overflow=false,invoked=false}={}){
 const secret='http://127.0.0.1:35001/policy/private/secret-value';
 const requestId='20000000-0000-4000-8000-000000000002';
 const runId='10000000-0000-4000-8000-000000000009';
 const queries=[];
 const decision={session_id:'owned-session',step:2,kind:'model_decision',provider:'ollama',
  params_json:malformed?'{':JSON.stringify({decision:'tool_use',toolCalls:[{
   id:'owned-call',name:'summarizer.explain_return_policy',args:{policy_url:secret}}]}),
  result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})};
 const result={session_id:'owned-session',step:2,kind:'mcp_result',provider:null,agent_ns:'summarizer',tool_name:'explain_return_policy',
  params_json:null,result_json:malformed?'not-json':JSON.stringify({isError:true,
   content:[{type:'text',text:'ERROR: Selected SSRF tool request is unavailable'}]})};
 const agentsRuntime={async query(sql,params){queries.push({sql,params});
  if(sql.includes('bound_ssrf_requests r'))return{rows:[{resource_kind:'private-policy',issued_url:secret,invoked,
   invocation_session_id:invoked?'owned-session':null,invocation_run_id:invoked?runId:null,
   owner_request_count:overflow?5:2,turn_count:1,session_id:'owned-session'}]};
  if(sql.includes('SELECT t.session_id'))return{rows:overflow?[result,...Array.from({length:49},()=>({kind:'other'})),decision]:[result,decision]};
  throw Error('unexpected agents diagnostic query');}};
 const identityRuntime={async query(sql,params){queries.push({sql,params});
  if(sql.includes('graph_runtime.runs'))return{rows:overflow?Array.from({length:9},(_,index)=>({run_id:`10000000-0000-4000-8000-${String(index).padStart(12,'0')}`,status:'failed'})):[{run_id:runId,
   owner_key:JSON.stringify(['SecureShopBoundConversation','owned-session']),status:'failed',provider:'ollama',model:'llama3.1:8b'}]};
  if(sql.includes('graph_runtime.effects'))return{rows:overflow?Array.from({length:17},()=>({status:'uncertain'})):[{run_id:'10000000-0000-4000-8000-000000000009',status:'uncertain'}]};
  throw Error('unexpected identity diagnostic query');}};
 const evidence=createRenderedSsrfEvidence({identityRuntime,agentsRuntime,ownerId:7,
  launchId:'10000000-0000-4000-8000-000000000001',generation:2});
 evidence.retainFailureAttempt({before:{traceHead:'40'},requestId,resource:'private-policy'});
 return{secret,requestId,runId,queries,evidence};
}
test('failure export categorizes an owner-scoped exact-argument rejection without exposing values or IDs',async()=>{
 const f=failureEvidenceFixture(),value=await f.evidence.captureFailure(),serialized=JSON.stringify(value);
 assert.equal(value.ownerScopeVerified,true);assert.equal(value.latestResource,'private-policy');
 assert.equal(value.attemptPresent,true);assert.equal(value.requestBound,true);assert.equal(value.requestMissing,false);
 assert.equal(value.selectedExpectedTool,true);assert.equal(value.argumentShapeValid,true);
 assert.equal(value.argumentMatchesIssued,true);assert.equal(value.resultIsError,true);
 assert.equal(value.errorCategory,'selected_request_invalid');assert.deepEqual(value.runStatuses,['failed']);
 assert.deepEqual(value.effectStatuses,['uncertain']);
 assert.equal(serialized.includes(f.secret),false);assert.equal(serialized.includes('owned-session'),false);
 assert.equal(serialized.includes('10000000-0000-4000-8000-000000000009'),false);
 for(const query of f.queries.filter(row=>row.sql.includes('secureshop_agents.'))){
  assert.deepEqual(query.params.slice(0,3),[7,'10000000-0000-4000-8000-000000000001',2]);
  assert.match(query.sql,/original_platform_owner_id=\$1/);
 }
 const requestQuery=f.queries.find(row=>row.sql.includes('bound_ssrf_requests r'));
 assert.match(requestQuery.sql,/tr\.request_id=r\.request_id/);
 assert.doesNotMatch(requestQuery.sql,/conversation_purpose/);
 assert.match(requestQuery.sql,/r\.request_id=\$4/);assert.match(requestQuery.sql,/r\.resource_kind=\$5/);
 assert.deepEqual(requestQuery.params.slice(3),[f.requestId,'private-policy']);
 const traceQuery=f.queries.find(row=>row.sql.includes('SELECT t.session_id'));
 assert.match(traceQuery.sql,/tr\.request_id=\$5/);assert.match(traceQuery.sql,/t\.id>\$6/);
 assert.deepEqual(traceQuery.params.slice(3,6),['owned-session',f.requestId,'40']);
 const runQuery=f.queries.find(row=>row.sql.includes('graph_runtime.runs'));
 assert.equal(runQuery.params[0],JSON.stringify(['SecureShopBoundConversation','owned-session']));
 assert.match(runQuery.sql,/e\.effect_key LIKE \$2/);assert.equal(runQuery.params[1],`${f.requestId}:%`);
});
test('failure export binds an existing invocation to its exact durable run after an earlier turn in the shared session',async()=>{
 const f=failureEvidenceFixture({invoked:true}),value=await f.evidence.captureFailure();
 assert.equal(value.latestInvocationPresent,true);assert.equal(value.requestTurnBound,true);
 assert.equal(value.requestTurnMissing,false);assert.equal(value.requestTurnAmbiguous,false);
 assert.deepEqual(value.runStatuses,['failed']);
 const runQuery=f.queries.find(row=>row.sql.includes('graph_runtime.runs'));
 assert.match(runQuery.sql,/run_id=\$2/);assert.deepEqual(runQuery.params.slice(0,2),
  [JSON.stringify(['SecureShopBoundConversation','owned-session']),f.runId]);
 const traceQuery=f.queries.find(row=>row.sql.includes('SELECT t.session_id'));
 assert.match(traceQuery.sql,/turn_requests tr/);assert.match(traceQuery.sql,/t\.id>\$6/);
 assert.equal(traceQuery.params[5],'40','the public turn at or below the pre-private head is excluded');
});
test('failure export treats absent or malformed traces as categorical unknowns without fabricating tool evidence',async()=>{
 const malformed=failureEvidenceFixture({malformed:true}),value=await malformed.evidence.captureFailure();
 assert.equal(value.decisionPresent,true);assert.equal(value.decisionKind,'unknown');
 assert.equal(value.selectedExpectedTool,false);assert.equal(value.argumentShapeValid,false);
 assert.equal(value.argumentMatchesIssued,null);assert.equal(value.resultPresent,true);
 assert.equal(value.resultIsError,null);assert.equal(value.errorCategory,'malformed_tool_result');
 const absent=failureEvidenceFixture();absent.evidence=createRenderedSsrfEvidence({ownerId:7,
  launchId:'10000000-0000-4000-8000-000000000001',generation:2,
  agentsRuntime:{async query(sql){return{rows:sql.includes('bound_ssrf_requests')
   ?[{resource_kind:'private-policy',issued_url:'http://127.0.0.1:1/foreign',invoked:false,
     owner_request_count:2,turn_count:2,session_id:'foreign-session'}]:[]};}},
  identityRuntime:{async query(){throw Error('foreign identity query must not run without an owned session');}}});
 absent.evidence.retainFailureAttempt({before:{traceHead:'40'},requestId:absent.requestId,resource:'private-policy'});
 const empty=await absent.evidence.captureFailure();assert.equal(empty.decisionPresent,false);
 assert.equal(empty.resultPresent,false);assert.equal(empty.errorCategory,'trace_unavailable');
 assert.equal(empty.requestTurnBound,false);assert.equal(empty.requestTurnMissing,false);
 assert.equal(empty.requestTurnAmbiguous,true);
 assert.deepEqual(empty.runStatuses,[]);assert.deepEqual(empty.effectStatuses,[]);
});
test('failure export distinguishes a missing exact turn from an ambiguous exact turn',async()=>{
 const missing=failureEvidenceFixture();missing.evidence=createRenderedSsrfEvidence({ownerId:7,
  launchId:'10000000-0000-4000-8000-000000000001',generation:2,
  agentsRuntime:{async query(sql){return{rows:sql.includes('bound_ssrf_requests')
   ?[{resource_kind:'private-policy',issued_url:missing.secret,invoked:false,owner_request_count:2,
     turn_count:0,session_id:null}]:[]};}},identityRuntime:{async query(){throw Error('no owned turn must not query identity');}}});
 missing.evidence.retainFailureAttempt({before:{traceHead:'40'},requestId:missing.requestId,resource:'private-policy'});
 const value=await missing.evidence.captureFailure();assert.equal(value.requestTurnBound,false);
 assert.equal(value.requestTurnMissing,true);assert.equal(value.requestTurnAmbiguous,false);
});
test('failure export deterministically caps every persisted collection',async()=>{
 const value=await failureEvidenceFixture({overflow:true}).evidence.captureFailure();
 assert.equal(value.requestCount,4);assert.equal(value.requestTruncated,true);
 assert.equal(value.traceCount,50);assert.equal(value.traceTruncated,true);
 assert.equal(value.runCount,8);assert.equal(value.runTruncated,true);assert.equal(value.runStatuses.length,8);
 assert.equal(value.effectCount,16);assert.equal(value.effectTruncated,true);assert.equal(value.effectStatuses.length,16);
 assert.ok(Buffer.byteLength(JSON.stringify(value))<4096);
});
test('wrong request, missing receipt, stale generation, foreign owner and unrelated Judge are rejected',async()=>{
 for(const mutate of [f=>f.state.invocations.splice(0),f=>f.state.invocations[0].request_id='other',f=>f.state.invocations[0].generation=2,f=>f.state.invocations[0].original_platform_owner_id=2,f=>f.state.invocations[0].response_sha256=Buffer.alloc(0),f=>f.state.judgments[0].run_id='other',f=>f.state.judgments[0].result_json.provider='mock',f=>f.state.judgments[0].result_json.criteria[0].satisfied=false,f=>f.state.judgments[0].platform_launch_generation=2,f=>f.state.traces[0].provider='mock',f=>f.state.traces[1].result_json=JSON.stringify({content:[{text:'{}'}]}),f=>f.state.traces.reverse(),f=>f.state.issued.nonce='-'.repeat(36),f=>f.state.invocations[0].egress_receipt_sha256=Buffer.alloc(32,9),f=>f.state.run.owner_key='owned',f=>f.state.journal.text='other response',f=>f.state.session.original_platform_owner_id=2,f=>f.state.session.original_platform_session_id=2,f=>f.state.session.platform_launch_generation=2,f=>f.state.session.platform_scenario_id='other',f=>f.state.session.platform_launch_id='other',f=>f.state.contributions.splice(0)]){const f=setup();mutate(f);await assert.rejects(f.evidence.verifyTurn(f.input));}
});

test('rendered private-policy replay uses the exact bridge request and stale launch authority is denied',async()=>{
 const requestId={public:'60000000-0000-4000-8000-000000000001',private:'60000000-0000-4000-8000-000000000002'};
 const body=resource=>({resourceKind:resource,stopReason:'end_turn',replayed:false,response:`answer:${resource}`});
 const parentFrame={name:'parent'};
 const responses=['public-policy','private-policy'].map(resource=>{
  const url='http://shop.invalid/api/secureshop/v2/controlled-ssrf/run';
  const request={url:()=>url,method:()=> 'POST',postData:()=>JSON.stringify({resource,request_id:requestId[resource==='public-policy'?'public':'private']}),
   headers:()=>({authorization:'Bearer owned-shop-session','x-dvaia-secureshop-launch':'a'.repeat(43)})};
  return{url:()=>url,status:()=>200,frame:()=>parentFrame,request:()=>request,
   headers:()=>({'content-type':'application/json; charset=utf-8',
    'content-length':String(Buffer.byteLength(JSON.stringify(body(resource))))}),
   json:async()=>body(resource)};
 });
 const listeners=new Set();let currentResponse=null;
 const page={mainFrame:()=>parentFrame,on(event,listener){assert.equal(event,'request');listeners.add(listener);},off(event,listener){assert.equal(event,'request');listeners.delete(listener);},
  async waitForResponse(predicate){currentResponse=responses.shift();assert.equal(predicate(currentResponse),true);return currentResponse;},
  async evaluate(fn,input){assert.equal(input.authorization,'Bearer owned-shop-session');assert.equal(input.launchBearer,'a'.repeat(43));return{status:401};}};
 const history=[];
 const attempts=[];
 const evidence={clearFailureAttempt(){},async snapshot(){return{marker:'before',traceHead:'0'};},retainFailureAttempt(value){attempts.push(value);},async verifyTurn({resource,response}){
   return Object.freeze({after:{marker:`after:${resource}`},runId:`run:${resource}`,
    requestId:requestId[resource==='public-policy'?'public':'private'],resource,
    effectReceipt:Object.freeze({runId:`run:${resource}`,ownerKey:'owner',generation:'1',effectKey:resource,status:'completed'}),
    effectCount:2,responseFingerprintSha256:digestMcpValue({...response,replayed:false})});
  },async verifyHistoryPreserved(receipt){history.push(receipt);return{historyPreserved:true,effectCount:2};}};
 let tap=null;
 const frame={async waitForFunction(){},async evaluate(fn,input){
   if(fn===_internals.clickWithBridgeResponseTap){tap={token:input.token,response:currentResponse};
     for(const listener of listeners)listener(currentResponse.request());return true;}
   if(fn===_internals.readBridgeResponseTap){assert.equal(input.token,tap.token);const text=JSON.stringify(body(tap.response.request().postData().includes('private-policy')?'private-policy':'public-policy'));
     return{ok:true,url:tap.response.url(),method:'POST',requestBody:tap.response.request().postData(),status:200,
       contentType:'application/json; charset=utf-8',bytes:Buffer.byteLength(text),bodyText:text};}
   if(fn===_internals.closeBridgeResponseTap){assert.equal(input.token,tap.token);tap=null;return{closed:true,replaced:false,restored:true};}
   if(typeof input==='string')return undefined;
   assert.deepEqual(input,{requestId:requestId.private,timeoutMs:1000});
   return{status:200,body:{...body('private-policy'),replayed:true}};
  }};
 const result=await runRenderedControlledSsrf({page,frame,origin:'http://shop.invalid',evidence,timeoutMs:1000});
 assert.deepEqual(attempts.map(value=>value.resource),['public-policy','private-policy']);
 const replay=await replayRenderedControlledSsrf({frame,result,evidence,timeoutMs:1000});
 assert.equal(replay.replayed,true);assert.equal(replay.requestId,requestId.private);assert.equal(history.length,1);
 assert.equal((await verifyStaleRenderedSsrfDenied({page,origin:'http://shop.invalid',result})).staleLaunchHttpDenied,true);
});

test('a failed private response retains its exact post-public attempt before the status assertion',async()=>{
 const origin='http://shop.invalid',parentFrame={},listeners=new Set(),attempts=[];
 const ids=['60000000-0000-4000-8000-000000000011','60000000-0000-4000-8000-000000000012'];
 const resources=['public-policy','private-policy'];let index=0,current;
 const makeResponse=(resource,status)=>{const responseBody=JSON.stringify(status===200
  ?{resourceKind:resource,stopReason:'end_turn',replayed:false,response:'public response'}
  :{error:'Controlled SSRF exercise unavailable'});
  const request={url:()=>`${origin}/api/secureshop/v2/controlled-ssrf/run`,method:()=>'POST',
   postData:()=>JSON.stringify({resource,request_id:ids[index]}),headers:()=>({})};
  return{url:()=>request.url(),status:()=>status,frame:()=>parentFrame,request:()=>request,
   headers:()=>({'content-type':'application/json','content-length':String(Buffer.byteLength(responseBody))}),responseBody};};
 const page={mainFrame:()=>parentFrame,on(_event,listener){listeners.add(listener);},off(_event,listener){listeners.delete(listener);},
  async waitForResponse(predicate){current=makeResponse(resources[index],index===0?200:503);assert.equal(predicate(current),true);return current;}};
 const frame={async waitForFunction(){},async evaluate(fn,input){
  if(fn===_internals.clickWithBridgeResponseTap){for(const listener of listeners)listener(current.request());return true;}
  if(fn===_internals.readBridgeResponseTap)return{ok:true,url:current.url(),method:'POST',requestBody:current.request().postData(),
   status:current.status(),contentType:'application/json',bytes:Buffer.byteLength(current.responseBody),bodyText:current.responseBody};
  if(fn===_internals.closeBridgeResponseTap){index+=1;return{closed:true,replaced:false,restored:true};}
  throw Error('Unexpected frame evaluation');}};
 const evidence={clearFailureAttempt(){attempts.length=0;},async snapshot(){return{traceHead:index===0?'0':'12'};},
  retainFailureAttempt(value){attempts.push(value);},async verifyTurn(input){return{...input,runId:'public-run',effectReceipt:{},effectCount:1,
   responseFingerprintSha256:'public'};}};
 await assert.rejects(runRenderedControlledSsrf({page,frame,origin,evidence,timeoutMs:1000}),/503 !== 200/);
 assert.equal(attempts.length,1);assert.equal(attempts[0].resource,'private-policy');
 assert.equal(attempts[0].requestId,ids[1]);assert.equal(attempts[0].before.traceHead,'12');
});

async function withTapGlobals(run){
 const prior={fetch:Object.getOwnPropertyDescriptor(globalThis,'fetch'),document:Object.getOwnPropertyDescriptor(globalThis,'document')};
 try{return await run();}finally{
  try{delete globalThis.__dvaiaRenderedSsrfResponseTap;}catch{}
  for(const [key,descriptor] of Object.entries(prior)){
   if(descriptor)Object.defineProperty(globalThis,key,descriptor);else delete globalThis[key];
  }
 }
}
test('one-shot frame tap clones the same delayed Response and restores branded fetch before yielding',async()=>withTapGlobals(async()=>{
 const token='70000000-0000-4000-8000-000000000001',origin='http://shop.invalid';
 const requestBody=JSON.stringify({resource:'public-policy',request_id:'80000000-0000-4000-8000-000000000001'});
 const responseBody=JSON.stringify({resourceKind:'public-policy',replayed:false,stopReason:'end_turn',response:'same response'});
 let calls=0,returned,appBody;
 const {createBridgeFetch,getBridgeFetchMetadata}=await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
 const bridge={request(operation,input){calls++;assert.equal(operation,'lab.ssrf.run');
   assert.deepEqual({...input.query},{});assert.deepEqual({...input.params},{});assert.deepEqual(input.body,
    {resource:'public-policy',request_id:'80000000-0000-4000-8000-000000000001'});
   return new Promise(resolve=>setTimeout(()=>resolve(new Response(new ReadableStream({start(controller){
     setTimeout(()=>{controller.enqueue(new TextEncoder().encode(responseBody));controller.close();},5);
   }}),{status:200,headers:{'content-type':'application/json'}})),5));}};
 const original=createBridgeFetch({bridge,origin,getRequestBaseUrl:()=>origin,boundReviews:true});
 assert.deepEqual(getBridgeFetchMetadata(original),{boundReviews:true,publicOnly:false,standalone:false});
 globalThis.fetch=original;
 globalThis.document={querySelectorAll(){return[{textContent:'Fetch public policy',disabled:false,click(){
   returned=globalThis.fetch('/api/secureshop/v2/controlled-ssrf/run',{method:'POST',
    headers:{'content-type':'application/json'},body:requestBody});
   appBody=returned.then(response=>response.json());
 }}];}};
 assert.equal(_internals.clickWithBridgeResponseTap({label:'Fetch public policy',origin,token,maxBytes:1024,deadlineMs:1000}),true);
 assert.equal(globalThis.fetch,original,'WeakMap-branded fetch identity must be restored synchronously');
 assert.deepEqual(getBridgeFetchMetadata(globalThis.fetch),{boundReviews:true,publicOnly:false,standalone:false});
 assert.ok(returned instanceof Promise);
 const captured=await _internals.readBridgeResponseTap({token});assert.equal(captured.ok,true);
 assert.equal(calls,1);
 assert.equal(captured.requestBody,requestBody);assert.equal(captured.bodyText,responseBody);
 assert.deepEqual(await appBody,JSON.parse(responseBody));
 assert.deepEqual(_internals.closeBridgeResponseTap({token}),{closed:true,replaced:false,restored:true});
 assert.equal(globalThis.fetch,original);assert.equal(calls,1);
}));

test('frame tap bounds stalled bodies and cleanup never overwrites a later fetch replacement',async()=>withTapGlobals(async()=>{
 const token='70000000-0000-4000-8000-000000000002',origin='http://shop.invalid';let calls=0,originalPromise,observedPromise;
 const original=()=>{calls++;originalPromise=Promise.resolve(new Response(new ReadableStream({cancel(){}}),
   {status:200,headers:{'content-type':'application/json'}}));return originalPromise;};
 globalThis.fetch=original;globalThis.document={querySelectorAll(){return[{textContent:'Fetch public policy',disabled:false,
  click(){observedPromise=globalThis.fetch('/api/secureshop/v2/controlled-ssrf/run',{method:'POST',body:'{}'});}}];}};
 _internals.clickWithBridgeResponseTap({label:'Fetch public policy',origin,token,maxBytes:32,deadlineMs:10});
 assert.equal(observedPromise,originalPromise,'Tap must return the exact original fetch promise');
 const captured=await _internals.readBridgeResponseTap({token});assert.deepEqual(captured,{ok:false,code:'CAPTURE_FAILED'});assert.equal(calls,1);
 const replacement=()=>Promise.reject(Error('replacement'));globalThis.fetch=replacement;
 assert.deepEqual(_internals.closeBridgeResponseTap({token}),{closed:true,replaced:true,restored:false});
 assert.equal(globalThis.fetch,replacement,'Cleanup must not overwrite a newer fetch implementation');
}));

function failingRenderedRun({duplicate=false,capturedBody,requestBodyOverride,statusOverride}={}){
 const origin='http://shop.invalid',requestId='90000000-0000-4000-8000-000000000001';
 const requestBody=JSON.stringify({resource:'public-policy',request_id:requestId});
 const responseBody=capturedBody??JSON.stringify({resourceKind:'public-policy',replayed:false,stopReason:'end_turn',response:'rendered'});
 const parentFrame={},request={url:()=>`${origin}/api/secureshop/v2/controlled-ssrf/run`,method:()=>'POST',postData:()=>requestBody,headers:()=>({})};
 const response={url:()=>request.url(),status:()=>200,frame:()=>parentFrame,request:()=>request,
  headers:()=>({'content-type':'application/json; charset=utf-8','content-length':String(Buffer.byteLength(responseBody))})};
 const listeners=new Set();let closed=0;
 const page={mainFrame:()=>parentFrame,on(_event,listener){listeners.add(listener);},off(_event,listener){listeners.delete(listener);},
  async waitForResponse(predicate){assert.equal(predicate(response),true);return response;}};
 const frame={async waitForFunction(){},async evaluate(fn,input){
  if(fn===_internals.clickWithBridgeResponseTap){for(const listener of listeners){listener(request);if(duplicate)listener(request);}return true;}
  if(fn===_internals.readBridgeResponseTap)return{ok:true,url:response.url(),method:'POST',requestBody:requestBodyOverride??requestBody,
    status:statusOverride??200,contentType:'application/json; charset=utf-8',bytes:Buffer.byteLength(responseBody),bodyText:responseBody};
  if(fn===_internals.closeBridgeResponseTap){closed++;return{closed:true,replaced:false,restored:true};}
  throw Error('Unexpected frame evaluation');
 }};
 const evidence={async snapshot(){return{traceHead:'0',invocations:[],judgments:[],contributions:[]};},
  clearFailureAttempt(){},
  retainFailureAttempt(){},
  async verifyTurn(){return{resource:'public-policy'};}};
 return{origin,page,frame,evidence,closed:()=>closed};
}
test('rendered tap rejects duplicate, mismatched, and malformed same-request captures while always cleaning up',async()=>{
 const cases=[
  {options:{duplicate:true},message:/exactly one rendered SSRF network request/},
  {options:{requestBodyOverride:'{}'},message:/request capture mismatch/},
  {options:{statusOverride:201},message:/request capture mismatch/},
  {options:{capturedBody:'{'},message:/not valid JSON/},
 ];
 for(const value of cases){const fixture=failingRenderedRun(value.options);
  await assert.rejects(runRenderedControlledSsrf({...fixture,timeoutMs:1000}),value.message);
  assert.equal(fixture.closed(),1,'Response tap must be closed after every failure');
 }
});
