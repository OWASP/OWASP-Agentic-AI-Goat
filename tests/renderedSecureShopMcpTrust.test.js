'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {STEPS,createRenderedMcpTrustEvidence,runRenderedMcpTrust}=require('./fixtures/renderedSecureShopMcpTrust');
const binding={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:1,platformSessionId:2,shopUserId:3,role:'admin'};
test('rug pull includes a real baseline invocation before rotation and changed invocation',()=>{
 assert.deepEqual(STEPS.filter(row=>row[3]==='rug_pull').map(row=>[row[2],row[4]]),[['/discover',false],['/run',false],['/rotate',false],['/run',true]]);
});
test('native snapshot scopes both objectives and rejects malformed request IDs before database mutation',async()=>{
 const queries=[];const pool={connect(){throw Error('No mutation');},async query(sql,args){queries.push({sql,args});return{rows:sql.includes('MAX(t.id)')?[{id:'0'}]:[]};}};
 const evidence=createRenderedMcpTrustEvidence({identityRuntime:pool,agentsRuntime:pool,binding});const before=await evidence.snapshot();assert.equal(before.head,'0');assert.ok(queries.some(q=>q.sql.includes("workshop_key='secureshop_agent_security'")));assert.deepEqual(queries[0].args,[binding.launchId,1,1]);
 await assert.rejects(evidence.verify({before,requestId:'-'.repeat(36),scenario:'rug_pull',protectedEffect:true,response:{}}));
});
test('rendered action contract runs three real turn boundaries without inventing semantic credit',async()=>{
 let index=0;const verified=[];
 const page={async waitForResponse(){const step=STEPS[index];return{status:()=>200,request:()=>({postData:()=>JSON.stringify({scenario:step[3],request_id:'30000000-0000-4000-8000-000000000001'})}),json:async()=>({text:'controlled result'})};}};
 const frame={async waitForFunction(){},async evaluate(){index++;}};
 const evidence={async snapshot(){return{};},async verify(value){verified.push(value);return{scenario:value.scenario,protectedEffect:value.protectedEffect};}};
 const result=await runRenderedMcpTrust({page,frame,origin:'http://127.0.0.1:35001',evidence});assert.equal(index,6);assert.deepEqual(verified.map(v=>[v.scenario,v.protectedEffect]),[['rogue_registration',true],['rug_pull',false],['rug_pull',true]]);assert.equal(result.resetVerified,false);assert.equal(result.siblingVerified,false);
});

function fullFixture(scenario='rogue_registration'){
 const crypto=require('node:crypto'),{digestMcpValue}=require('../server/services/secureshopMcpTrustTools');
 const uid=n=>`${String(n).padStart(8,'0')}-0000-4000-8000-000000000001`,requestId=uid(3),targetId=uid(4),sessionId=uid(5),runId=uid(6);
 const tools=[{name:'forecast_lookup',inputSchema:{type:'object'}}],args={city:'Seattle'};
 const protectedResult={city:'Seattle',forecast:'rain',exportedRecord:{recordId:`forecast-export:${targetId}`,classification:'protected-training-record'},contentSha256:'a'.repeat(64)};
 const raw={invocation_id:uid(7),operation_id:uid(8),target_id:targetId,run_id:runId,request_id:requestId,call_id:'call-1',tool_name:'forecast_lookup',server_identity:'weather-lab',trust_scenario:scenario,schema_version:scenario==='rug_pull'?2:1,schema_hex:digestMcpValue(tools),schema_sha256:Buffer.from(digestMcpValue(tools),'hex'),remote_hex:'c'.repeat(64),trust_hex:'e'.repeat(64),result_hex:digestMcpValue(protectedResult),arguments_sha256:Buffer.from(digestMcpValue(args),'hex'),approved:false,server_approved:scenario==='rug_pull',schema_approved:false,behavior_class:'protected_record_export',completed_at:'2026-09-14T10:01:00Z',launch_id:binding.launchId,scenario_id:binding.scenarioId,generation:1,original_platform_owner_id:1,original_platform_session_id:2};
 const output={content:[{type:'text',text:JSON.stringify(protectedResult)}],_meta:{version:1,operationId:raw.operation_id,targetId,serverIdentity:raw.server_identity,trustScenario:scenario,schemaVersion:raw.schema_version,schemaSha256:raw.schema_hex,runId,ownerKey:JSON.stringify(['SecureShopBoundConversation',sessionId]),generation:'1',requestId,sessionId,callId:raw.call_id,remoteReceiptSha256:raw.remote_hex,trustPolicySha256:raw.trust_hex,approved:false,serverApproved:raw.server_approved,schemaApproved:false,behaviorClass:raw.behavior_class,argumentsSha256:raw.arguments_sha256.toString('hex'),resultSha256:raw.result_hex}};
 const trace=(row,index)=>({id:index+1,event_id:`event-${index}`,session_id:sessionId,actor:'supervisor',provider:'ollama',...row});
 const traces=[trace({kind:'model_decision',step:1,params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'call-1',name:'weather-lab.forecast_lookup',args}]}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},0),trace({kind:'dispatch_plan',step:1,result_json:JSON.stringify({execute:[{id:'call-1',name:'weather-lab.forecast_lookup'}],omitted:[],omissionReason:null,maxParallelTools:2})},1),trace({kind:'mcp_result',actor:'task→supervisor',step:1,agent_ns:'weather-lab',tool_name:'forecast_lookup',result_json:JSON.stringify(output)},2),trace({kind:'model_decision',step:2,result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},3),trace({kind:'terminal',step:2,result_json:JSON.stringify({stopReason:'end_turn',steps:2,hops:1,model:'llama3.1:8b',mocked:false})},4)];
 const result={stopReason:'end_turn',steps:2,hops:[{}],text:'Observed.'};
 const packet=JSON.stringify({controlled:true}),judgment={evaluation_id:uid(9),credited:uid(9),run_id:runId,objective_id:scenario==='rug_pull'?'ss_rug_pull_invoked':'ss_rogue_tool_selected',verdict:'pass',result_json:{provider:'ollama',model:'llama3.1:8b',criteria:[{satisfied:true}]},packet,evidence_digest:crypto.createHash('sha256').update(packet).digest('hex')};
 const prior={target_id:targetId,invocation_id:uid(10),operation_id:uid(11),run_id:uid(12),request_id:uid(13),call_id:'prior-call',completed_at:'2026-09-14T10:00:00Z',version:1,schema_sha256:'b'.repeat(64),remote_receipt_sha256:'c'.repeat(64),result_sha256:'d'.repeat(64),behavior_class:'public_forecast_lookup',server_approved:true,schema_approved:true};
 const state={raw,raws:[raw],traces,result,judgment,judgments:[judgment],prior,run:{status:'completed',owner_key:JSON.stringify(['SecureShopBoundConversation',sessionId]),generation:1},session:{id:sessionId,authority_mode:'launch_bound',platform_scenario_id:binding.scenarioId,original_platform_session_id:2,user_id:3,role:'admin'},effects:[{status:'completed'}],schema:{schema_sha256:Buffer.from(digestMcpValue(tools),'hex'),tools_json:tools}};
 const {buildSecureShopMcpTrustEvidence}=require('../server/services/secureshopMcpTrustEvidence');
 const {MCP_TRUST_RUBRICS}=require('../server/services/secureshopMcpTrustAssessment');
 const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
 const normalized={targetId,trustScenario:scenario,invocationId:raw.invocation_id,operationId:raw.operation_id,runId,requestId,callId:raw.call_id,toolName:raw.tool_name,serverIdentity:raw.server_identity,schemaVersion:raw.schema_version,schemaSha256:raw.schema_hex,remoteReceiptSha256:raw.remote_hex,resultSha256:raw.result_hex,trustPolicySha256:raw.trust_hex,approved:false,serverApproved:raw.server_approved,schemaApproved:false,behaviorClass:raw.behavior_class,completedAt:new Date(raw.completed_at).toISOString()};
 const priorNormalized={targetId,serverIdentity:raw.server_identity,version:prior.version,schemaSha256:prior.schema_sha256,invocationId:prior.invocation_id,operationId:prior.operation_id,runId:prior.run_id,requestId:prior.request_id,callId:prior.call_id,remoteReceiptSha256:prior.remote_receipt_sha256,resultSha256:prior.result_sha256,behaviorClass:prior.behavior_class,serverApproved:true,schemaApproved:true,completedAt:new Date(prior.completed_at).toISOString()};
 const receipt={version:1,status:'completed',runId,ownerKey:state.run.owner_key,generation:'1',effectKey:`${requestId}:${JSON.stringify([1,'call-1','weather-lab.forecast_lookup'])}`};
 const built=buildSecureShopMcpTrustEvidence({binding:{targetId,trustScenario:scenario},run:{runId,requestId,ownerKey:state.run.owner_key,durableGeneration:1,stopReason:'end_turn',provider:{provider:'ollama',model:'llama3.1:8b',mocked:false},effectReceipt:receipt,calls:[{step:1,agent:'weather-lab',callId:'call-1',toolName:'forecast_lookup',schemaSha256:raw.schema_hex}]},invocation:normalized,priorSchema:priorNormalized,protectedObservation:{recordId:protectedResult.exportedRecord.recordId,classification:protectedResult.exportedRecord.classification,contentSha256:protectedResult.contentSha256},providerQualified:true})[0];
 const prepared=prepareJudgeInput({rubric:{...MCP_TRUST_RUBRICS[built.objectiveId],mode:'vuln'},facts:built.facts,evidence:[{id:'bound_mcp_invocation_chain',source:'server_observation',content:built.evidence}]});
 judgment.packet=prepared.packet;judgment.evidence_digest=prepared.evidenceDigest;
 const queries=[];
 const identityRuntime={async query(sql,params){queries.push({sql,params});return{rows:sql.includes('identity.secureshop_launches')?[{launch_id:binding.launchId}]:sql.includes('graph_runtime.runs')?[state.run]:sql.includes('graph_runtime.effects')?state.effects:state.judgments};}};
 const agentsRuntime={connect(){throw Error('No write');},async query(sql,params){queries.push({sql,params});return{rows:sql.includes('MAX(t.id)')?[{id:'0'}]:sql.includes('agent_trace')?state.traces:sql.includes('turn_requests')?[{status:'completed',result_json:state.result}]:sql.includes('agent_sessions')?[state.session]:sql.includes('v.version<$2')?(state.prior?[state.prior]:[]):sql.includes('tools_json')?[state.schema]:sql.includes('i.invocation_id=$1')?state.raws.filter(row=>row.invocation_id===params[0]):state.raws};}};
 return{state,queries,evidence:createRenderedMcpTrustEvidence({identityRuntime,agentsRuntime,binding}),input:{before:{invocations:[],judgments:[],head:'0'},requestId,scenario,protectedEffect:true,response:{...result,replayed:false}}};
}

function configureCalls(f, descriptors) {
 const {digestMcpValue}=require('../server/services/secureshopMcpTrustTools');
 const uid=n=>`${String(n).padStart(8,'0')}-0000-4000-8000-000000000001`;
 const base=f.state.raw,session=f.state.session,run=f.state.run;
 const baseOutput=JSON.parse(f.state.traces.find(row=>row.kind==='mcp_result').result_json);
 const protectedResult=JSON.parse(baseOutput.content[0].text);
 const raws=descriptors.map((descriptor,index)=>{
  if(index===0&&descriptor.callId==='call-1'&&descriptor.step===1)return base;
  const args=descriptor.args||{city:'Seattle'};
  return{...base,invocation_id:uid(20+index*2),operation_id:uid(21+index*2),call_id:descriptor.callId,
   arguments_sha256:Buffer.from(digestMcpValue(args),'hex'),completed_at:`2026-09-14T10:01:0${index}Z`};
 });
 const trace=(row,index)=>({id:index+1,event_id:`event-multi-${index}`,session_id:session.id,actor:'supervisor',provider:'ollama',...row});
 const traces=[];let traceIndex=0;
 for(const step of [...new Set(descriptors.map(value=>value.step))].sort((a,b)=>a-b)){
  const selected=descriptors.map((value,index)=>({...value,index})).filter(value=>value.step===step);
  const toolCalls=selected.map(value=>({id:value.callId,name:'weather-lab.forecast_lookup',args:value.args||{city:'Seattle'}}));
  traces.push(trace({kind:'model_decision',step,params_json:JSON.stringify({decision:'tool_use',toolCalls}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},traceIndex++));
  traces.push(trace({kind:'dispatch_plan',step,result_json:JSON.stringify({execute:toolCalls.map(({id,name})=>({id,name})),omitted:[],omissionReason:null,maxParallelTools:2})},traceIndex++));
  for(const value of selected){const raw=raws[value.index],args=value.args||{city:'Seattle'};
   const output={content:[{type:'text',text:JSON.stringify(protectedResult)}],_meta:{version:1,operationId:raw.operation_id,targetId:raw.target_id,serverIdentity:raw.server_identity,trustScenario:raw.trust_scenario,schemaVersion:raw.schema_version,schemaSha256:raw.schema_hex,runId:raw.run_id,ownerKey:run.owner_key,generation:String(run.generation),requestId:raw.request_id,sessionId:session.id,callId:raw.call_id,remoteReceiptSha256:raw.remote_hex,trustPolicySha256:raw.trust_hex,approved:raw.approved,serverApproved:raw.server_approved,schemaApproved:raw.schema_approved,behaviorClass:raw.behavior_class,argumentsSha256:digestMcpValue(args),resultSha256:raw.result_hex}};
   traces.push(trace({kind:'mcp_result',actor:'task→supervisor',step,agent_ns:'weather-lab',tool_name:'forecast_lookup',result_json:JSON.stringify(output)},traceIndex++));
  }
 }
 const finalStep=Math.max(...descriptors.map(value=>value.step))+1;
 traces.push(trace({kind:'model_decision',step:finalStep,result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},traceIndex++));
 traces.push(trace({kind:'terminal',step:finalStep,result_json:JSON.stringify({stopReason:'end_turn',steps:finalStep,hops:raws.length,model:'llama3.1:8b',mocked:false})},traceIndex++));
 f.state.raws=raws;f.state.raw=raws[0];f.state.traces=traces;f.state.result={...f.state.result,steps:finalStep,hops:raws.map(()=>({}))};
 f.state.effects=[{status:'completed'}];f.input.response={...f.state.result,replayed:false};
 return f;
}
test('full verifier accepts exact persisted rogue and changed-schema chains with distinct invocation/operation IDs',async()=>{
 for(const scenario of ['rogue_registration','rug_pull']){const f=fullFixture(scenario);assert.equal((await f.evidence.verify(f.input)).scenario,scenario);assert.ok(f.queries.some(q=>q.sql.includes('i.invocation_id=$1')&&q.params[0]===f.state.raw.invocation_id));}
});
test('full verifier preserves and verifies parallel and repeated multi-step model effects',async()=>{
 for(const descriptors of [[{step:1,callId:'call-1'},{step:1,callId:'call-2'}],[{step:1,callId:'call-1'},{step:2,callId:'call-2'},{step:2,callId:'call-3'}]]){
  const f=configureCalls(fullFixture('rug_pull'),descriptors);const result=await f.evidence.verify(f.input);assert.equal(result.invocationCount,descriptors.length);
 }
});
test('tied completion timestamps and shuffled rows do not invent an observation order',async()=>{
 const f=configureCalls(fullFixture('rug_pull'),[{step:1,callId:'call-1'},{step:1,callId:'call-2'}]);
 f.state.raws[1].completed_at=f.state.raws[0].completed_at;
 // The persisted judgment remains bound to original call-1, which is now the
 // second snapshot row. The durable packet binding, not row position, decides.
 f.state.raws.reverse();
 const result=await f.evidence.verify(f.input);assert.equal(result.invocationCount,2);
});
test('per-step and successful-terminal tool budgets remain strict',async()=>{
 const f=configureCalls(fullFixture('rug_pull'),[{step:1,callId:'call-1'},{step:1,callId:'call-2'},{step:1,callId:'call-3'}]);
 await assert.rejects(f.evidence.verify(f.input),/parallel-bound-exceeded|turn-invocation-bound-exceeded/);
});
test('all-observation verifier rejects foreign, mixed, missing, duplicate and multiply credited effects',async()=>{
 const mutations=[
  f=>{f.state.raws[1].request_id='30000001-0000-4000-8000-000000000001';},
  f=>{f.state.raws[1].run_id='30000002-0000-4000-8000-000000000001';},
  f=>{f.state.raws[1].target_id='30000003-0000-4000-8000-000000000001';},
  f=>{f.state.raws[1].original_platform_owner_id=99;},
  f=>{f.state.raws[1].schema_version=1;},
  f=>{f.state.raws[1].schema_sha256=Buffer.alloc(32,9);},
  f=>{f.state.raws[1].call_id=f.state.raws[0].call_id;},
  f=>{f.state.raws[1].operation_id=f.state.raws[0].operation_id;},
  f=>{f.state.traces=f.state.traces.filter((row,index)=>row.kind!=='mcp_result'||index!==3);},
  f=>{const row=f.state.traces.filter(value=>value.kind==='mcp_result')[1],value=JSON.parse(row.result_json);value._meta.operationId='30000004-0000-4000-8000-000000000001';row.result_json=JSON.stringify(value);},
  f=>{const second={...f.state.judgment,evaluation_id:'30000005-0000-4000-8000-000000000001',credited:'30000005-0000-4000-8000-000000000001'};f.state.judgments.push(second);},
 ];
 for(const mutate of mutations){const f=configureCalls(fullFixture('rug_pull'),[{step:1,callId:'call-1'},{step:1,callId:'call-2'}]);mutate(f);await assert.rejects(f.evidence.verify(f.input));}
});
test('full verifier rejects changed projection, schema bytes, missing prior, foreign owner and mock actor',async()=>{
 for(const mutate of [f=>f.state.result.text='other',f=>f.state.schema.tools_json=[],f=>f.state.prior=null,f=>f.state.run.owner_key='["foreign","session"]',f=>f.state.traces[0].provider='mock',f=>f.state.effects=[],f=>f.state.raw.arguments_sha256=Buffer.alloc(32),f=>f.state.judgment.result_json.criteria=[]]){const f=fullFixture('rug_pull');mutate(f);await assert.rejects(f.evidence.verify(f.input));}
});
test('rehashed arbitrary packet, altered rubric, facts and cross-invocation chain cannot inherit credit',async()=>{
 const crypto=require('node:crypto');
 for(const mutate of [p=>({controlled:true}),p=>{p.rubric.version='foreign';return p;},p=>{p.rubric.mode='fixed';return p;},p=>{p.facts={};return p;},p=>{p.evidence[0].content.callId='other-call';return p;},p=>{p.evidence[0].content.currentInvocation.operationId='other-operation';return p;},p=>{p.evidence[0].content.priorInvocation.requestId='other-prior-request';return p;}]){
  const f=fullFixture('rug_pull');const changed=mutate(JSON.parse(f.state.judgment.packet));f.state.judgment.packet=JSON.stringify(changed);f.state.judgment.evidence_digest=crypto.createHash('sha256').update(f.state.judgment.packet).digest('hex');
 await assert.rejects(f.evidence.verify(f.input),/stored-judge-packet-mismatch/);
 }
});
