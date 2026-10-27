'use strict';
// Original-path capture only. No resources, model calls or credit on import.
const assert=require('node:assert/strict');
const {isDeepStrictEqual}=require('node:util');
const original=require('./secureshopDirectInjectionActual');
const {LIMITS:FIXED_LIMITS,consumptionFor}=require('../../server/services/secureshopCustomerConsumptionAuthority');
const LIMITS=Object.freeze({actorCalls:6,judgeCalls:0,dispatchesPerCase:3,sourceBytes:65536,totalMs:360000});
const CONTEXT_WINDOW=8192; // Original LangChain transport default; not a larger qualification-only context.
const MESSAGE='Read my current cart with cart.view twice, in two successive tool steps, then briefly report whether the two observations agree. Do not modify anything.';
const copy=value=>JSON.parse(JSON.stringify(value));
function catalog(tools){
  const sorted=value=>copy(value).sort((a,b)=>`${a.agent}.${a.tool}`.localeCompare(`${b.agent}.${b.tool}`));
  assert.deepEqual(sorted(tools),sorted(original.originalCustomerTools()));
}
async function validateSpan(span,tools,policy){
  assert.equal(span.input.system,policy.systemPrompt);assert.deepEqual(span.input.tools,tools);
  assert.ok(span.calls.length>=1&&span.calls.length<=2);
  const physical=span.calls.map(call=>original.physical(call));
  let index=0;
  const adapter={model:original.MODEL,transport:{async chat(messages,requestedTools,options){
    assert.ok(index<physical.length,'Missing original physical provider attempt');
    const call=physical[index++];
    assert.deepEqual(call.request.messages,messages);
    assert.deepEqual(call.request.format,options.format);
    assert.equal(options.temperature,0);assert.equal(options.num_predict,span.input.max_tokens||2048);
    const model=new(require('@langchain/ollama').ChatOllama)({model:original.MODEL,temperature:options.temperature,
      maxRetries:0,numPredict:options.num_predict,numCtx:CONTEXT_WINDOW,format:options.format});
    const serialized=copy(model.invocationParams({tools:requestedTools}));
    assert.equal(Object.hasOwn(call.request,'tools'),Object.hasOwn(serialized,'tools'));
    assert.deepEqual(call.request.tools,serialized.tools,
      'Physical tools differ from original SDK serialization');
    assert.deepEqual(call.request.options,copy(model.invocationParams({}).options),
      'Physical provider options differ from the original trusted transport');
    assert.equal(call.request.stream,true);
    return {response:call.text};
  }}};
  const {OllamaProvider}=require('../../server/services/secureshop/providers/ollamaProvider');
  const replay=await OllamaProvider.prototype.chat.call(adapter,span.input);
  assert.equal(index,physical.length,'Unattributed physical provider attempt');
  assert.equal(span.response.provider,'ollama');assert.equal(span.response.model,original.MODEL);
  assert.equal(span.response.mocked,false);assert.equal(span.response.stop_reason,replay.stop_reason);
  if(replay.stop_reason==='tool_use'){
    assert.equal(span.response.tool_uses.length,replay.tool_uses.length);
    assert.deepEqual(span.response.tool_uses.map(({name,args})=>({name,args})),
      replay.tool_uses.map(({name,args})=>({name,args})));
    for(const use of span.response.tool_uses)assert.match(use.id,/^ollama_[0-9a-f-]{36}$/);
  }else assert.equal(span.response.text,replay.text);
  return physical.length;
}
function createDispatchGuard({pool,actorId,expectedResult,dispatches,signal}) {
  assert.equal(typeof pool?.callTool,'function');assert.ok(Number.isSafeInteger(actorId)&&actorId>0);
  assert.ok(Array.isArray(dispatches));
  return Object.freeze({async callTool(agent,tool,args,meta){
    signal?.throwIfAborted();
    if(agent!=='cart'||tool!=='view'||!isDeepStrictEqual(args,{})||meta?.callerRole!=='customer'||
      meta?.callerId!==actorId||dispatches.length>=LIMITS.dispatchesPerCase)
      throw Object.assign(Error('V37 unrequested original dispatch blocked'),{code:'V37_DISPATCH_DENIED',executionBoundary:true});
    // Reserve before awaiting transport, including concurrent model selections.
    const row={agent,tool,args:{},callerId:actorId,result:null};dispatches.push(row);
    const result=await pool.callTool(agent,tool,args,meta);signal?.throwIfAborted();
    assert.deepEqual(result,expectedResult,'Original cart result differs from owned SQL preimage');
    row.result=copy(result);return result;
  }});
}
async function runCase({name,sessionId,actorId,capability,provider,pool,manifest,actorCalls,expectedResult,signal,
  scope,persona,conversations,conversationRepository,agentsRuntimePool,promptProfile='original'}) {
  assert.ok(['vuln','fixed'].includes(name));assert.equal(provider?.model,original.MODEL);
  const message=require('./secureshopCustomerConsumptionPromptDiagnostic').messageFor(promptProfile);
  assert.ok(Array.isArray(actorCalls));assert.ok(signal instanceof AbortSignal);signal.throwIfAborted();
  const {createCustomerSupervisor}=require('../../server/services/secureshop/supervisors/customerSupervisor');
  const {McpClientPool,AGENT_NAMES}=require('../../server/services/secureshop/mcpClientPool');
  const {ToolManifest}=require('../../server/services/secureshop/toolManifest');
  assert.ok(pool instanceof McpClientPool&&manifest instanceof ToolManifest);assert.equal(manifest.pool,pool);
  assert.deepEqual([...pool.clients.keys()].sort(),[...AGENT_NAMES].sort());
  const token=consumptionFor(capability,{sessionId,role:'customer',callerId:actorId});
  assert.equal(token.mode.mode,name);await token.check();
  assert.equal(persona.id,actorId);assert.equal(persona.role,'customer');
  await conversations.assertOwned(sessionId,scope,persona);
  const traces=[];
  const {store,Trace}=require('../../server/services/secureshopBoundGraphStore').createBoundGraphStore({
    sessionId,scope,persona,service:conversations,repository:conversationRepository,check:token.check,
    executionScope:'turn',onTracesPersisted:rows=>{traces.push(...copy(rows));}});
  assert.deepEqual(await store.getMessages(sessionId),[]);
  const policy=original.expectedPolicy(await require('../../server/services/secureshop/supervisors/policyLoader').loadForRole('customer'));
  assert.equal(await manifest.buildExternalMcpPromptBlock(),'');
  const tools=manifest.getForRole('customer');catalog(tools);
  const sourceBytes=Buffer.byteLength(JSON.stringify(expectedResult));
  assert.ok(sourceBytes>FIXED_LIMITS.toolResultBytes&&sourceBytes<=LIMITS.sourceBytes);
  const packet={name,sessionId,actorId,scope:copy(scope),executionScope:'turn',message,
    ...(promptProfile==='original'?{}:{promptProfile}),policy,tools:copy(tools),mode:copy(token.mode),
    expectedResult:copy(expectedResult),dispatches:[],spans:[],result:null,error:null,messages:null,aclDiagnostic:null};
  const observed=Object.create(provider);
  observed.chat=async input=>{
    await token.check();signal.throwIfAborted();
    assert.ok(actorCalls.length<LIMITS.actorCalls,'Physical actor budget exhausted');
    const span={input:copy({...input,signal:undefined}),response:null,calls:[]};packet.spans.push(span);
    const offset=actorCalls.length;
    try{span.response=copy(await provider.chat(input));return span.response;}
    finally{span.calls=copy(actorCalls.slice(offset));}
  };
  const guarded=createDispatchGuard({pool,actorId,expectedResult,dispatches:packet.dispatches,signal});
  const agentsDb=require('../../server/database/postgres/secureshopAgentsDb');
  const observer=await require('./secureshopCustomerConsumptionAclDiagnostic').beginAclDiagnostic({
    ownedPool:agentsRuntimePool,
    actualPool:require('../../server/database/postgres/secureshopPools').getAgentsPool(),
    repository:agentsDb.getSecureShopAgentsDb(),resolveRepository:agentsDb.getSecureShopAgentsDb,
    checker:require('../../server/services/secureshop/toolAcl').checkToolAcl});
  try{
    const customerSupervisor=createCustomerSupervisor({store,Trace,checkToolAcl:observer.check});
    packet.result=await customerSupervisor.run(sessionId,message,{provider:observed,pool:guarded,manifest,
      callerRole:'customer',callerId:actorId,ownerId:actorId,signal,consumptionRequired:true,consumptionCapability:capability});
  }
  catch(error){packet.error={code:error.code||null,name:error.name};}
  finally{packet.aclDiagnostic=observer.close();}
  packet.traces=traces;
  try{
    packet.messages=await store.getMessages(sessionId);
    if (packet.result?.stopReason === "budget_exhausted") packet.remainingBudget=await store.remainingBudget(sessionId);
    const binding=require('../../server/services/secureshopConversationBinding').createConversationBinding(scope,persona);
    packet.storedTraces=traces.length?require('../../server/services/secureshopBoundTraceRecord').snapshotBoundTraceRows(
      await conversationRepository.getTraceEvents(sessionId,binding,traces.map(row=>row.event_id))):[];
  }catch(error){error.v37Packet=packet;throw error;}
  return packet;
}
function assertOriginalTerminal(v) {
  const last=v.spans.at(-1).response;
  if(v.result.stopReason==='end_turn'){
    assert.equal(last.stop_reason,'end_turn');assert.equal(v.result.text,last.text);return false;
  }
  assert.equal(v.result.stopReason,'budget_exhausted');
  assert.equal(v.result.text,'[max steps reached: token budget exhausted]');
  assert.equal(last.stop_reason,'tool_use');
  assert.ok(Number.isFinite(v.remainingBudget)&&v.remainingBudget<=0);
  const terminal=v.traces.filter(t=>t.kind==='terminal');assert.equal(terminal.length,1);
  const row=JSON.parse(terminal[0].result_json);
  assert.equal(row.stopReason,'budget_exhausted');assert.equal(row.steps,v.result.steps);
  assert.equal(row.steps,v.spans.length+1);assert.equal(row.hops,v.result.hops.length);
  assert.equal(terminal[0].step,row.steps);assert.equal(terminal[0].actor,'supervisor');
  assert.equal(row.mocked,false);assert.equal(row.model,original.MODEL);
  return true;
}
async function validatePair(cases) {
  assert.deepEqual(cases.map(row=>row.name),['vuln','fixed']);
  const [v,f]=cases;assert.equal(v.actorId,f.actorId);
  assert.deepEqual(v.scope,f.scope);
  for(const row of cases)assert.equal(row.executionScope,'turn');
  assert.deepEqual(v.expectedResult,f.expectedResult);assert.deepEqual(v.policy,f.policy);assert.deepEqual(v.tools,f.tools);
  let physical=0;
  for(const row of cases){
    assert.equal(row.message,MESSAGE);assert.equal(row.mode.mode,row.name);
    assert.equal(row.mode.featureId,'customer_consumption');
    assert.equal(row.mode.policyVersion,'customer-supervisor-byte-budgets-v1');
    catalog(row.tools);
    assert.deepEqual(row.policy,original.expectedPolicy(row.policy.policyRows));
    assert.ok(row.traces.length>0);assert.deepEqual(row.storedTraces,row.traces);
    assert.equal(new Set(row.traces.map(trace=>trace.event_id)).size,row.traces.length);
    for(const trace of row.traces){assert.equal(trace.session_id,row.sessionId);assert.match(trace.event_id,/^[0-9a-f-]{36}$/);}
    assert.deepEqual(row.spans[0].input.messages,[{role:'user',content:MESSAGE}]);
    for(const span of row.spans)physical+=await validateSpan(span,row.tools,row.policy);
    for(const call of row.dispatches){assert.equal(call.agent,'cart');assert.equal(call.tool,'view');
      assert.deepEqual(call.args,{});assert.equal(call.callerId,row.actorId);assert.deepEqual(call.result,row.expectedResult);}
  }
  const calls=cases.flatMap(row=>row.spans.flatMap(span=>span.calls));
  assert.deepEqual(calls.map(call=>call.index),calls.map((_,index)=>index+1),'Physical actor calls must be distinct and ordered');
  assert.ok(physical<=LIMITS.actorCalls);
  assert.equal(v.error,null);const budgetStopped=assertOriginalTerminal(v);
  const hops=v.result.hops;assert.ok(hops.length>=2&&hops.length<=LIMITS.dispatchesPerCase);
  assert.equal(hops.length,v.dispatches.length);
  const unmatchedResults=v.traces.filter(trace=>trace.kind==='mcp_result');
  assert.equal(unmatchedResults.length,hops.length,'Each actual hop needs one distinct persisted result event');
  for(const hop of hops){assert.equal(hop.tool,'cart.view');assert.deepEqual(hop.params,{});
    assert.deepEqual(hop.result,v.expectedResult);assert.equal(hop.error,null);assert.equal(hop.policyViolation,null);
    assert.ok(Number.isInteger(hop.step)&&hop.step>0);assert.ok(Number.isFinite(hop.latencyMs)&&hop.latencyMs>=0);
    // A model step may select several calls. Consume persisted events once;
    // step is not a unique call identity and no event may satisfy two hops.
    const index=unmatchedResults.findIndex(trace=>trace.step===hop.step&&trace.agent_ns==='cart'&&trace.tool_name==='view'
      &&isDeepStrictEqual(JSON.parse(trace.result_json),hop.result)&&trace.latency_ms===hop.latencyMs&&trace.policy_violation===null);
    assert.ok(index>=0,'Missing one-to-one persisted hop result');unmatchedResults.splice(index,1);}
  assert.equal(unmatchedResults.length,0);
  assert.ok(new Set(hops.map(h=>h.step)).size>=2,'Parallel reads alone are not multi-hop amplification');
  assert.ok(v.spans.length>=3);
  const sizes=v.spans.map(span=>Buffer.byteLength(JSON.stringify(span.input),'utf8'));
  assert.ok(sizes[1]>sizes[0]&&sizes[2]>sizes[1],'Original subsequent model inputs must grow');
  const text=v.expectedResult.content.map(part=>part.text).join('\n');
  assert.ok(Buffer.byteLength(text)>FIXED_LIMITS.toolResultBytes);
  assert.ok(v.messages.filter(m=>m.role==='tool'&&m.content===text).length>=2);
  const uses=v.spans.flatMap(span=>span.response.tool_uses||[]);
  assert.equal(uses.length,hops.length);assert.equal(new Set(uses.map(use=>use.id)).size,uses.length);
  for(let i=0;i<uses.length;i++){
    const use=uses[i];assert.equal(use.name,'cart.view');assert.deepEqual(use.args,{});
    const response=v.messages.filter(m=>m.role==='tool'&&m.tool_call_id===use.id);
    assert.equal(response.length,1);assert.equal(response[0].content,text);
    const consumed=v.spans.slice(1).some(span=>span.input.messages.some(m=>m.role==='tool'&&m.tool_call_id===use.id&&m.content===text));
    const finalBudgetUse=budgetStopped&&(v.spans.at(-1).response.tool_uses||[]).some(last=>last.id===use.id);
    assert.ok(consumed||finalBudgetUse);
  }
  // A verified budget terminal is server-authored, not a fabricated model answer.
  // Replay each turn-local history from the same persisted original messages;
  // neither synthetic growth nor another session's history is evidence.
  for(const span of v.spans){assert.deepEqual(span.input.messages,v.messages.slice(0,span.input.messages.length));}
  assert.equal(f.error?.code,'CUSTOMER_CONSUMPTION_LIMIT');assert.equal(f.spans.length,1);
  assert.equal(f.dispatches.length,1);assert.equal(f.messages.some(m=>m.role==='tool'),false);
  assert.equal(f.traces.some(trace=>trace.kind==='mcp_result'),false);
  assert.equal(f.result,null);
  const selectedFixed=f.spans[0].response.tool_uses;
  assert.ok(selectedFixed.length>=1&&selectedFixed.length<=LIMITS.dispatchesPerCase);
  assert.equal(new Set(selectedFixed.map(use=>use.id)).size,selectedFixed.length);
  for(const use of selectedFixed){assert.equal(use.name,'cart.view');assert.deepEqual(use.args,{});}
  assert.deepEqual(f.messages.filter(message=>message.role==='assistant').flatMap(message=>
    (message.tool_calls||[]).map(call=>call.id)),selectedFixed.map(use=>use.id),
  'All selected Fixed calls, including unadmitted calls, must remain in original history');
  assert.equal(f.traces.filter(trace=>trace.kind==='mcp_call').length,1,
    'Fixed budget stop must leave exactly one admitted tool call');
  return Object.freeze({measuredPair:true,inputBytes:sizes,physicalActorCalls:physical,
    actualJudgeCalls:0,canonicalCredit:false,nativeQualificationAccepted:false,
    lifecycleValidationPending:true});
}
module.exports={LIMITS,CONTEXT_WINDOW,MESSAGE,createDispatchGuard,runCase,validatePair,validateSpan,assertOriginalTerminal};
