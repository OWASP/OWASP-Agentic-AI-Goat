'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {createCustomerConsumptionAuthority,consumptionFor,LIMITS}=require('../server/services/secureshopCustomerConsumptionAuthority');
const {createSupervisorGraph}=require('../server/agent-runtime/secureshopSupervisorGraph');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:1,platformSessionId:2};
const persona={id:3,role:'customer'},credential={sessionId:'33333333-3333-4333-8333-333333333333',authorityVersion:'1'};
async function capability(mode='fixed',signal,version='1') {
  let current=true,revision=1;const check=async()=>{if(!current)throw Error('revoked');};
  const launches={assertCurrent:check};
  const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({launches,
    progress:{getEvaluationScope:async()=>({mode,generation:1,modeStamp:String(revision)})}});
  const authority=createCustomerConsumptionAuthority({modeAuthority,
    launches,conversations:{assertOwned:check},
    personaAuthority:{capture:async()=>({binding:{...scope,personaId:3,role:'customer',...credential,authorityVersion:version},assertRemoteAdmission:check})}});
  return {cap:await authority.capture({scope,persona,personaSession:{...credential,authorityVersion:version},sessionId:'owned',signal}),revoke:()=>{current=false;},revise:()=>{revision++;}};
}
test('canonical persona decimal-string authority version is exact, never coerced',async()=>{
  for(const value of ['1','9007199254740993'])await capability('fixed',undefined,value);
  for(const value of [1,0,'0','01','1.0','-1',null,{},''])
    await assert.rejects(capability('fixed',undefined,value),{code:'CUSTOMER_CONSUMPTION_AUTHORITY'});
});
function graph(text,count=1,onModel=()=>{},hooks={}) {
  const messages=[],traces=[];let calls=0,dispatches=0;
  const store={appendUserMessage:async(_,content)=>messages.push({role:'user',content}),
    appendAssistantMessage:async(_,content)=>messages.push({role:'assistant',content}),
    appendAssistantToolCalls:async(_,calls)=>messages.push({role:'assistant',content:'',tool_calls:calls}),
    appendToolResult:async(_,id,content)=>{await hooks.beforeToolPersistence?.(id,content);
      messages.push({role:'tool',tool_call_id:id,content});await hooks.afterToolPersistence?.(id,content);},
    getMessages:async()=>structuredClone(messages),remainingBudget:async()=>1000000,addUsedTokens:async()=>{}};
  class Trace {record(row){traces.push(row);}async flush(){}}
  const run=createSupervisorGraph({store,Trace,buildBasePrompt:()=> 'original system',buildPolicyBlock:async()=> 'original policy',
    checkToolAcl:async()=>({allowed:true,policyViolation:null})});
  const provider={chat:async()=>{onModel();return ++calls===1?{stop_reason:'tool_use',tool_uses:Array.from({length:count},(_,i)=>({id:`call-${i}`,name:'cart.view',args:{}}))}:{stop_reason:'end_turn',text:'done'};}};
  const options={provider,pool:{callTool:async(...args)=>{dispatches++;
    return hooks.callTool?hooks.callTool(...args):{content:[{type:'text',text}]};}},manifest:{getForRole:()=>[]},role:'customer',callerId:3};
  return {messages,traces,calls:()=>calls,dispatches:()=>dispatches,run:cap=>run('owned','original question',{...options,...(cap===undefined?{}:{consumptionRequired:true,consumptionCapability:cap})},{maxSteps:8,maxParallelTools:4})};
}
function deferred(){let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};}
const nextTurn=()=>new Promise(resolve=>setImmediate(resolve));
test('Fixed oversized actual graph tool result is rejected before result trace/persistence/next model',async()=>{
  const g=graph('界'.repeat(12000)),{cap}=await capability();
  await assert.rejects(g.run(cap),{code:'CUSTOMER_CONSUMPTION_LIMIT'});
  assert.equal(g.calls(),1);assert.equal(g.messages.some(m=>m.role==='tool'),false);
  assert.equal(g.traces.some(t=>t.kind==='tool_result'),false);
});
test('legacy and configured vulnerable graph preserve verbatim teaching result',async()=>{
  for(const cap of [undefined,(await capability('vuln')).cap]){
    const text='x'.repeat(40000),g=graph(text);await g.run(cap);
    assert.equal(g.messages.find(m=>m.role==='tool').content,text);assert.equal(g.calls(),2);
  }
});
test('forged, missing configured, wrong-session and stale authority fail closed',async()=>{
  assert.throws(()=>consumptionFor({}, {sessionId:'owned',role:'customer',callerId:3}),{code:'CUSTOMER_CONSUMPTION_AUTHORITY'});
  assert.throws(()=>consumptionFor(undefined,{sessionId:'owned',role:'customer',callerId:3}),{code:'CUSTOMER_CONSUMPTION_AUTHORITY'});
  const fixture=await capability();
  assert.throws(()=>consumptionFor(fixture.cap,{sessionId:'foreign',role:'customer',callerId:3}));
  fixture.revoke();const g=graph('small');await assert.rejects(g.run(fixture.cap),{code:'CUSTOMER_CONSUMPTION_AUTHORITY'});assert.equal(g.calls(),0);assert.equal(g.messages.length,0);
});
test('UTF8 exact per-result boundary and cumulative appends are bounded',async()=>{
  const {cap}=await capability();const c=consumptionFor(cap,{sessionId:'owned',role:'customer',callerId:3});
  c.tool('x'.repeat(LIMITS.toolResultBytes));assert.throws(()=>c.tool('界'.repeat(11000)),{code:'CUSTOMER_CONSUMPTION_LIMIT'});
  c.input({system:'original',messages:[],tools:[]});
  for(let i=0;i<3;i++)c.append({role:'tool',content:'x'.repeat(32768)});
  assert.throws(()=>c.append({role:'tool',content:'x'.repeat(32768)}),{code:'CUSTOMER_CONSUMPTION_LIMIT'});
  assert.throws(()=>c.input({system:'x'.repeat(LIMITS.providerInputBytes),messages:[]}),{code:'CUSTOMER_CONSUMPTION_LIMIT'});
});
test('canonical mode revision changes invalidate captured capability',async()=>{
  const f=await capability();f.revise();const g=graph('small');
  await assert.rejects(g.run(f.cap),{code:'ANALYTICS_MODE_STALE'});
  assert.equal(g.calls(),0);assert.equal(g.messages.length,0);
});
test('oversized existing history is rejected before adding user or model dispatch',async()=>{
  const f=await capability(),g=graph('small');
  g.messages.push({role:'tool',content:'x'.repeat(LIMITS.providerInputBytes)});
  await assert.rejects(g.run(f.cap),{code:'CUSTOMER_CONSUMPTION_LIMIT'});
  assert.equal(g.calls(),0);assert.equal(g.messages.length,1);
});
test('parallel individually bounded results cannot race the aggregate reservation',async()=>{
  const {cap}=await capability(),g=graph('x'.repeat(32700),4);
  await assert.rejects(g.run(cap),{code:'CUSTOMER_CONSUMPTION_LIMIT'});
  assert.equal(g.calls(),1);assert.ok(g.messages.filter(m=>m.role==='tool').length<4);
});
test('cancellation while provider returns prevents subsequent tool persistence',async()=>{
  const controller=new AbortController(),{cap}=await capability('fixed',controller.signal);
  const g=graph('small',1,()=>controller.abort());
  const result=await g.run(cap);assert.equal(result.stopReason,'cancelled');
  assert.equal(g.calls(),1);assert.equal(g.messages.some(m=>m.role==='tool'),false);
});
test('Fixed first oversized result stops sibling dispatch and leaves no delayed writes after rejection',async()=>{
  const delayed=deferred(),{cap}=await capability();
  const g=graph('',2,()=>{},{callTool:async(_ns,_tool,_args,{callId})=>{
    if(callId==='call-1')await delayed.promise;
    return {content:[{type:'text',text:callId==='call-0'?'x'.repeat(40000):'small'}]};
  }});
  try{await assert.rejects(g.run(cap),{code:'CUSTOMER_CONSUMPTION_LIMIT'});}
  finally{delayed.resolve();}
  await nextTurn();
  assert.equal(g.dispatches(),1);assert.equal(g.calls(),1);
  assert.equal(g.messages.find(m=>m.tool_calls)?.tool_calls.length,2,'retain the complete model selection');
  assert.equal(g.messages.filter(m=>m.role==='tool').length,0);
  assert.equal(g.traces.filter(t=>t.kind==='mcp_result').length,0);
});
test('Fixed bounded batch waits for complete persistence before dispatching its sibling',async()=>{
  const entered=deferred(),persist=deferred(),{cap}=await capability();
  const g=graph('small',2,()=>{},{beforeToolPersistence:async id=>{
    if(id==='call-0'){entered.resolve();await persist.promise;}
  }});
  const running=g.run(cap);
  try{await entered.promise;await nextTurn();assert.equal(g.dispatches(),1);
    assert.equal(g.messages.filter(m=>m.role==='tool').length,0);}
  finally{persist.resolve();await running;}
  assert.equal(g.dispatches(),2);assert.equal(g.calls(),2);
  assert.deepEqual(g.messages.filter(m=>m.role==='tool').map(m=>m.tool_call_id),['call-0','call-1']);
  assert.equal(g.traces.filter(t=>t.kind==='mcp_result').length,2);
});
test('Fixed aggregate rejection prevents later selected calls from dispatching',async()=>{
  const {cap}=await capability(),g=graph('x'.repeat(32700),4);
  g.messages.push({role:'assistant',content:'h'.repeat(40000)});
  await assert.rejects(g.run(cap),{code:'CUSTOMER_CONSUMPTION_LIMIT'});
  assert.equal(g.dispatches(),3);assert.equal(g.calls(),1);
  assert.equal(g.messages.filter(m=>m.role==='tool').length,2);
  assert.equal(g.traces.filter(t=>t.kind==='mcp_result').length,2);
  await nextTurn();assert.equal(g.dispatches(),3);
});
test('Fixed authority revocation after one persisted result fences the next selected effect',async()=>{
  const f=await capability(),g=graph('small',2,()=>{},{afterToolPersistence:id=>{
    if(id==='call-0')f.revoke();
  }});
  await assert.rejects(g.run(f.cap),{code:'CUSTOMER_CONSUMPTION_AUTHORITY'});
  assert.equal(g.dispatches(),1);assert.equal(g.calls(),1);
  assert.equal(g.messages.filter(m=>m.role==='tool').length,1);
});
test('legacy and configured vulnerable batches retain concurrent verbatim dispatch',async()=>{
  for(const cap of [undefined,(await capability('vuln')).cap]){
    const entered=deferred(),release=deferred(),text='x'.repeat(40000);
    const g=graph('',2,()=>{},{callTool:async()=>{entered.resolve();await release.promise;
      return {content:[{type:'text',text}]};}});
    const running=g.run(cap);
    try{await entered.promise;await nextTurn();assert.equal(g.dispatches(),2);}
    finally{release.resolve();await running;}
    assert.equal(g.calls(),2);
    assert.deepEqual(g.messages.filter(m=>m.role==='tool').map(m=>m.content),[text,text]);
  }
});
