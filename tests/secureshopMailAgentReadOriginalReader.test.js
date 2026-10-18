'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createMailAgentReadOriginalReader, PURPOSE } = require('../server/services/secureshopMailAgentReadOriginalReader');
const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
function fixture() {
  const scope = { launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:1,platformSessionId:2 };
  const persona = { id:10,role:'merchant' }, personaSession = { sessionId:randomUUID(),authorityVersion:'1' };
  const sessionId = randomUUID(), requestId = randomUUID(), runId = randomUUID(), choiceId = randomUUID();
  const input = {scope,persona,personaSession,sessionId,requestId,check:async()=>{}};
  const binding = createConversationBinding(scope, persona), sha = 'a'.repeat(64);
  const modeCapability = {version:1,featureId:'merchant_assistant',policyVersion:'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'merchant_assistant'}};
  const mailModeCapability = {version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'mail'}};
  const body='Synthetic customer message';
  const header={id:7,threadId:7,from:'customer@example.test',to:'other@example.test',subject:'Private',createdAt:'2026-10-15T12:00:00.000Z',sha256:sha};
  const packet={version:1,kind:'detail',readOperationId:randomUUID(),mailModeCapability,receiptSha256:sha,
    recipient:{id:11,username:'customer',email:'customer@example.test',role:'customer'},messageId:7,messageSha256:sha,status:'complete',
    message:{...header,bodyMarkdown:body,bodyHtml:body,headersRaw:'',sourceBytes:Buffer.byteLength(body)*2,oversized:false}};
  const mailRead={version:1,choiceId,modeCapability,result:packet}, origin={step:1,callId:'call-1'};
  const selection={choiceId,intent:'mail_detail'}, message='Read the selected message';
  const envelope=JSON.stringify({version:1,role:'merchant',sceneId:randomUUID(),sceneGeneration:4,targetId:randomUUID(),message,selection});
  const args={choiceId}, observation={content:[{type:'text',text:JSON.stringify({mail:packet,origin})}]};
  const identity={model:'controlled-native',mocked:false,fallback:false};
  const row=(kind,step,values)=>({id:'0',event_id:randomUUID(),session_id:sessionId,kind,step,actor:'supervisor',provider:'controlled-native',params_json:null,result_json:JSON.stringify(identity),...values});
  const traces=[row('model_decision',1,{params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:origin.callId,name:'merchant.mail_detail',args}]})}),
    row('local_tool_call',1,{actor:'supervisor→task',agent_ns:'merchant',tool_name:'mail_detail',params_json:JSON.stringify(args),policy_violation:null}),
    row('local_tool_result',1,{actor:'task→supervisor',agent_ns:'merchant',tool_name:'mail_detail',result_json:JSON.stringify(observation),policy_violation:null}),
    row('model_decision',2,{params_json:null,result_json:JSON.stringify({...identity,decision:'final',text:body,stopReason:'end_turn'})}),
    row('terminal',2,{result_json:JSON.stringify({...identity,stopReason:'end_turn',steps:2,hops:1})})];
  traces.forEach((r,i)=>r.id=String(i+1));
  const result={stopReason:'end_turn',text:body,steps:2,modeCapability,hops:[{step:1,tool:'merchant.mail_detail',params:args,result:observation,error:null,policyViolation:null}],
    taskMetadata:{roleChat:{mailRead,mailOrigin:origin,mailSelection:selection,mailContinuation:null,mailSourceMessage:message,mailReadRunId:runId,mailReadTraceEventIds:traces.map(r=>r.event_id)}}};
  const turn={session_id:sessionId,request_id:requestId,status:'completed',request_version:1,
    request_hash:createTurnRequest({sessionId,requestId,binding,message:envelope,version:1}).hash,result_json:result};
  const saved={sessionId,requestId,status:'completed',stopReason:'end_turn',replayed:true,text:body,mailRead,hops:result.hops,modeCapability};
  const owner=JSON.stringify(['SecureShopBoundConversation',sessionId]),effectKey=`${requestId}:${JSON.stringify([1,origin.callId,'merchant.mail_detail'])}`;
  const run={run_id:runId,owner_key:owner,generation:'3',status:'completed'},effect={...run,effect_key:effectKey};
  const messages=[{role:'user',content:envelope},
    {role:'assistant',content:'',tool_calls:[{id:origin.callId,type:'function',
      function:{name:'merchant.mail_detail',arguments:JSON.stringify(args)}}]},
    {role:'tool',tool_call_id:origin.callId,content:observation.content[0].text},
    {role:'assistant',content:body}];
  messages.forEach(row=>row.modeCapability=structuredClone(modeCapability));
  let reads=0,queries=0;
  const deps={journal:{readBoundRequest:async()=>turn},conversations:{getBoundSession:async()=>({id:sessionId,purpose:PURPOSE,state:'active',binding}),
    getMessages:async()=>messages,getTraceEvents:async()=>traces},identityPool:{query:async sql=>{queries++;assert.match(sql,/^SELECT /);return {rows:[sql.includes('graph_runtime.runs')?run:effect]};}},
    readRequest:async(...args)=>{reads++;assert.deepEqual(args,[scope,persona,personaSession,sessionId,requestId]);return saved;},qualifyModel:()=>true};
  return {input,deps,turn,saved,traces,packet,run,effect,envelope,messages,counts:()=>({reads,queries})};
}
test('original detail joins immutable turn, qualified selected tool, observed bytes and completed graph effect without replay',async()=>{
  const f=fixture(),out=await createMailAgentReadOriginalReader(f.deps).read(f.input);
  assert.equal(out.mail.message.bodyMarkdown,'Synthetic customer message');assert.deepEqual(f.counts(),{reads:2,queries:2});
  assert.equal(JSON.parse(out.envelope).requestId,undefined);assert.equal(out.effect.effect_key,f.effect.effect_key);
});
for(const [name,mutate] of [
  ['same persona',f=>f.packet.recipient.id=10],
  ['fixed mail',f=>f.packet.mailModeCapability.effectiveMode='fixed'],
  ['fixed assistant',f=>f.saved.modeCapability.effectiveMode='fixed'],
  ['oversized body',f=>{f.packet.status='oversized';f.packet.message=null;}],
  ['missing captured traces',f=>delete f.turn.result_json.taskMetadata.roleChat.mailReadTraceEventIds],
  ['modified original request hash',f=>f.turn.request_hash='b'.repeat(64)],
  ['foreign trace session',f=>f.traces[1].session_id=randomUUID()],
  ['reordered traces',f=>f.traces[1].id='9'],
  ['model selected other choice',f=>{const p=JSON.parse(f.traces[0].params_json);p.toolCalls[0].args.choiceId=randomUUID();f.traces[0].params_json=JSON.stringify(p);}],
  ['unqualified provider',f=>f.deps.qualifyModel=()=>false],
  ['mock response',f=>f.traces[0].result_json=JSON.stringify({model:'controlled-native',mocked:true})],
  ['modified source bytes',f=>f.packet.message.bodyMarkdown='Forged'],
  ['failed effect',f=>f.effect.status='failed'],
  ['foreign graph owner',f=>f.run.owner_key='foreign'],
  ['different final model',f=>f.traces[3].result_json=JSON.stringify({model:'other',mocked:false,text:f.saved.text})],
  ['stale current authority',f=>f.input.check=async()=>{throw Error('stale')}],
])test('rejects '+name,async()=>{const f=fixture();mutate(f);await assert.rejects(createMailAgentReadOriginalReader(f.deps).read(f.input),{code:'MAIL_AGENT_READ_ORIGINAL_UNAVAILABLE'});});
test('second retained read changing denies rather than repairing or replaying',async()=>{
 const f=fixture();let calls=0;f.deps.readRequest=async()=>++calls===1?f.saved:{...f.saved,text:'changed'};
 await assert.rejects(createMailAgentReadOriginalReader(f.deps).read(f.input),{code:'MAIL_AGENT_READ_ORIGINAL_UNAVAILABLE'});assert.equal(calls,2);
});

module.exports={fixture};

test('initial graph owner generation zero is valid without changing exact effect ownership',async()=>{
  const f=fixture();f.run.generation='0';f.effect.generation='0';
  const out=await createMailAgentReadOriginalReader(f.deps).read(f.input);
  assert.equal(out.run.generation,'0');assert.equal(out.effect.generation,'0');
});
for(const generation of ['-1','00','01','1.0','9223372036854775808'])
  test('rejects noncanonical or out-of-range graph generation '+generation,async()=>{
    const f=fixture();f.run.generation=generation;f.effect.generation=generation;
    await assert.rejects(createMailAgentReadOriginalReader(f.deps).read(f.input),
      {code:'MAIL_AGENT_READ_ORIGINAL_UNAVAILABLE'});
  });

test('repeated identical text binds the original call sequence rather than another turn',async()=>{
  const f=fixture(),previous=structuredClone(f.messages);
  previous[1].tool_calls[0].id='older-call';previous[2].tool_call_id='older-call';
  f.messages.unshift(...previous);
  const out=await createMailAgentReadOriginalReader(f.deps).read(f.input);
  assert.equal(out.envelope,f.envelope);assert.equal(out.requestId,f.input.requestId);
  assert.equal(out.effect.effect_key,f.effect.effect_key);
});
for(const [name,mutate] of [
  ['current user absent with identical earlier turn',f=>{
    const previous=structuredClone(f.messages);previous[1].tool_calls[0].id='older-call';
    previous[2].tool_call_id='older-call';f.messages.splice(0,1);f.messages.unshift(...previous);
  }],
  ['only other turn has matching text',f=>{f.messages[1].tool_calls[0].id='older-call';f.messages[2].tool_call_id='older-call';}],
  ['duplicate original call identity',f=>f.messages.push(...structuredClone(f.messages))],
  ['different adjacent request text',f=>f.messages[0].content='Changed original'],
  ['different adjacent tool observation',f=>f.messages[2].content='Changed observation'],
  ['different adjacent final answer',f=>f.messages[3].content='Changed final'],
])test('rejects '+name,async()=>{
  const f=fixture();mutate(f);
  await assert.rejects(createMailAgentReadOriginalReader(f.deps).read(f.input),
    {code:'MAIL_AGENT_READ_ORIGINAL_UNAVAILABLE'});
});

test('detail at a later selected step binds the same user segment across earlier tool pairs',async()=>{
  const f=fixture(),meta=f.turn.result_json.taskMetadata.roleChat;
  meta.mailOrigin.step=2;f.turn.result_json.steps=3;
  for(const row of f.traces)row.step++;
  for(const row of f.traces.filter(r=>r.kind==='terminal')){
    const value=JSON.parse(row.result_json);value.steps=3;row.result_json=JSON.stringify(value);
  }
  const observation=f.turn.result_json.hops[0].result;
  const content=JSON.parse(observation.content[0].text);content.origin.step=2;
  observation.content[0].text=JSON.stringify(content);f.messages[2].content=observation.content[0].text;
  f.turn.result_json.hops[0].step=2;
  f.traces.find(r=>r.kind==='local_tool_result').result_json=JSON.stringify(observation);
  f.effect.effect_key=`${f.input.requestId}:${JSON.stringify([2,meta.mailOrigin.callId,'merchant.mail_detail'])}`;
  f.messages.splice(1,0,
    {role:'assistant',content:'',tool_calls:[{id:'earlier-step',type:'function',function:{name:'merchant.catalog_search',arguments:'{}'}}]},
    {role:'tool',tool_call_id:'earlier-step',content:'Earlier owned observation'});
  f.messages.forEach(row=>row.modeCapability=structuredClone(f.saved.modeCapability));
  const out=await createMailAgentReadOriginalReader(f.deps).read(f.input);
  assert.equal(out.origin.step,2);assert.equal(out.envelope,f.envelope);
});

for(const index of [0,1,2,3])test('rejects mismatched stored message mode at segment position '+index,async()=>{
  const f=fixture();f.messages[index].modeCapability={...f.saved.modeCapability,effectiveMode:'fixed'};
  await assert.rejects(createMailAgentReadOriginalReader(f.deps).read(f.input),{code:'MAIL_AGENT_READ_ORIGINAL_UNAVAILABLE'});
});
test('does not cross a subsequent user boundary to borrow the final answer',async()=>{
  const f=fixture();f.messages.splice(3,0,{role:'user',content:'Other turn',modeCapability:f.saved.modeCapability});
  await assert.rejects(createMailAgentReadOriginalReader(f.deps).read(f.input),{code:'MAIL_AGENT_READ_ORIGINAL_UNAVAILABLE'});
});
test('allows complete later tool pairs before this turn final answer',async()=>{
  const f=fixture();f.messages.splice(3,0,
    {role:'assistant',content:'',tool_calls:[{id:'later-step',type:'function',function:{name:'merchant.catalog_search',arguments:'{}'}}],modeCapability:f.saved.modeCapability},
    {role:'tool',tool_call_id:'later-step',content:'Later owned observation',modeCapability:f.saved.modeCapability});
  const out=await createMailAgentReadOriginalReader(f.deps).read(f.input);assert.equal(out.text,f.saved.text);
});
