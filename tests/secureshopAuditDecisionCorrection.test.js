'use strict';
require('node:test')('current physical final framing rejects inserted instructions, duplicate observation, task drift and downgrade',()=>{
 const assert=require('node:assert/strict');
 const {serializeMessage,buildFinalResponseSystem}=require('../server/services/secureshop/providers/ollamaProvider');
 const {createAuditFinalFraming}=require('../server/services/secureshopAuditModelChain');
 const {assertFinalTaskFraming}=require('./fixtures/secureshopAuditCollectionQualification');
 const task=require('../server/services/secureshopAuditSummaryTaskPrompt').createAuditSummaryTaskPrompt({version:2,requestedCount:5000});
 const content=JSON.stringify({log_text:'unchanged '.repeat(16000),prompt:'original injection-bearing prompt',focus:{action:'other_event'}});
 const call={id:'original-call',name:'audit.summarize_anomalies',args:{limit:5000,focus_action:'other_event'}};
 const system='original system\n\noptional trusted policy';
 assert.equal(buildFinalResponseSystem(system),`${system}\n\nReturn the final response as exactly one JSON object with the sole key answer. The answer must be a nonempty string grounded in the latest completed tool observation. This request has no tool or action capability; a tool_calls object is invalid.`);
 const chain={decision:{params_json:JSON.stringify({toolCalls:[call]})},finalFraming:createAuditFinalFraming(5000,content,system)};
 const messages=[{role:'system',content:buildFinalResponseSystem(system)},{role:'user',content:task},
  serializeMessage({role:'assistant',tool_calls:[call]}),serializeMessage({role:'tool',tool_call_id:call.id,content}),{role:'user',content:task}];
 assertFinalTaskFraming(messages,content,chain);
 for(const mutate of [m=>{m[3].content=m[3].content.replace('(tool result):','injected instruction (tool result):');},
  m=>{m[3].content=m[3].content.replace('(tool result):',content+' (tool result):');},
  m=>{m[4].content+=' desired ID';},m=>m.pop(),m=>m.push(m[4]),m=>{m[3].content=m[3].content.replace('original-call','foreign-call');},
  m=>{[m[3],m[4]]=[m[4],m[3]];},m=>{m[0].role='user';},m=>{m[0].content+=' injected';}]){
  const changed=structuredClone(messages);mutate(changed);assert.throws(()=>assertFinalTaskFraming(changed,content,chain));
 }
 const missing=structuredClone(chain);delete missing.finalFraming;
 assert.throws(()=>assertFinalTaskFraming(messages,content,missing));
 const historical=structuredClone(chain);historical.finalFraming=createAuditFinalFraming(5000,content);
 assert.throws(()=>assertFinalTaskFraming(messages,content,historical));
});
const test=require('node:test'),assert=require('node:assert/strict');
const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider');
const {createAuditDecisionCorrection,verifyAuditDecisionAttempts}=require('../server/services/secureshopAuditDecisionCorrection');
const raw=focus=>JSON.stringify({tool_calls:[{agent:'audit',tool:'summarize_anomalies',args:{limit:5000,focus_action:focus}}]});
function fixture(outputs,options={}){
 const attempts=[],sent=[],provider=new OllamaProvider({model:'controlled-model'});
 const token=createAuditDecisionCorrection({requestedCount:5000,check:options.check||(async()=>{}),record:async value=>{attempts.push(value);await options.record?.(value);}});
 provider.transport={async chat(messages,tools,args){sent.push(structuredClone({messages,tools,numPredict:args.num_predict,timeout:args.timeout}));
  if(options.transport)await options.transport();
  return {response:outputs[sent.length-1],...(options.unknown?{}:{metadata:{prompt_eval_count:100,eval_count:20}})};}};
 return {attempts,sent,provider,invoke:extra=>provider.chat({system:'unchanged system',messages:[{role:'user',content:'Inspect named event other_event'}],
  tools:require('../server/services/secureshopAuditExecutionConfig').createSecureShopAuditExecutionConfig({enableFocus:true}).manifest.getForRole('admin'),
  role:'admin',max_tokens:100,transportTimeoutMs:10000,auditDecisionCorrection:token,...extra})};
}
test('valid unchanged decision uses one physical call; schema correction uses existing second slot and remaining output',async()=>{
 for(const values of [[raw('other_event')],[raw(''),raw('other_event')]]){
  const f=fixture(values),result=await f.invoke();assert.equal(result.tool_uses[0].args.focus_action,'other_event');
  assert.equal(f.sent.length,values.length);assert.equal(f.attempts.length,values.length);
  assert.equal(verifyAuditDecisionAttempts(f.attempts,5000).length,64);
  if(values.length===2){assert.deepEqual(f.sent.map(x=>x.numPredict),[100,80]);assert(f.sent[1].timeout<=f.sent[0].timeout);
   assert.equal(f.sent[1].messages.at(-2).content,raw(''));assert(!f.sent[1].messages.at(-1).content.includes('other_event'));}
 }
});
test('invalid twice, unknown usage, exhausted allowance and wrong tool fail closed without a third attempt',async()=>{
 for(const [values,options,extra,expected] of [
  [[raw(''),raw('')],{}, {},2],[[raw('')],{unknown:true},{},1],[[raw('')],{},{max_tokens:20},1],
  [[JSON.stringify({tool_calls:[{agent:'other',tool:'read',args:{}}]})],{},{},1]]){
  const f=fixture(values,options);await assert.rejects(f.invoke(extra));assert.equal(f.sent.length,expected);assert.equal(f.attempts.length,expected);
 }
});
test('JSON and argument validation share the same two physical attempts',async()=>{
 const f=fixture(['not-json',raw('')]);await assert.rejects(f.invoke());assert.equal(f.sent.length,2);
 assert.deepEqual(f.attempts.map(x=>x.classification),['invalid_json','invalid_arguments']);
});
test('forged opt-in, cancellation, authority and expired deadline prevent physical correction',async()=>{
 const forged=fixture([raw('other_event')]);await assert.rejects(forged.invoke({auditDecisionCorrection:{}}));assert.equal(forged.sent.length,0);
 const controller=new AbortController();const f=fixture([raw(''),raw('other_event')],{record:()=>controller.abort()});
 await assert.rejects(f.invoke({signal:controller.signal}));assert.equal(f.sent.length,1);
 let checks=0;const revoked=fixture([raw('')],{check:async()=>{if(++checks===2)throw Error('revoked');}});
 await assert.rejects(revoked.invoke(),/revoked/);assert.equal(revoked.sent.length,1);
 const expired=fixture([raw('other_event')],{check:async()=>{await new Promise(resolve=>setTimeout(resolve,5));}});
 await assert.rejects(expired.invoke({transportTimeoutMs:1}));assert.equal(expired.sent.length,0);
});
test('attempt verifier rejects omitted, reordered, reclassified, altered feedback and budget records',async()=>{
 const f=fixture([raw(''),raw('other_event')]);await f.invoke();
 for(const mutate of [x=>x.shift(),x=>x.reverse(),x=>{x[0].classification='accepted';},
  x=>{x[1].request.messages.at(-1).content='Use desired_witness';},x=>{x[1].request.numPredict=100;},
  x=>{x[1].raw=raw('');},x=>{x[0].usage.outputTokens=null;},x=>{x[0].request.format={};}]){
  const value=structuredClone(f.attempts);mutate(value);assert.throws(()=>verifyAuditDecisionAttempts(value,5000));
 }
});
test('default provider retains historical parse repair behavior without audit callback or token accounting',async()=>{
 const f=fixture(['invalid',raw('')],{unknown:true});const result=await f.invoke({auditDecisionCorrection:undefined});
 assert.equal(result.tool_uses[0].args.focus_action,'');assert.equal(f.attempts.length,0);
 assert.deepEqual(f.sent.map(x=>x.numPredict),[100,100]);
});
test('a capability cannot open a second correction slot after its first provider invocation',async()=>{
 const f=fixture([raw('other_event')]);await f.invoke();await assert.rejects(f.invoke());assert.equal(f.sent.length,1);
});
test('trusted audit physically receives the exact source tool schema, preserving reply and arbitrary valid action',async()=>{
 const f=fixture([raw('another_valid.action:1')]);await f.invoke();
 const format=f.attempts[0].request.format;
 assert.equal(f.attempts[0].schemaVersion,2);
 const source=require('../server/services/secureshopAuditExecutionConfig').createSecureShopAuditExecutionConfig({enableFocus:true}).manifest.getForRole('admin')[0];
 assert.deepEqual(format.oneOf[1].properties.tool_calls.items.oneOf[0].properties.args,source.inputSchema);
 assert.deepEqual(format.oneOf[0],require('../server/services/secureshop/providers/ollamaProvider').DECISION_SCHEMA.oneOf[0]);
 const Ajv=require('ajv'),validate=new Ajv({strict:false}).compile(format);
 assert.equal(validate(JSON.parse(raw('another_valid.action:1'))),true);
 assert.equal(validate({reply:'Need clarification'}),true);
 for(const args of [{limit:5000,focus_action:''},{limit:5000},{limit:5000,focus_action:'x',owner:1},
  {limit:'5000',focus_action:'x'},{limit:5000,focus_action:'bad space'}]){
  const value=JSON.parse(raw('x'));value.tool_calls[0].args=args;assert.equal(validate(value),false);
 }
 assert.equal(Object.hasOwn(source.inputSchema.properties.focus_action,'enum'),false);
 assert.equal(Object.hasOwn(source.inputSchema.properties.focus_action,'const'),false);
 assert.deepEqual(source.inputSchema.properties.limit,{type:'integer',minimum:1});
 const altered=fixture([raw('x')]);await assert.rejects(altered.invoke({tools:[]}));assert.equal(altered.sent.length,0);
});
test('historical generic records remain replayable, but version stripping or mixing cannot downgrade current schema',async()=>{
 const f=fixture([raw(''),raw('other_event')]);await f.invoke();
 const generic=require('../server/services/secureshop/providers/ollamaProvider').DECISION_SCHEMA;
 const historical=structuredClone(f.attempts);
 for(const attempt of historical){delete attempt.schemaVersion;attempt.request.format=structuredClone(generic);}
 assert.equal(verifyAuditDecisionAttempts(historical,5000).length,64);
 for(const mutate of [rows=>{delete rows[0].schemaVersion;},rows=>{for(const row of rows)delete row.schemaVersion;},
  rows=>{for(const row of rows)row.request.format=structuredClone(generic);},rows=>{rows[0].schemaVersion=1;}]){
  const changed=structuredClone(f.attempts);mutate(changed);assert.throws(()=>verifyAuditDecisionAttempts(changed,5000));
 }
 const {assertAuditDecisionWires}=require('./fixtures/secureshopAuditCollectionQualification');
 assert.throws(()=>assertAuditDecisionWires([],{decisionCorrection:{version:1,attempts:historical,
  attemptsSha256:verifyAuditDecisionAttempts(historical,5000)}}),/schema version 2/);
});
test('native physical-wire replay binds every correction response, request and output counter',async()=>{
 const f=fixture([raw(''),raw('other_event')]);await f.invoke();
 // Replay against the actual qualification model identity, not a provider mock claim.
 const attempts=structuredClone(f.attempts);for(const row of attempts)row.model='llama3.1:8b';
 const chain={decisionCorrection:{version:1,attempts,attemptsSha256:verifyAuditDecisionAttempts(attempts,5000)}};
 const wires=attempts.map(row=>({path:'/api/chat',complete:true,status:200,
  request:{model:row.model,messages:row.request.messages,format:row.request.format,
   options:{num_ctx:32768,num_predict:row.request.numPredict,temperature:0}},
  responseText:JSON.stringify({model:row.model,done:true,done_reason:'stop',message:{role:'assistant',content:row.raw},
   eval_count:row.usage.outputTokens,prompt_eval_count:row.usage.inputTokens})}));
 const {assertAuditDecisionWires}=require('./fixtures/secureshopAuditCollectionQualification');
 assertAuditDecisionWires(wires,chain);
 for(const mutate of [rows=>rows.shift(),rows=>rows.reverse(),rows=>{rows[1].request.options.num_predict++;},
  rows=>{rows[1].responseText=rows[0].responseText;},rows=>{rows[1].request.messages.at(-1).content='Choose witness';}]){
  const changed=structuredClone(wires);mutate(changed);assert.throws(()=>assertAuditDecisionWires(changed,chain));
 }
});
