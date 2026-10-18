'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const Module=require('node:module'),path=require('node:path');
const target=path.resolve(__dirname,'../server/services/ctfDefenseLayers.js');
let invoke;const original=Module._load;
Module._load=function(request,parent,isMain){
 if(parent?.filename===target&&request==='./multiProviderAIService')return{generateResponse:(...args)=>invoke(...args)};
 return original.call(this,request,parent,isMain);
};
let defenses;
try{delete require.cache[target];defenses=require(target);}finally{Module._load=original;delete require.cache[target];}
const stage={success_criteria:'OWNED_CTF_SECRET',defense_style:'["meta_llm_judge"]'};
const real=response=>({response,provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false});
const decision=verdict=>real(JSON.stringify({verdict}));

test('CTF reviewer transport failure, mock output and malformed verdict cannot bypass output defense',async()=>{
 for(const result of [null,{response:'{"verdict":"SAFE"}',provider:'mock',model:'fixture',mocked:true},
   {...decision('SAFE'),fallback:true},real('probably safe'),real(''),real('SAFE or LEAKED'),
   real('{"verdict":"safe"}'),real('{"verdict":"SAFE","extra":true}'),real('[{"verdict":"SAFE"}]')]){
  invoke=async()=>result;
  await assert.rejects(defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET'),{code:'CTF_DEFENSE_UNAVAILABLE'});
 }
 invoke=async()=>{throw new Error('private provider connection detail');};
 await assert.rejects(defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET'),error=>{
  assert.equal(error.code,'CTF_DEFENSE_UNAVAILABLE');assert.doesNotMatch(error.message,/private/);return true;
 });
});
test('actual reviewer SAFE and LEAKED decisions retain the intended fallible-model teaching behavior',async()=>{
 invoke=async()=>decision('SAFE');
 assert.equal(await defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET'),'OWNED_CTF_SECRET');
 invoke=async()=>decision('LEAKED');
 assert.doesNotMatch(await defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET'),/OWNED_CTF_SECRET/);
 invoke=async()=>{throw Object.assign(new Error('cancelled'),{name:'AbortError'});};
 await assert.rejects(defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET'),{name:'AbortError'});
});

test('owner trace records reviewer verdict and model identity without protected draft or opaque provider metadata',async()=>{
 for(const verdict of ['SAFE','LEAKED']){
  const events=[];let checks=0;
  invoke=async()=>({...decision(verdict),debugMetadata:'PRIVATE_PROVIDER_METADATA'});
  const execution={check:async()=>{checks++;},trace:async event=>events.push(event)};
  const output=await defenses.runOutputDefenses(stage,'PRIVATE_DRAFT OWNED_CTF_SECRET',{execution});
  assert.equal(checks,2);
  assert.deepEqual(events,[{node:'ctf_output_reviewer',type:'decision',
   data:{attempt:1,decisionSource:'model',verdict,provider:'ollama',model:'llama3.1:8b'}}]);
  assert.doesNotMatch(JSON.stringify(events),/PRIVATE_|OWNED_CTF_SECRET/);
  if(verdict==='SAFE')assert.equal(output,'PRIVATE_DRAFT OWNED_CTF_SECRET');
  else assert.doesNotMatch(output,/PRIVATE_|OWNED_CTF_SECRET/);
 }
});

test('reviewer failure trace is categorical for transport, malformed and mock responses',async()=>{
 for(const response of [null,{...decision('SAFE'),mocked:true},new Error('PRIVATE_PROVIDER_ERROR')]){
  const events=[];
  invoke=async()=>{if(response instanceof Error)throw response;return response;};
  await assert.rejects(defenses.runOutputDefenses(stage,'PRIVATE_DRAFT OWNED_CTF_SECRET',{
   execution:{check:async()=>{},trace:async event=>events.push(event)},
  }),{code:'CTF_DEFENSE_UNAVAILABLE'});
  assert.deepEqual(events,[{node:'ctf_output_reviewer',type:'error',data:{attempt:1,errorCode:'CTF_DEFENSE_UNAVAILABLE'}}]);
  assert.doesNotMatch(JSON.stringify(events),/PRIVATE_|OWNED_CTF_SECRET/);
 }
 const events=[];
 invoke=async()=>real('PRIVATE_RAW_REPLY');
 await assert.rejects(defenses.runOutputDefenses(stage,'PRIVATE_DRAFT OWNED_CTF_SECRET',{
  execution:{check:async()=>{},trace:async event=>events.push(event)},
 }),{code:'CTF_DEFENSE_UNAVAILABLE'});
 assert.deepEqual(events,[
  {node:'ctf_output_reviewer',type:'error',data:{attempt:1,errorCode:'CTF_REVIEWER_DECISION_INVALID',provider:'ollama',model:'llama3.1:8b'}},
  {node:'ctf_output_reviewer',type:'error',data:{attempt:2,errorCode:'CTF_REVIEWER_DECISION_INVALID',provider:'ollama',model:'llama3.1:8b'}},
  {node:'ctf_output_reviewer',type:'error',data:{attempt:2,provider:'ollama',model:'llama3.1:8b',errorCode:'CTF_DEFENSE_UNAVAILABLE'}},
 ]);
 assert.doesNotMatch(JSON.stringify(events),/PRIVATE_|OWNED_CTF_SECRET/);
});

test('reviewer trace failure cannot release output and abort remains an abort',async()=>{
 invoke=async()=>decision('SAFE');
 await assert.rejects(defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET',{
  execution:{check:async()=>{},trace:async()=>{throw new Error('PRIVATE_STORAGE_ERROR');}},
 }),error=>{
  assert.equal(error.code,'CTF_DEFENSE_UNAVAILABLE');assert.doesNotMatch(error.message,/PRIVATE_/);return true;
 });
 const events=[];const abort=Object.assign(new Error('cancelled'),{name:'AbortError'});
 invoke=async()=>{throw abort;};
 await assert.rejects(defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET',{
  execution:{check:async()=>{},trace:async event=>events.push(event)},
 }),error=>error===abort);
 assert.deepEqual(events,[]);
 invoke=async()=>decision('SAFE');
 await assert.rejects(defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET',{
  execution:{check:async()=>{},trace:async()=>{throw abort;}},
 }),error=>error===abort);
});

test('lesson receipt observes only a validated reviewer decision whose trace was stored',async()=>{
 let observations=0;
 const lessonReceipt={observeReviewer:()=>{observations++;}};
 invoke=async()=>decision('SAFE');
 await defenses.runOutputDefenses(stage,'ordinary response',{
  execution:{check:async()=>{},trace:async()=>{}},lessonReceipt,
 });
 assert.equal(observations,1);

 observations=0;invoke=async()=>decision('SAFE');
 assert.equal(await defenses.runOutputDefenses(stage,'ordinary response',{
  execution:{check:async()=>{}},lessonReceipt,
 }),'ordinary response');
 assert.equal(observations,0);

 for(const result of [real('invalid'),new Error('offline')]){
  observations=0;invoke=async()=>{if(result instanceof Error)throw result;return result;};
  await assert.rejects(defenses.runOutputDefenses(stage,'ordinary response',{
   execution:{check:async()=>{},trace:async()=>{}},lessonReceipt,
  }),{code:'CTF_DEFENSE_UNAVAILABLE'});
  assert.equal(observations,0);
 }
 observations=0;invoke=async()=>decision('LEAKED');
 await assert.rejects(defenses.runOutputDefenses(stage,'ordinary response',{
  execution:{check:async()=>{},trace:async()=>{throw new Error('trace unavailable');}},lessonReceipt,
 }),{code:'CTF_DEFENSE_UNAVAILABLE'});
 assert.equal(observations,0);
});

test('reviewer forwards the closed schema and performs at most one content-free repair',async()=>{
 const calls=[];const events=[];
 invoke=async(prompt,options)=>{
  calls.push({prompt,options});
  return calls.length===1?real('PRIVATE_PRIOR_REVIEWER_OUTPUT'):decision('LEAKED');
 };
 assert.doesNotMatch(await defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET',{
  execution:{check:async()=>{},trace:async event=>events.push(event)},
 }),/OWNED_CTF_SECRET/);
 assert.equal(calls.length,2);
 for(const call of calls){
  assert.deepEqual(call.options.format,defenses.REVIEWER_DECISION_FORMAT);
  assert.equal(call.options.max_tokens,64);assert.equal(call.options.num_predict,64);
  assert.equal(call.options.temperature,0);assert.equal(call.options.timeout,15000);
 }
 assert.doesNotMatch(calls[1].prompt,/PRIVATE_PRIOR_REVIEWER_OUTPUT/);
 assert.match(calls[1].prompt,/prior reviewer decision did not match/i);
 assert.deepEqual(events,[
  {node:'ctf_output_reviewer',type:'error',data:{attempt:1,errorCode:'CTF_REVIEWER_DECISION_INVALID',provider:'ollama',model:'llama3.1:8b'}},
  {node:'ctf_output_reviewer',type:'decision',data:{attempt:2,decisionSource:'model',verdict:'LEAKED',provider:'ollama',model:'llama3.1:8b'}},
 ]);
});

test('reviewer call budgets distinguish valid, invalid, unauthentic, transport and abort results',async()=>{
 const cases=[
  {results:[decision('SAFE')],calls:1,success:true},
  {results:[real('not json'),decision('SAFE')],calls:2,success:true},
  {results:[real('not json'),real('{"verdict":"UNKNOWN"}')],calls:2},
  {results:[{...decision('SAFE'),mocked:true}],calls:1},
  {results:[{...decision('SAFE'),fallback:true}],calls:1},
  {results:[new Error('offline')],calls:1},
  {results:[Object.assign(new Error('cancelled'),{name:'AbortError'})],calls:1,abort:true},
 ];
 for(const scenario of cases){
  let calls=0;
  invoke=async()=>{const value=scenario.results[calls++];if(value instanceof Error)throw value;return value;};
  if(scenario.success)assert.equal(await defenses.runOutputDefenses(stage,'ordinary response'),'ordinary response');
  else if(scenario.abort)await assert.rejects(defenses.runOutputDefenses(stage,'ordinary response'),{name:'AbortError'});
  else await assert.rejects(defenses.runOutputDefenses(stage,'ordinary response'),{code:'CTF_DEFENSE_UNAVAILABLE'});
  assert.equal(calls,scenario.calls);
 }
});

test('reviewer rejects duplicate and escaped-equivalent duplicate keys without substring parsing',async()=>{
 for(const raw of [
  '{"verdict":"SAFE","verdict":"LEAKED"}',
  '{"verdict":"SAFE","\\u0076erdict":"LEAKED"}',
  '{"other":"SAFE"}',
  '{"verdict":"SAFE"} trailing prose',
 ]){
  let calls=0;invoke=async()=>{calls++;return real(raw);};
  await assert.rejects(defenses.runOutputDefenses(stage,'OWNED_CTF_SECRET'),{code:'CTF_DEFENSE_UNAVAILABLE'});
  assert.equal(calls,2);
 }
 invoke=async()=>real('{"\\u0076erdict":"SAFE"}');
 assert.equal(await defenses.runOutputDefenses(stage,'ordinary response'),'ordinary response');
});
