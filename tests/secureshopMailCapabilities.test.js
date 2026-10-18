'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createMailCapabilities}=require('../server/services/secureshopMailCapabilities');
const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider');
const {OpenAIProvider}=require('../server/services/secureshop/providers/openaiProvider');
const {ProviderRouter}=require('../server/services/secureshop/providerRouter');
const {resolveJudgeProviderConfig,registerConfiguredJudge}=require('../server/agent-runtime/judgeProviderConfiguration');
const tags=models=>new Response(JSON.stringify({models:models.map(name=>({name}))}));
test('Judge resolution preserves aliases and distinct configured Judge model',()=>{assert.deepEqual(resolveJudgeProviderConfig({JUDGE_PROVIDER:'chatgpt',JUDGE_MODEL:'judge-a',OPENAI_MODEL:'actor-a',OPENAI_API_KEY:'private'}),{provider:'openai',model:'judge-a',apiKey:'private'});assert.equal(resolveJudgeProviderConfig({OLLAMA_MODEL:'actor',JUDGE_MODEL:'judge'}).model,'judge');assert.throws(()=>resolveJudgeProviderConfig({JUDGE_PROVIDER:'unsupported'}));});
test('exact actor and Judge identities, cache coalescing, and changed model invalidate probe',async()=>{
 const provider=new OllamaProvider({model:'actor',baseUrl:'http://owned.invalid'});let configuration={provider:'ollama',model:'judge',baseURL:'http://judge.invalid'},calls=0;
 const judge=registerConfiguredJudge(async()=>{},()=>configuration),service=createMailCapabilities({provider,judge,fetchImpl:async()=>{calls++;return tags(['actor','judge']);}});
 const values=await Promise.all([service.read(),service.read()]);assert.equal(calls,2);assert.deepEqual(values[0],values[1]);assert.equal(values[0].actor.model,'actor');assert.equal(values[0].judge.model,'judge');assert.equal(values[0].judge.status,'available');await service.read();assert.equal(calls,2);
 configuration={...configuration,model:'absent'};assert.equal((await service.read()).judge.status,'model_missing');assert.equal(calls,4);await assert.rejects(service.assertAvailable('judge'),{code:'MAIL_MODEL_UNAVAILABLE'});
});
test('whole deadline includes hung response body and aborts underlying probe',async()=>{
 let signal;const provider=new OllamaProvider({model:'actor'}),service=createMailCapabilities({provider,judge:async()=>{},timeoutMs:25,fetchImpl:async(_,{signal:s})=>{signal=s;return new Response(new ReadableStream({start(){}}));}});
 const start=Date.now(),value=await service.read();assert(Date.now()-start<1000);assert.equal(signal.aborted,true);assert.equal(value.actor.canAttempt,false);
});
test('router selects configured cloud without claiming reachability; unknown injections and mock cannot borrow env',async()=>{
 const cloud=new OpenAIProvider({apiKey:'secret',model:'cloud-a'}),provider=new ProviderRouter({openai:cloud,mock:{}});let calls=0;
 const service=createMailCapabilities({provider,judge:async()=>{},fetchImpl:async()=>{calls++;throw Error('unexpected');}}),result=await service.read();assert.equal(result.actor.status,'configured_unprobed');assert.equal(result.actor.canAttempt,true);assert.equal(result.judge.status,'unknown_unprobed');assert.equal(result.judge.canAttempt,false);assert.equal(JSON.stringify(result).includes('secret'),false);assert.equal(calls,0);
 const unknown=await createMailCapabilities({provider:{chat(){},model:'llama3.1:8b'},judge:async()=>{}}).read();assert.equal(unknown.actor.canAttempt,false);
 const mock=await createMailCapabilities({provider:new ProviderRouter({mock:{}}),judge:async()=>{}}).read();assert.equal(mock.actor.status,'mock_only');
});
test('missing local model preserves prospective configured cloud fallback without claiming actual selection',async()=>{
 const provider=new ProviderRouter({ollama:new OllamaProvider({model:'missing'}),openai:new OpenAIProvider({apiKey:'secret',model:'cloud'})});const result=await createMailCapabilities({provider,judge:async()=>{},fetchImpl:async()=>tags(['other'])}).read();assert.equal(result.actor.provider,'openai');assert.equal(result.actor.status,'configured_unprobed');assert.equal(result.actor.canAttempt,true);assert.equal(result.actor.selection,'prospective_route');assert.equal(result.actor.candidates[0].status,'model_missing');
});

test('slow actor body does not erase independent available Judge',async()=>{const provider=new OllamaProvider({model:'actor',baseUrl:'http://actor.invalid'}),judge=registerConfiguredJudge(async()=>{},()=>({provider:'ollama',model:'judge',baseURL:'http://judge.invalid'}));const value=await createMailCapabilities({provider,judge,timeoutMs:25,fetchImpl:async url=>String(url).includes('actor')?new Response(new ReadableStream({start(){}})):tags(['judge'])}).read();assert.equal(value.actor.canAttempt,false);assert.equal(value.judge.status,'available');});
