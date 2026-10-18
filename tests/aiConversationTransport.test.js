'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createMultiProviderAIService}=require('../server/services/multiProviderAIService');
const {withOwnerExecution}=require('../server/agent-runtime/ownerWorkflowRoutes');
function service(chat){const ai=createMultiProviderAIService({env:{AI_PROVIDER:'ollama'},logger:{log(){}},providerFactory:()=>({chat,generate(){throw Error('Conversation must not be flattened');}})});ai.ensureOllamaModel=async()=>true;ai.checkOllamaAvailable=async()=>true;return ai;}
test('Ollama conversation keeps tool roles, schema and request options in the LangChain chat call',async()=>{
 const messages=[{role:'system',content:'policy'},{role:'assistant',content:'',tool_calls:[{id:'a',function:{name:'read',arguments:{}}}]},{role:'tool',tool_call_id:'a',content:'actual observation'}];
 const signal=new AbortController().signal,format={type:'object',properties:{action:{enum:['read_email']}},required:['action']};
 const options={signal,format,ownerId:'learner',temperature:0,max_tokens:128,timeout:2345};let calls=0;
 const ai=service(async(m,tools,o)=>{calls++;assert.deepEqual(m,messages);assert.deepEqual(tools,[]);for(const [key,value] of Object.entries(options))assert.deepEqual(o[key],value);return{response:'{"action":"read_email"}'};});
 assert.equal((await ai.chatWithMessages(messages,options)).response,'{"action":"read_email"}');assert.equal(calls,1);
});
test('already cancelled owned conversation stops before availability checks',async()=>{
 const controller=new AbortController();controller.abort(new DOMException('reset','AbortError'));let checks=0;
 const ai=service(async()=>{throw Error('must not invoke');});ai.checkOllamaAvailable=async()=>{checks++;return true;};
 await withOwnerExecution({signal:controller.signal},()=>assert.rejects(ai.chatWithMessages([{role:'user',content:'x'}]),e=>e===controller.signal.reason));assert.equal(checks,0);
});
test('cancellation during model readiness stops before chat invocation',async()=>{
 const controller=new AbortController();let calls=0;const ai=service(async()=>{calls++;return{response:'late'};});
 ai.ensureOllamaModel=async()=>{controller.abort(new DOMException('reset','AbortError'));return true;};
 await assert.rejects(ai.chatWithOllama([{role:'user',content:'x'}],{signal:controller.signal}),e=>e===controller.signal.reason);assert.equal(calls,0);
});
