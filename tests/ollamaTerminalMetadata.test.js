'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
// Actual installed SDK, controlled fetch only: no provider or socket is used.
for(const reason of ['stop','length']) test(`SDK preserves fragmented ${reason} terminal metadata and exact text`,async()=>{
 const original=global.fetch;let calls=0;
 global.fetch=async()=>{calls++;const bytes=Buffer.from(JSON.stringify({model:'controlled',response:'visible text',done:false})+'\n'+JSON.stringify({model:'controlled',response:'',done:true,done_reason:reason,eval_count:1500})+'\n');return new Response(new ReadableStream({start(c){for(let i=0;i<bytes.length;i+=7)c.enqueue(bytes.subarray(i,i+7));c.close();}}));};
 try{const provider=createLangChainProvider({provider:'ollama',model:'controlled',baseURL:'http://127.0.0.1:1'});const result=await provider.generate('controlled',{timeout:1000,allowFallback:false});assert.equal(result.response,'visible text');assert.deepEqual({done:result.metadata.done,reason:result.metadata.done_reason},{done:true,reason});assert.equal(result.mocked,false);assert.equal(result.fallback,false);assert.equal(calls,1);}finally{global.fetch=original;}
});
for(const kind of ['error','oversize','cancel']) test(`SDK ${kind} cannot publish successful terminal metadata`,async()=>{
 const original=global.fetch;const controller=new AbortController();
 global.fetch=async(_url,init)=>new Response(new ReadableStream({start(c){if(kind==='error')c.error(new Error('controlled stream error'));else if(kind==='oversize'){c.enqueue(Buffer.from(JSON.stringify({response:"x".repeat(16*1024*1024+1),done:false})+"\n"));c.close();}else{init.signal.addEventListener('abort',()=>c.error(init.signal.reason),{once:true});queueMicrotask(()=>controller.abort(new Error('controlled cancellation')));}}}));
 try{const provider=createLangChainProvider({provider:'ollama',model:'controlled',baseURL:`http://127.0.0.1:1/${kind}`});await assert.rejects(provider.generate('controlled',{timeout:1000,signal:controller.signal}));}finally{global.fetch=original;}
});
for(const reason of ['stop','length']) test(`graph ${reason} retains model text/provenance and projects existing diagnostic fields`,async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');const events=[];
 const model={provider:'ollama',async generateResponse(prompt){return prompt.includes('Select exactly one tool')?{response:JSON.stringify({tool:'general_chat',params:{}}),provider:'ollama'}:{response:'unchanged visible text',provider:'ollama',metadata:{done:true,done_reason:reason}};}};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{}},runLedger:{begin:async()=>({durableGeneration:0}),assertCurrent:async()=>{},finish:async()=>{},recordEvent:async(_context,event)=>events.push(event)}});
 const result=await agent.invoke(`terminal-${reason}`,'hello','fixed',{includeRunMetadata:true});assert.equal(result.response,'unchanged visible text');assert.equal(result.run.responseSource,'model');assert.equal(result.run.responseErrorCode,reason==='length'?'MODEL_OUTPUT_LIMIT':undefined);const event=events.find(e=>e.node==='model'&&e.type==='node_end'&&e.data.responseSource);assert.equal(event.data.errorCode,reason==='length'?'MODEL_OUTPUT_LIMIT':undefined);
});
