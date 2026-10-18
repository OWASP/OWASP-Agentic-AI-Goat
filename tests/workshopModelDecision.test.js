'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('authDb forbidden');return load.call(this,r,p,m);};
const {test}=require('node:test'),assert=require('node:assert/strict');
const {createAgent}=require('../server/services/ariaAgentService');
const traces=require('../server/agent-runtime/runTraceStore');
// Controlled in-process protocol stubs; provider metadata below simulates the
// Ollama contract and is not evidence of an actual model run.
function fixture(responses){const saved=[],tools=[];return {saved,tools,agent:createAgent({store:{getHistory:()=>[],saveMessage:async(u,r,m)=>saved.push([u,r,m]),viewCart:async u=>{tools.push(u);return {items:[],total:0};}},model:{provider:'ollama',generateResponse:async()=>({response:responses.shift(),provider:'ollama',model:'fixture',tokens:3})},runLedger:null})};}
test('Controlled model protocol selects validated tool independently of regex and traces its provenance',async()=>{
 const {agent,tools}=fixture(['{"tool":"view_cart","params":{}}','{"tool":"general_chat","params":{}}','Your cart is empty.']);
 const dto=await agent.invoke(7,'Can you inspect the items I selected?', 'fixed',{includeRunMetadata:true});assert.equal(dto.toolUsed,'view_cart');assert.deepEqual(tools,[7]);assert.equal(dto.run.decisionSource,'model');
 const run=traces.getRun(dto.run.runId,'["ARIA","7"]');assert.ok(run.events.some(e=>e.type==='decision'&&e.data.tool==='view_cart'));assert.equal(traces.getRun(dto.run.runId,'["ARIA","8"]'),null);
});
test('Invalid model tool retries once then fails without executing or silent regex fallback',async()=>{
 const {agent,tools}=fixture(['{"tool":"delete_everything","params":{}}','not json']);const dto=await agent.invoke(7,'show cart','fixed',{includeRunMetadata:true});assert.equal(dto.toolUsed,null);assert.equal(dto.run.decisionSource,'unavailable');assert.deepEqual(tools,[]);assert.match(dto.response,/could not validate/);
});
test('Structured decision repair validates parameters before executing',async()=>{
 const {agent,tools}=fixture(['{"tool":"view_cart","params":{"userId":8}}','{"tool":"view_cart","params":{}}','{"tool":"general_chat","params":{}}','Your cart is empty.']);const dto=await agent.invoke(7,'cart','fixed',{includeRunMetadata:true});assert.equal(dto.toolUsed,'view_cart');assert.deepEqual(tools,[7]);
});
test('A result self-identifying as mock cannot supply a model decision',async()=>{
 const tools=[];const model={provider:'ollama',async generateResponse(){return {response:'{"tool":"view_cart","params":{}}',provider:'mock',model:'mock'};}};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},viewCart:async()=>{tools.push('called');return {};}},runLedger:null});
 const dto=await agent.invoke(9,'show cart','fixed',{includeRunMetadata:true});
 assert.deepEqual(tools,[]);assert.equal(dto.toolUsed,null);assert.equal(dto.run.decisionSource,'unavailable');assert.equal(dto.run.responseSource,undefined);assert.match(dto.response,/could not validate/);
});
