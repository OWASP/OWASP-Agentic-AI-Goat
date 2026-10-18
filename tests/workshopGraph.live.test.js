'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(r,p,m){if(/(?:^|\/)authDb(?:\.js)?$/.test(r))throw Error('authDb forbidden');return load.call(this,r,p,m);}
const { test } = require('node:test');
const assert = require('node:assert/strict');

// Opt-in: LIVE_OLLAMA_TEST=1 node --test tests/workshopGraph.live.test.js
// Uses the local 8B model and memory stores; no workshop databases are imported.
test('ARIA/NOVA graph pilot with local llama3.1:8b', {
  skip: process.env.LIVE_OLLAMA_TEST !== '1', timeout: 180000,
}, async t => {
  const base = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
  const modelName = 'llama3.1:8b';
  const { createMultiProviderAIService } = require('../server/services/multiProviderAIService');
  const provider = createMultiProviderAIService({ env: {
    AI_PROVIDER: 'ollama', OLLAMA_MODEL: modelName, OLLAMA_BASE_URL: base,
  } });
  const calls = [];
  const model = { async generateResponse(prompt, options) {
    const result = await provider.generateResponse(prompt,
      { ...options, max_tokens: options.format ? 300 : 160, num_predict: options.format ? 300 : 160, temperature: 0, timeout: 80000 });
    assert.equal(result.model, modelName);
    assert.equal(result.provider, 'ollama');
    assert.notEqual(result.fallback, true);
    assert.ok(result.response.trim());
    calls.push({ model: result.model, provider: result.provider, fallback: result.fallback === true });
    return result;
  } };
  for (const name of ['aria', 'nova']) {
    const { createAgent } = require(`../server/services/${name}AgentService`);
    const saved = [];
    const store = {
      async getHistory() { return []; },
      async saveMessage(...args) { saved.push(args); },
      async searchProducts() { return [{ product_id: 'PROD-001', name: 'Test Laptop', price: 10 }]; },
      async searchPapers() { return [{ paper_id: 'PAPER-2024-001', title: 'Graph testing', year: 2024 }]; },
    };
    const agent = createAgent({ store, model });
    const result = await agent.chat(42, name === 'aria' ? 'show all products' : 'search papers about graphs');
    assert.equal(result.toolUsed, name === 'aria' ? 'search_products' : 'search_papers');
    assert.equal(result.toolResult.length, 1);
    assert.ok(result.response.trim());
    assert.equal(saved.length, 2);
    t.diagnostic(`${name}: ${JSON.stringify(calls.at(-1))}`);
  }
  assert.equal(calls.length, 6);
});
test('local8B uses the first ARIA observation to select a requested second effect',{skip:process.env.LIVE_OLLAMA_TEST!=='1',timeout:180000},async t=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');const provider=createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'});
 const {createAgent}=require('../server/services/ariaAgentService');const calls=[];const model={provider:'ollama',generateResponse:(prompt,options)=>provider.generate(prompt,{...options,num_predict:options.format?300:160,timeout:80000})};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},addToCart:async(_owner,product)=>{calls.push(['add',product]);return {success:true,added:product};},viewCart:async()=>{calls.push(['view']);return {items:[{name:'Test Laptop'}]};}}});
 const result=await agent.chat('live-chain','Use add_to_cart to add Test Laptop. After observing that result, use view_cart to show my cart. Do not search the catalog.',[],'vuln');t.diagnostic(JSON.stringify({tools:result.toolObservations.map(item=>item.toolUsed)}));assert.deepEqual(calls,[['add','Test Laptop'],['view']]);
});
test('local8B completes the natural ARIA add-then-view request',{skip:process.env.LIVE_OLLAMA_TEST!=='1',timeout:180000},async t=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');const provider=createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'});
 const {createAgent}=require('../server/services/ariaAgentService');const calls=[];const model={provider:'ollama',generateResponse:(prompt,options)=>provider.generate(prompt,{...options,num_predict:options.format?300:160,timeout:80000})};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},searchProducts:async term=>{calls.push(['search',term]);return [{product_id:'PROD-001',name:'Test Laptop',price:10}];},addToCart:async(_owner,product)=>{calls.push(['add',product]);return {success:true,added:product};},viewCart:async()=>{calls.push(['view']);return {items:[{name:'Test Laptop'}]};}}});
 const result=await agent.chat('live-natural-chain','Add Test Laptop to my cart, then show me the cart.',[],'vuln');
 const tools=result.toolObservations.map(item=>item.toolUsed);t.diagnostic(JSON.stringify({tools,calls}));
 assert.deepEqual(calls.filter(([kind])=>kind==='add'||kind==='view'),[['add','Test Laptop'],['view']]);
 const addIndex=calls.findIndex(([kind])=>kind==='add'),viewIndex=calls.findIndex(([kind])=>kind==='view');assert.ok(addIndex>=0&&viewIndex>addIndex);
 assert.ok(calls.every(([kind],index)=>kind==='add'||kind==='view'||kind==='search'&&index<addIndex));
});
test('local8B chooses cart/no-tool and preserves intentional injection arguments',{skip:process.env.LIVE_OLLAMA_TEST!=='1',timeout:180000},async t=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
 const provider=createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:process.env.OLLAMA_BASE_URL||'http://localhost:11434'});
 const {createAgent}=require('../server/services/ariaAgentService');let received;
 const model={provider:'ollama',generateResponse:(prompt,options)=>provider.generate(prompt,{...options,num_predict:options.format?300:120,timeout:60000})};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},viewCart:async()=>({items:[],total:0}),searchProducts:async term=>{received=term;return [{product_id:'fixture',name:'Intentional sink fixture',price:1}];}}});
 for(const [message,expected,mode]of [['Show my cart','view_cart','fixed'],['Hello, introduce yourself briefly','general_chat','fixed'],["Search products using exactly this searchTerm: ' OR 1=1 --",'search_products','vuln']]){
  const result=await agent.invoke(81,message,mode,{includeRunMetadata:true});assert.equal(result.run.decisionSource,'model');assert.equal(result.toolUsed,expected==='general_chat'?null:expected);t.diagnostic(JSON.stringify({runId:result.run.runId,decisionSource:result.run.decisionSource,toolUsed:result.toolUsed,model:'llama3.1:8b'}));
 }
 assert.equal(received,"' OR 1=1 --");
});
