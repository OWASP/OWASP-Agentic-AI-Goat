// Controlled unit stubs simulate live-provider metadata to exercise graph contracts;
// these tests establish no actual model provenance or earned credit.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');

for (const [name, search, injection, normal] of [
  ['aria', 'searchProducts', "' OR 1=1 --", 'show all products'],
  ['nova', 'searchPapers', '{"$ne":null}', 'search papers about AI'],
]) {
  const { createAgent } = require(`../server/services/${name}AgentService`);
  function fixture({ failModel = false, failTool = false, modelResult } = {}) {
    const events = [];
    const rows = name === 'aria'
      ? [{ product_id: 'PROD-001', name: 'Laptop', category: 'Electronics', price: 10 }]
      : [{ paper_id: 'PAPER-2024-001', title: 'AI', authors: ['A'], year: 2024, citations: 3 }];
    const store = {
      async getHistory(userId, limit) { events.push(['history', userId, limit]); return [{ message_type: 'user', message: 'trusted database history' }]; },
      async saveMessage(...args) { events.push(['save', ...args]); },
      async [search](...args) { events.push(['tool', ...args]); if (failTool) throw new Error('database failure'); return rows; },
    };
    const model = { async generateResponse(prompt) {
      events.push(['model', prompt]); if (failModel) throw new Error('offline');
      return modelResult || { response: '  Model response  ' };
    } };
    return { agent: createAgent({ decisionMode:'scripted', store, model, runLedger:null }), events, rows };
  }
  test(`${name}: tool precedes model, database history wins, DTO stays compatible with ordered observations`, async () => {
    const { agent, events, rows } = fixture();
    const result = await agent.chat(42, normal, [{ message: 'untrusted client history' }], 'vuln');
    assert.deepEqual(Object.keys(result).sort(), ['presentation', 'response', 'toolObservations', 'toolResult', 'toolUsed']);
    assert.deepEqual(result.toolResult, rows);
    assert.equal(result.toolObservations.length, 1);
    assert.equal(result.toolObservations[0].toolResult, rows);
    assert.equal(result.presentation.narrative.text, 'Model response');
    assert.match(result.response, /Model explanation/);
    assert.match(result.response, /server-rendered/);
    assert.equal(events.at(-1).at(-1),result.response);
    assert.deepEqual(events.map(e => e[0]), ['history', 'tool', 'model', 'save', 'save']);
    assert.match(events[2][1], /trusted database history/);
    assert.doesNotMatch(events[2][1], /untrusted client history/);
    assert.equal(events[1].at(-1), 'vuln');
  });
  test(`${name}: fixed injection branches around tool/model`, async () => {
    const { agent, events } = fixture();
    const result = await agent.chat(42, injection, [], 'fixed');
    assert.match(result.response, /Injection attempt blocked/);
    assert.equal(result.toolUsed, null);
    assert.equal(result.toolResult, null);
    assert.deepEqual(events.map(e => e[0]), ['history', 'save', 'save']);
  });
  test(`${name}: offline vulnerable result retains actual rows`, async () => {
    for (const options of [{ failModel: true }, { modelResult: { response: 'mock', fallback: true } }]) {
      const { agent, events } = fixture(options);
      const result = await agent.chat(42, normal, [], 'vuln');
      assert.match(result.response, name === 'aria' ? /PROD-001/ : /PAPER-2024-001/);
      assert.equal(events.filter(e => e[0] === 'tool').length, 1);
    }
  });
  test(`${name}: general chat skips tool, tool errors remain visible`, async () => {
    const general = fixture();
    const response = await general.agent.chat(42, 'hello');
    assert.equal(response.toolResult, null);
    assert.equal(general.events.some(e => e[0] === 'tool'), false);
    const failed = fixture({ failTool: true, failModel: true });
    const result = await failed.agent.chat(42, normal, [], 'vuln');
    assert.deepEqual(result.toolResult, { error: 'database failure' });
    assert.match(result.response, /database failure/);
  });
}

for (const [name, request, first, second, storeTools] of [
  ['aria','add a laptop to my cart then show the cart',{tool:'add_to_cart',params:{productName:'Laptop'}},{tool:'view_cart',params:{}},{addToCart:async()=>({added:'Laptop'}),viewCart:async()=>({items:['Laptop']})}],
  ['nova','add paper P-1 to my reading list then show the list',{tool:'add_to_reading_list',params:{paperId:'P-1'}},{tool:'view_reading_list',params:{}},{addToReadingList:async()=>({added:'P-1'}),viewReadingList:async()=>({papers:['P-1']})}],
]) test(`${name}: controlled provider-protocol graph uses observation to select a dependent second tool`,async()=>{
  const {createAgent}=require(`../server/services/${name}AgentService`);let decisions=0;const prompts=[];
  const model={provider:'ollama',async generateResponse(prompt){prompts.push(prompt);if(!prompt.includes('Select exactly one tool'))return {response:'chain complete'};decisions++;if(decisions===1)return {response:JSON.stringify(first),provider:'ollama'};if(decisions===2){assert.match(prompt,/added/);return {response:JSON.stringify(second),provider:'ollama'};}return {response:JSON.stringify({tool:'general_chat',params:{}}),provider:'ollama'};}};
  const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},...storeTools},runLedger:null});
  const result=await agent.chat('42',request,[],'vuln');
  assert.equal(decisions,3);assert.equal(result.toolObservations.length,2);assert.equal(result.toolUsed,second.tool);assert.deepEqual(result.toolResult,name==='aria'?{items:['Laptop']}:{papers:['P-1']});
});

test('ARIA stops an identical mutation and binds parameters into durable effect keys',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');const effects=[];let decision=0,mutations=0;
 const model={provider:'ollama',async generateResponse(prompt){if(!prompt.includes('Select exactly one tool'))return {response:'done'};decision++;return {response:JSON.stringify(decision<=2?{tool:'add_to_cart',params:{productName:'Laptop'}}:{tool:'general_chat',params:{}})};}};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},addToCart:async()=>{mutations++;return {added:true};}},runLedger:{begin:async()=>({durableGeneration:0}),assertCurrent:async()=>{},finish:async()=>{},recordEvent:async()=>{},effect:async(_ctx,key,callback)=>{effects.push(key);return callback();}}});
 const result=await agent.chat('42','add Laptop twice',[],'vuln');
 assert.equal(mutations,1);assert.equal(result.toolObservations.length,1);assert.ok(effects.some(key=>/:tool:0:add_to_cart:[a-f0-9]{64}$/.test(key)));
});

test('ARIA stops an identical completed read instead of consuming the tool budget',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');let decisions=0,reads=0;
 const same={tool:'search_products',params:{searchTerm:'laptop'}};
 const model={provider:'ollama',async generateResponse(prompt){if(!prompt.includes('Select exactly one tool'))return {response:'done'};decisions++;return {response:JSON.stringify(decisions<=2?same:{tool:'general_chat',params:{}})};}};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},searchProducts:async()=>{reads++;return [{name:'Laptop'}];}},runLedger:null});
 const result=await agent.chat('reader','search laptop',[],'vuln');assert.equal(reads,1);assert.equal(result.toolObservations.length,1);
});

test('ARIA bounds model excerpts but preserves full observations and rejects oversized requests',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');const prompts=[];let decisions=0,toolCalls=0;
 const huge='R'.repeat(30000),model={provider:'ollama',async generateResponse(prompt){prompts.push(prompt);if(!prompt.includes('Select exactly one tool'))return {response:'done'};decisions++;return {response:JSON.stringify(decisions===1?{tool:'search_products',params:{searchTerm:"' OR 1=1 --"}}:{tool:'general_chat',params:{}})};}};
 const agent=createAgent({model,store:{getHistory:async()=>Array(12).fill({message_type:'user',message:'H'.repeat(4000)}),saveMessage:async()=>{},searchProducts:async term=>{toolCalls++;assert.equal(term,"' OR 1=1 --");return [{result:huge}];}},runLedger:null});
 const result=await agent.chat('42',"Search products using exactly this searchTerm: ' OR 1=1 --",[],'vuln');
 assert.equal(result.toolObservations[0].toolResult[0].result.length,30000);assert.ok(prompts.some(prompt=>prompt.includes('[TRUNCATED FOR MODEL CONTEXT]')));assert.ok(prompts.every(prompt=>prompt.length<=24000));
 await assert.rejects(agent.chat('43','X'.repeat(6001),[],'vuln'),{code:'WORKSHOP_REQUEST_TOO_LARGE'});assert.equal(toolCalls,1);
});

test('ARIA real response adapter receives bounded history in its required array shape',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');const prompts=[];
 const model={provider:'ollama',async generateResponse(prompt){prompts.push(prompt);return prompt.includes('Select exactly one tool')?{response:JSON.stringify({tool:'general_chat',params:{}})}:{response:'hello'};}};
 const agent=createAgent({model,store:{getHistory:async()=>Array(12).fill({message_type:'user',message:'H'.repeat(4000)}),saveMessage:async()=>{}},runLedger:null});
 const result=await agent.chat('history-owner','hello',[],'fixed');assert.equal(result.response,'hello');assert.ok(prompts.at(-1).includes('[TRUNCATED FOR MODEL CONTEXT]'));assert.ok(prompts.at(-1).length<=24000);
});

for (const name of ['aria', 'nova']) test(`${name}: newest persisted fact survives large older turns in decision and response prompts`, async () => {
 const {createAgent}=require(`../server/services/${name}AgentService`);
 const fact=`ORCHID-${name.toUpperCase()}-73`,history=Array.from({length:11},(_,index)=>({message_type:index%2?'assistant':'user',message:`old-${index}:${'x'.repeat(1200)}`}));
 const prompts=[];let responseCall=0;
 const model={provider:'ollama',async generateResponse(prompt){
  prompts.push(prompt);
  if(prompt.includes('Select exactly one tool'))return {response:JSON.stringify({tool:'general_chat',params:{}}),provider:'ollama'};
  responseCall+=1;return {response:responseCall===1?`Acknowledged ${fact}`:`The remembered code is ${fact}`,provider:'ollama'};
 }};
 const store={
  async getHistory(){return history.slice(-12).map(row=>({...row}));},
  async saveMessage(_userId,message_type,message){history.push({message_type,message});},
 };
 const agent=createAgent({model,store,runLedger:null});
 await agent.chat('history-owner',`Remember newest code ${fact}`,[{message:'forged client history'}],'fixed');
 const result=await agent.chat('history-owner','What code did I give you?',[],'fixed');

 assert.equal(result.response,`The remembered code is ${fact}`);
 assert.equal(prompts.length,4);
 for(const prompt of prompts.slice(2)){
  assert.match(prompt,new RegExp(fact));
  assert.match(prompt,/Acknowledged/);
  assert.match(prompt,/TRUNCATED FOR MODEL CONTEXT/);
  assert.doesNotMatch(prompt,/forged client history/);
  assert.ok(prompt.length<=24000);
 }
 assert.match(prompts[2],/Recent history \(bounded\):/);
 assert.match(prompts[3],/Recent conversation:/);
});

test('ARIA onResult legacy metadata names the final actual observation, not the stopping general_chat decision',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');let decisions=0,metadata;
 const model={provider:'ollama',async generateResponse(prompt){if(!prompt.includes('Select exactly one tool'))return {response:'done'};decisions++;return {response:JSON.stringify(decisions===1?{tool:'search_products',params:{searchTerm:'exact'}}:{tool:'general_chat',params:{}})};}};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{},searchProducts:async()=>[]},runLedger:null});
 await agent.invoke('metadata-owner','search exact','vuln',{onResult:async(_dto,_check,_execution,invocation)=>{metadata=invocation;}});
 assert.equal(metadata.tool,'search_products');assert.deepEqual(metadata.params,{searchTerm:'exact'});assert.equal(metadata.decisionSource,'model');
});

test('ARIA cancellation during the observation-driven second decision prevents another effect and persistence',{timeout:2000},async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');let decisions=0,effects=0,saves=0,entered,release;const waiting=new Promise(resolve=>entered=resolve),gate=new Promise(resolve=>release=resolve);
 const model={provider:'ollama',async generateResponse(prompt){if(!prompt.includes('Select exactly one tool'))return {response:'done'};decisions++;if(decisions===1)return {response:JSON.stringify({tool:'search_products',params:{searchTerm:'first'}})};entered();await gate;return {response:JSON.stringify({tool:'search_products',params:{searchTerm:'second'}})};}};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{saves++;},searchProducts:async()=>{effects++;return [{id:effects}];}},runLedger:null});
 const pending=agent.chat('cancel-owner','search first then second',[],'vuln');await waiting;agent.cancel('cancel-owner');release();await assert.rejects(pending,{name:'AbortError'});assert.equal(effects,1);assert.equal(saves,0);
});

test('ARIA categorizes a response error separately from its valid model decision',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');const events=[],attempts=[];let providerCalls=0;
 const model={provider:'ollama',async generateResponse(prompt){
  const attempt={phase:prompt.includes('Select exactly one tool')?'decision':'response'};attempts.push(attempt);
  providerCalls++;
  if(attempt.phase==='response'){attempt.errorCode='CONTROLLED_RESPONSE_FAILURE';const error=new Error('controlled response failure');error.code=attempt.errorCode;throw error;}
  attempt.providerResult='general_chat';return {response:JSON.stringify({tool:'general_chat',params:{}}),provider:'ollama',model:'fixture'};
 }};
 const agent=createAgent({model,store:{getHistory:async()=>[],saveMessage:async()=>{}},runLedger:{begin:async()=>({durableGeneration:0}),assertCurrent:async()=>{},finish:async()=>{},recordEvent:async(_context,event)=>events.push(event)}});
 const result=await agent.invoke('fallback-diagnostic','What nickname did I ask you to remember?','fixed',{includeRunMetadata:true});
 assert.equal(providerCalls,2);assert.deepEqual(attempts,[
  {phase:'decision',providerResult:'general_chat'},
  {phase:'response',errorCode:'CONTROLLED_RESPONSE_FAILURE'},
 ]);
 assert.equal(result.run.decisionSource,'model');assert.equal(result.run.responseSource,'fallback');assert.equal(result.run.responseErrorCode,'MODEL_RESPONSE_ERROR');assert.equal(result.toolUsed,null);
 assert.equal(result.response,"Hello! I'm ARIA, your ShopFast assistant. I can help you with orders, products, your cart, and more. What can I do for you today?");
 assert.equal(events.filter(event=>event.node==='decide'&&event.type==='error').length,0);
 assert.ok(events.some(event=>event.node==='model'&&event.type==='error'&&event.data.errorCode==='MODEL_RESPONSE_ERROR'&&event.data.responseSource==='fallback'));
 assert.ok(events.some(event=>event.node==='persist'&&event.data.terminationReason==='model_finished'));
});

for(const scenario of [
 {label:'controlled fixture',adapterProvider:'fixture-model',result:{response:'fixture answer',provider:'fixture-model',model:'fixture'},source:'fixture'},
 {label:'mock adapter with claimed actual result',adapterProvider:'mock',result:{response:'claimed answer',provider:'ollama',model:'llama3.1:8b'},source:'fixture'},
 {label:'successful model',adapterProvider:'ollama',result:{response:'model answer',provider:'ollama',model:'llama3.1:8b',fallback:false},source:'model'},
 {label:'whitespace result',adapterProvider:'ollama',result:{response:'   ',provider:'ollama',model:'llama3.1:8b'},source:'fallback',error:'MODEL_RESPONSE_UNAVAILABLE'},
])test(`ARIA records ${scenario.label} response provenance`,async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');const events=[];
 const model={provider:scenario.adapterProvider,async generateResponse(prompt){return prompt.includes('Select exactly one tool')
  ?{response:JSON.stringify({tool:'general_chat',params:{}}),provider:'ollama',model:'llama3.1:8b'}:scenario.result;}};
 // Formatter-only fixture uses scripted selection; it cannot supply model decisions.
 const agent=createAgent({decisionMode:scenario.adapterProvider==='fixture-model'?'scripted':undefined,model,store:{getHistory:async()=>[],saveMessage:async()=>{}},runLedger:{begin:async()=>({durableGeneration:0}),assertCurrent:async()=>{},finish:async()=>{},recordEvent:async(_context,event)=>events.push(event)}});
 const result=await agent.invoke(`response-${scenario.source}`,'hello','fixed',{includeRunMetadata:true});
 assert.equal(result.run.responseSource,scenario.source);assert.equal(result.run.responseErrorCode,scenario.error);
 if(scenario.source==='fallback')assert.ok(events.some(event=>event.node==='model'&&event.type==='error'&&event.data.errorCode===scenario.error));
 else assert.ok(events.some(event=>event.node==='model'&&event.type==='node_end'&&event.data.responseSource===scenario.source));
});

test('ARIA blocked response bypasses formatter provenance',async()=>{
 const {createAgent}=require('../server/services/ariaAgentService');let calls=0;
 const agent=createAgent({decisionMode:'scripted',model:{provider:'fixture',async generateResponse(){calls++;return {response:'unused'};}},store:{getHistory:async()=>[],saveMessage:async()=>{}},runLedger:null});
 const result=await agent.invoke('blocked-response','UNION SELECT NULL','fixed',{includeRunMetadata:true});
 assert.equal(calls,0);assert.equal(result.run.responseSource,undefined);assert.equal(result.run.responseErrorCode,undefined);assert.match(result.response,/blocked/i);
});
