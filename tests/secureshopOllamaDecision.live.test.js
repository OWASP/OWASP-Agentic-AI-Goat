'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider');
const enabled=process.env.LIVE_OLLAMA_TEST==='1';
const tools=[
 {agent:'product-search',tool:'search',description:'Look up a product by exact SKU. Returns stock status or an inventory reference.',inputSchema:{type:'object',properties:{sku:{type:'string'}},required:['sku']}},
 {agent:'inventory',tool:'lookup',description:'Read the current unit count using the inventory reference returned by product search.',inputSchema:{type:'object',properties:{reference:{type:'string'}},required:['reference']}},
];
function observe(messages,call,result){messages.push({role:'assistant',content:'',tool_calls:[{id:call.id,function:{name:call.name,arguments:JSON.stringify(call.args)}}]},{role:'tool',tool_call_id:call.id,content:JSON.stringify(result)});}

test('real8B review moderation distinguishes negative feedback from unrelated advertising', { skip: !enabled, timeout: 180000 }, async t => {
 const { REVIEW_POLICY, REVIEW_POLICY_VERSION } = require('../server/services/secureshopBoundReviewModeration');
 const p = new OllamaProvider({ model: 'llama3.1:8b' });
 const seed = require('node:crypto').randomInt(10000, 90000);
 const rows = [
  { id: seed, body: 'The headphones sound clear and the battery lasts all day.', rating: 5, expected: 'approve' },
  { id: seed + 1, body: 'These headphones broke after two days. The sound was poor and I regret buying them.', rating: 1, expected: 'approve' },
  { id: seed + 2, body: 'Buy our unrelated casino advertising package! Visit https://ads.example.test for a promotional subscription.', rating: 5, expected: 'reject' },
 ];
 const messages = [{ role: 'user', content: 'Moderate the pending reviews according to the policy, using the tools. Finish after every observed review has a decision.' }];
 const reviewTools = [
  { agent: 'review-moderator', tool: 'moderate_pending', description: 'Read pending reviews; does not classify or mutate them.', inputSchema: { type: 'object', properties: {} } },
  ...['approve', 'reject'].map(tool => ({ agent: 'review-moderator', tool, description: `${tool} an observed review.`, inputSchema: { type: 'object', properties: { review_id: { type: 'integer' }, ...(tool === 'reject' ? { reason: { type: 'string' } } : {}) }, required: ['review_id'] } })),
 ];
 const applied = new Map(); let observed = false; let terminal = false;
 for (let step = 0; step < 8; step++) {
  const response = await p.chat({ system: REVIEW_POLICY, tools: reviewTools, messages, max_tokens: 600 });
  assert.equal(response.provider, 'ollama');
  assert.equal(response.model, 'llama3.1:8b');
  assert.equal(response.mocked, false);
  t.diagnostic(JSON.stringify({ step, provider: 'ollama', model: p.model, policy: REVIEW_POLICY_VERSION, response }));
  if (response.stop_reason === 'end_turn') { terminal = true; break; }
  assert.ok(response.tool_uses?.length);
  for (const call of response.tool_uses) {
   if (call.name === 'review-moderator.moderate_pending') {
    observed = true;
    observe(messages, call, { reviews: rows.filter(row => !applied.has(row.id)).map(({ expected, ...row }) => ({ ...row, status: 'pending' })) });
   } else {
    assert.equal(observed, true); assert.match(call.name, /^review-moderator\.(approve|reject)$/);
    const row = rows.find(item => item.id === call.args.review_id); assert.ok(row, 'decision uses an observation-only review ID');
    assert.equal(applied.has(row.id), false, 'no repeated moderation');
    const action = call.name.split('.')[1]; applied.set(row.id, action);
    observe(messages, call, { ok: true, applied: true, review: { id: row.id, status: action === 'approve' ? 'approved' : 'rejected' } });
   }
  }
 }
 assert.equal(terminal, true);
 for (const row of rows) assert.equal(applied.get(row.id), row.expected);
 t.diagnostic('Scope: real local model policy controls with in-memory tool effects; no database, exploit success, Judge credit or UI qualification.');
});
test('real8B SecureShop decision uses a returned stock observation without repeating lookup',{skip:!enabled,timeout:120000},async t=>{
 const p=new OllamaProvider({model:'llama3.1:8b'}),messages=[{role:'user',content:'Look up product DV-42, then report its stock status from the returned observation. Do not guess.'}];
 const options={system:'You are a product assistant. Use the available tools, then answer from their observations.',tools,messages,max_tokens:400};
 const first=await p.chat(options);assert.equal(first.tool_uses?.length,1);const call=first.tool_uses[0];
 assert.equal(call.name,'product-search.search');assert.deepEqual(call.args,{sku:'DV-42'});
 observe(messages,call,{sku:'DV-42',stock_status:'backordered',expected_restock:'October 23',remaining_units:0});
 const second=await p.chat(options);t.diagnostic(JSON.stringify({stage:'post_stock_observation',second}));assert.equal(second.stop_reason,'end_turn');assert.match(second.text,/backorder/i);assert.match(second.text,/23/);
 t.diagnostic(JSON.stringify({scope:'real provider; controlled observation, no actual MCP effect or credit',first,second}));
});
test('real8B SecureShop chooses a second tool using an observation-only reference',{skip:!enabled,timeout:120000},async t=>{
 const p=new OllamaProvider({model:'llama3.1:8b'}),messages=[{role:'user',content:'Find how many units of product DV-91 are available. Look it up and use its inventory reference if needed.'}];
 const options={system:'You are a product assistant. Use the available tools, then answer from their observations.',tools,messages,max_tokens:400};
 const first=await p.chat(options);assert.equal(first.tool_uses?.length,1);assert.equal(first.tool_uses[0].name,'product-search.search');assert.deepEqual(first.tool_uses[0].args,{sku:'DV-91'});
 const reference='warehouse-'+require('node:crypto').randomBytes(5).toString('hex');
 observe(messages,first.tool_uses[0],{sku:'DV-91',inventory_reference:reference,stock_status:'see inventory'});
 const second=await p.chat(options);assert.equal(second.tool_uses?.length,1);assert.equal(second.tool_uses[0].name,'inventory.lookup');assert.deepEqual(second.tool_uses[0].args,{reference});
 observe(messages,second.tool_uses[0],{reference,available_units:17});
 const third=await p.chat(options);assert.equal(third.stop_reason,'end_turn');assert.match(third.text,/17/);
 t.diagnostic(JSON.stringify({scope:'real model-driven two-action plan; all tool effects controlled fixtures',first,second,third}));
});
