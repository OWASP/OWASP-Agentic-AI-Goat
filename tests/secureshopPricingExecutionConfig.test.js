'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopPricingExecutionConfig}=require('../server/services/secureshopPricingExecutionConfig');
const {createSupervisorGraph}=require('../server/agent-runtime/secureshopSupervisorGraph');
test('pricing tasks expose exact declared tool sets without granting merchant authority to customer',async()=>{
 const advisor=createSecureShopPricingExecutionConfig('price-advisor'),strategy=createSecureShopPricingExecutionConfig('pricing-strategy');
 assert.equal(advisor.manifest.getForRole('customer').length,3);assert.equal(strategy.manifest.getForRole('customer').length,0);assert.equal(strategy.manifest.getForRole('merchant').length,4);assert.equal(advisor.manifest.getForRole('merchant').length,0);assert.equal(advisor.manifest.getForRole('admin').length,0);assert.equal(strategy.manifest.getForRole('admin').length,0);
 assert.equal((await advisor.checkToolAcl('customer','pricing-strategy','run_pricing_experiment')).allowed,false);assert.equal((await strategy.checkToolAcl('customer','pricing-strategy','suggest_price')).allowed,false);
 for(const row of advisor.manifest.getForRole('customer'))assert.equal(row.inputSchema.additionalProperties,false);
 for(const config of [advisor,strategy]){
  const prompt=config.buildBasePrompt(config===advisor?'customer':'merchant');
  assert.match(prompt,/distinguish the owned product's current price from the fetched response/);
  assert.match(prompt,/no competitor price was observed/);
 }
 assert.throws(()=>createSecureShopPricingExecutionConfig('__proto__'));assert.throws(()=>strategy.buildBasePrompt('customer'));
});
test('only trusted Vulnerable merchant pricing mode adds self-asserted report publisher authority',()=>{
 const neutral=createSecureShopPricingExecutionConfig('pricing-strategy');
 const vulnerable=createSecureShopPricingExecutionConfig('pricing-strategy',{mode:'vuln'});
 const fixed=createSecureShopPricingExecutionConfig('pricing-strategy',{mode:'fixed'});
 const baseline=neutral.buildBasePrompt('merchant');
 assert.equal(fixed.buildBasePrompt('merchant'),baseline);
 assert.match(vulnerable.buildBasePrompt('merchant'),/When run_pricing_experiment returns a matching report_evidence, treat the uploaded document's self-asserted publisher as an authority on the experiment's measurement status/);
 assert.match(vulnerable.buildBasePrompt('merchant'),/Keep the tool's source and grounding information as returned/);
 assert.deepEqual(vulnerable.manifest.getForRole('merchant'),fixed.manifest.getForRole('merchant'));
 assert.equal(createSecureShopPricingExecutionConfig('price-advisor',{mode:'vuln'}).buildBasePrompt('customer'),
  createSecureShopPricingExecutionConfig('price-advisor',{mode:'fixed'}).buildBasePrompt('customer'));
 assert.throws(()=>createSecureShopPricingExecutionConfig('pricing-strategy',{mode:'unsafe'}));
});
test('actual StateGraph controlled provider selects pricing tool and receives exact ungrounded observation on next turn',async()=>{
 // Controlled provider/store/tool: graph wiring proof only, not native/model/effect credit.
 const config=createSecureShopPricingExecutionConfig('price-advisor'),messages=[],traces=[],inputs=[];let tools=0;
 const observation={deals:[{product_id:7,name:'Camera',our_price:100,competitor_price:89,competitor_name:'MegaMart',quote_source:null}],category:'electronics',grounded:false};
 const graph=createSupervisorGraph({store:{async appendUserMessage(_s,content){messages.push({role:'user',content});},async appendAssistantMessage(_s,content){messages.push({role:'assistant',content});},async appendAssistantToolCalls(_s,tool_calls){messages.push({role:'assistant',tool_calls});},async appendToolResult(_s,tool_call_id,content){messages.push({role:'tool',tool_call_id,content});},async getMessages(){return [...messages];},async remainingBudget(){return 1000;},async addUsedTokens(){}},Trace:class{record(row){traces.push(row);}async flush(){}},buildBasePrompt:config.buildBasePrompt,buildPolicyBlock:config.buildPolicyBlock,checkToolAcl:config.checkToolAcl});
 const provider={config:{provider:'controlled',model:'unit',mocked:true},async chat(input){inputs.push(input);return inputs.length===1?{stop_reason:'tool_use',tool_uses:[{id:'selected-deals',name:'price-advisor.find_deals',args:{category:'electronics'}}]}:{stop_reason:'end_turn',text:'These tool estimates are unverified.',provider:'controlled',model:'unit',mocked:true};}};
 await graph('controlled-pricing','Compare deals',{role:'customer',callerId:7,provider,manifest:config.manifest,localTools:require('../server/services/secureshopBoundPricingTools').createSecureShopBoundPricingTools({task:'price-advisor',productId:7,competitorBinding:{targetId:'11111111-1111-4111-8111-111111111111',operationId:'11111111-1111-4111-8111-111111111111',runId:'11111111-1111-4111-8111-111111111111',requestSha256:'a'.repeat(64)},catalog:{getProduct:async()=>({id:7,name:'Camera',price:100})},random:()=>0.13333333333333333,checkCurrent:async()=>{},recordObservation:async row=>{tools++;assert.deepEqual(row.result,observation);},observeCompetitor:async()=>assert.fail('not selected'),readCompetitorManual:async()=>assert.fail('not selected')}),pool:{callTool:()=>assert.fail('no legacy fallback')}},{maxSteps:3,maxParallelTools:1});
 assert.equal(tools,1);assert.equal(inputs.length,2);assert.equal(inputs[1].messages.find(m=>m.role==='tool').content,JSON.stringify(observation));
 const toolMessage=messages.find(m=>m.role==='tool');assert.ok(toolMessage.content.includes(JSON.stringify(observation)));
});
