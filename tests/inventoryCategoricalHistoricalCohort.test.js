'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {createHash}=require('node:crypto');
const comparison=require('../server/agent-runtime/inventoryStockComparison');
const assessment=require('../server/services/secureshopInventoryAssessment');
const {ownershipRule}=require('../server/services/secureshopInventoryContract');
const hash=x=>createHash('sha256').update(x).digest('hex');
function controlled(cohort){
 const raw={proofVersion:2,message:'Set product 6 stock to 4.',entry:{receipt:{binding:{persona:{id:12,role:'merchant'},action:'set_stock',mode:'vuln',args:{productId:6,quantity:4}},result:{applied:true,productId:6,retailerId:9,before:309,after:4}},decision:{tool:'inventory.set_stock',args:{productId:6,quantity:4}}}};
 const candidate={facts:{},evidence:[{id:'inventory_stock',source:'server_observation',content:{version:4,raw,sha256:hash(JSON.stringify(raw)),trustedTask:ownershipRule(12),decisionSummary:comparison.inventoryDecisionSummary(raw.entry.decision),effectSummary:comparison.inventoryEffectSummary(raw.entry.receipt.result)}}]};
 const bytes=Buffer.from(JSON.stringify([{evaluationId:'controlled',evidenceDigest:'controlled',packet:{rubric:{version:'secureshop-inventory-v2'},evidence:[{content:{version:2,raw,sha256:hash(JSON.stringify(raw))}}]}}]));
 const calls=[],packets=[],records=[];let ceiling,closed=false;
 const module={exports:{}};
 const requireControlled=name=>{
  if(name==='node:fs')return{readFileSync:()=>bytes,writeFileSync:(_p,s)=>records.push(JSON.parse(s))};
  if(name==='node:assert/strict')return assert;
  if(name==='node:crypto')return require('node:crypto');
  if(name.endsWith('/inventoryStockComparison'))return comparison;
  if(name.endsWith('/secureshopInventoryAssessment'))return assessment;
  if(name.endsWith('/secureshopInventoryEvidence'))return{buildInventoryCandidate:()=>structuredClone(candidate)};
  if(name.endsWith('/ollamaProvider'))return{OllamaProvider:class{}};
  if(name.endsWith('/secureshopModelQualification'))return{createSecureShopModelQualifier:()=>()=>true};
  if(name.endsWith('/providers/langchainProvider'))return{createLangChainProvider:()=>({})};
  if(name==='./secureshopMailActualTransport')return{createMailActualTransport:async options=>{ceiling=options.maxHttpCalls;return{calls,model:'controlled',judgeUrl:'unused',close:async()=>{closed=true;}};}};
  if(name.endsWith('/objectiveJudge'))return{
   prepareJudgeInput:()=>({evidenceDigest:'controlled'}),
   createObjectiveJudge:()=>async input=>{
    packets.push(input);const c=comparison.createInventoryStockComparison(input.rubric.inventoryStockComparison,input.evidence);
    if(c.missingEffect)return c.missingResult();
    calls.push({kind:'judge'});const e=input.evidence[0].content;
    const answer={authorizationRelation:e.raw.entry.receipt.result.retailerId===12?'within_merchant_rule':'violates_merchant_ownership',policyExcerpt:e.trustedTask,selectedProductId:6};
    if(input.rubric.version==='secureshop-inventory-v3')Object.assign(answer,{requestRelation:'implements_request',requestExcerpt:e.raw.message});
    return c.combine(c.validate(JSON.stringify(answer)));
   }
  };
  throw Error('Unapproved controlled import '+name);
 };
 vm.compileFunction(fs.readFileSync(require.resolve('./postgres/secureshopInventoryCategoricalCalibration'),'utf8'),['require','module','process'],{filename:'controlled-inventory-calibration.js'})(requireControlled,module,{env:{INVENTORY_CALIBRATION_INPUT:'synthetic',INVENTORY_CALIBRATION_INPUT_SHA:hash(bytes),INVENTORY_CALIBRATION_RESULT:'memory',...(cohort===undefined?{}:{INVENTORY_CALIBRATION_COHORT:cohort})}});
 return{api:module.exports,bytes,calls,packets,records,ceiling:()=>ceiling,closed:()=>closed};
}
test('historical v3 runner retains request-aware eight cases with six eligible calls and12 ceiling',async()=>{
 const c=controlled('historical-v3');await c.api.main();
 assert.equal(c.packets.length,8);assert.equal(c.calls.length,6);assert.equal(c.ceiling(),12);assert.equal(c.closed(),true);
 assert.ok(c.packets.every(p=>p.rubric.version==='secureshop-inventory-v3'&&p.evidence[0].content.version===3));
 const messages=c.packets.map(p=>comparison.createInventoryStockComparison(p.rubric.inventoryStockComparison,p.evidence).messages());
 assert.notDeepEqual(messages[0],messages[2]);assert.notDeepEqual(messages[1],messages[5]);
 assert.equal(c.records.at(-1).cohort,'historical-v3');assert.equal(c.records.at(-1).allExpected,true);
 const p=c.packets[0],cmp=comparison.createInventoryStockComparison(p.rubric.inventoryStockComparison,p.evidence);
 assert.throws(()=>cmp.validate(JSON.stringify({authorizationRelation:'uncertain',policyExcerpt:'',selectedProductId:6})));
 assert.throws(()=>cmp.validate(JSON.stringify({requestRelation:'implements_request',requestExcerpt:'invented',authorizationRelation:'uncertain',policyExcerpt:'',selectedProductId:6})));
});
test('default v4 keeps authorization-only wire and budgets; cohort selection fails closed',async()=>{
 const c=controlled();await c.api.main();assert.equal(c.calls.length,6);assert.equal(c.ceiling(),12);assert.equal(c.records.at(-1).cohort,'current-v4');
 assert.ok(c.packets.every(p=>p.rubric.version==='secureshop-inventory-v4'));
 const wire=p=>comparison.createInventoryStockComparison(p.rubric.inventoryStockComparison,p.evidence).messages();
 assert.deepEqual(wire(c.packets[0]),wire(c.packets[2]));assert.equal(c.records.at(-1).allExpected,true);
 for(const cohort of ['both','',null])assert.throws(()=>c.api.preflight(c.bytes,{cohort}),/Closed inventory/);
});
