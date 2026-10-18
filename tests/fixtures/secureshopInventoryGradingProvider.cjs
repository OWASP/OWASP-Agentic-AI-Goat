'use strict';
// Private frozen process: controlled decisions and explicit qualifier override.
// No real model, transplanted packet, direct completion seed or shared gate edit.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(process.env.INVENTORY_GRADING_APP,'1');
const file=path.join(process.env.LISTINGS_EVIDENCE_ROOT,'controlled-inventory-provider.json'),counts={actualModelCalls:0,judgeCalls:0,decisions:0,finals:0,metadataOverride:true,qualifierOverride:true};const save=()=>fs.writeFileSync(file,JSON.stringify(counts),{mode:0o600});save();
const qualification=require('../../server/services/secureshopModelQualification'),priorQualifier=qualification.createSecureShopModelQualifier;
qualification.createSecureShopModelQualifier=provider=>provider?.config?.provider==='controlled-inventory-grading'?identity=>identity?.provider==='controlled-inventory-grading'&&identity.model==='grading-fixture'&&identity.mocked===false&&identity.fallback!==true:priorQualifier(provider);
const production=require('../../server/services/secureshopInventoryProduction'),original=production.createInventoryProduction;production.PRODUCTION_QUALIFIED=true;
production.createInventoryProduction=options=>{
 let foreign;
 const inventory=require('../../server/services/secureshopBoundInventory'),createInventory=inventory.createBoundInventory;
 // Select from the actual owned stock read, never a hardcoded or foreign target.
 inventory.createBoundInventory=input=>{const value=createInventory(input);return{...value,async execute(...args){const receipt=await value.execute(...args);if(receipt.binding.action==='stock_levels'){foreign=receipt.result.items.find(row=>row.retailerId!==receipt.binding.persona.id&&row.quantity!==4);assert.ok(foreign);}return receipt;}};};
 const provider={config:{provider:'controlled-inventory-grading',model:'grading-fixture',mocked:false},async chat(){const step=counts.decisions++;assert.ok(counts.decisions<=2);save();if(step)assert.ok(foreign);return{provider:'controlled-inventory-grading',model:'grading-fixture',mocked:false,fallback:false,stop_reason:'tool_use',tool_uses:[{id:randomUUID(),name:step?'inventory.set_stock':'inventory.stock_levels',args:step?{productId:foreign.productId,quantity:4}:{}}]};},async finalResponse(){counts.finals++;assert.equal(counts.finals,1);save();return{provider:'controlled-inventory-grading',model:'grading-fixture',mocked:false,fallback:false,stop_reason:'end_turn',responseMode:'structured_final',text:'Controlled inventory stock operation saved.'};}};
 const judge=async input=>{counts.judgeCalls++;assert.ok(counts.judgeCalls<=2);save();if(counts.judgeCalls===1)throw Error('Controlled transient Judge outage');const {prepareJudgeInput,JUDGE_VERSION}=require('../../server/agent-runtime/objectiveJudge'),p=prepareJudgeInput(input);assert.equal(p.rubric.objectiveId,'ss_inventory_cross_merchant_stock');return{family:p.rubric.family,scenario:p.rubric.scenario,objectiveId:p.rubric.objectiveId,rubricVersion:p.rubric.version,mode:p.rubric.mode,evidenceDigest:p.evidenceDigest,judgeVersion:JUDGE_VERSION,runId:input.execution.runId,verdict:'pass',criteria:p.rubric.criteria.map(c=>({id:c.id,satisfied:true,evidenceRefs:['inventory_stock']})),explanation:'Explicit controlled inventory canonical retry fixture',provider:'controlled-inventory-grading',model:'grading-fixture'};};
 return original({...options,provider,assessmentDependencies:{...options.assessmentDependencies,judge}});
};
