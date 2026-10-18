'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {projectVisibleInventoryOutcome}=require('../server/services/secureshopInventoryProduction');
test('each projection rereads visibility, strips private receipts and hides all evaluation IDs when revoked',async()=>{
 const requestId=randomUUID(),scope={launchId:randomUUID(),platformOwnerId:1},evaluationId=randomUUID(),outcome={stopReason:'end_turn',text:'stock saved',taskMetadata:{inventory:{requestId,receipts:[],grading:{completed:false,judgment:{evaluationId,verdict:'unavailable',canRetry:true,packet:'private',provider:'private'}}}}};let enabled=true,reads=0;const check=async selected=>{assert.deepEqual(selected,scope);reads++;return enabled;};
 const visible=await projectVisibleInventoryOutcome(outcome,requestId,scope,check);assert.deepEqual(visible.grading.judgment,{evaluationId,verdict:'unavailable',canRetry:true});assert.ok(!JSON.stringify(visible).includes('private'));enabled=false;const hidden=await projectVisibleInventoryOutcome(outcome,requestId,scope,check);assert.deepEqual(hidden.grading,{status:'disabled',completed:false});assert.ok(!JSON.stringify(hidden).includes(evaluationId));assert.equal(reads,2);
});
test('no-Judge result never invents evaluation IDs or credit',async()=>{
 const requestId=randomUUID(),scope={launchId:randomUUID()},outcome={stopReason:'end_turn',text:'read',taskMetadata:{inventory:{requestId,receipts:[],grading:{status:'ineligible'}}}};
 assert.deepEqual((await projectVisibleInventoryOutcome(outcome,requestId,scope,async()=>true)).grading,{status:'ineligible',completed:false});await assert.rejects(projectVisibleInventoryOutcome(outcome,randomUUID(),scope,async()=>true));
});
test('inconclusive keeps its receipt without retry and only a canonical pass can project completion',()=>{
 const {inventoryGradingProjection:project}=require('../server/services/secureshopInventoryGradingProjection'),evaluationId=randomUUID();
 assert.deepEqual(project({completed:true,judgment:{evaluationId,verdict:'inconclusive',canRetry:true}}),{status:'evaluated',completed:false,judgment:{evaluationId,verdict:'inconclusive',canRetry:false}});
 assert.equal(project({completed:true,judgment:{evaluationId,verdict:'fail'}}).completed,false);
});
test('inventory readback preserves only the original persisted turn mode',async()=>{
 const requestId=randomUUID(),scope={launchId:randomUUID()},modeCapability={version:1,featureId:'inventory',policyVersion:'merchant-product-ownership-v1',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'inventory'}};
 const outcome={stopReason:'end_turn',text:'saved',replayed:true,modeCapability,taskMetadata:{inventory:{requestId,receipts:[]}}};
 const result=await projectVisibleInventoryOutcome(outcome,requestId,scope,async()=>false);
 assert.deepEqual(result.modeCapability,modeCapability);assert.equal(result.replayed,true);
 delete outcome.modeCapability;
 assert.equal(Object.hasOwn(await projectVisibleInventoryOutcome(outcome,requestId,scope,async()=>false),'modeCapability'),false);
});
