'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {readTurnModeProjection}=require('../server/database/postgres/secureshopTurnModeProjection');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
test('recovery mode comes from the exact original completed owned request, never current selection',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},persona={id:3,role:'merchant'},sessionId=randomUUID(),requestId=randomUUID(),message='Original teaching question';
 const request=createTurnRequest({sessionId,requestId,binding:createConversationBinding(scope,persona),message});
 const modeCapability={version:1,featureId:'pricing',policyVersion:'older-fixed-policy-v1',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'pricing'}};
 const row={session_id:sessionId,request_hash:request.hash,request_version:request.version,status:'completed',result_json:{stopReason:'end_turn',receipt:'exact',modeCapability}};
 let rows=[row];const client={async query(sql,args){assert.match(sql,/s.original_platform_session_id=\$7/);assert.deepEqual(args,[requestId,'secureshop_pricing_strategy',scope.launchId,scope.scenarioId,1,7,8,3,'merchant']);return{rows};}};
 const options={scope,persona,requestId,message,purpose:'secureshop_pricing_strategy',featureId:'pricing',verifyResult:r=>r.receipt==='exact'};
 assert.deepEqual(await readTurnModeProjection(client,options),modeCapability);
 await assert.rejects(readTurnModeProjection(client,{...options,message:'replacement'}),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 await assert.rejects(readTurnModeProjection(client,{...options,verifyResult:()=>false}),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 row.result_json.modeCapability={...modeCapability,owner:7};await assert.rejects(readTurnModeProjection(client,options),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 delete row.result_json.modeCapability;assert.equal(await readTurnModeProjection(client,options),undefined);
 rows=[];assert.equal(await readTurnModeProjection(client,options),undefined);
 rows=[row,row];await assert.rejects(readTurnModeProjection(client,options),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
});
test('only explicit Pricing denial projection accepts an exact tool_denied terminal',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},persona={id:3,role:'merchant'},sessionId=randomUUID(),requestId=randomUUID(),message='Compare this product';
 const request=createTurnRequest({sessionId,requestId,binding:createConversationBinding(scope,persona),message});
 const modeCapability={version:1,featureId:'pricing',policyVersion:'fixed-policy-v1',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'pricing'}};
 const row={session_id:sessionId,request_hash:request.hash,request_version:request.version,status:'completed',result_json:{stopReason:'tool_denied',receipt:'exact',modeCapability}};
 const client={async query(){return{rows:[row]};}};
 const options={scope,persona,requestId,message,purpose:'secureshop_pricing_strategy',featureId:'pricing',verifyResult:r=>r.receipt==='exact'};
 const denied={...options,expectedStopReason:'tool_denied'};
 await assert.rejects(readTurnModeProjection(client,options),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 assert.deepEqual(await readTurnModeProjection(client,denied),modeCapability);
 for(const override of [{expectedStopReason:'cancelled'},{expectedStopReason:['end_turn','tool_denied']},{featureId:'analytics'},{purpose:'secureshop_analytics'},{message:'changed'},{verifyResult:()=>false}]){
  await assert.rejects(readTurnModeProjection(client,{...denied,...override}),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 }
 for(const stopReason of ['end_turn','cancelled',undefined]){
  row.result_json.stopReason=stopReason;
  await assert.rejects(readTurnModeProjection(client,denied),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 }
 row.result_json.stopReason='tool_denied';row.status='started';
 assert.equal(await readTurnModeProjection(client,denied),undefined);
});
