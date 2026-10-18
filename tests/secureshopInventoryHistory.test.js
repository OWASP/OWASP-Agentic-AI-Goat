'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createInventoryHistoryRepository}=require('../server/database/postgres/secureshopInventoryHistoryRepository');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {request}=require('../server/services/secureshopInventoryContract');
const {hash}=require('../server/services/secureshopCouponContract');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const sorted=value=>Array.isArray(value)?value.map(sorted):value&&typeof value==='object'
 ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,sorted(value[key])])):value;

function fixture(){
 const birth={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:71,platformSessionId:72};
 const scope={launchId:randomUUID(),scenarioId:birth.scenarioId,generation:1,platformOwnerId:71,platformSessionId:73};
 const target=createSceneBinding({...birth,targetId:randomUUID()},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:scope,withLease:work=>work()});
 const persona={id:1000000012,role:'merchant'};
 const personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const sessionId=randomUUID(),requestId=randomUUID(),operationId=randomUUID(),runId=randomUUID(),message='Set stock to 9';
 const binding=request({target:{...birth,targetId:target.targetId},persona,personaSession,mode:'vuln',operationId,action:'set_stock',args:{productId:2,quantity:9},execution:{runId,requestId,callId:'call-1'}});
 const receipt={version:1,operationId,requestSha256:hash(binding),binding,result:{applied:true,productId:2,before:3,after:9}};
 const outcome={stopReason:'end_turn',text:'Stock updated',taskMetadata:{inventory:{version:1,targetId:target.targetId,requestId,personaSession,mode:'vuln',message,receipts:[{receipt}],effects:[{status:'completed'}]}}};
 const turn={session_id:sessionId,request_id:requestId,request_version:1,request_hash:createTurnRequest({sessionId,requestId,binding:createConversationBinding(birth,persona),message:JSON.stringify({version:1,message,mode:'vuln',personaSession})}).hash,result_json:outcome,
  platform_launch_id:birth.launchId,platform_scenario_id:birth.scenarioId,platform_launch_generation:1,original_platform_owner_id:71,original_platform_session_id:72,user_id:persona.id,role:'merchant'};
 const operation={operation_id:operationId,target_id:target.targetId,shop_user_id:persona.id,persona_session_id:personaSession.sessionId,authority_version:'1',mode:'vuln',action:'set_stock',run_id:runId,request_id:requestId,call_id:'call-1',state:'completed',request_sha256:hash(binding),request_json:JSON.stringify(binding),result_json:JSON.stringify(receipt)};
 operation.result_sha256=hash(operation.result_json);
 const state={turn,operation,current:true,grant:true,targetActive:true,queries:[]};
 const agentsPool={async query(sql,args){state.queries.push({store:'agents',sql,args});if(sql.includes('FROM secureshop_agents.bound_persona_sessions'))return{rowCount:1,rows:[{one:1}]};
  if(sql.includes('SELECT tr.*'))return{rows:state.turn?[state.turn]:[]};
  if(sql.includes('SELECT tr.request_id'))return{rows:state.turn?[{request_id:requestId,finished_at:new Date('2026-01-01'),mode:'vuln'}]:[]};
  throw Error('Unexpected agents query');}};
 const client={async query(sql,args){state.queries.push({store:'review',sql,args});if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:state.grant}]};if(sql.startsWith('SELECT 1 FROM secureshop_review.product_targets'))return{rowCount:state.targetActive?1:0,rows:state.targetActive?[{one:1}]:[]};
  if(sql.includes('FROM secureshop_review.owned_inventory_operations'))return{rows:state.operation?[state.operation]:[]};return{rows:[],rowCount:0};},release(){}};
 const reviewPool={connect:async()=>client};
 const repo=createInventoryHistoryRepository({agentsPool,reviewPool,checkCurrent:async()=>{if(!state.current)throw Object.assign(Error('stale'),{code:'STALE_LAUNCH'});}});
 return{repo,state,scope,target,persona,requestId,receipt};
}
test('current merchant can read retained completed turn through its selected target without a model or old bearer',async()=>{
 const f=fixture();f.state.turn.result_json=sorted(f.state.turn.result_json); // PostgreSQL jsonb object ordering is not the original request encoding.
 const result=await f.repo.read({scope:f.scope,target:f.target,persona:f.persona,requestId:f.requestId});
 assert.deepEqual(result,{ok:true,status:'completed',historical:true,requestId:f.requestId,mode:'vuln',answer:'Stock updated',operations:[{action:'set_stock',result:f.receipt.result}]});
 assert.equal(Object.hasOwn(result,'grading'),false);
 const history=await f.repo.list({scope:f.scope,target:f.target,persona:f.persona});
 assert.equal(history.operations.length,1);assert.equal(history.operations[0].requestId,f.requestId);
 assert.equal(JSON.stringify(history).includes('Set stock to 9'),false);
 assert.equal(f.state.queries.some(q=>/INSERT|UPDATE|DELETE/i.test(q.sql)),false);
});
test('history denies foreign actor, redacted receipt, changed original request and missing effect',async()=>{
 const f=fixture(),input={scope:f.scope,target:f.target,persona:f.persona,requestId:f.requestId};
 await assert.rejects(f.repo.read({...input,persona:{id:f.persona.id+1,role:'merchant'}}),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 f.state.operation.state='redacted';await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 f.state.operation.state='completed';f.state.turn.request_hash='0'.repeat(64);await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
});
test('history denies a missing review receipt, altered result digest, retired target and lost scene grant',async()=>{
 const f=fixture(),input={scope:f.scope,target:f.target,persona:f.persona,requestId:f.requestId};
 const receipt=f.state.operation;f.state.operation=null;await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 f.state.operation=receipt;receipt.result_sha256='0'.repeat(64);await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 receipt.result_sha256=hash(receipt.result_json);f.state.targetActive=false;await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 f.state.targetActive=true;f.state.grant=false;await assert.rejects(f.repo.read(input),{code:'SHOP_SCENE_STALE'});
});
test('history denies stale current launch and a different selected target',async()=>{
 const f=fixture(),input={scope:f.scope,target:f.target,persona:f.persona,requestId:f.requestId};
 f.state.current=false;await assert.rejects(f.repo.read(input),{code:'STALE_LAUNCH'});
 f.state.current=true;const other=createSceneBinding({...f.target,targetId:randomUUID()},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:f.scope,withLease:work=>work()});
 await assert.rejects(f.repo.read({...input,target:other}),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 await assert.rejects(f.repo.read({...input,target:{...f.target}}),{code:'SHOP_SCENE_STALE'});
});
test('historical access-bound requests retain exact permission and cannot present a write receipt as read only',async()=>{
 const f=fixture(),turn=f.state.turn,meta=turn.result_json.taskMetadata.inventory;meta.version=2;meta.access='write';
 const origin={launchId:turn.platform_launch_id,scenarioId:turn.platform_scenario_id,generation:turn.platform_launch_generation,platformOwnerId:turn.original_platform_owner_id,platformSessionId:turn.original_platform_session_id};
 turn.request_hash=createTurnRequest({sessionId:turn.session_id,requestId:f.requestId,binding:createConversationBinding(origin,f.persona),message:JSON.stringify({version:2,message:meta.message,access:meta.access,mode:meta.mode,personaSession:meta.personaSession})}).hash;
 const input={scope:f.scope,target:f.target,persona:f.persona,requestId:f.requestId};
 assert.equal((await f.repo.read(input)).operations[0].result.after,9);
 meta.access='read';await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 meta.version=1;delete meta.access;await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
});

function v3HistoryHash(f){const turn=f.state.turn,meta=turn.result_json.taskMetadata.inventory;
 const birth={launchId:turn.platform_launch_id,scenarioId:turn.platform_scenario_id,generation:turn.platform_launch_generation,platformOwnerId:turn.original_platform_owner_id,platformSessionId:turn.original_platform_session_id};
 return createTurnRequest({sessionId:turn.session_id,requestId:f.requestId,binding:createConversationBinding(birth,f.persona),message:JSON.stringify({version:3,message:meta.message,access:meta.access,stockChange:{productId:meta.stockChange.productId,quantity:meta.stockChange.quantity},mode:meta.mode,personaSession:meta.personaSession})}).hash;
}
test('v3 historical intent survives jsonb reordering while wrong product/quantity remains denied',async()=>{
 const f=fixture(),meta=f.state.turn.result_json.taskMetadata.inventory;Object.assign(meta,{version:3,access:'write',stockChange:{productId:2,quantity:9}});
 f.state.turn.request_hash=v3HistoryHash(f);f.state.turn.result_json=sorted(f.state.turn.result_json);
 const input={scope:f.scope,target:f.target,persona:f.persona,requestId:f.requestId};assert.equal((await f.repo.read(input)).operations[0].result.after,9);
 for(const stockChange of [{productId:3,quantity:9},{productId:2,quantity:10}]){
  f.state.turn.result_json.taskMetadata.inventory.stockChange=stockChange;f.state.turn.request_hash=v3HistoryHash(f);
  await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 }
 const current=f.state.turn.result_json.taskMetadata.inventory;current.access='read';current.stockChange=null;
 await assert.rejects(f.repo.read(input),{code:'INVENTORY_HISTORY_NOT_FOUND'});
});
test('legacy history cannot be upgraded with a new stock tuple',async()=>{
 for(const version of [1,2]){const f=fixture();Object.assign(f.state.turn.result_json.taskMetadata.inventory,{version,access:'write',stockChange:{productId:2,quantity:9}});
  await assert.rejects(f.repo.read({scope:f.scope,target:f.target,persona:f.persona,requestId:f.requestId}),{code:'INVENTORY_HISTORY_NOT_FOUND'});
 }
});
