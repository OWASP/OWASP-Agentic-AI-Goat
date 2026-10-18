'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createInventoryRecoveryRepository}=require('../server/database/postgres/secureshopInventoryRecoveryRepository');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
function fixture(){const input={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},requestId:randomUUID()},sessionId=randomUUID(),message='Set my stock to 3',mode='vuln';const outcome={stopReason:'end_turn',text:'Stock updated',taskMetadata:{inventory:{version:1,requestId:input.requestId,message,mode,personaSession:input.personaSession,receipts:[]}}};let rows=[{session_id:sessionId,status:'completed',request_version:1,request_hash:createTurnRequest({sessionId,requestId:input.requestId,binding:createConversationBinding(input.scope,input.persona),message:JSON.stringify({version:1,message,mode,personaSession:input.personaSession})}).hash,result_json:outcome}],queries=[];
 const personaAuthority={capture(value){return{binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},assertRemoteAdmission:async()=>{},async withPersonaEffect(work){return work({query:async(sql,args)=>{queries.push({sql,args});return{rows:sql.startsWith('SELECT tr.')?rows:[]};}});}};}};
 const repository=createInventoryRecoveryRepository({personaAuthority,checkCurrent:async()=>{},mode});return{input,repository,outcome,get row(){return rows[0];},set rows(value){rows=value;},queries};}
test('recovery verifies exact durable request and original persona session without rerunning a graph',async()=>{const f=fixture(),found=await f.repository.read(f.input);assert.equal(found.status,'completed');assert.deepEqual(found.outcome,f.outcome);const query=f.queries.find(q=>q.sql.startsWith('SELECT tr.'));assert.match(query.sql,/conversation_purpose='secureshop_inventory'/);assert.deepEqual(query.args,[f.input.requestId,f.input.scope.launchId,f.input.scope.scenarioId,1,1,2,2]);await assert.rejects(f.repository.read({...f.input,personaSession:{...f.input.personaSession,sessionId:randomUUID()}}),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});f.row.request_hash='0'.repeat(64);await assert.rejects(f.repository.read(f.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});});
test('absent, pending and uncertain recovery do not expose incomplete content',async()=>{const f=fixture();f.row.status='started';assert.deepEqual(await f.repository.read(f.input),{status:'pending',requestId:f.input.requestId});f.row.status='uncertain';assert.deepEqual(await f.repository.read(f.input),{status:'uncertain',requestId:f.input.requestId});f.rows=[];assert.deepEqual(await f.repository.read(f.input),{status:'not_found',requestId:f.input.requestId});});
test('access-bound completed turns recover exactly and altered permission cannot reuse their hash',async()=>{
 for(const access of ['read','write']){const f=fixture(),meta=f.outcome.taskMetadata.inventory;meta.version=2;meta.access=access;
  f.row.request_hash=createTurnRequest({sessionId:f.row.session_id,requestId:f.input.requestId,binding:createConversationBinding(f.input.scope,f.input.persona),message:JSON.stringify({version:2,message:meta.message,access,mode:meta.mode,personaSession:meta.personaSession})}).hash;
  assert.deepEqual((await f.repository.read(f.input)).outcome,f.outcome);
  meta.access=access==='read'?'write':'read';await assert.rejects(f.repository.read(f.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});
 }
 const f=fixture();f.outcome.taskMetadata.inventory.access='write';await assert.rejects(f.repository.read(f.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});
});
test('public inventory projection strips receipt bindings, prompt text and private evidence',()=>{const {projectInventoryOutcome}=require('../server/services/secureshopInventoryProduction'),id=randomUUID(),outcome={text:'Changed',stopReason:'end_turn',taskMetadata:{inventory:{requestId:id,message:'private request',receipts:[{receipt:{binding:{action:'set_stock',personaSession:{sessionId:'private'}},result:{applied:true,productId:7,before:4,after:2}}}],effects:['private']}}};assert.deepEqual(projectInventoryOutcome(outcome,id),{ok:true,status:'completed',requestId:id,answer:'Changed',operations:[{action:'set_stock',result:{applied:true,productId:7,before:4,after:2}}],replayed:false});});

function v3Hash(f){const meta=f.outcome.taskMetadata.inventory;return createTurnRequest({sessionId:f.row.session_id,requestId:f.input.requestId,binding:createConversationBinding(f.input.scope,f.input.persona),message:JSON.stringify({version:3,message:meta.message,access:meta.access,stockChange:meta.stockChange,mode:meta.mode,personaSession:meta.personaSession})}).hash;}
test('v3 recovery binds explicit read null and exact absolute stock intent to original request hash',async()=>{
 for(const access of ['read','write']){
  const f=fixture(),meta=f.outcome.taskMetadata.inventory;Object.assign(meta,{version:3,access,stockChange:access==='read'?null:{productId:7,quantity:0}});
  if(access==='write')meta.receipts=[{receipt:{binding:{action:'set_stock',args:{productId:7,quantity:0}}}}];
  f.row.request_hash=v3Hash(f);assert.deepEqual((await f.repository.read(f.input)).outcome,f.outcome);
  meta.stockChange=access==='read'?{productId:7,quantity:0}:{productId:7,quantity:1};
  await assert.rejects(f.repository.read(f.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});
 }
});
test('self-consistent v3 hash cannot bless off-intent receipts or inject new authority into legacy versions',async()=>{
 const f=fixture(),meta=f.outcome.taskMetadata.inventory;Object.assign(meta,{version:3,access:'write',stockChange:{productId:7,quantity:3},receipts:[{receipt:{binding:{action:'set_stock',args:{productId:8,quantity:3}}}}]});
 f.row.request_hash=v3Hash(f);await assert.rejects(f.repository.read(f.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});
 meta.receipts[0].receipt.binding.args={productId:7,quantity:4};await assert.rejects(f.repository.read(f.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});
 Object.assign(meta,{access:'read',stockChange:null});f.row.request_hash=v3Hash(f);await assert.rejects(f.repository.read(f.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});
 for(const version of [1,2]){const legacy=fixture();Object.assign(legacy.outcome.taskMetadata.inventory,{version,access:'write',stockChange:{productId:7,quantity:3}});await assert.rejects(legacy.repository.read(legacy.input),{code:'INVENTORY_RECOVERY_UNAVAILABLE'});}
});
