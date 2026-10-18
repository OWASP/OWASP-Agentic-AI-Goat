'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createBoundInventory}=require('../server/services/secureshopBoundInventory');
function fixture(){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const input={target:{...scope,targetId:randomUUID()},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},operationId:randomUUID(),action:'set_stock',args:{productId:7,quantity:2},execution:null};
 let prior=null,writes=0,valid=true,afterCommit=false,afterRead=false;
 const receipt={version:1,result:{applied:true,before:9,after:2}};
 const repository={async recover(){if(afterRead)valid=false;return prior;},async execute(raw){assert.equal(raw.mode,'vuln');writes++;prior=receipt;if(afterCommit)valid=false;return receipt;}};
 const fence={binding:{...scope,personaId:3,role:'merchant',...input.personaSession},async assertRemoteAdmission(){if(!valid)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},async withCrossStoreEffect(work){await this.assertRemoteAdmission();return work();}};
 const service=createBoundInventory({repository,checkCurrent:async()=>{},mode:'vuln'});
 return{service,input,fence,receipt,get writes(){return writes;},revokeAfterRead(){afterRead=true;},revokeAfterCommit(){afterCommit=true;}};
}
test('inventory effects use captured merchant authority and replay without another mutation',async()=>{const f=fixture();assert.deepEqual(await f.service.execute(f.input,{fence:f.fence}),f.receipt);assert.deepEqual(await f.service.execute(f.input,{fence:f.fence}),f.receipt);assert.equal(f.writes,1);});
test('missing read receipt still checks authority before any mutation',async()=>{const f=fixture();f.revokeAfterRead();await assert.rejects(f.service.execute(f.input,{fence:f.fence}),{code:'SHOP_AUTH_INVALID'});assert.equal(f.writes,0);});
test('committed effect followed by authority loss is uncertain and never reported successful',async()=>{const f=fixture();f.revokeAfterCommit();await assert.rejects(f.service.execute(f.input,{fence:f.fence}),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});assert.equal(f.writes,1);});
test('foreign persona fence and aborted request cannot mutate inventory',async()=>{const f=fixture();await assert.rejects(f.service.execute(f.input,{fence:{...f.fence,binding:{...f.fence.binding,personaId:8}}}),{code:'SHOP_AUTH_INVALID'});const controller=new AbortController();controller.abort();await assert.rejects(f.service.execute(f.input,{fence:f.fence,signal:controller.signal}),{name:'AbortError'});assert.equal(f.writes,0);});

test('canonical inventory selection overrides factory default and fences mode change after effect',async()=>{
 const f=fixture();let mode='fixed',stamp='first',writes=0;
 const modeAuthority=require('../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode,generation:0,modeStamp:stamp})},launches:{assertCurrent:async()=>{}}});
 const service=createBoundInventory({mode:'vuln',modeAuthority,checkCurrent:async()=>{},repository:{recover:async()=>null,execute:async raw=>{assert.equal(raw.mode,'fixed');writes++;stamp='next';return f.receipt;}}});
 await assert.rejects(service.execute(f.input,{fence:f.fence}),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});assert.equal(writes,1);
});
