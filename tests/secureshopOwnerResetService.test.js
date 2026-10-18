'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopOwnerResetService}=require('../server/services/secureshopOwnerResetService');
const {createSecureShopOwnerResetRepository}=require('../server/database/postgres/secureshopOwnerResetRepository');
const A='11111111-1111-4111-8111-111111111111',B='22222222-2222-4222-8222-222222222222';
test('owner reset recovers every mapped launch and reactivates only eligible entries',async()=>{
 const events=[];const rows=[
  {resetId:A,launchId:'a',platformSessionId:3,toGeneration:2,reactivate:true},
  {resetId:B,launchId:'b',platformSessionId:4,toGeneration:5,reactivate:false},
 ];
 const repository={assertReady:async()=>true,begin:async({ownerId})=>{events.push(['begin',ownerId]);return{operationId:A,launches:rows};},
  read:async()=>({launches:rows}),complete:async scope=>{events.push(['complete',scope]);return{completed:true};}};
 const service=createSecureShopOwnerResetService({repository,
  launchResetCoordinator:{recover:async resetId=>{events.push(['recover',resetId]);return{resetId,resolved:true,activated:false};}},
  launches:{commitReset:async input=>events.push(['commit',input])}});
 assert.deepEqual(await service.resetOwner(7),{completed:true});
 assert.deepEqual(events,[['begin',7],['recover',A],['commit',{resetId:A,launchId:'a',platformSessionId:3,
  platformOwnerId:7,expectedGeneration:2}],['recover',B],['complete',{ownerId:7,operationId:A}]]);
});
test('owner reset cannot complete on false recovery or changed mapping',async()=>{
 const row={resetId:A,launchId:'a',platformSessionId:3,toGeneration:2,reactivate:false};
 const base={assertReady:async()=>true,begin:async()=>({operationId:A,launches:[row]}),complete:async()=>{throw Error('must not complete');}};
 await assert.rejects(createSecureShopOwnerResetService({repository:{...base,read:async()=>({launches:[row]})},
  launchResetCoordinator:{recover:async()=>({resetId:A,resolved:false,activated:false})},launches:{commitReset:async()=>{}}}).resetOwner(7),/incomplete/);
 await assert.rejects(createSecureShopOwnerResetService({repository:{...base,read:async()=>({launches:[{...row,resetId:B}]})},
  launchResetCoordinator:{recover:async()=>({resetId:A,resolved:true,activated:false})},launches:{commitReset:async()=>{}}}).resetOwner(7),/mapping changed/);
});
test('owner reset preserves debt when persona retirement blocks aggregate recovery',async()=>{
 const events=[];const row={resetId:A,launchId:'a',platformSessionId:3,toGeneration:2,reactivate:true};
 const service=createSecureShopOwnerResetService({repository:{assertReady:async()=>true,
  begin:async()=>({operationId:A,launches:[row]}),read:async()=>{events.push('read');return{launches:[row]};},
  complete:async()=>events.push('complete')},
 launchResetCoordinator:{recover:async()=>{throw Object.assign(Error('active persona remains'),
  {code:'RETIREMENT_INCOMPLETE'});}},launches:{commitReset:async()=>events.push('commit')}});
 await assert.rejects(service.resetOwner(7),{code:'RETIREMENT_INCOMPLETE'});
 assert.deepEqual(events,[]);
});
test('session revocation during cleanup truthfully suppresses reactivation',async()=>{
 const events=[];const row={resetId:A,launchId:'a',platformSessionId:3,toGeneration:2,reactivate:true};
 const service=createSecureShopOwnerResetService({repository:{assertReady:async()=>true,
  begin:async()=>({operationId:A,launches:[row]}),read:async()=>({launches:[row]}),
  complete:async()=>({completed:true})},
 launchResetCoordinator:{recover:async()=>({resetId:A,status:'aborted',resolved:true,activated:false})},
 launches:{commitReset:async()=>events.push('incorrect-reactivation')}});
 assert.deepEqual(await service.resetOwner(7),{completed:true});assert.deepEqual(events,[]);
});
test('a replayed committed reset is not committed a second time',async()=>{
 const events=[];const row={resetId:A,launchId:'a',platformSessionId:3,toGeneration:2,reactivate:true};
 const service=createSecureShopOwnerResetService({repository:{assertReady:async()=>true,
  begin:async()=>({operationId:A,launches:[row]}),read:async()=>({launches:[row]}),
  complete:async()=>({completed:true})},
 launchResetCoordinator:{recover:async()=>({resetId:A,status:'committed',resolved:true,activated:false})},
 launches:{commitReset:async()=>events.push('duplicate')}});
 assert.deepEqual(await service.resetOwner(7),{completed:true});assert.deepEqual(events,[]);
});
test('readiness requires the immutable mapping and admission guards',async()=>{
 const pool={connect:async()=>{},query:async()=>({rows:[{operations:true,launches:true,reset_identity:true,
  journal_guard:true,mapping_guard:true,admission_guard:false}]})};
 await assert.rejects(createSecureShopOwnerResetRepository(pool).assertReady(),{code:'RESET_STORAGE_NOT_READY'});
});
test('completed exact owner operation returns before recovery and preserves supplied identifier',async()=>{
 const service=createSecureShopOwnerResetService({repository:{assertReady:async()=>true,begin:async input=>{assert.deepEqual(input,{ownerId:7,operationId:A});return{operationId:A,status:'completed',launches:[{launchId:'retained'}]};},read:async()=>{throw Error('unexpected read');},complete:async()=>{throw Error('unexpected complete');}},launchResetCoordinator:{recover:async()=>{throw Error('unexpected recovery');}},launches:{commitReset:async()=>{throw Error('unexpected commit');}}});
 assert.deepEqual(await service.resetOwner(7,{operationId:A}),{operationId:A,completed:true,launchCount:1});
});
