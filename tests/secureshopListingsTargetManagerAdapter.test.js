'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID,createHash}=require('node:crypto');
const {createListingsTargetManager}=require('../server/services/secureshopListingsTargetManager');
function fixture({proof=true,drift=false,fetchOverride,scene=false}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},targetId=randomUUID(),origin='http://127.0.0.1:8095',runtimeDigest='a'.repeat(64),binding={scope,targetId,mode:'vuln'},calls=[];
 const config={...binding,origin,token:'t'.repeat(43),runtimeIdentity:'b'.repeat(64),runtimeDigest,executorId:randomUUID()};
 const merchantId=1000000001,current=scene?{...scope,launchId:randomUUID(),platformSessionId:7}:scope;
 const {createSceneBinding,authorizeSceneMerchant}=require('../server/services/secureshopSceneBinding');
 let revoked=false;const target=scene?authorizeSceneMerchant(createSceneBinding({...scope,targetId},{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:current,withLease:async work=>{if(revoked)throw Object.assign(Error(),{code:'SHOP_SCENE_STALE'});return work();}}),merchantId):null;
 const manager=createListingsTargetManager({origin,runtimeDigest,controlToken:'c'.repeat(43),launches:{async assertCurrent(s){assert.deepEqual(s,current);},async readExistingProductsTarget(){assert.equal(scene,false,'scene grants do not create launch reservations');return{targetId};}},products:{async open(binding){if(scene)assert.equal(binding,target);return{targetId};},async readCleanupReceipt(_scope,{operationId}){return proof?{...scope,targetId,operationId,receiptSha256:'d'.repeat(64)}:null;}},resolveMode:async()=> 'vuln',timeoutMs:50,fetchImpl:fetchOverride|| (async(url,options)=>{
  calls.push({url,options});let value;
  if(url.endsWith('/manager/health'))value={version:1,ready:true,capability:'owned-listings-manager.v1',runtimeDigest,limits:{maxPersistedTargets:200,maxResidentTargets:32,maxConcurrentExecutions:4,maxQueuedExecutions:16}};
  else if(url.endsWith('/targets/retire')){const x=JSON.parse(options.body);value={version:1,operationId:x.operationId,targetId,bindingSha256:createHash('sha256').update(JSON.stringify(binding)).digest('hex'),canonicalReceiptSha256:x.canonicalReceiptSha256,operationCount:0,tombstonesSha256:'e'.repeat(64),retired:true};}
  else if(url.endsWith('/targets'))value={...config,...(drift?{targetId:randomUUID()}:{})};
  else value={version:1,ready:true,identity:config.runtimeIdentity,runtimeDigest,mode:'vuln',isolation:'owned-listings.v1'};
  return new Response(JSON.stringify(value));
 })});return{manager,binding,config,calls,target,merchantId,revoke(){revoked=true;}};
}
test('canonical target and server mode precede private provisioning and target health verification',async()=>{
 const f=fixture();assert.deepEqual(await f.manager.resolveConfiguration(f.binding),f.config);assert.equal(f.calls.length,3);
 await assert.rejects(f.manager.resolveConfiguration({...f.binding,mode:'fixed'}),{code:'LISTINGS_TARGET_MISMATCH'});assert.equal(f.calls.length,3);
});
test('wrong target registration never passes configuration to composition',async()=>{
 const f=fixture({drift:true});await assert.rejects(f.manager.resolveConfiguration(f.binding),{code:'LISTINGS_MANAGER_BINDING'});assert.equal(f.calls.length,2);
});
test('retirement requires canonical repository cleanup proof before any control request',async()=>{
 const denied=fixture({proof:false});await assert.rejects(denied.manager.retire(denied.binding,{operationId:randomUUID()}),{code:'LISTINGS_CLEANUP_PROOF'});assert.equal(denied.calls.length,0);
 const f=fixture(),operationId=randomUUID();const result=await f.manager.retire(f.binding,{operationId});assert.equal(result.operationId,operationId);assert.equal(result.retired,true);assert.equal(JSON.parse(f.calls[1].options.body).canonicalReceiptSha256,'d'.repeat(64));
});
test('manager HTTP failure releases body without awaiting cancellation and malformed UTF8 is denied',async()=>{
 let cancelled=0;
 const failed=fixture({fetchOverride:async()=>({ok:false,body:{cancel(){cancelled++;return new Promise(()=>{});}}})});
 await assert.rejects(failed.manager.health(),{code:'LISTINGS_MANAGER_UNAVAILABLE'});assert.equal(cancelled,1);
 const malformed=fixture({fetchOverride:async()=>new Response(Buffer.from([123,34,120,34,58,34,255,34,125]))});
 await assert.rejects(malformed.manager.health(),TypeError);
});

test('retained manager namespace authorizes every current private grant and never requires a new reservation',async()=>{
 const f=fixture({scene:true}),options={targetBinding:f.target,merchantId:f.merchantId};
 assert.deepEqual(await f.manager.resolveConfiguration(f.binding,options),f.config);
 assert.deepEqual(JSON.parse(f.calls[1].options.body),f.binding);
 const calls=f.calls.length;
 await assert.rejects(f.manager.resolveConfiguration(f.binding,{...options,targetBinding:JSON.parse(JSON.stringify(f.target))}),{code:'LISTINGS_TARGET_MISMATCH'});
 await assert.rejects(f.manager.resolveConfiguration(f.binding,{...options,merchantId:f.merchantId+1}),{code:'LISTINGS_TARGET_MISMATCH'});
 f.revoke();await assert.rejects(f.manager.resolveConfiguration(f.binding,options),{code:'SHOP_SCENE_STALE'});assert.equal(f.calls.length,calls);
});
