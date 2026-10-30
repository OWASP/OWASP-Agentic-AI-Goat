'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {MessageChannel}=require('node:worker_threads');
test('Analytics references persist over the real frame channel without storing questions or clearing other workflows',async()=>{
 const {createScopedShopStateStore}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const {createHostShopStateChannel,connectFrameShopState}=await import('../client/src/pages/secureshop/bridge/stateChannel.mjs');
 const {attachShopStorage,SHOP_ANALYTICS_KEY}=await import('../client/src/pages/secureshop/utils/shopStorage.mjs');
 const {readAnalyticsReferences,saveAnalyticsReference,forgetAnalyticsReference}=await import('../client/src/pages/secureshop/pages/merchant/analyticsRecovery.mjs');
 const values=new Map(),launchId='11111111-1111-4111-8111-111111111111';
 const storage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
 const store=createScopedShopStateStore({storage,scenarioId:launchId,generation:1,isCurrent:()=>true});
 const ports=new MessageChannel(),host=createHostShopStateChannel({port:ports.port1,store}),frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});
 const release=attachShopStorage(frame),reference={scopeKey:'a'.repeat(64),operationId:'22222222-2222-4222-8222-222222222222',state:'pending'};
 try {
  assert.deepEqual(readAnalyticsReferences(),[]);
  frame.setItem('ss_system_rebuild_recovery',JSON.stringify({version:1,references:[reference]}));await frame.flush();
  await saveAnalyticsReference(reference);
  const state=JSON.parse(values.get(`owasp-ai-goat:secureshop:${launchId}:1`));
  assert.deepEqual(JSON.parse(state[SHOP_ANALYTICS_KEY]),{version:1,references:[reference]});
  await assert.rejects(saveAnalyticsReference({...reference,question:'private question'}));
  await saveAnalyticsReference({...reference,state:'unknown'});
  await assert.rejects(forgetAnalyticsReference(reference),/changed/);
  await forgetAnalyticsReference({...reference,state:'unknown'});
  const after=JSON.parse(values.get(`owasp-ai-goat:secureshop:${launchId}:1`));
  assert.equal(after[SHOP_ANALYTICS_KEY],null);assert.equal(after.ss_system_rebuild_recovery,state.ss_system_rebuild_recovery);
 } finally {release();frame.close();host.close();}
});
