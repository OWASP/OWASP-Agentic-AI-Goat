'use strict';
const test=require('node:test'),assert=require('node:assert/strict');

test('real workshop controller scopes parent state to launch identity, never retrieval target identity',async()=>{
 const {createSecureShopWorkshopController}=await import('../client/src/pages/secureshop/SecureShopWorkshopController.mjs');
 const launchId='11111111-1111-4111-8111-111111111111',targetScenarioId='22222222-2222-4222-8222-222222222222',generation=7,values=new Map();
 const storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};
 const frame={style:{},isConnected:true,setAttribute(){},remove(){this.isConnected=false;}};
 const documentRef={createElement:()=>frame},container={isConnected:true,replaceChildren(value){this.child=value;}};
 const bodies=[{launch:null},{launch:{launchId,generation,credentialVersion:1,expiresAt:'2099-01-01T00:00:00.000Z'},bearer:'a'.repeat(43)}];
 const controller=createSecureShopWorkshopController({storage,documentRef,origin:'http://127.0.0.1:9999',getPlatformToken:()=> 'platform-token',
  fetchImpl:async()=>({ok:true,status:200,json:async()=>bodies.shift()}),
  mountFrame:({stateStore})=>{stateStore.replace({secureshop_v2_token:'persona-token',ss_guest_cart:null});return{ready:Promise.resolve(),close(){}};},
  compileOperation(){},setTimer:()=>({unref(){}}),clearTimer(){}});
 const launch=await controller.start(container);assert.equal(launch.launchId,launchId);assert.equal(launch.generation,generation);
 const launchKey=`dvaia:secureshop:${launchId}:${generation}`,targetKey=`dvaia:secureshop:${targetScenarioId}:${generation}`;
 assert.equal(JSON.parse(values.get(launchKey)).secureshop_v2_token,'persona-token');assert.equal(values.has(targetKey),false);
 controller.close();
});

test('System rebuild recovery crosses the real scoped parent state channel',async()=>{
 const {MessageChannel}=require('node:worker_threads');
 const {createScopedShopStateStore}=await import('../client/src/pages/secureshop/bridge/stateStore.mjs');
 const {createHostShopStateChannel,connectFrameShopState}=await import('../client/src/pages/secureshop/bridge/stateChannel.mjs');
 const scenarioId='11111111-1111-4111-8111-111111111111',generation=7,key=`dvaia:secureshop:${scenarioId}:${generation}`,values=new Map();
 const storage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
 const store=createScopedShopStateStore({storage,scenarioId,generation,isCurrent:()=>true});
 const ports=new MessageChannel(),host=createHostShopStateChannel({port:ports.port1,store}),frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});
 const unrelated=JSON.stringify({version:1,references:[{scopeKey:'a'.repeat(64),operationId:'00000000-0000-4000-8000-000000000001',state:'unknown'}]});
 const pending=JSON.stringify({version:1,references:[{scopeKey:'b'.repeat(64),operationId:'00000000-0000-4000-8000-000000000002',state:'pending'}]});
 frame.setItem('ss_system_config_recovery',unrelated);frame.setItem('ss_system_diagnostic_recovery',unrelated);frame.setItem('ss_system_rebuild_recovery',pending);await frame.flush();
 const parent=JSON.parse(values.get(key));assert.equal(parent.ss_system_rebuild_recovery,pending);assert.equal(parent.ss_system_config_recovery,unrelated);assert.equal(parent.ss_system_diagnostic_recovery,unrelated);
 frame.removeItem('ss_system_rebuild_recovery');await frame.flush();const recovered=JSON.parse(values.get(key));assert.equal(recovered.ss_system_rebuild_recovery,null);assert.equal(recovered.ss_system_config_recovery,unrelated);assert.equal(recovered.ss_system_diagnostic_recovery,unrelated);
 frame.close();host.close();
});
