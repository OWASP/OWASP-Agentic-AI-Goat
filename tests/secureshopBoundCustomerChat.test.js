'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const express=require('express');
const {capture}=require('../server/database/postgres/secureshopCustomerChatBindingRepository');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {createBoundCustomerChatRouter}=require('../server/routes/secureshop/boundCustomerChat');
const {createSecureShopBoundCustomerChat}=require('../server/services/secureshopBoundCustomerChat');
const launch={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:4,platformSessionId:5};
const persona={id:6,role:'customer'},session={sessionId:'30000000-0000-4000-8000-000000000001',authorityVersion:'2'};
const target=createSceneBinding({...launch,targetId:'40000000-0000-4000-8000-000000000001'},
 {sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,
  grantId:'60000000-0000-4000-8000-000000000001',execution:launch,withLease:work=>work()});
const requestId='70000000-0000-4000-8000-000000000001';
test('customer turn digest binds exact practice, persona, and message',()=>{
 const input={scope:launch,persona,personaSession:session,target,sessionId:session.sessionId,requestId,message:'catalog question'};
 const a=capture(input),b=capture(input);
 assert.deepEqual(a,b);assert.match(a.requestHash,/^[a-f0-9]{64}$/);assert.match(a.envelopeSha256,/^[a-f0-9]{64}$/);
 assert.notEqual(capture({...input,message:'different question'}).requestHash,a.requestHash);
 assert.throws(()=>capture({...input,target:{...target}}),/practice authority|unavailable/i);
});
test('mid-stream stale launch sends bounded error without writing a sent header',async t=>{
 const app=express();app.use(express.json());
 const router=createBoundCustomerChatRouter({launches:{resolveCapability:async()=>launch},
  authenticatePersona(req,_res,next){req.ssUser=persona;req.ssPersonaSession=session;next()},
  runtime:{createSession:async()=>({id:session.sessionId}),readRequest:async()=>({status:'unconfirmed'}),confirmProfile:async()=>({}),
   async run({stream}){stream.send('tool_call',{id:'call1',tool:'catalog.search',params:{search:'x'},step:1});
    throw Object.assign(new Error('stale'),{code:'STALE_LAUNCH'})}}});
 app.use('/api/secureshop',router);const server=app.listen(0,'127.0.0.1');
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 await new Promise(resolve=>server.once('listening',resolve));
 const response=await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/chat`,{
  method:'POST',headers:{'content-type':'application/json','x-dvaia-secureshop-launch':'a'.repeat(43)},
  body:JSON.stringify({sessionId:session.sessionId,requestId,message:'hello'})});
 assert.equal(response.status,200);
 const body=await response.text();assert.match(body,/event: tool_call/);assert.match(body,/event: error/);
 assert.match(body,/SHOP_AUTH_UNAVAILABLE/);assert.doesNotMatch(body,/event: done/);
});
function runtimeFixture({switchAfterCommit=false}={}){
 const other=createSceneBinding({...launch,targetId:'40000000-0000-4000-8000-000000000002'},
  {sceneId:'50000000-0000-4000-8000-000000000002',sceneGeneration:1,grantId:'60000000-0000-4000-8000-000000000002',execution:launch,withLease:work=>work()});
 let current=target,modelCalls=0,productReads=0,stored=null,claim=null;const sessions=new Map(),messages=[];
 const conversations={async acquireBoundSession({id,binding,purpose}){const prior=[...sessions.values()][0];if(prior)return prior;const row={id,binding,purpose,state:'pending'};sessions.set(id,row);return row},async activateBoundSession(id){sessions.get(id).state='active';return true},
  async getBoundSession(id){return sessions.get(id)},async getMessages(){return messages},async appendMessage(_id,_b,value){messages.push(value)},async getTokens(){return 0},async addTokens(){},async appendTraces(){}};
 const journal={async claim({sessionId,requestId,binding,message}){const digest=require('../server/services/secureshopTurnRequest').createTurnRequest({sessionId,requestId,binding,message}).hash;if(claim){if(claim.request_hash!==digest)throw Object.assign(Error('conflict'),{code:'TURN_REQUEST_CONFLICT'});return claim.status==='completed'?{status:'completed',result:claim.result_json}:claim}claim={status:'claimed',claimId:requestId,request_hash:digest};return claim},
  async complete({result}){claim={...claim,status:'completed',result_json:structuredClone(result)};if(switchAfterCommit)current=other},async markUncertain(){if(claim?.status!=='completed')claim={...claim,status:'uncertain'}},
  async readBoundRequest(){return claim&&{status:claim.status,request_hash:claim.request_hash,request_version:1,result_json:claim.result_json}}};
 const bindings={async reserve(input){stored=capture(input);return stored},async read(){return stored&&{launch_id:stored.launchId,scenario_id:stored.scenarioId,generation:stored.generation,
  owner_id:stored.ownerId,execution_session_id:stored.executionSessionId,persona_id:stored.personaId,
  persona_session_id:stored.personaSessionId,authority_version:stored.authorityVersion,
  scene_id:stored.sceneId,scene_generation:stored.sceneGeneration,grant_id:stored.grantId,target_id:stored.targetId,
  envelope_sha256:stored.envelopeSha256,request_hash:stored.requestHash}}};
 const authority={async capture(input){return{binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},async assertRemoteAdmission(){},async withPersonaEffect(work){return work({})},async withCrossStoreEffect(work){return work()}}}};
 const coordinator={async run(owner,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;return work({runId:'80000000-0000-4000-8000-000000000001',ownerKey:owner,durableGeneration:1,signal:options.signal,async check(){},async effect(_key,fn){return fn()},async effectWithReceipt(_key,fn){return{value:await fn(),receipt:{}}},async trace(){}})}};
 const provider={async chat(){modelCalls++;return modelCalls===1?{provider:'ollama',model:'llama3.1:8b',mocked:false,stop_reason:'tool_use',tool_uses:[{id:'search-1',name:'catalog.search',args:{search:'headphones'}}]}
  :{provider:'ollama',model:'llama3.1:8b',mocked:false,stop_reason:'end_turn',text:'Found headphones.',tool_uses:[]}},async finalResponse(){return{provider:'ollama',model:'llama3.1:8b',mocked:false,stop_reason:'end_turn',text:'Found headphones.',responseMode:'structured_final'}}};
 const runtime=createSecureShopBoundCustomerChat({launches:{async assertCurrent(){}},personaAuthority:authority,conversations,journal,coordinator,provider,
  catalog:{async prepareTarget(){return target}},productRepository:{async list(value){assert.equal(value,target);productReads++;return{rows:[{id:1,name:'Headphones',description:'Comfortable',price:99,category:'Electronics',stock_quantity:2}],total:1}}},
  commerceRepository:{async listCart(){return{items:[],subtotal:0}}},scenes:{async readExisting(){return current}},bindingRepository:bindings});
 return{runtime,get modelCalls(){return modelCalls},get productReads(){return productReads},get stored(){return stored}};
}
test('customer chat streams real local observation, journals answer, and GET does not redispatch',async()=>{
 const f=runtimeFixture(),sessionRow=await f.runtime.createSession(launch,persona,session),events=[];
 const input={scope:launch,persona,personaSession:session,sessionId:sessionRow.id,requestId,message:'Find headphones',stream:{send:(name,data)=>events.push({name,data})}};
 const first=await f.runtime.run(input);assert.equal(first.text,'Found headphones.');assert.equal(f.productReads,1);
 assert.deepEqual(events.map(e=>e.name).filter(x=>['tool_call','tool_result','assistant_message','done'].includes(x)),['tool_call','tool_result','assistant_message','done']);
 const recovered=await f.runtime.readRequest(launch,persona,session,sessionRow.id,requestId);
 assert.equal(recovered.status,'completed');assert.equal(recovered.hops[0].tool,'catalog.search');assert.equal(recovered.modeCapability.effectiveMode,'vuln');
 assert.equal(f.productReads,1);assert.equal(f.modelCalls,2);
});
test('saved customer turn denies a replacement persona session without retiring its current launch',async t=>{
 const f=runtimeFixture(),conversation=await f.runtime.createSession(launch,persona,session);
 await f.runtime.run({scope:launch,persona,personaSession:session,sessionId:conversation.id,requestId,message:'Find headphones'});
 const replacement={sessionId:'30000000-0000-4000-8000-000000000002',authorityVersion:session.authorityVersion};
 await assert.rejects(f.runtime.readRequest(launch,persona,replacement,conversation.id,requestId),
  {code:'CUSTOMER_CHAT_REFERENCE_STALE'});
 await assert.rejects(f.runtime.readRequest(launch,persona,{...session,authorityVersion:'3'},conversation.id,requestId),
  {code:'CUSTOMER_CHAT_REFERENCE_STALE'});
 const app=express();let admittedSession=replacement;
 app.use('/api/secureshop',createBoundCustomerChatRouter({launches:{resolveCapability:async()=>launch},
  authenticatePersona(req,_res,next){req.ssUser=persona;req.ssPersonaSession=admittedSession;next()},runtime:f.runtime}));
 const server=app.listen(0,'127.0.0.1');t.after(()=>new Promise(resolve=>server.close(resolve)));
 await new Promise(resolve=>server.once('listening',resolve));
 const url=`http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/operations/${conversation.id}/${requestId}`;
 const options={headers:{'x-dvaia-secureshop-launch':'a'.repeat(43)}};
 const denied=await fetch(url,options);
 assert.equal(denied.status,401);assert.equal(denied.headers.get('x-dvaia-secureshop-launch-state'),null);
 assert.deepEqual(await denied.json(),{error:'Shop session unavailable'});
 admittedSession=session;
 const original=await fetch(url,options);assert.equal(original.status,200);
 assert.equal((await original.json()).text,'Found headphones.');
 assert.equal(f.productReads,1);assert.equal(f.modelCalls,2);
});
test('saved customer route retains launch-wide fences for genuine stale authority and scene errors',async t=>{
 const app=express();let current=true,errorCode='STALE_LAUNCH',reads=0;
 app.use('/api/secureshop',createBoundCustomerChatRouter({launches:{resolveCapability:async()=>current?launch:null},
  authenticatePersona(req,_res,next){req.ssUser=persona;req.ssPersonaSession=session;next()},
  runtime:{createSession:async()=>({id:session.sessionId}),confirmProfile:async()=>{},run:async()=>{},
   async readRequest(){reads++;throw Object.assign(Error('denied'),{code:errorCode})}}}));
 const server=app.listen(0,'127.0.0.1');t.after(()=>new Promise(resolve=>server.close(resolve)));
 await new Promise(resolve=>server.once('listening',resolve));
 const url=`http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/operations/${session.sessionId}/${requestId}`;
 const options={headers:{'x-dvaia-secureshop-launch':'a'.repeat(43)}};
 for(const code of ['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE','CONVERSATION_UNAVAILABLE','SHOP_AUTH_INVALID','SHOP_SCENE_STALE']){
  errorCode=code;const response=await fetch(url,options);
  assert.equal(response.status,401,code);assert.equal(response.headers.get('x-dvaia-secureshop-launch-state'),'unavailable',code);
  assert.deepEqual(await response.json(),{error:'Shop session unavailable'});
 }
 current=false;const before=reads,response=await fetch(url,options);
 assert.equal(response.status,401);assert.equal(response.headers.get('x-dvaia-secureshop-launch-state'),'unavailable');
 assert.equal(reads,before);assert.deepEqual(await response.json(),{error:'SecureShop launch unavailable'});
});
test('scene change after journal commit cannot publish stale terminal success',async()=>{
 const f=runtimeFixture({switchAfterCommit:true}),sessionRow=await f.runtime.createSession(launch,persona,session),names=[];
 await assert.rejects(f.runtime.run({scope:launch,persona,personaSession:session,sessionId:sessionRow.id,requestId,message:'Find headphones',
  stream:{send:name=>names.push(name)}}),{code:'SHOP_SCENE_STALE'});
 assert.equal(f.productReads,1);assert.ok(names.includes('tool_result'));assert.equal(names.includes('done'),false);assert.equal(names.includes('assistant_message'),false);
 await assert.rejects(f.runtime.readRequest(launch,persona,session,sessionRow.id,requestId),{code:'SHOP_SCENE_STALE'});
});

function couponProbeCaptureFixture(){
 let current=target,existingReads=0,retainedReads=0,modelCalls=0,writes=0,
  authorityStale=false,launchStale=false,modeEpoch=1,onRetained=null;
 const denied=()=>{throw Object.assign(Error('stale authority'),{code:'SHOP_AUTH_INVALID'})};
 const write=async()=>{writes++;throw Error('Capture must not write')};
 const noop=async()=>{};
 const domain=Object.fromEntries(['search','cartView','resolveChoice','readOperation','readTurnOperations','prepareCart'].map(name=>[name,write]));
 const runtime=createSecureShopBoundCustomerChat({
  launches:{async assertCurrent(){if(launchStale)throw Object.assign(Error('retired launch'),{code:'STALE_LAUNCH'})}},
  personaAuthority:{async capture(input){if(input.sessionId!==session.sessionId||input.authorityVersion!==session.authorityVersion)denied();
   return{binding:{...input.scope,personaId:input.personaId,role:input.role,sessionId:input.sessionId,authorityVersion:input.authorityVersion},
    async assertRemoteAdmission(){if(authorityStale)denied()},withPersonaEffect:write,withCrossStoreEffect:write}}},
  modeAuthority:{async capture(_scope,featureId){const epoch=modeEpoch;return{snapshot:{version:1,featureId,
   policyVersion:require('../server/services/secureshopFeatureModeAuthority').POLICIES[featureId],mode:'vuln',generation:epoch,modeStamp:String(epoch),scope:launch},
   async assertCurrent(){if(modeEpoch!==epoch)throw Object.assign(Error('mode changed'),{code:'SECURESHOP_FEATURE_MODE_STALE'})}}},assertToken:value=>value},
  conversations:{getBoundSession:noop},journal:{readBoundRequest:noop},coordinator:{run:write},
  provider:{async chat(){modelCalls++;throw Error('No model during capture')},finalResponse:write},
  catalog:{prepareTarget:write},productRepository:{list:write},commerceRepository:{listCart:write,conversation:domain},
  profileCommerce:{conversational:write},toolPolicyRepository:{admitTool:write},
  scenes:{async readExisting(){existingReads++;throw Error('Provisioning read forbidden')},
   async readRetained(){retainedReads++;await onRetained?.();return current}},
  bindingRepository:{reserve:write,read:noop}});
 return{runtime,setTarget:value=>{current=value},setHook:value=>{onRetained=value},
  rotateMode:()=>{modeEpoch++},revoke:()=>{authorityStale=true},retire:()=>{launchStale=true},
  get counts(){return{existingReads,retainedReads,modelCalls,writes}}};
}
const couponProbeCaptureInput=()=>({scope:launch,persona,personaSession:session});
test('coupon probe capture and repeated check use retained scene SELECT only',async()=>{
 const f=couponProbeCaptureFixture(),captured=await f.runtime.captureCouponProbe(couponProbeCaptureInput());
 assert.equal(captured.target,target);assert.deepEqual(captured.personaSession,session);
 assert.equal(captured.mode.snapshot.featureId,'customer_chat');assert.equal(captured.couponMode.snapshot.featureId,'coupons');
 await captured.check();await captured.check();
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:4,modelCalls:0,writes:0});
});
for(const key of ['targetId','sceneId','sceneGeneration','grantId'])test(`coupon probe capture rejects retained ${key} drift`,async()=>{
 const f=couponProbeCaptureFixture(),captured=await f.runtime.captureCouponProbe(couponProbeCaptureInput());
 const replacement=createSceneBinding({...launch,targetId:key==='targetId'?'40000000-0000-4000-8000-000000000002':target.targetId},
  {sceneId:key==='sceneId'?'50000000-0000-4000-8000-000000000002':target.scene.sceneId,
   sceneGeneration:key==='sceneGeneration'?2:target.scene.sceneGeneration,
   grantId:key==='grantId'?'60000000-0000-4000-8000-000000000002':target.scene.grantId,execution:launch,withLease:work=>work()});
 f.setTarget(replacement);await assert.rejects(captured.check(),{code:'SHOP_SCENE_STALE'});
 assert.equal(f.counts.existingReads,0);assert.equal(f.counts.writes,0);
});
test('coupon probe capture rejects absent scene without provisioning it',async()=>{
 const f=couponProbeCaptureFixture();f.setTarget(null);
 await assert.rejects(f.runtime.captureCouponProbe(couponProbeCaptureInput()),{code:'SHOP_SCENE_STALE'});
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:1,modelCalls:0,writes:0});
});
test('coupon probe retained await is fenced by persona, launch, mode and cancellation',async()=>{
 for(const [mutation,code] of [['revoke','SHOP_AUTH_INVALID'],['rotateMode','SECURESHOP_FEATURE_MODE_STALE'],['retire','STALE_LAUNCH']]){
  const f=couponProbeCaptureFixture(),captured=await f.runtime.captureCouponProbe(couponProbeCaptureInput());
  f[mutation]();await assert.rejects(captured.check(),{code});assert.equal(f.counts.existingReads,0);
 }
 for(const mutation of ['revoke','rotateMode']){
  const f=couponProbeCaptureFixture(),captured=await f.runtime.captureCouponProbe(couponProbeCaptureInput());
  f.setHook(()=>f[mutation]());await assert.rejects(captured.check());assert.equal(f.counts.writes,0);
 }
 const f=couponProbeCaptureFixture(),controller=new AbortController();
 const captured=await f.runtime.captureCouponProbe({...couponProbeCaptureInput(),signal:controller.signal});
 f.setHook(()=>controller.abort());await assert.rejects(captured.check(),{name:'AbortError'});
 assert.equal(f.counts.existingReads,0);assert.equal(f.counts.writes,0);
});
test('coupon probe capture denies foreign credential and role without scene effects',async()=>{
 const f=couponProbeCaptureFixture();
 await assert.rejects(f.runtime.captureCouponProbe({...couponProbeCaptureInput(),persona:{id:6,role:'merchant'}}),{code:'OWNER_MISMATCH'});
 await assert.rejects(f.runtime.captureCouponProbe({...couponProbeCaptureInput(),personaSession:{...session,authorityVersion:'3'}}),{code:'SHOP_AUTH_INVALID'});
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:0,modelCalls:0,writes:0});
});

test('product search capture and repeated check use retained scene SELECT only',async()=>{
 const f=couponProbeCaptureFixture(),captured=await f.runtime.captureProductSearch(couponProbeCaptureInput());
 assert.equal(captured.target,target);assert.deepEqual(captured.personaSession,session);
 assert.equal(captured.mode.snapshot.featureId,'customer_chat');assert.equal(captured.searchMode.snapshot.featureId,'product_search');
 await captured.check();await captured.check();
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:4,modelCalls:0,writes:0});
});
for(const key of ['targetId','sceneId','sceneGeneration','grantId'])test(`product search capture rejects retained ${key} drift`,async()=>{
 const f=couponProbeCaptureFixture(),captured=await f.runtime.captureProductSearch(couponProbeCaptureInput());
 const replacement=createSceneBinding({...launch,targetId:key==='targetId'?'40000000-0000-4000-8000-000000000002':target.targetId},
  {sceneId:key==='sceneId'?'50000000-0000-4000-8000-000000000002':target.scene.sceneId,
   sceneGeneration:key==='sceneGeneration'?2:target.scene.sceneGeneration,
   grantId:key==='grantId'?'60000000-0000-4000-8000-000000000002':target.scene.grantId,execution:launch,withLease:work=>work()});
 f.setTarget(replacement);await assert.rejects(captured.check(),{code:'SHOP_SCENE_STALE'});
 assert.equal(f.counts.existingReads,0);assert.equal(f.counts.writes,0);
});
test('product search capture rejects absent scene without provisioning it',async()=>{
 const f=couponProbeCaptureFixture();f.setTarget(null);
 await assert.rejects(f.runtime.captureProductSearch(couponProbeCaptureInput()),{code:'SHOP_SCENE_STALE'});
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:1,modelCalls:0,writes:0});
});
test('product search retained await is fenced by persona, launch, mode and cancellation',async()=>{
 for(const [mutation,code] of [['revoke','SHOP_AUTH_INVALID'],['rotateMode','SECURESHOP_FEATURE_MODE_STALE'],['retire','STALE_LAUNCH']]){
  const f=couponProbeCaptureFixture(),captured=await f.runtime.captureProductSearch(couponProbeCaptureInput());
  f[mutation]();await assert.rejects(captured.check(),{code});assert.equal(f.counts.existingReads,0);
 }
 for(const mutation of ['revoke','rotateMode']){
  const f=couponProbeCaptureFixture(),captured=await f.runtime.captureProductSearch(couponProbeCaptureInput());
  f.setHook(()=>f[mutation]());await assert.rejects(captured.check());assert.equal(f.counts.writes,0);
 }
 const f=couponProbeCaptureFixture(),controller=new AbortController();
 const captured=await f.runtime.captureProductSearch({...couponProbeCaptureInput(),signal:controller.signal});
 f.setHook(()=>controller.abort());await assert.rejects(captured.check(),{name:'AbortError'});
 assert.equal(f.counts.existingReads,0);assert.equal(f.counts.writes,0);
});
test('product search capture denies foreign credential and role without scene effects',async()=>{
 const f=couponProbeCaptureFixture();
 await assert.rejects(f.runtime.captureProductSearch({...couponProbeCaptureInput(),persona:{id:6,role:'merchant'}}),{code:'OWNER_MISMATCH'});
 await assert.rejects(f.runtime.captureProductSearch({...couponProbeCaptureInput(),personaSession:{...session,authorityVersion:'3'}}),{code:'SHOP_AUTH_INVALID'});
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:0,modelCalls:0,writes:0});
});

test('order status capture and repeated check use retained scene SELECT only',async()=>{
 const f=couponProbeCaptureFixture(),captured=await f.runtime.captureOrderStatus(couponProbeCaptureInput());
 assert.equal(captured.target,target);assert.deepEqual(captured.personaSession,session);
 assert.equal(captured.mode.snapshot.featureId,'customer_chat');assert.equal(captured.orderStatusMode.snapshot.featureId,'order_status');
 await captured.check();await captured.check();
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:4,modelCalls:0,writes:0});
});
for(const key of ['targetId','sceneId','sceneGeneration','grantId'])test(`order status capture rejects retained ${key} drift`,async()=>{
 const f=couponProbeCaptureFixture(),captured=await f.runtime.captureOrderStatus(couponProbeCaptureInput());
 const replacement=createSceneBinding({...launch,targetId:key==='targetId'?'40000000-0000-4000-8000-000000000002':target.targetId},
  {sceneId:key==='sceneId'?'50000000-0000-4000-8000-000000000002':target.scene.sceneId,
   sceneGeneration:key==='sceneGeneration'?2:target.scene.sceneGeneration,
   grantId:key==='grantId'?'60000000-0000-4000-8000-000000000002':target.scene.grantId,execution:launch,withLease:work=>work()});
 f.setTarget(replacement);await assert.rejects(captured.check(),{code:'SHOP_SCENE_STALE'});
 assert.equal(f.counts.existingReads,0);assert.equal(f.counts.writes,0);
});
test('order status capture rejects absent scene without provisioning it',async()=>{
 const f=couponProbeCaptureFixture();f.setTarget(null);
 await assert.rejects(f.runtime.captureOrderStatus(couponProbeCaptureInput()),{code:'SHOP_SCENE_STALE'});
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:1,modelCalls:0,writes:0});
});
test('order status retained await is fenced by persona, launch, mode and cancellation',async()=>{
 for(const [mutation,code] of [['revoke','SHOP_AUTH_INVALID'],['rotateMode','SECURESHOP_FEATURE_MODE_STALE'],['retire','STALE_LAUNCH']]){
  const f=couponProbeCaptureFixture(),captured=await f.runtime.captureOrderStatus(couponProbeCaptureInput());
  f[mutation]();await assert.rejects(captured.check(),{code});assert.equal(f.counts.existingReads,0);
 }
 for(const mutation of ['revoke','rotateMode']){
  const f=couponProbeCaptureFixture(),captured=await f.runtime.captureOrderStatus(couponProbeCaptureInput());
  f.setHook(()=>f[mutation]());await assert.rejects(captured.check());assert.equal(f.counts.writes,0);
 }
 const f=couponProbeCaptureFixture(),controller=new AbortController();
 const captured=await f.runtime.captureOrderStatus({...couponProbeCaptureInput(),signal:controller.signal});
 f.setHook(()=>controller.abort());await assert.rejects(captured.check(),{name:'AbortError'});
 assert.equal(f.counts.existingReads,0);assert.equal(f.counts.writes,0);
});
test('order status capture denies foreign credential and role without scene effects',async()=>{
 const f=couponProbeCaptureFixture();
 await assert.rejects(f.runtime.captureOrderStatus({...couponProbeCaptureInput(),persona:{id:6,role:'merchant'}}),{code:'OWNER_MISMATCH'});
 await assert.rejects(f.runtime.captureOrderStatus({...couponProbeCaptureInput(),personaSession:{...session,authorityVersion:'3'}}),{code:'SHOP_AUTH_INVALID'});
 assert.deepEqual(f.counts,{existingReads:0,retainedReads:0,modelCalls:0,writes:0});
});
