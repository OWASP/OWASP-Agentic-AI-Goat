'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopBoundCommerce}=require('../server/services/secureshopBoundCommerce');
const {POLICIES}=require('../server/services/secureshopFeatureModeAuthority');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');

const scope=Object.freeze({launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:2,platformOwnerId:7,platformSessionId:8});
const target=Object.freeze({...scope,targetId:'30000000-0000-4000-8000-000000000001'});
function fixture(){const calls=[];const repository={};for(const name of ['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'])repository[name]=async(...args)=>{calls.push([name,...args]);return name==='listCart'?{items:[],subtotal:0}:name==='listOrders'?[]:name==='getOrder'?null:name==='checkout'?{orderId:1,total:2}:name==='addCart'?{id:3}:1;};const catalog={async prepareTarget(input){calls.push(['target',input]);return target;},async hasProduct(input){calls.push(['hasProduct',input]);return true;}};return {calls,service:createSecureShopBoundCommerce({repository,catalog})};}

test('bound commerce uses authenticated customer identity and provisions products before cart mutation',async()=>{const f=fixture();const input={scope,persona:{id:41,role:'customer'},productId:9,quantity:2};assert.deepEqual(await f.service.add(input),{id:3});assert.deepEqual(f.calls.map(row=>row[0]),['target','hasProduct','addCart']);assert.equal(f.calls[2][2].shopUserId,41);assert.equal(f.calls[2][2].productId,9);});
test('bound commerce rejects non-customer personas before target or repository access',async()=>{const f=fixture();await assert.rejects(()=>f.service.orders({scope,persona:{id:41,role:'merchant'}}),error=>error.code==='OWNER_MISMATCH');assert.deepEqual(f.calls,[]);});

test('confirmed coupon uses the original branded modes and exact existing scene without provisioning',async()=>{
  const sessionId='40000000-0000-4000-8000-000000000001',sceneId='50000000-0000-4000-8000-000000000001',grantId='60000000-0000-4000-8000-000000000001';
  const existing=createSceneBinding({...target,launchId:'10000000-0000-4000-8000-000000000002'},
    {sceneId,sceneGeneration:3,grantId,execution:scope,withLease:work=>work()});
  let current=true,provisioned=0,resolved=0,applied=0,read=0;
  const tokens=new WeakSet();
  const token=featureId=>{const value=Object.freeze({snapshot:Object.freeze({featureId,policyVersion:POLICIES[featureId],mode:'vuln',scope}),
    async assertCurrent(){if(!current)throw Error('stale');},async assertCurrentAtEffect(){if(!current)throw Error('stale');}});tokens.add(value);return value;};
  const couponMode=token('coupons'),customerMode=token('customer_chat');
  const modeAuthority={assertToken(value){if(!tokens.has(value))throw Error('unbranded');return value;}};
  const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name=>[name,async()=>null]));
  const commerce=createSecureShopBoundCommerce({repository,modeAuthority,personaAuthority:{capture(value){return{
    binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},
    async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();},
  };}},catalog:{async prepareTarget(){provisioned++;return existing;},async hasProduct(){return true;}},
  resolveExistingTarget:async()=>{resolved++;return existing;},withSelectedSceneEffect:async(context,work)=>{
    assert.deepEqual(context.expectedTarget,{targetId:existing.targetId,sceneId,sceneGeneration:3,grantId});return work();},
  couponWorkflow:{async applyConfirmed(value,options){applied++;assert.equal(value.target,existing);
    assert.equal(options.customerMode,customerMode);assert.equal(options.couponMode,couponMode);return{ok:true};},
   async readConfirmed(value,options){read++;assert.equal(value.target,existing);
    assert.equal(options.customerMode,customerMode);assert.equal(options.couponMode,couponMode);
    return{state:'completed',request:{operationId:value.operationId,code:value.code,mode:value.mode},
      result:{ok:true}};}}});
  const input={scope,persona:{id:41,role:'customer'},personaSession:{sessionId,authorityVersion:'1'},
    code:'WELCOME10',operationId:'70000000-0000-4000-8000-000000000001',expectedTarget:{targetId:existing.targetId,sceneId,sceneGeneration:3,grantId},
    customerMode,couponMode,async checkCurrent(){if(!current)throw Error('stale');}};
  assert.deepEqual(await commerce.applyConfirmedCoupon(input),{ok:true});assert.equal(provisioned,0);assert.equal(resolved,1);assert.equal(applied,1);
  assert.deepEqual(await commerce.readConfirmedCoupon(input),{state:'completed',
    request:{operationId:input.operationId,code:input.code,mode:'vuln'},result:{ok:true}});
  assert.equal(read,1);assert.equal(applied,1);assert.equal(provisioned,0);
  for(const changed of [{expectedTarget:{...input.expectedTarget,grantId:'80000000-0000-4000-8000-000000000001'}},
    {customerMode:couponMode},{couponMode:{...couponMode}}])await assert.rejects(commerce.applyConfirmedCoupon({...input,...changed}));
  assert.equal(applied,1);assert.equal(provisioned,0);
  current=false;await assert.rejects(commerce.applyConfirmedCoupon(input));assert.equal(applied,1);
  await assert.rejects(commerce.readConfirmedCoupon(input));assert.equal(read,1);
});

test('commerce captures exact session before awaits and denies revoked or substituted authority',async()=>{
  const sessionId='40000000-0000-4000-8000-000000000001';
  const input={scope:{...scope},persona:{id:41,role:'customer'},personaSession:{sessionId,authorityVersion:'1'},productId:9,quantity:2};
  let capture, checks=0, writes=0, observed;
  const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async(target,request)=>{writes++;observed={target,request};return {id:3};}]));
  const catalog={async prepareTarget(request){return {...target,platformOwnerId:request.scope.platformOwnerId};},async hasProduct(){return true;}};
  const personaAuthority={async capture(value){capture=value;input.scope.platformOwnerId=99;input.persona.id=42;input.personaSession.authorityVersion='9';input.productId=22;return {binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},async withCrossStoreEffect(work){return work();},async assertRemoteAdmission(){checks++;}};}};
  const service=createSecureShopBoundCommerce({repository,catalog,personaAuthority});
  assert.deepEqual(await service.add(input),{id:3});assert.equal(writes,1);assert.equal(checks,3);assert.equal(capture.authorityVersion,'1');assert.equal(observed.request.shopUserId,41);assert.equal(observed.request.productId,9);assert.equal(observed.target.platformOwnerId,7);
  const base={scope,persona:{id:41,role:'customer'},personaSession:{sessionId,authorityVersion:'1'}};
  for(const returned of [null,{binding:{...scope,personaId:42,role:'customer',sessionId,authorityVersion:'1'},async assertRemoteAdmission(){}}]){
    const bad=createSecureShopBoundCommerce({repository,catalog,personaAuthority:{capture:()=>returned}});
    await assert.rejects(bad.orders(base),{code:'SHOP_AUTH_INVALID'});
  }
  await assert.rejects(service.orders({...base,personaSession:undefined}),{code:'SHOP_AUTH_INVALID'});
  await assert.rejects(service.orders({...base,apiAuthority:{binding:scope,async assertRemoteAdmission(){}}}),{code:'SHOP_API_KEY_INVALID'});
  assert.equal(writes,1);
});

test('commerce does not return success when revocation follows a committed write',async()=>{
  const sessionId='40000000-0000-4000-8000-000000000001';let revoked=false,writes=0;
  const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async()=>{writes++;revoked=true;return {orderId:1};}]));
  const catalog={async prepareTarget(){return target;},async hasProduct(){return true;}};
  const personaAuthority={capture(value){return {binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},async withCrossStoreEffect(work){return work();},async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};}};
  const service=createSecureShopBoundCommerce({repository,catalog,personaAuthority});
  const input={scope,persona:{id:41,role:'customer'},personaSession:{sessionId,authorityVersion:'1'},shippingAddress:'owned',paymentMethod:'teaching'};
  await assert.rejects(service.checkout(input),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});assert.equal(writes,1,'committed effect is not rolled back by a post-check');
  await assert.rejects(service.checkout(input),{code:'SHOP_AUTH_INVALID'});assert.equal(writes,1,'revoked authority cannot admit another write');
});

test('API order reads use branded key authority without provisioning and reject rotated keys',async()=>{
  let version=1, reads=0, provisioned=0, existing=null, seenTarget;
  const authRepository=Object.fromEntries(['findCredential','createSession','readSession','extendSession','revokeSession','listSessions','revokeOwnedSession','changePassword','readApiKey','rotateApiKey'].map(k=>[k,async()=>null]));
  authRepository.authenticateApiKey=async()=>({id:41,username:'student_customer',email:'owned@example.invalid',role:'customer',apiKeyVersion:version});
  const auth=require('../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:authRepository,launches:{async assertCurrent(){}},jwtSecret:'controlled-commerce-api-secret-at-least-32-bytes'});
  const apiAuthority=await auth.captureApiKeyAuthority({scope,presentedKey:'sk_ss_live_'+'a'.repeat(32)});
  const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async(value)=>{reads++;seenTarget=value;return [{id:1}];}]));
  const service=createSecureShopBoundCommerce({repository,catalog:{async prepareTarget(){provisioned++;return target;},async hasProduct(){return true;}},personaAuthority:{capture(){throw Error('API key must not manufacture a session');}},resolveExistingTarget:async()=>existing});
  const input={scope,persona:{id:41,role:'customer'},apiAuthority};
  assert.deepEqual(await service.orders(input),[]);assert.equal(await service.order({...input,orderId:1}),null);assert.equal(reads,0);
  existing={...target,kind:'products'};assert.deepEqual(await service.orders(input),[{id:1}]);assert.equal(reads,1);assert.equal(provisioned,0);
  const sceneTarget=require('../server/services/secureshopSceneBinding').createSceneBinding({
    ...target,launchId:'10000000-0000-4000-8000-000000000002',platformSessionId:9,
  },{sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,
    grantId:'60000000-0000-4000-8000-000000000001',execution:scope,withLease:work=>work()});
  existing=sceneTarget;assert.deepEqual(await service.orders(input),[{id:1}]);
  assert.equal(seenTarget,sceneTarget);assert.equal(reads,2);assert.equal(provisioned,0);
  existing={...sceneTarget};await assert.rejects(service.orders(input),{code:'SHOP_SCENE_STALE'});
  existing=sceneTarget;
  await assert.rejects(service.checkout({...input,shippingAddress:'owned',paymentMethod:'teaching'}),{code:'SHOP_API_KEY_INVALID'});assert.equal(reads,2);
  version=2;await assert.rejects(service.orders(input),{code:'SHOP_API_KEY_INVALID'});assert.equal(reads,2);assert.equal(provisioned,0);
});

test('merchant metrics use their exact persona authority and discard a revoked read', async()=>{
  let revoked=false, reads=0, revokeAfterRead=false;
  const empty={current:{revenue:0,orders:0},previous:{revenue:0,orders:0},days:[],top:null};
  const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name=>[name,async()=>null]));
  repository.merchantOverview=async(value,id)=>{assert.deepEqual(value,target);assert.equal(id,12);reads++;if(revokeAfterRead)revoked=true;return empty;};
  const personaAuthority={async capture(value){assert.equal(value.role,'merchant');return {
    binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},
    async withCrossStoreEffect(work){return work();},
    async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},
  };}};
  const service=createSecureShopBoundCommerce({repository,personaAuthority,catalog:{async prepareTarget(){return target;},async hasProduct(){return true;}}});
  const input={scope,persona:{id:12,role:'merchant'},personaSession:{sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'}};
  assert.equal((await service.merchantOverview(input)).kpis.retailer_id,12);
  await assert.rejects(service.merchantOverview({...input,persona:{id:12,role:'customer'}}),{code:'OWNER_MISMATCH'});
  assert.equal(reads,1);
  revokeAfterRead=true;
  await assert.rejects(service.merchantOverview(input),{code:'SHOP_AUTH_INVALID'});
  assert.equal(reads,2);
  await assert.rejects(service.merchantOverview(input),{code:'SHOP_AUTH_INVALID'});
  assert.equal(reads,2);
});
test('merchant top products projects only owned reporting rows after session fences',async()=>{
 let revoked=false,revokeAfterRead=false,reads=0,products=[{id:'9',name:'Owned purchase',revenue:'6.75',email:'private@example.invalid'}];
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name=>[name,async()=>null]));
 repository.merchantOverview=async(value,id,window,limit)=>{assert.equal(value,target);assert.equal(id,12);assert.equal(window.days,30);assert.equal(limit,8);reads++;if(revokeAfterRead)revoked=true;return {products};};
 const personaAuthority={capture(value){return {binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},async withCrossStoreEffect(work){return work();},async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};}};
 const service=createSecureShopBoundCommerce({repository,personaAuthority,catalog:{async prepareTarget(){return target;},async hasProduct(){return true;}}});
 const input={scope,persona:{id:12,role:'merchant'},personaSession:{sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'}};
 assert.deepEqual(await service.merchantTopProducts(input),{rows:[{id:9,name:'Owned purchase',revenue:6.75}],periodDays:30,source:'owned-commerce'});
 products=[];assert.deepEqual((await service.merchantTopProducts(input)).rows,[]);
 for(const row of [{id:0,name:'bad',revenue:1},{id:1,name:null,revenue:1},{id:1,name:'bad',revenue:null},{id:1,name:'bad',revenue:''},{id:1,name:'bad',revenue:-1},{id:1,name:'bad',revenue:'Infinity'}]){products=[row];await assert.rejects(service.merchantTopProducts(input),/Invalid stored top product/);}
 products=Array(9).fill({id:1,name:'overflow',revenue:1});await assert.rejects(service.merchantTopProducts(input),/Invalid stored top products/);
 const before=reads;
 await assert.rejects(service.merchantTopProducts({...input,persona:{id:12,role:'customer'}}),{code:'OWNER_MISMATCH'});
 for(const limit of [0,51,'8',1.5])await assert.rejects(service.merchantTopProducts({...input,limit}),{code:'INVALID_ARGUMENT'});
 assert.equal(reads,before);
 products=[];revokeAfterRead=true;await assert.rejects(service.merchantTopProducts(input),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,before+1);
 await assert.rejects(service.merchantTopProducts(input),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,before+1);
});

test('cart sum rejection becomes invalid argument only after authority post-check and never unwraps uncertain effects', async () => {
  const { CART_QUANTITY_LIMIT_REJECTED } = require('../server/database/postgres/secureshopBoundCommerceRepository');
  const sessionId = '40000000-0000-4000-8000-000000000001';
  let mode = 'rejected', checks = 0, callbackComplete = false;
  const repository = Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name => [name, async () => {
    if (mode === 'lost-ack') throw Object.assign(Error('after possible commit'), { code: 'INVALID_ARGUMENT' });
    return CART_QUANTITY_LIMIT_REJECTED;
  }]));
  const personaAuthority = { capture(value) { return {
    binding: { ...value.scope, personaId: value.personaId, role: value.role, sessionId: value.sessionId, authorityVersion: value.authorityVersion },
    async assertRemoteAdmission() { checks++; if (mode === 'revoked-after' && callbackComplete) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); },
    async withCrossStoreEffect(work) {
      try { const result = await work(); callbackComplete = true; return result; }
      catch (cause) { throw Object.assign(Error('uncertain'), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', cause }); }
    },
  }; } };
  const service = createSecureShopBoundCommerce({ repository, personaAuthority, catalog: {
    async prepareTarget() { return target; }, async hasProduct() { return true; },
  } });
  const input = { scope, persona: { id: 41, role: 'customer' }, personaSession: { sessionId, authorityVersion: '1' }, productId: 9, quantity: 98 };
  await assert.rejects(service.add(input), { code: 'INVALID_ARGUMENT' });
  assert.equal(callbackComplete, true); assert.equal(checks, 3);
  mode = 'lost-ack'; callbackComplete = false;
  await assert.rejects(service.add(input), error => error.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' && error.cause.code === 'INVALID_ARGUMENT');
  mode = 'revoked-after'; callbackComplete = false;
  await assert.rejects(service.add(input), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' });
});

test('empty checkout maps only completed rejection after post-check; failures and revocation stay uncertain', async () => {
  const { EMPTY_CART_REJECTED, CART_STOCK_REJECTED } = require('../server/database/postgres/secureshopBoundCommerceRepository');
  let rejection = EMPTY_CART_REJECTED;
  let failure, revoked = false, completed = false, checks = 0;
  const repository = Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name => [name, async () => {
    if (failure) throw failure;
    return rejection;
  }]));
  const service = createSecureShopBoundCommerce({ repository, catalog: { async prepareTarget() { return target; }, async hasProduct() { return true; } }, personaAuthority: {
    capture(value) { return {
      binding: { ...value.scope, personaId: value.personaId, role: value.role, sessionId: value.sessionId, authorityVersion: value.authorityVersion },
      async assertRemoteAdmission() { checks++; if (revoked && completed) throw Error('authority retired'); },
      async withCrossStoreEffect(work) { try { const result = await work(); completed = true; return result; } catch (cause) { throw Object.assign(Error('uncertain'), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', cause }); } },
    }; },
  } });
  const input = { scope, persona: { id: 41, role: 'customer' }, personaSession: { sessionId: '40000000-0000-4000-8000-000000000001', authorityVersion: '1' }, shippingAddress: 'owned', paymentMethod: 'teaching' };
  await assert.rejects(service.checkout(input), { code: 'INVALID_ARGUMENT' });
  assert.equal(checks, 3);
  rejection = CART_STOCK_REJECTED;
  await assert.rejects(service.checkout(input), { code: 'INVALID_ARGUMENT' });
  for (const phase of ['savepoint', 'rollback', 'commit']) {
    failure = Error(phase); completed = false;
    await assert.rejects(service.checkout(input), error => error.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' && error.cause === failure);
  }
  failure = undefined; completed = false; revoked = true;
  await assert.rejects(service.checkout(input), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' });
});

test('checkout text validation follows authority admission and precedes provisioning or mutation', async () => {
  const events = [];
  let denied = false, repositoryFailure;
  const repository = Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name => [name, async (_, request) => {
    events.push('repository');
    if (repositoryFailure) throw repositoryFailure;
    return request;
  }]));
  const service = createSecureShopBoundCommerce({ repository, catalog: {
    async prepareTarget() { events.push('target'); return target; }, async hasProduct() { return true; },
  }, personaAuthority: { capture(value) { return {
    binding: { ...value.scope, personaId: value.personaId, role: value.role, sessionId: value.sessionId, authorityVersion: value.authorityVersion },
    async assertRemoteAdmission() { events.push('admission'); if (denied) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); },
    async withCrossStoreEffect(work) { events.push('effect'); try { return await work(); } catch (cause) { throw Object.assign(Error('uncertain'), { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', cause }); } },
  }; } } });
  const input = { scope, persona: { id: 41, role: 'customer' }, personaSession: { sessionId: '40000000-0000-4000-8000-000000000001', authorityVersion: '1' }, shippingAddress: 'owned', paymentMethod: 'teaching' };
  for (const [key, limit] of [['shippingAddress',4096],['paymentMethod',256]]) {
    for (const value of ['', ' \n ', null, 12, {}, 'x'.repeat(limit + 1), 'é'.repeat(limit / 2 + 1)]) {
      events.length = 0;
      await assert.rejects(service.checkout({ ...input, [key]: value }), { code: 'INVALID_ARGUMENT' });
      assert.deepEqual(events, ['admission']);
    }
    events.length = 0;
    const value = 'é'.repeat(limit / 2);
    assert.equal((await service.checkout({ ...input, [key]: value }))[key], value);
    assert.deepEqual(events, ['admission','target','admission','effect','repository','admission']);
  }
  denied = true; events.length = 0;
  await assert.rejects(service.checkout({ ...input, shippingAddress: '' }), { code: 'SHOP_AUTH_INVALID' });
  assert.deepEqual(events, ['admission']);
  denied = false; repositoryFailure = Object.assign(Error('possible write'), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(service.checkout(input), error => error.code === 'PERSONA_EFFECT_OUTCOME_UNCERTAIN' && error.cause === repositoryFailure);
});
test('conversational commerce retains private scene and exact arguments under persona effect fence',async()=>{
 const sessionId='40000000-0000-4000-8000-000000000001';let inside=false,called=0;
 const scene=require('../server/services/secureshopSceneBinding').createSceneBinding({...target,platformOwnerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId},
  {sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,grantId:'60000000-0000-4000-8000-000000000001',execution:scope,withLease:work=>work()});
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name=>[name,async()=>null]));
 const args={proposalId:'70000000-0000-4000-8000-000000000001'};
 repository.conversation={async confirmCheckout(actual,request){assert.equal(inside,true);assert.equal(actual,scene);assert.equal(request.proposalId,'70000000-0000-4000-8000-000000000001');assert.equal(request.shopUserId,41);called++;return {status:'declined'};}};
 const authority={capture(value){args.proposalId='70000000-0000-4000-8000-000000000002';return {binding:{...value.scope,personaId:value.personaId,role:value.role,sessionId:value.sessionId,authorityVersion:value.authorityVersion},async assertRemoteAdmission(){},async withCrossStoreEffect(work){inside=true;try{return await work();}finally{inside=false;}}};}};
 const service=createSecureShopBoundCommerce({repository,personaAuthority:authority,resolveExistingTarget:async()=>scene,catalog:{prepareTarget(){throw Error('Must not prepare');},hasProduct(){throw Error('Must not check a model ID');}}});
 const input={scope,persona:{id:41,role:'customer'},personaSession:{sessionId,authorityVersion:'1'},method:'confirmCheckout',args};
 assert.deepEqual(await service.conversational(input),{status:'declined'});assert.equal(called,1);
 await assert.rejects(service.conversational({...input,persona:{id:41,role:'merchant'}}),{code:'OWNER_MISMATCH'});
 await assert.rejects(service.conversational({...input,apiAuthority:{}}),{code:'SERVICE_UNAVAILABLE'});
 assert.equal(called,1);
});
test('profile form uses trusted persona fallback and rejects a switched scene before save',async()=>{
 const scene=require('../server/services/secureshopSceneBinding').createSceneBinding(target,
  {sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,
   grantId:'60000000-0000-4000-8000-000000000001',execution:scope,withLease:work=>work()});
 let reads=0,writes=0,authorityChecks=0;
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name=>[name,async()=>null]));
 repository.conversation={async profileForm(_target,args){reads++;assert.deepEqual(args.canonicalProfile,
   {fullName:' Retained ',email:'legacy@example.test',phone:null});return {version:1,fields:args.canonicalProfile,
    expectedSnapshotSha256:'b'.repeat(64),scopeKey:'a'.repeat(64)};},
  async saveProfile(_target,args){writes++;assert.equal(args.expectedScopeKey,'a'.repeat(64));
   return {scopeKey:'a'.repeat(64),status:'completed'};}};
 const service=createSecureShopBoundCommerce({repository,personaRepository:{async readPersona(){return {
   id:41,email:'legacy@example.test',full_name:' Retained ',phone:null};}},
  personaAuthority:{capture(value){return {binding:{...value.scope,personaId:value.personaId,role:value.role,
   sessionId:value.sessionId,authorityVersion:value.authorityVersion},
   async assertRemoteAdmission(){authorityChecks++;},async withCrossStoreEffect(work){return work();}};}},
  resolveExistingTarget:async()=>scene,catalog:{prepareTarget(){throw Error('No provisioning');},hasProduct(){return true;}}});
 const input={scope,persona:{id:41,role:'customer'},personaSession:{sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'}};
 const expectedTarget={targetId:scene.targetId,sceneId:scene.scene.sceneId,
  sceneGeneration:scene.scene.sceneGeneration,grantId:scene.scene.grantId};
 const form=await service.conversational({...input,method:'profileForm',args:{},expectedTarget});
 assert.equal(form.fields.fullName,' Retained ');assert.equal(reads,1);assert.ok(authorityChecks>=3);
 await assert.rejects(service.conversational({...input,method:'saveProfile',args:{operationId:'70000000-0000-4000-8000-000000000001',
  expectedSnapshotSha256:'b'.repeat(64),fields:{fullName:'Next',email:'legacy@example.test',phone:null}},
  expectedTarget:{...expectedTarget,sceneId:'50000000-0000-4000-8000-000000000002'},expectedScopeKey:'a'.repeat(64)}),
  {code:'SHOP_SCENE_STALE'});
 assert.equal(writes,0);
});
test('profile save reads canonical persona before the cross-store effect lock',async()=>{
 const scene=require('../server/services/secureshopSceneBinding').createSceneBinding(target,
  {sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,
   grantId:'60000000-0000-4000-8000-000000000001',execution:scope,withLease:work=>work()});
 const events=[];let effectHeld=false;
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder']
  .map(name=>[name,async()=>null]));
 repository.conversation={async saveProfile(actual,args){
  events.push('save');assert.equal(effectHeld,true);assert.equal(actual,scene);
  assert.deepEqual(args.canonicalProfile,{fullName:'Owned',email:'owned@example.test',phone:null});
  assert.equal(args.expectedScopeKey,'a'.repeat(64));return {scopeKey:'a'.repeat(64),status:'completed'};
 }};
 const service=createSecureShopBoundCommerce({repository,
  personaRepository:{async readPersona(){events.push('persona');assert.equal(effectHeld,false);
   return{id:41,full_name:'Owned',email:'owned@example.test',phone:null};}},
  personaAuthority:{capture(value){return{binding:{...value.scope,personaId:value.personaId,role:value.role,
   sessionId:value.sessionId,authorityVersion:value.authorityVersion},
   async assertRemoteAdmission(){assert.equal(effectHeld,false,'remote admission would self-lock inside the effect');events.push('admission');},
   async withCrossStoreEffect(work){events.push('effect');effectHeld=true;
    try{return await work();}finally{effectHeld=false;events.push('release');}}};}},
  resolveExistingTarget:async()=>scene,catalog:{prepareTarget(){throw Error('No provisioning');},hasProduct(){return true;}}});
 const input={scope,persona:{id:41,role:'customer'},
  personaSession:{sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'},
  method:'saveProfile',expectedTarget:{targetId:scene.targetId,sceneId:scene.scene.sceneId,
   sceneGeneration:scene.scene.sceneGeneration,grantId:scene.scene.grantId},expectedScopeKey:'a'.repeat(64),
  args:{operationId:'70000000-0000-4000-8000-000000000001',expectedSnapshotSha256:'b'.repeat(64),
   fields:{fullName:'Next',email:'owned@example.test',phone:null}}};
 assert.equal((await service.conversational(input)).status,'completed');
 assert.equal(events.filter(event=>event==='persona').length,1);
 assert.ok(events.indexOf('persona')<events.indexOf('effect'));
 assert.deepEqual(events.slice(-3),['save','release','admission']);
});
test('conversational recovery reads keep current authority without entering the mutation uncertainty fence',async()=>{
 const facade=require('../server/services/secureshopConversationalCommerce').createConversationalCommerce;
 const sessionId='40000000-0000-4000-8000-000000000001',operationId='70000000-0000-4000-8000-000000000001';
 const scene=require('../server/services/secureshopSceneBinding').createSceneBinding(target,
  {sceneId:'50000000-0000-4000-8000-000000000001',sceneGeneration:1,
   grantId:'60000000-0000-4000-8000-000000000001',execution:scope,withLease:work=>work()});
 let effects=0,checks=0,revoked=false,reads=0;
 const foreign=Object.assign(Error('foreign operation'),{code:'COMMERCE_OPERATION_CONFLICT'});
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(name=>[name,async()=>null]));
 repository.conversation={
  async readOperation(actual,request){assert.equal(actual,scene);assert.equal(request.operationId,operationId);reads++;throw foreign;},
  async readTurnOperations(actual){assert.equal(actual,scene);reads++;revoked=true;return {operations:[]};},
 };
 const service=createSecureShopBoundCommerce({repository,resolveExistingTarget:async()=>scene,
  catalog:{prepareTarget(){throw Error('Recovery cannot provision a target');},hasProduct(){throw Error('Recovery cannot select a product');}},
  personaAuthority:{capture(value){return{binding:{...value.scope,personaId:value.personaId,role:value.role,
   sessionId:value.sessionId,authorityVersion:value.authorityVersion},
   async assertRemoteAdmission(){checks++;if(revoked)throw Object.assign(Error('retired'),{code:'SHOP_AUTH_INVALID'});},
   async withCrossStoreEffect(){effects++;throw Error('Read entered effect boundary');}};}}});
 const input={scope,persona:{id:41,role:'customer'},personaSession:{sessionId,authorityVersion:'1'}};
 await assert.rejects(facade({commerce:service}).readOperation({...input,args:{operationId}}),error=>
  error===foreign&&error.code==='COMMERCE_OPERATION_CONFLICT');
 assert.equal(checks,3);assert.equal(effects,0);
 await assert.rejects(service.conversational({...input,method:'readTurnOperations',args:{sessionId,requestId:operationId}}),
  {code:'SHOP_AUTH_INVALID'});
 assert.equal(reads,2);assert.equal(effects,0);
});
