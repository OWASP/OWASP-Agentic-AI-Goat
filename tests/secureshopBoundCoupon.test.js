'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');const {createBoundCoupon}=require('../server/services/secureshopBoundCoupon');
const {POLICIES}=require('../server/services/secureshopFeatureModeAuthority');
function fixture(){const events=[],scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona={id:3,role:'customer'},personaSession={sessionId:randomUUID(),authorityVersion:'1'},input={target:{...scope,targetId:randomUUID()},persona,personaSession,operationId:randomUUID(),code:"' OR 1=1--"};let prior=null,revoked=false,admissionFails=false;
 const fence={binding:{...scope,personaId:3,role:'customer',...personaSession},async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_REVOKED'});},async withCrossStoreEffect(fn){events.push('fence');return fn();}};
 const repository={recover:async()=>prior,async admitCoupon(raw){events.push('admit');if(admissionFails)throw Error('uncertain admission');prior={state:'admitted',request:{code:raw.code}};return prior;},async completeCoupon(){events.push('persist');return{ok:true};}};
 const service={async provision(){events.push('provision');},async lookupCoupon(){events.push('lookup');return{};}};
 const workflow=createBoundCoupon({repository,service,readCoupons:async()=>[{id:1,code:'WELCOME10',discount_percent:10,active:1}],checkCurrent:async()=>{},mode:'vuln'});
 return{workflow,input,fence,events,repository,service,set prior(v){prior=v;},set revoked(v){revoked=v;},set admissionFails(v){admissionFails=v;}};
}
test('canonical debt commits before remote creation; no remote work on uncertain admission',async()=>{const f=fixture();await f.workflow.apply(f.input,{fence:f.fence});assert.deepEqual(f.events,['fence','admit','provision','lookup','fence','persist']);const failed=fixture();failed.admissionFails=true;await assert.rejects(failed.workflow.apply(failed.input,{fence:failed.fence}));assert.deepEqual(failed.events,['fence','admit']);});
test('completed replay avoids remote SQL and cannot restore an older coupon',async()=>{const f=fixture();f.prior={state:'completed',request:{code:f.input.code},result:{ok:true,code:'OLD'}};assert.equal((await f.workflow.apply(f.input,{fence:f.fence})).code,'OLD');assert.deepEqual(f.events,[]);await assert.rejects(f.workflow.apply({...f.input,code:'changed'},{fence:f.fence}),{code:'COMMERCE_OPERATION_CONFLICT'});});
test('revocation after remote lookup prevents local coupon persistence',async()=>{const f=fixture();f.service.lookupCoupon=async()=>{f.revoked=true;return{};};await assert.rejects(f.workflow.apply(f.input,{fence:f.fence}),{code:'SHOP_AUTH_REVOKED'});assert.ok(!f.events.includes('persist'));});
test('middleware session expiry metadata does not change canonical coupon authority',async()=>{const f=fixture();await f.workflow.apply({...f.input,personaSession:{...f.input.personaSession,expiresAt:'2099-01-01T00:00:00.000Z'}},{fence:f.fence});assert.ok(f.events.includes('persist'));});
test('coupon still rejects wrong canonical session, version and owner before effects',async()=>{for(const change of [{personaSession:{sessionId:randomUUID(),authorityVersion:'1'}},{personaSession:{sessionId:null,authorityVersion:'2'}},{target:{platformOwnerId:99}}]){const f=fixture(),input={...f.input,...change};if(change.personaSession?.sessionId===null)input.personaSession.sessionId=f.input.personaSession.sessionId;if(change.target)input.target={...f.input.target,...change.target};await assert.rejects(f.workflow.apply(input,{fence:f.fence}),{code:'SHOP_AUTH_INVALID'});assert.deepEqual(f.events,[]);}});

test('confirmed coupon checks both original modes inside each durable boundary and replays without remote lookup',async()=>{
 const f=fixture(),scope={launchId:f.input.target.launchId,scenarioId:f.input.target.scenarioId,generation:f.input.target.generation,platformOwnerId:f.input.target.platformOwnerId,platformSessionId:f.input.target.platformSessionId};
 let current=true,modeChecks=0,admissions=0,completions=0,prior=null;const owned=new WeakSet();
 const makeToken=featureId=>{const value=Object.freeze({snapshot:Object.freeze({featureId,policyVersion:POLICIES[featureId],mode:'vuln',scope}),
  async assertCurrent(){if(!current)throw Error('stale');},async assertCurrentAtEffect(){modeChecks++;if(!current)throw Error('stale');}});owned.add(value);return value;};
 const customerMode=makeToken('customer_chat'),couponMode=makeToken('coupons');
 const repository={async recover(raw,_kind,atEffect){await atEffect();return prior;},async admitCoupon(raw,atEffect){await atEffect();admissions++;prior={state:'admitted',request:{code:raw.code,mode:raw.mode}};await atEffect();return prior;},
  async completeCoupon(raw,{atEffect}){await atEffect();completions++;prior={...prior,state:'completed',result:{ok:true}};await atEffect();return prior.result;}};
 const workflow=createBoundCoupon({repository,service:f.service,readCoupons:async()=>[{id:1,code:'WELCOME10',discount_percent:10,active:1}],checkCurrent:async()=>{},mode:'vuln',
  modeAuthority:{assertToken(value){if(!owned.has(value))throw Error('unbranded');return value;}}});
 const options={fence:f.fence,customerMode,couponMode,async checkCurrent(){if(!current)throw Error('stale');},
  async withSelectedSceneEffect(work){return work();}};
 assert.deepEqual(await workflow.applyConfirmed(f.input,options),{ok:true});assert.equal(admissions,1);assert.equal(completions,1);assert.ok(modeChecks>=10);
 const remoteCount=f.events.length;assert.deepEqual(await workflow.applyConfirmed(f.input,options),{ok:true});assert.equal(f.events.length,remoteCount);
 await assert.rejects(workflow.applyConfirmed(f.input,{...options,customerMode:couponMode}),{code:'COMMERCE_MODE_CHANGED'});
 current=false;await assert.rejects(workflow.applyConfirmed(f.input,options));assert.equal(completions,1);
});

test('confirmed saved coupon read is SELECT-only and withholds admitted debt',async()=>{
 const f=fixture(),scope={launchId:f.input.target.launchId,scenarioId:f.input.target.scenarioId,
  generation:f.input.target.generation,platformOwnerId:f.input.target.platformOwnerId,
  platformSessionId:f.input.target.platformSessionId};
 const owned=new WeakSet(),makeToken=featureId=>{const value=Object.freeze({
  snapshot:Object.freeze({featureId,policyVersion:POLICIES[featureId],mode:'vuln',scope}),
  async assertCurrent(){},async assertCurrentAtEffect(){checks++;}});owned.add(value);return value;};
 let checks=0,reads=0,prior=null,leases=0;
 const workflow=createBoundCoupon({repository:{
  async recover(_raw,_kind,atEffect){reads++;await atEffect();return prior;},
  async admitCoupon(){throw Error('GET cannot admit');},async completeCoupon(){throw Error('GET cannot complete');}},
 service:{async provision(){throw Error('GET cannot provision');},async lookupCoupon(){throw Error('GET cannot call remote');}},
 readCoupons:async()=>{throw Error('GET cannot list coupons');},checkCurrent:async()=>{},mode:'vuln',
 modeAuthority:{assertToken(value){if(!owned.has(value))throw Error('unbranded');return value;}}});
 const options={fence:f.fence,customerMode:makeToken('customer_chat'),couponMode:makeToken('coupons'),
  async checkCurrent(){},async withSelectedSceneEffect(work){leases++;return work();}};
 assert.equal(await workflow.readConfirmed(f.input,options),null);
 prior={state:'admitted',request:{operationId:f.input.operationId,code:f.input.code,mode:'vuln'},result:null};
 assert.equal(await workflow.readConfirmed(f.input,options),null);
 prior={...prior,state:'completed',result:{ok:false,error:'coupon not found'}};
 assert.deepEqual(await workflow.readConfirmed(f.input,options),prior);
 assert.equal(reads,3);assert.equal(leases,3);assert.ok(checks>=6);
 prior={...prior,request:{...prior.request,code:'changed'}};
 await assert.rejects(workflow.readConfirmed(f.input,options),{code:'COMMERCE_OPERATION_CONFLICT'});
});

test('confirmed admission holds selected-scene lease through local debt and rejects a later scene switch before remote work',async()=>{
 const f=fixture(),scope={launchId:f.input.target.launchId,scenarioId:f.input.target.scenarioId,generation:f.input.target.generation,platformOwnerId:f.input.target.platformOwnerId,platformSessionId:f.input.target.platformSessionId};
 const owned=new WeakSet(),makeToken=featureId=>{const value=Object.freeze({snapshot:Object.freeze({featureId,policyVersion:POLICIES[featureId],mode:'vuln',scope}),
  async assertCurrent(){},async assertCurrentAtEffect(){}});owned.add(value);return value;};
 let selected='original',held=false,releaseDebt,enteredDebt,releaseScene;const debtEntered=new Promise(resolve=>{enteredDebt=resolve;});
 const debtWait=new Promise(resolve=>{releaseDebt=resolve;});const sceneWait=new Promise(resolve=>{releaseScene=resolve;});
 const repository={async recover(){return null;},async admitCoupon(raw,atEffect){await atEffect();enteredDebt();await debtWait;await atEffect();return{state:'admitted',request:{code:raw.code,mode:raw.mode}};},
  async completeCoupon(){throw Error('completion must not run');}};
 const workflow=createBoundCoupon({repository,service:f.service,readCoupons:async()=>[{id:1,code:'WELCOME10',discount_percent:10,active:1}],checkCurrent:async()=>{},mode:'vuln',
  modeAuthority:{assertToken(value){if(!owned.has(value))throw Error('unbranded');return value;}}});
 const options={fence:f.fence,customerMode:makeToken('customer_chat'),couponMode:makeToken('coupons'),
  async checkCurrent(){if(selected!=='original')throw Error('scene switched');},
  async withSelectedSceneEffect(work){assert.equal(held,false);assert.equal(selected,'original');held=true;try{return await work();}
   finally{held=false;releaseScene();}}};
 const ongoing=workflow.applyConfirmed(f.input,options);
 await debtEntered;let switched=false;const switchScene=sceneWait.then(()=>{selected='replacement';switched=true;});
 assert.equal(held,true);assert.equal(switched,false);
 releaseDebt();await switchScene;await assert.rejects(ongoing,/scene switched/);
 assert.equal(f.events.includes('provision'),false,'no sidecar call follows a selected-scene switch');
});
