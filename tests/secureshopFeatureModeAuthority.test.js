'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createFeatureModeAuthority,captureFeatureMode,guardFeatureFence}=require('../server/services/secureshopFeatureModeAuthority');
function fixture(mode='vuln'){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8};
 let current={mode,generation:0,modeStamp:'first'},live=true;
 const authority=createFeatureModeAuthority({progress:{async getEvaluationScope(id,key){assert.equal(id,7);assert.equal(key,'secureshop_agent_security');return {...current};}},launches:{async assertCurrent(value){assert.deepEqual(value,scope);if(!live)throw Object.assign(Error('revoked'),{code:'SESSION_UNAVAILABLE'});}}});
 return {scope,authority,set current(value){current=value;},get current(){return current;},set live(value){live=value;}};
}
test('feature tokens bind owner, session, launch and policy without accepting caller mode',async()=>{
 const f=fixture('fixed'),token=await f.authority.capture({...f.scope,mode:'vuln'},'mail');
 assert.equal(token.snapshot.mode,'fixed');assert.equal(token.snapshot.featureId,'mail');
 assert.equal(token.snapshot.generation,0);assert.equal(token.snapshot.scope.generation,1);
 assert.equal(Object.isFrozen(token.snapshot.scope),true);assert.equal(f.authority.assertToken(token),token);
 assert.throws(()=>f.authority.assertToken({...token}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 await assert.rejects(f.authority.capture(f.scope,'whole-shop'),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 await assert.rejects(f.authority.capture({...f.scope,platformOwnerId:9},'mail'));
});
test('same-mode stamp and session revocation invalidate captured feature authority',async()=>{
 const f=fixture(),token=await f.authority.capture(f.scope,'coupons');
 await token.assertCurrent();f.current={...f.current,modeStamp:'second'};
 await assert.rejects(token.assertCurrent(),{code:'ANALYTICS_MODE_STALE'});
 const next=await f.authority.capture(f.scope,'coupons');f.live=false;
 await assert.rejects(next.assertCurrent(),{code:'SESSION_UNAVAILABLE'});
});
test('ticket rendering uses current branded mode and refuses stale or forged tokens',async()=>{
 const f=fixture('fixed');
 const token=await captureFeatureMode(f.authority,{...f.scope,mode:'vuln'},'support_tickets');
 assert.equal(token.snapshot.mode,'fixed');
 assert.equal(token.snapshot.policyVersion,'owned-ticket-render-v1');
 assert.throws(()=>f.authority.assertToken({...token}),{code:'SECURESHOP_FEATURE_MODE_STALE'});
 await token.assertCurrent();
 f.current={mode:'vuln',generation:1,modeStamp:'ticket-mode-changed'};
 await assert.rejects(token.assertCurrent(),{code:'ANALYTICS_MODE_STALE'});
 const current=await captureFeatureMode(f.authority,f.scope,'support_tickets');
 assert.equal(current.snapshot.mode,'vuln');
 f.live=false;
 await assert.rejects(current.assertCurrent(),{code:'SESSION_UNAVAILABLE'});
});
test('System diagnostic has a distinct canonical mode policy and stale epoch fence',async()=>{
 const f=fixture('fixed');
 const token=await captureFeatureMode(f.authority,f.scope,'system_diagnostic');
 assert.equal(token.snapshot.featureId,'system_diagnostic');
 assert.equal(token.snapshot.policyVersion,'owned-system-diagnostic-shell-v1');
 assert.equal(token.snapshot.mode,'fixed');
 f.current={...f.current,mode:'vuln',modeStamp:'changed'};
 await assert.rejects(token.assertCurrent(),{code:'ANALYTICS_MODE_STALE'});
});
test('isolated customer IDOR uses canonical mode and rejects stale effect dispatch',async()=>{
 const f=fixture('fixed');
 const token=await captureFeatureMode(f.authority,{...f.scope,mode:'vuln'},'customer_idor');
 assert.equal(token.snapshot.mode,'fixed');
 assert.equal(token.snapshot.policyVersion,'reserved-synthetic-cart-and-order-ownership-v1');
 let effects=0;
 const fence=guardFeatureFence({async assertRemoteAdmission(){},async withCrossStoreEffect(work){effects++;return work();}},token);
 await fence.withCrossStoreEffect(async()=>{});assert.equal(effects,1);
 f.current={...f.current,modeStamp:'changed'};
 await assert.rejects(fence.withCrossStoreEffect(async()=>{}),{code:'ANALYTICS_MODE_STALE'});
 assert.equal(effects,1);
});
test('feature effect fence rejects stale dispatch and preserves uncertainty after a committed effect',async()=>{
 const f=fixture(),token=await f.authority.capture(f.scope,'pricing');let effects=0;
 const fence=guardFeatureFence({binding:{},async assertRemoteAdmission(){},async withCrossStoreEffect(work){effects++;return work();}},token);
 f.current={...f.current,mode:'fixed'};
 await assert.rejects(fence.withCrossStoreEffect(async()=>1),{code:'ANALYTICS_MODE_STALE'});assert.equal(effects,0);
 const fresh=guardFeatureFence({binding:{},async assertRemoteAdmission(){},async withCrossStoreEffect(work){effects++;return work();}},await f.authority.capture(f.scope,'pricing'));
 await assert.rejects(fresh.withCrossStoreEffect(async()=>{f.current={...f.current,modeStamp:'changed'};return 2;}),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN'});assert.equal(effects,1);
});
test('null fixture authority preserves explicit mode while configured failures never fall back',async()=>{
 const f=fixture();assert.equal((await captureFeatureMode(null,f.scope,'coupons','fixed')).snapshot.mode,'fixed');
 await assert.rejects(captureFeatureMode({capture:async()=>{throw Error('unavailable');},assertToken:v=>v},f.scope,'mail','vuln'),/unavailable/);
});
test('mode change while persona effect waits for its lock rejects before the callback',async()=>{
 const f=fixture(),token=await f.authority.capture(f.scope,'mail');let admitted,release,effects=0;
 const waiting=new Promise(resolve=>{admitted=resolve;}),gate=new Promise(resolve=>{release=resolve;});
 const fence=guardFeatureFence({async assertRemoteAdmission(){},async withPersonaEffect(work){admitted();await gate;return work({});}},token);
 const result=fence.withPersonaEffect(async()=>{effects++;});await waiting;
 f.current={...f.current,mode:'fixed',modeStamp:'after-lock-wait'};release();
 await assert.rejects(result,{code:'ANALYTICS_MODE_STALE'});assert.equal(effects,0);
});
test('effect callback recheck uses the nonlocking canonical snapshot seam',async()=>{
 const f=fixture();let normal=0,effect=0,inside=false;
 const token={async assertCurrent(){assert.equal(inside,false);normal++;},async assertCurrentAtEffect(){assert.equal(inside,true);effect++;}};
 const fence=guardFeatureFence({async assertRemoteAdmission(){},async withPersonaEffect(work){inside=true;try{return await work({});}finally{inside=false;}}},token);
 assert.equal(await fence.withPersonaEffect(async()=>42),42);assert.equal(normal,2);assert.equal(effect,1);
});
test('coupon effect uses canonical fixed selection and cannot replay a vulnerable receipt as fixed',async()=>{
 const f=fixture('fixed'),{createBoundCoupon}=require('../server/services/secureshopBoundCoupon');let admission,lookups=0,prior;
 const persona={id:3,role:'customer'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const input={target:{...f.scope,targetId:randomUUID()},persona,personaSession,operationId:randomUUID(),code:"' OR 1=1--",mode:'vuln'};
 const fence={binding:{...f.scope,personaId:3,role:'customer',...personaSession},async assertRemoteAdmission(){},async withCrossStoreEffect(work){return work();}};
 const workflow=createBoundCoupon({mode:'vuln',modeAuthority:f.authority,checkCurrent:async()=>{},readCoupons:async()=>[{id:1,code:'WELCOME10',discount_percent:10,active:1}],repository:{recover:async()=>prior,admitCoupon:async raw=>{admission=raw;return {request:raw};},completeCoupon:async()=>({ok:true})},service:{provision:async()=>{},lookupCoupon:async request=>{lookups++;assert.equal(request.mode,'fixed');return {};}}});
 await workflow.apply(input,{fence});assert.equal(admission.mode,'fixed');assert.equal(lookups,1);
 prior={state:'completed',request:{code:input.code,mode:'vuln'},result:{ok:true}};
 await assert.rejects(workflow.apply(input,{fence}),{code:'COMMERCE_OPERATION_CONFLICT'});assert.equal(lookups,1);
});
