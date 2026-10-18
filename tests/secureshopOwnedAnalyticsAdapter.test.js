'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createOwnedAnalyticsAdapter}=require('../server/services/secureshopOwnedAnalyticsAdapter');
function fixture({foreign=false,revoked=false}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const persona={id:3,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const target={targetId:randomUUID(),scope,sourceManifestSha256:'a'.repeat(64)};let executed=0,inside=false;
 const adapter=createOwnedAnalyticsAdapter({schema:'products(id integer)',launches:{assertCurrent:async()=>{}},personaAuthority:{capture:async()=>({binding:{...scope,personaId:3,role:'merchant',...personaSession},assertRemoteAdmission:async()=>{assert.equal(inside,false,'persona lock must not be reacquired inside cross-store transaction');if(revoked)throw Error('revoked');},withCrossStoreEffect:async work=>{inside=true;try{return await work();}finally{inside=false;}}})},targetService:{resolve:async()=>foreign?{...target,targetId:randomUUID()}:target,execute:async input=>{assert.equal(inside,true);executed++;return input;}}});
 const input={target,scope,persona,personaSession,signal:undefined,checkCurrent:async()=>{assert.equal(inside,false,'caller current check may acquire the same persona lock');},operationId:randomUUID(),runId:randomUUID(),requestId:randomUUID(),sessionId:randomUUID(),callId:'query-1',sql:'SELECT * FROM shop_users'};
 return {adapter,input,executed:()=>executed};
}
test('owned query dispatch is within original credential cross-store fence and preserves raw SQL',async()=>{
 const f=fixture(),result=await f.adapter.execute(f.input);assert.equal(result.sql,f.input.sql);assert.equal(f.executed(),1);assert.equal(Object.hasOwn(result,'persona'),false);
});
test('valid foreign target UUID and revoked original credential reject before SQL dispatch',async()=>{
 for(const options of [{foreign:true},{revoked:true}]){const f=fixture(options);await assert.rejects(f.adapter.execute(f.input));assert.equal(f.executed(),0);}
});

function chartFixture({role='merchant',onProvision,receiptTarget,revoked=false,stale=false,staleAfterProvision=false}={}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const persona={id:3,role},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const target={targetId:randomUUID(),scope,sourceManifestSha256:'a'.repeat(64)};
 const calls={provision:0,chart:0,resolve:0,execute:0,current:0,remote:0,locks:0},controller=new AbortController();let inside=false;
 const adapter=createOwnedAnalyticsAdapter({schema:'products(id integer)',launches:{assertCurrent:async()=>{calls.current++;if(stale||staleAfterProvision&&calls.provision>0)throw Object.assign(Error('stale'),{code:'STALE_LAUNCH'});}},personaAuthority:{capture:async()=>({binding:{...scope,personaId:persona.id,role,...personaSession},assertRemoteAdmission:async()=>{assert.equal(inside,false);calls.remote++;if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});},withCrossStoreEffect:async work=>{calls.locks++;inside=true;try{return await work();}finally{inside=false;}}})},targetService:{provision:async value=>{assert.equal(inside,true);assert.equal(value,scope);calls.provision++;await onProvision?.(controller);return target;},topProducts:async(value,limit)=>{assert.equal(inside,true);assert.equal(value,scope);assert.equal(limit,8);calls.chart++;return {...(receiptTarget||target),rows:[{id:1,name:'Owned product',revenue:'12.50'}]};},resolve:async()=>{calls.resolve++;throw Error('chart must not resolve before provision');},execute:async()=>{calls.execute++;throw Error('chart must not execute a model query');}}});
 const input={scope,persona,personaSession,limit:8,signal:controller.signal,checkCurrent:async()=>{assert.equal(inside,false);}};
 return {adapter,input,calls,controller,target};
}
test('first, repeated, and concurrent chart reads provision the exact owner target without a model query',async()=>{
 const f=chartFixture();for(const result of await Promise.all([f.adapter.topProducts(f.input),f.adapter.topProducts(f.input)]))assert.deepEqual(result.rows,[{id:1,name:'Owned product',revenue:'12.50'}]);
 assert.deepEqual((await f.adapter.topProducts(f.input)).rows,[{id:1,name:'Owned product',revenue:'12.50'}]);
 assert.deepEqual({provision:f.calls.provision,chart:f.calls.chart,resolve:f.calls.resolve,execute:f.calls.execute,locks:f.calls.locks},{provision:3,chart:3,resolve:0,execute:0,locks:3});
 assert.ok(f.calls.current>=6);assert.ok(f.calls.remote>=6);
});
test('chart admission rejects role, limit, revoked persona, stale launch, and abort before provisioning',async()=>{
 for(const options of [{role:'customer'},{revoked:true},{stale:true}]){const f=chartFixture(options);await assert.rejects(f.adapter.topProducts(f.input));assert.equal(f.calls.provision,0);assert.equal(f.calls.chart,0);}
 for(const limit of [0,26,1.5]){const f=chartFixture();await assert.rejects(f.adapter.topProducts({...f.input,limit}),{code:'ANALYTICS_TARGET_INVALID'});assert.equal(f.calls.provision,0);}
 const aborted=chartFixture();aborted.controller.abort();await assert.rejects(aborted.adapter.topProducts(aborted.input));assert.equal(aborted.calls.provision,0);
});
test('chart provision failure, foreign target, mismatched receipt and mid-provision abort never dispatch an untrusted chart',async()=>{
 for(const state of ['pending','retiring']){const failure=chartFixture({onProvision:()=>{throw Object.assign(Error(state),{code:'ANALYTICS_TARGET_UNAVAILABLE'});}});await assert.rejects(failure.adapter.topProducts(failure.input),{code:'ANALYTICS_TARGET_UNAVAILABLE'});assert.equal(failure.calls.chart,0);}
 const foreign=chartFixture({onProvision:()=>{}});const original=foreign.target;foreign.target.scope={...foreign.input.scope,platformOwnerId:99};await assert.rejects(foreign.adapter.topProducts(foreign.input),{code:'ANALYTICS_TARGET_INVALID'});assert.equal(foreign.calls.chart,0);foreign.target.scope=original.scope;
 const aborted=chartFixture({onProvision:controller=>controller.abort()});await assert.rejects(aborted.adapter.topProducts(aborted.input));assert.equal(aborted.calls.chart,0);
 const stale=chartFixture({staleAfterProvision:true});await assert.rejects(stale.adapter.topProducts(stale.input),{code:'STALE_LAUNCH'});assert.equal(stale.calls.chart,0);
 const mismatch=chartFixture({receiptTarget:{targetId:randomUUID(),scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},sourceManifestSha256:'b'.repeat(64)}});await assert.rejects(mismatch.adapter.topProducts(mismatch.input),{code:'ANALYTICS_RECEIPT_MISMATCH'});assert.equal(mismatch.calls.chart,1);
});
