'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');const c=require('../server/services/secureshopCouponContract');
const coupons=[{id:1,code:'WELCOME10',discount_percent:10,active:1},{id:2,code:'OFF',discount_percent:100,active:0}];
test('canonical seeded inactive empty coupon remains in the bank but cannot be selected',()=>{
 const rows=require('../db/postgres/seeds/secureshop.json').coupons.map(({id,code,discount_percent,active})=>({id,code,discount_percent,active}));
 const inactive=rows.find(row=>row.code===''&&row.active===0);assert(inactive);
 assert.deepEqual(c.bank(rows),rows.slice().sort((a,b)=>a.id-b.id));
 assert.throws(()=>c.bank([{...inactive,active:1}]),{code:'COUPON_INVALID'});
 assert.throws(()=>c.selected([inactive],rows),{code:'COUPON_RESULT_INVALID'});
 for(const mode of ['vuln','fixed'])assert.deepEqual(JSON.parse(c.statement({...input(),mode,code:'WELCOME10',coupons:rows}).values[0]),rows);
});
function input(){return{scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},operationId:randomUUID(),persona:{id:3,role:'customer'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',code:"' OR 1=1--",coupons};}
test('actual SQL predicate sink retains bypass while fixed statement binds exact input',()=>{const raw=input(),v=c.statement(raw),f=c.statement({...raw,mode:'fixed'});assert.match(v.text,/code='' OR 1=1--'/);assert.equal(v.values.length,1);assert.ok(!f.text.includes(raw.code));assert.equal(f.values[1],raw.code);assert.deepEqual(JSON.parse(f.values[0]),coupons);});
test('selected legitimate active coupon need not equal injected code; fabricated and inactive rows fail',()=>{assert.deepEqual(c.selected([coupons[0]],coupons),coupons[0]);assert.throws(()=>c.selected([coupons[1]],coupons));assert.throws(()=>c.selected([{...coupons[0],discount_percent:100}],coupons));assert.equal(c.selected([],coupons),null);});
test('cent arithmetic handles zero/full discounts, half-cent ties and stable multi-line allocation',()=>{assert.deepEqual(c.money([1,1,1],50),{subtotalCents:3,discountCents:2,totalCents:1,lineDiscountCents:[1,1,0]});assert.deepEqual(c.money([101,203,307],0).lineDiscountCents,[0,0,0]);assert.deepEqual(c.money([101,203,307],100).lineDiscountCents,[101,203,307]);assert.equal(c.money([5],10).discountCents,1);for(let p=0;p<=100;p++){const r=c.money([100*3,501*2,999*99],p);assert.equal(r.lineDiscountCents.reduce((a,b)=>a+b),r.discountCents);assert.equal(r.totalCents+r.discountCents,r.subtotalCents);}const large=c.money([9999999999*99*256],99);assert.ok(Number.isSafeInteger(large.totalCents));});
test('closed snapshots reject authority fields, getters and invalid discounts without evaluation',()=>{const raw=input();assert.throws(()=>c.lookup({...raw,targetId:randomUUID()}));let reads=0;const row={...coupons[0]};Object.defineProperty(row,'code',{get(){reads++;return'x';}});assert.throws(()=>c.bank([row]));assert.equal(reads,0);assert.throws(()=>c.bank([{...coupons[0],discount_percent:101}]));});
