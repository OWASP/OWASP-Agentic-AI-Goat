'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopBoundCommerceRepository}=require('../server/database/postgres/secureshopBoundCommerceRepository');
const {createSecureShopBoundCommerce}=require('../server/services/secureshopBoundCommerce');
const scope={targetId:'30000000-0000-4000-8000-000000000001',launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:7,platformSessionId:8};
test('recommendations parameterize owner/target, project local ranking provenance, and fence return',async()=>{
 const queries=[];let checks=0,retired=false;
 const client={async query(sql,args){queries.push([sql,args]);if(sql.includes('FROM secureshop_review.product_targets'))return {rows:[{lifecycle:'active'}]};if(sql.includes('WITH effective'))return {rows:[{id:'3',name:'Current overlay',price:'0.00',category:'Books',image_url:null,affinity_score:'2',private:'secret'},{id:'4',name:'Fallback',price:'2',category:'Other',affinity_score:'0'}]};return {rows:[]};},release(){}};
 const repository=createSecureShopBoundCommerceRepository({query(){},async connect(){return client;}},{checkCurrent:async()=>{checks++;if(retired&&checks%2===0)throw Error('retired');}});
 const result=await repository.recommendations(scope,41);
 assert.equal(checks,2);assert.equal(result.feed[0].price,0);assert.equal(result.feed[0].private,undefined);
 assert.deepEqual(result.feed.map(x=>x.recommendation_reason),['owned_category_affinity','catalog_fallback']);assert.equal(result.provenance.modelUsed,false);
 const [sql,args]=queries.find(([sql])=>sql.includes('WITH effective'));assert.deepEqual(args,[scope.targetId,41]);
 for(const fragment of ['h.shop_user_id=$2','c.shop_user_id=$2','h.target_id=$1','p.target_id=$1',"h.status <> 'cancelled'", "h.payment_status='approved'",'e.archived_at IS NULL','e.stock_quantity>0','LIMIT 6']) assert.ok(sql.includes(fragment),fragment);
 retired=true;await assert.rejects(repository.recommendations(scope,41),/retired/);assert.equal(queries.at(-1)[0],'ROLLBACK');
 assert.throws(()=>repository.recommendations(scope,'42'),{code:'INVALID_ARGUMENT'});
});
test('recommendations use current customer session and discard results after session revocation',async()=>{
 let reads=0,revoked=false;
 const repository=Object.fromEntries(['listCart','addCart','updateCart','removeCart','checkout','listOrders','getOrder'].map(k=>[k,async()=>{}]));
 repository.recommendations=async(target,owner)=>{assert.equal(owner,41);assert.equal(target.targetId,scope.targetId);reads++;revoked=true;return {feed:[]};};
 const service=createSecureShopBoundCommerce({repository,catalog:{prepareTarget:async()=>scope,hasProduct:async()=>true},personaAuthority:{capture(v){return {binding:{...v.scope,personaId:v.personaId,role:v.role,sessionId:v.sessionId,authorityVersion:v.authorityVersion},withCrossStoreEffect:async f=>f(),assertRemoteAdmission:async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};}}});
 const input={scope,persona:{id:41,role:'customer'},personaSession:{sessionId:'40000000-0000-4000-8000-000000000001',authorityVersion:'1'}};
 await assert.rejects(service.recommendations({...input,persona:{id:41,role:'merchant'}}),{code:'OWNER_MISMATCH'});
 await assert.rejects(service.recommendations({...input,personaSession:undefined}),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,0);
 await assert.rejects(service.recommendations(input),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,1);
 await assert.rejects(service.recommendations(input),{code:'SHOP_AUTH_INVALID'});assert.equal(reads,1);
});
