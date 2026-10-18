'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createSecureShopStorePublicCatalogRepository:create}=require('../server/database/postgres/secureshopStorePublicCatalogRepository');
function fixture({change=false,inactive=false,missingTarget=false}={}) {
 let reads=0;const sql=[];
 const identityPool={connect:async()=>{},query:async()=>({rows:[{tenant_id:'tenant',owner_id:777,is_active:!inactive,scene_id:'scene',product_target_id:'target',scene_generation:change&&reads++?2:1}]})};
 const client={release(){},async query(text,args){sql.push({text,args});
  if(text.startsWith('SELECT target_id'))return {rows:missingTarget?[]:[{target_id:'target'}]};
  if(text.includes('SELECT product_id AS id'))return {rows:[{id:42,name:'Merchant listing',price:'12.50',status:'active',images:[],private_owner_id:99,avg_rating:'4.5',review_count:2}]};
  return {rows:[]};
 }};
 const reviewPool={query:client.query,connect:async()=>client};
 const commercePool={connect:async()=>{throw new Error('Unexpected seed fallback');},query:async()=>{throw new Error('Unexpected seed fallback');}};
 return {repository:create({identityPool,reviewPool,commercePool}),sql};
}
test('public product reads active default-store overlay with explicit projection and no writes',async()=>{
 const {repository,sql}=fixture();const {product}=await repository.product(42);
 assert.equal(product.name,'Merchant listing');assert.equal(product.price,12.5);assert.equal(product.private_owner_id,undefined);
 assert.ok(sql.some(q=>q.text.includes('REPEATABLE READ READ ONLY')));
 assert.ok(sql.some(q=>q.text.includes('original_platform_owner_id=$2')&&q.args[1]===777));
 assert.ok(sql.some(q=>q.text.includes('product_target_listing_overlays')&&q.args[0]==='target'&&q.args[1]===42));
 assert.ok(sql.every(q=>!/\b(INSERT|UPDATE|DELETE)\b/.test(q.text)));
});
test('changed scene fences response instead of returning stale store data',async()=>{
 await assert.rejects(fixture({change:true}).repository.product(42),/changed during read/);
});
test('inactive tenant or missing active target never falls back to static seed data',async()=>{
 await assert.rejects(fixture({inactive:true}).repository.product(42),/Default storefront unavailable/);
 await assert.rejects(fixture({missingTarget:true}).repository.product(42),/Store catalog unavailable/);
});
test('seed catalog is used only before a default scene exists',async()=>{
 const row={tenant_id:'tenant',owner_id:777,is_active:true,scene_id:null,product_target_id:null,scene_generation:null};
 const identityPool={query:async()=>({rows:[row]}),connect:async()=>{}};
 let seedReads=0;
 const client={release(){},async query(sql){if(sql.includes('FROM secureshop.products')){seedReads++;return {rows:[{id:1,name:'Seed',price:3,images:[]}]};}return {rows:[]};}};
 const commercePool={query:client.query,connect:async()=>client};
 const reviewPool={query:async()=>{throw new Error('Unexpected target access');},connect:async()=>{throw new Error('Unexpected target access');}};
 const repository=create({identityPool,reviewPool,commercePool});
 assert.equal((await repository.product(1)).product.name,'Seed');assert.equal(seedReads,1);
});
