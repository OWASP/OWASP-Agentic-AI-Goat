'use strict';
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {Pool}=require('pg');
exports.qualifyRecommendations=async function(environment){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const urls=[environment.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL,environment.SECURESHOP_REVIEW_DATABASE_URL];
 for(const raw of urls){const u=new URL(raw);assert.equal(u.hostname,'127.0.0.1');assert.equal(u.pathname,'/owasp_ai_goat_test_full_backend_secureshop_review');}
 const [migration,runtime]=urls.map(connectionString=>new Pool({connectionString,max:1,statement_timeout:3000}));
 const scope={targetId:randomUUID(),launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:9101,platformSessionId:9201};
 try{
  await migration.query(`INSERT INTO secureshop_review.product_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256) VALUES($1,$2,$3,1,9101,9201,12,8,$4)`,[scope.targetId,scope.launchId,scope.scenarioId,Buffer.alloc(32,1)]);
  for(let id=1;id<=8;id++)await migration.query(`INSERT INTO secureshop_review.product_target_products(target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description,price,category,images,stock_quantity,status,template_source) VALUES($1,$2,12,12,$3,$4,'owned',2,$5,'[]',$6,'active','')`,[scope.targetId,id,Buffer.alloc(32,id),'Product '+id,id%2?'Books':'Home',id===8?0:5]);
  const repository=require('../../server/database/postgres/secureshopBoundCommerceRepository').createSecureShopBoundCommerceRepository(runtime,{checkCurrent:async()=>{}});
  assert.deepEqual((await repository.recommendations(scope,41)).feed.map(p=>p.id),[1,2,3,4,5,6]);
  await repository.addCart(scope,{shopUserId:41,productId:2,quantity:1});
  assert.deepEqual((await repository.recommendations(scope,41)).feed.map(p=>p.id),[4,6,1,3,5,7]);
  await repository.checkout(scope,{shopUserId:41,shippingAddress:'owned synthetic address',paymentMethod:'test'});
  await repository.addCart(scope,{shopUserId:41,productId:1,quantity:1});
  assert.deepEqual((await repository.recommendations(scope,41)).feed.map(p=>p.id),[2,4,6,3,5,7]);
  assert.deepEqual((await repository.recommendations(scope,42)).feed.map(p=>p.id),[1,2,3,4,5,6]);
  await migration.query("UPDATE secureshop_review.product_target_orders SET status='cancelled' WHERE target_id=$1",[scope.targetId]);
  assert.deepEqual((await repository.recommendations(scope,41)).feed.map(p=>p.id),[3,5,7,2,4,6]);
  await assert.rejects(repository.recommendations({...scope,platformOwnerId:9999},41),{code:'PRODUCT_TARGET_UNAVAILABLE'});
  return {passed:true,modelCalls:0,checks:['catalog fallback','own cart category ranking','approved purchase weighting','other persona isolation','cancelled order exclusion','out-of-stock exclusion','foreign owner denial']};
 }finally{await Promise.all([migration.end(),runtime.end()]);}
};
