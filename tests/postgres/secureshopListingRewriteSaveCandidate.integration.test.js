'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{Pool}=require('pg');
const {randomUUID}=require('node:crypto');
const {migrate}=require('../../db/postgres/migrate');
const {qualifyListingRewriteSaves}=require('../fixtures/secureshopListingRewriteSaveNative');
test('owned rewrite save candidate native',{skip:process.env.OWNED_LISTING_CANDIDATE_NATIVE!=='1',timeout:300000},async()=>{
 const fresh=new Pool({connectionString:process.env.OWNED_LISTING_FRESH_MIGRATION_URL,max:2}),migration=new Pool({connectionString:process.env.OWNED_LISTING_WORKING_MIGRATION_URL,max:2}),runtime=new Pool({connectionString:process.env.OWNED_LISTING_WORKING_RUNTIME_URL,max:4});
 try{
  await migrate(fresh,process.env.OWNED_LISTING_CANDIDATE_MIGRATIONS);assert.deepEqual(await migrate(fresh,process.env.OWNED_LISTING_CANDIDATE_MIGRATIONS),[]);
  await migrate(migration,process.env.OWNED_LISTING_PRIOR_MIGRATIONS);
  const targetId=randomUUID();
  await migration.query(`INSERT INTO secureshop_review.product_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256) VALUES($1,$2,$3,1,9997,9998,12,1,$4)`,[targetId,randomUUID(),randomUUID(),Buffer.alloc(32,1)]);
  await migration.query(`INSERT INTO secureshop_review.product_target_products(target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description_html,price,stock_quantity,status) VALUES($1,1,12,12,$2,'Preserved seed','<i>Instructor raw HTML</i>',5,2,'active')`,[targetId,Buffer.alloc(32,2)]);
  await migrate(migration,process.env.OWNED_LISTING_CANDIDATE_MIGRATIONS);
  assert.equal((await runtime.query('SELECT description_html FROM secureshop_review.product_target_products WHERE target_id=$1',[targetId])).rows[0].description_html,'<i>Instructor raw HTML</i>');assert.deepEqual(await migrate(migration,process.env.OWNED_LISTING_CANDIDATE_MIGRATIONS),[]);
  const result=await qualifyListingRewriteSaves({migration,runtime});
  fs.writeFileSync(process.env.OWNED_LISTING_RESULT,JSON.stringify({status:'passed',...result}));
 }finally{await Promise.all([fresh.end(),migration.end(),runtime.end()]);}
});
