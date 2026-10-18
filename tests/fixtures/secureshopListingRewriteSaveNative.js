'use strict';
// Controlled authority/model-shaped receipt, real PostgreSQL publication/CRUD.
// Caller owns disposable migrated pools. This helper never reads application env.
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createListingJournalRepository}=require('../../server/database/postgres/secureshopListingJournalRepository');
const {createListingRewriteSaveRepository}=require('../../server/database/postgres/secureshopListingRewriteSaveRepository');
const {prepareListingAdmission,hash}=require('../../server/services/secureshopListingJournalContract');
async function qualifyListingRewriteSaves({migration,runtime}){
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7711,platformSessionId:7712},targetId=randomUUID(),persona={id:12,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const target={...scope,targetId};
 const products=require('../../server/database/postgres/secureshopBoundProductRepository').createSecureShopBoundProductRepository(runtime,{checkCurrent:async()=>{},checkCleanup:async()=>{}});
 await migration.query(`INSERT INTO secureshop_review.product_targets(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,own_merchant_id,source_count,source_sha256) VALUES($1,$2,$3,1,$4,$5,12,1,$6)`,[targetId,scope.launchId,scope.scenarioId,scope.platformOwnerId,scope.platformSessionId,Buffer.alloc(32,1)]);
 await migration.query(`INSERT INTO secureshop_review.product_target_products(target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description,description_html,price,stock_quantity,status) VALUES($1,71,12,12,$2,'Raw seed','Raw description','<i>Raw seeded HTML</i>',5,2,'active')`,[targetId,Buffer.alloc(32,2)]);
 const authority={capture(v){return{binding:{...v.scope,personaId:v.personaId,role:v.role,sessionId:v.sessionId,authorityVersion:v.authorityVersion},assertRemoteAdmission:async()=>{},withCrossStoreEffect:async work=>work()};}};
 const dependencies={pool:runtime,personaAuthority:authority,capabilityKey:Buffer.alloc(32,7),resolveRetainedTarget:async()=>target};
 const journal=createListingJournalRepository(dependencies),saves=createListingRewriteSaveRepository(dependencies);
 async function completed(title='Lamp',description='Preview source'){
  const revision=String((await runtime.query('SELECT revision FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=$1',[targetId])).rows[0]?.revision||0);
  const raw={scope,persona,personaSession,targetId,mode:'vuln',catalogRevision:revision,request:{version:1,action:'rewrite',operationId:randomUUID(),title,description}};
  const admission=prepareListingAdmission(raw),html='<b>Controlled generated HTML</b>';
  const receipt={version:1,operationId:raw.request.operationId,requestSha256:admission.requestSha256,sourceSha256:hash(JSON.stringify([title,description])),provider:'ollama',model:'llama3.1:8b',callId:randomUUID(),mocked:false,fallback:false,html,htmlSha256:hash(html)};
  await journal.admit(raw);await journal.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
  await journal.transition(raw,{eventId:randomUUID(),expectedSequence:1,state:'effect_received',receipt});
  await journal.transition(raw,{eventId:randomUUID(),expectedSequence:2,state:'completed',receipt});
  return{admission,saveOperationId:randomUUID(),productId:null,item:{name:title,description,price:12,category:null,images:[],templateSource:null}};
 }
 const rawBefore=await products.get(target,71);await products.updateListing(target,12,71,{description:'New raw description'});
 assert.equal((await products.get(target,71)).description_html,rawBefore.description_html);
 const first=await completed(),receipt=await saves.save(first),id=receipt.productId;
 assert.equal((await products.get(target,id)).description_html,'<b>Controlled generated HTML</b>');
 const beforeRead=(await runtime.query(`SELECT
   (SELECT count(*)::int FROM secureshop_review.owned_listing_rewrite_saves) AS saves,
   (SELECT count(*)::int FROM secureshop_review.owned_listing_generated_products) AS generated,
   (SELECT count(*)::int FROM secureshop_review.product_target_listing_overlays) AS overlays,
   (SELECT count(*)::int FROM secureshop_review.owned_listing_events) AS events`)).rows;
 assert.deepEqual(await saves.read({admission:first.admission,saveOperationId:first.saveOperationId}),receipt);
 assert.deepEqual((await runtime.query(`SELECT
   (SELECT count(*)::int FROM secureshop_review.owned_listing_rewrite_saves) AS saves,
   (SELECT count(*)::int FROM secureshop_review.owned_listing_generated_products) AS generated,
   (SELECT count(*)::int FROM secureshop_review.product_target_listing_overlays) AS overlays,
   (SELECT count(*)::int FROM secureshop_review.owned_listing_events) AS events`)).rows,beforeRead,'saved GET never mutates Listings receipts, provenance, overlays or journal');
 await products.updateListing(target,12,id,{price:33,imageUrl:'https://owned.invalid/image'});
 assert.equal((await products.get(target,id)).description_html,'<b>Controlled generated HTML</b>');
 assert.equal((await runtime.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_generated_products WHERE target_id=$1 AND product_id=$2',[targetId,id])).rows[0].n,1);
 assert.deepEqual(await saves.save(first),receipt); // Replay bypasses changed revision, cannot overwrite new price.
 assert.equal((await products.get(target,id)).price,33);
 const stale=await completed();await products.updateListing(target,12,71,{price:7});
 await assert.rejects(saves.save(stale),error=>error.code==='40001');
 const countsBefore=(await runtime.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_rewrite_saves')).rows[0].n;
 await assert.rejects(saves.save({...first,item:{...first.item,price:99}}),error=>error.code==='23505');
 assert.equal((await runtime.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_rewrite_saves')).rows[0].n,countsBefore);
 await products.updateListing(target,12,id,{description:'Ordinary source edit'});
 assert.equal((await products.get(target,id)).description_html,null);
 assert.equal((await runtime.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_generated_products WHERE target_id=$1 AND product_id=$2',[targetId,id])).rows[0].n,0);
 const another=await saves.save(await completed('Other lamp'));
 // Direct raw HTML write is a deliberate content sink; preserve content but remove provenance.
 await products.updateListing(target,12,another.productId,{price:13});
 await runtime.query('UPDATE secureshop_review.product_target_listing_overlays SET description_html=$3 WHERE target_id=$1 AND product_id=$2',[targetId,another.productId,'<em>Explicit raw replacement</em>']);
 assert.equal((await products.get(target,another.productId)).description_html,'<em>Explicit raw replacement</em>');
 assert.equal((await runtime.query('SELECT count(*)::int n FROM secureshop_review.owned_listing_generated_products WHERE target_id=$1 AND product_id=$2',[targetId,another.productId])).rows[0].n,0);
 const update=await completed('Updated lamp','Updated source');update.productId=id;await saves.save(update);
 assert.equal((await products.get(target,id)).description_html,'<b>Controlled generated HTML</b>');
 const grants=(await runtime.query("SELECT has_table_privilege(current_user,'secureshop_review.owned_listing_generated_products','INSERT,UPDATE,DELETE') provenance,has_table_privilege(current_user,'secureshop_review.owned_listing_rewrite_saves','INSERT,UPDATE,DELETE') receipts")).rows[0];assert.deepEqual(grants,{provenance:false,receipts:false});
 await assert.rejects(runtime.query('SELECT secureshop_review.consume_owned_listing_rewrite($1,$2,$3,$4,$5,$6,$7)',[randomUUID(),first.admission.request.operationId,first.admission.bindingJson,null,JSON.stringify(first.item),hash(JSON.stringify(first.item)),'0'.repeat(64)]),error=>error.code==='42501');
 return{actualModelCalls:0,authority:'controlled cross-store fence, real SQL',checks:['raw-seeded-html-preserved','generated-save-create-update','price-image-retains-provenance','source-edit-invalidates','explicit-raw-html-preserved-without-model-credit','revision-CAS','UUID-replay-no-overwrite','conflict-rollback','private-provenance-grants','forged-capability-denied']};
}
module.exports={qualifyListingRewriteSaves};
