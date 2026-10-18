'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {prepareListingAdmission}=require('../server/services/secureshopListingJournalContract');
const {prepareListingRewriteSave}=require('../server/services/secureshopListingRewriteSaveContract');
const {createListingRewriteSaveRepository}=require('../server/database/postgres/secureshopListingRewriteSaveRepository');
function input(){return {admission:prepareListingAdmission({scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'0',request:{version:1,action:'rewrite',operationId:randomUUID(),title:'Lamp',description:'A lamp'}}),saveOperationId:randomUUID(),productId:null,item:{name:'Lamp',description:'A lamp',price:12,category:null,images:[],templateSource:null}};}
function fixture(raw,{changeReceipt=()=>{},revoke=false,commitError=false,revokeAfter=false,resolveTarget,sceneAllowed=true}={}){
 const prepared=prepareListingRewriteSave(raw),queries=[],releases=[];let assertions=0,insideFence=false;
 const b=prepared.admission.binding;
 const fence={binding:{...b.scope,personaId:b.persona.id,role:'merchant',...b.personaSession},async assertRemoteAdmission(){assertions++;if(insideFence)throw Error('nonreentrant authority lock');},async withCrossStoreEffect(work){if(revoke)throw Error('revoked');insideFence=true;try{const value=await work({query(){throw Error('agents SQL connection must never be used');}});if(revokeAfter)throw Error('authority failed after committed separate-store effect');return value;}finally{insideFence=false;}}};
 const pool={async connect(){return{async query(sql,values){queries.push({sql,values});if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:sceneAllowed}]};if(sql.includes('owned_listing_scene_admissions'))return{rows:[]};if(sql==='COMMIT'&&commitError)throw Error('lost commit response');if(sql.startsWith('SELECT secureshop_review.consume')){
 const receipt={version:1,saveOperationId:raw.saveOperationId,rewriteOperationId:prepared.admission.request.operationId,targetId:b.targetId,requestedProductId:raw.productId,productId:4,bindingSha256:prepared.admission.bindingSha256,requestSha256:prepared.itemSha256,sourceSha256:prepared.sourceSha256,htmlSha256:'a'.repeat(64)};changeReceipt(receipt);return{rows:[{receipt:JSON.stringify(receipt)}]};}return{rows:[]};},release(value){releases.push(value);}};}};
 return{queries,releases,repo:createListingRewriteSaveRepository({pool,personaAuthority:{async capture(){return fence;}},capabilityKey:Buffer.alloc(32,1),resolveTarget})};
}
test('source-edited, client HTML or overprecision input cannot consume a rewrite',()=>{
 for(const edit of [x=>{x.item.description='Changed';},x=>{x.item.description_html='<img>';},x=>{x.item.price=1.005;},x=>{x.productId=0;}]){const x=input();edit(x);assert.throws(()=>prepareListingRewriteSave(x),{code:'LISTING_SAVE_INVALID'});}
 const x=input();x.item.price=99;x.item.images=['https://synthetic.invalid/a'];assert.equal(prepareListingRewriteSave(x).item.price,99);
});
test('one atomic review function call with private capability under cross-store fence',async()=>{
 const raw=input(),f=fixture(raw);const receipt=await f.repo.save(raw);
 assert.equal(receipt.productId,4);assert.equal(f.queries.filter(q=>q.sql.startsWith('SELECT secureshop_review.consume')).length,1);
 assert.equal(f.queries.at(-1).sql,'COMMIT');assert.deepEqual(f.releases,[false]);assert.equal(Object.hasOwn(receipt,'capability'),false);
});
test('authority revocation at fence admission performs no review write',async()=>{
 const raw=input(),f=fixture(raw,{revoke:true});await assert.rejects(f.repo.save(raw),/revoked/);
 assert.equal(f.queries.length,0);
});
test('forged returned binding fails and rolls back',async()=>{
 const raw=input(),f=fixture(raw,{changeReceipt:r=>{r.targetId=randomUUID();}});await assert.rejects(f.repo.save(raw),{code:'LISTING_SAVE_RECEIPT_INVALID'});
 assert.equal(f.queries.at(-1).sql,'ROLLBACK');
});
test('lost COMMIT response is unknown, never reported as a definite failed save',async()=>{
 const raw=input(),f=fixture(raw,{commitError:true});await assert.rejects(f.repo.save(raw),{code:'LISTING_OUTCOME_UNCERTAIN'});
});
test('hostile image arrays are rejected without executing accessors',()=>{
 let invoked=0;
 const accessor=[];Object.defineProperty(accessor,'0',{enumerable:true,get(){invoked++;return 'x';}});
 const custom=['x'];Object.setPrototypeOf(custom,Object.create(Array.prototype));
 const symbol=['x'];symbol[Symbol('hidden')]='x';
 for(const images of [accessor,custom,symbol,new Array(1)]){const raw=input();raw.item.images=images;assert.throws(()=>prepareListingRewriteSave(raw),{code:'LISTING_SAVE_INVALID'});}
 assert.equal(invoked,0);
});

test('nonreentrant authority fence succeeds; post-commit authority failure stays uncertain',async()=>{
 const raw=input(),f=fixture(raw,{revokeAfter:true});await assert.rejects(f.repo.save(raw),{code:'LISTING_OUTCOME_UNCERTAIN'});assert.equal(f.queries.at(-1).sql,'COMMIT');
});

test('retained-scene rewrite save verifies the current private merchant grant before SQL and commit',async()=>{
 let raw=input(),b=raw.admission.binding;
 raw.admission=prepareListingAdmission({...b,persona:{id:1000000001,role:'merchant'},request:raw.admission.request});b=raw.admission.binding;
 const {createSceneBinding,authorizeSceneMerchant}=require('../server/services/secureshopSceneBinding');
 let leased=0;const target=authorizeSceneMerchant(createSceneBinding({...b.scope,launchId:randomUUID(),platformSessionId:8,targetId:b.targetId},{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:b.scope,withLease:async work=>{leased++;return work();}}),b.persona.id);
 const f=fixture(raw,{resolveTarget:async()=>target});const receipt=await f.repo.save(raw);assert.equal(receipt.productId,4);assert.equal(leased,1);
 const grant=f.queries.filter(x=>x.sql.includes('assert_scene_execution_grant'));assert.equal(grant.length,2);assert.equal(grant[0].values[0],target.scene.grantId);assert.equal(grant[0].values[4],b.scope.launchId);
 assert.ok(f.queries.findIndex(x=>x.sql.includes('secureshop-bound-audit-owner'))<f.queries.findIndex(x=>x.sql.includes('assert_scene_execution_grant')));
 const denied=fixture(raw,{resolveTarget:async()=>target,sceneAllowed:false});await assert.rejects(denied.repo.save(raw),{code:'SHOP_SCENE_STALE'});assert.equal(denied.queries.some(x=>x.sql.includes('consume_owned_listing_rewrite')),false);
});
