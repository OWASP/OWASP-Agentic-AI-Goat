'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {prepareListingTemplateClient}=require('../server/services/secureshopListingTemplateActivation');
const {assertListingTemplateSchema}=require('../server/services/secureshopListingsProduction');
const {startManagedListingTemplate}=require('../scripts/start-application');

const ROOT='/controlled/root',HOME='/controlled/home';
const ID='a'.repeat(64),IMAGE='sha256:'+'b'.repeat(64);
const record=Object.freeze({value:Object.freeze({enabled:true,containerId:ID,imageId:IMAGE,port:8109})});
const ready=Object.freeze({ready:true,enabled:true,containerId:ID,imageId:IMAGE,baseUrl:'http://127.0.0.1:8109'});

test('absent and disabled template package never start Docker or create a client',async()=>{
 for(const captured of [null,{value:{enabled:false}}]){
  const result=await prepareListingTemplateClient({root:ROOT,home:HOME,capture:()=>captured,
   startExisting:()=>assert.fail('disabled package cannot start'),createClient:()=>assert.fail('disabled package cannot create client')});
  assert.equal(result,undefined);
 }
});
test('enabled template client binds exact retained resource across start and inert health',async()=>{
 let captured=0,started=0,health=0;
 const client=await prepareListingTemplateClient({root:ROOT,home:HOME,capture:()=>record,
  assertCaptured:(value,options)=>{assert.equal(value,record);assert.deepEqual(options,{root:ROOT,home:HOME});captured++;},
  startExisting:async options=>{assert.deepEqual(options,{root:ROOT,home:HOME,environment:{}});started++;return ready;},
  createClient:options=>{assert.deepEqual(options,{baseUrl:ready.baseUrl});return{health:async()=>{health++;return true;},execute:async()=>{}};},
  environment:{}});
 assert.equal(typeof client.execute,'function');assert.equal(started,1);assert.equal(health,1);assert.equal(captured,2);
});
test('retargeted or unready template package cannot enter the bound application',async()=>{
 for(const bad of [{...ready,containerId:'c'.repeat(64)},{...ready,baseUrl:'http://127.0.0.1:8110'},
  {...ready,enabled:false}]){
  await assert.rejects(prepareListingTemplateClient({root:ROOT,home:HOME,capture:()=>record,
   assertCaptured:()=>{},startExisting:async()=>bad,createClient:()=>assert.fail('no client before exact resource')}),
   {code:'LISTING_TEMPLATE_START_UNAVAILABLE'});
 }
 await assert.rejects(prepareListingTemplateClient({root:ROOT,home:HOME,capture:()=>record,
  assertCaptured:()=>{},startExisting:async()=>ready,
  createClient:()=>({health:async()=>false,execute:async()=>{}})}),{code:'LISTING_TEMPLATE_START_UNAVAILABLE'});
});
test('start_all skips only absent/disabled package and fails closed for enabled mismatch',async()=>{
 for(const result of [{ready:false,enabled:false,absent:true},{ready:false,enabled:false,preservedDisabled:true}]){
  assert.deepEqual(await startManagedListingTemplate({workspace:ROOT,home:HOME,environment:{},
   startExisting:async()=>result}),result);
 }
 assert.deepEqual(await startManagedListingTemplate({workspace:ROOT,home:HOME,environment:{},
  startExisting:async options=>{assert.deepEqual(options,{root:ROOT,home:HOME,environment:{}});return ready;}}),ready);
 await assert.rejects(startManagedListingTemplate({workspace:ROOT,home:HOME,environment:{},
  startExisting:async()=>({...ready,baseUrl:'http://0.0.0.0:8109'})}),{code:'LISTING_TEMPLATE_START_UNAVAILABLE'});
});
test('template schema gate requires exact table and function privileges plus conversation purpose',async()=>{
 let missing=false,purpose=true,missingTrigger=false,corrected=true;
 const triggers=[
  ['owned_listing_template_operation_immutable','owned_listing_template_operations','guard_owned_listing_template_storage()',27],
  ['owned_listing_template_event_immutable','owned_listing_template_events','guard_owned_listing_template_storage()',27],
  ['owned_listing_template_cleanup_immutable','owned_listing_template_cleanup_receipts','guard_owned_listing_template_storage()',27],
  ['z_product_target_template_retirement','product_targets','cleanup_owned_listing_template_lifecycle()',17],
  ['z_owner_template_cleanup','bound_audit_owner_deletion_receipts','cleanup_owned_listing_template_lifecycle()',5],
 ].map(([tgname,table,fn,type])=>({tgname,relation:'secureshop_review.'+table,
  function:'secureshop_review.'+fn,type}));
 const reviewPool={async query(sql,args){if(sql.includes('pg_get_functiondef'))return{rows:[{definition:corrected
   ?"requested_state='effect_received' AND requested_payload#>>'{effect,requestSha256}' IS DISTINCT FROM prior.payload_json->>'executorRequestSha256'; prior.payload_json IS DISTINCT FROM requested_payload; prior.payload_sha256 IS DISTINCT FROM encode(sha256(convert_to(requested_payload::text"
   :"requested_payload#>>'{effect,requestSha256}' IS DISTINCT FROM prior.payload_json->>'executorRequestSha256'"}]};
  return{rows:args?args[0].map(name=>({name,ready:!missing}))
   :missingTrigger?triggers.slice(1):triggers};}};
 const agentsPool={async query(){return{rows:[{definition:purpose?"CHECK (conversation_purpose IN ('secureshop_listing_template'))":'CHECK (true)'}]};}};
 assert.equal(await assertListingTemplateSchema({agentsPool,reviewPool}),true);
 missing=true;await assert.rejects(assertListingTemplateSchema({agentsPool,reviewPool}),{code:'LISTING_TEMPLATE_SCHEMA_UNAVAILABLE'});
 missing=false;purpose=false;await assert.rejects(assertListingTemplateSchema({agentsPool,reviewPool}),{code:'LISTING_TEMPLATE_SCHEMA_UNAVAILABLE'});
 purpose=true;missingTrigger=true;await assert.rejects(assertListingTemplateSchema({agentsPool,reviewPool}),{code:'LISTING_TEMPLATE_SCHEMA_UNAVAILABLE'});
 missingTrigger=false;corrected=false;await assert.rejects(assertListingTemplateSchema({agentsPool,reviewPool}),{code:'LISTING_TEMPLATE_SCHEMA_UNAVAILABLE'});
});
