'use strict';
const {Pool}=require('pg');
const crypto=require('node:crypto');
const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
const {assertListingsSchema}=require('../../server/services/secureshopListingsProduction');
const fail=code=>Object.assign(new Error('Owned Listings activation unavailable; private state preserved'),{code});
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function databaseName(url){try{const value=new URL(url);if(!['postgres:','postgresql:'].includes(value.protocol)||!/^\/[A-Za-z0-9_]+$/.test(value.pathname))throw Error();return value.pathname.slice(1);}catch{throw fail('LISTINGS_ACTIVATION_DATABASE_INVALID');}}
async function assertRetainedBindings(reviewPool){
 let cursor=null;
 for(;;){
  const rows=(await reviewPool.query(`SELECT a.operation_id,a.target_id,a.binding_json,a.binding_sha256,
   t.launch_id AS birth_launch_id,t.scenario_id AS birth_scenario_id,t.generation::text AS birth_generation,
   t.original_platform_owner_id AS birth_owner_id,t.original_platform_session_id AS birth_session_id,
   c.grant_id,c.target_id AS scene_target_id,c.merchant_id AS scene_merchant_id,c.binding_sha256 AS scene_binding_sha256,
   g.target_id AS grant_target_id,g.launch_id AS grant_launch_id,g.scenario_id AS grant_scenario_id,
   g.generation::text AS grant_generation,g.original_platform_owner_id AS grant_owner_id,
   g.original_platform_session_id AS grant_session_id
   FROM secureshop_review.owned_listing_admissions a
   LEFT JOIN secureshop_review.product_targets t ON t.target_id=a.target_id
   LEFT JOIN secureshop_review.owned_listing_scene_admissions c ON c.operation_id=a.operation_id
   LEFT JOIN secureshop_review.scene_execution_grants g ON g.grant_id=c.grant_id
   WHERE a.action='import' AND ($1::uuid IS NULL OR a.operation_id>$1::uuid)
   ORDER BY a.operation_id LIMIT 256`,[cursor])).rows;
  for(const row of rows){
   let binding,scope;try{binding=JSON.parse(row.binding_json);scope=createLaunchScope(binding?.scope);}catch{throw fail('LISTINGS_ACTIVATION_HISTORY_INVALID');}
   if(!UUID.test(row.operation_id)||binding.targetId!==row.target_id||!['vuln','fixed'].includes(binding.mode)
    ||crypto.createHash('sha256').update(row.binding_json).digest('hex')!==row.binding_sha256
    ||!row.birth_launch_id||!row.birth_scenario_id||!row.birth_generation||!row.birth_owner_id||!row.birth_session_id)throw fail('LISTINGS_ACTIVATION_HISTORY_INVALID');
   if(row.grant_id){
    if(row.scene_target_id!==row.target_id||row.scene_merchant_id!==binding.persona?.id||row.scene_binding_sha256!==row.binding_sha256||row.grant_target_id!==row.target_id
     ||row.grant_launch_id!==scope.launchId||row.grant_scenario_id!==scope.scenarioId||Number(row.grant_generation)!==scope.generation
     ||row.grant_owner_id!==scope.platformOwnerId||row.grant_owner_id!==row.birth_owner_id||row.grant_session_id!==scope.platformSessionId)throw fail('LISTINGS_ACTIVATION_HISTORY_INVALID');
   }else if(row.birth_launch_id!==scope.launchId||row.birth_scenario_id!==scope.scenarioId
    ||Number(row.birth_generation)!==scope.generation||row.birth_owner_id!==scope.platformOwnerId
    ||row.birth_session_id!==scope.platformSessionId)throw fail('LISTINGS_ACTIVATION_HISTORY_INVALID');
  }
  if(rows.length<256)return true;
  cursor=rows.at(-1).operation_id;
 }
}
async function assertActivationReadiness({applicationEnvironment,makePool=options=>new Pool(options),assertSchema=assertListingsSchema,assertHistory=assertRetainedBindings}={}){
 const env=applicationEnvironment||{};
 if(env.SS_ENABLE!=='true'||env.SS_BOUND_REVIEWS_ENABLED!=='true'||env.PLATFORM_DATABASE_ENGINE!=='postgres'||env.WORKSHOP_DATABASE_ENGINE!=='postgres')throw fail('LISTINGS_ACTIVATION_PREREQUISITES');
 const specs=[['agents','SECURESHOP_AGENTS_DATABASE_URL'],['review','SECURESHOP_REVIEW_DATABASE_URL']];
 const pools={};
 try{
  for(const [name,key]of specs){databaseName(env[key]);pools[name]=makePool({connectionString:env[key],max:1,connectionTimeoutMillis:5000,idleTimeoutMillis:1000,query_timeout:15000,options:'-c statement_timeout=10000 -c lock_timeout=2000'});}
  for(const [name,key]of specs){const row=(await pools[name].query('SELECT current_database() AS name')).rows[0];if(row?.name!==databaseName(env[key]))throw fail('LISTINGS_ACTIVATION_DATABASE_MISMATCH');}
  await assertSchema({agentsPool:pools.agents,reviewPool:pools.review});
  await assertHistory(pools.review);
  return true;
 }finally{
  const closed=await Promise.allSettled(Object.values(pools).map(pool=>pool.end()));
  if(closed.some(result=>result.status!=='fulfilled'))throw fail('LISTINGS_ACTIVATION_POOL_CLEANUP');
 }
}
module.exports={assertActivationReadiness,assertRetainedBindings};
