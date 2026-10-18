'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const managed=require('./secureshopListingsManagedConfiguration');
const {createLaunchScope}=require('./secureshopConversationBinding');
const fail=code=>Object.assign(new Error('Owned Listings runtime unavailable'),{code});
function loadConfiguration({root=path.resolve(__dirname,'../..'),home=os.homedir()}={}){
 const file=managed.managedPath({root,home});try{fs.lstatSync(file);}catch(error){if(error.code==='ENOENT')return null;throw error;}
 const value=managed.load({filePath:file}),qualified=require('../../scripts/install/secureshop-owned-listings-qualified-candidate').qualifiedInstalledPackage({root,architecture:value.architecture,configuration:value});
 if(value.workspaceId!==require('../../scripts/application-data-root').workspaceId(root)||value.sourceManifestSha256!==qualified.qualifiedSourceSha256||value.runtimeDigest!==qualified.runtimeDigest)throw fail('LISTINGS_RUNTIME_PACKAGE_CHANGED');return value;
}
function createListingsRuntime({configuration,launches,products,reviewPool,mode='vuln',modeAuthority,createManager=require('./secureshopListingsTargetManager').createListingsTargetManager}={}){
 const value=managed.validate(configuration);if(!['vuln','fixed'].includes(mode)||typeof reviewPool?.query!=='function')throw fail('LISTINGS_RUNTIME_CONFIGURATION');
 const manager=createManager({origin:value.manager.url,controlToken:value.manager.token,runtimeDigest:value.runtimeDigest,launches,products,resolveMode:async scope=>(await require('./secureshopFeatureModeAuthority').captureFeatureMode(modeAuthority,scope,'listings',mode)).snapshot.mode});
 const capabilityKey=Buffer.from(crypto.hkdfSync('sha256',Buffer.from(value.manager.token),Buffer.from(value.runtimeDigest,'hex'),Buffer.from('dvaia/listings/journal-capability/v1'),32));
 const retirementListeners=new Set();
 async function reconcile(raw,options={}){
  const scope=createLaunchScope(raw),targetId=raw.targetId;
  // Immutable admission bindings survive content redaction and record the mode
  // actually used before a reset or process restart changes configuration.
  const rows=(await reviewPool.query(`SELECT a.binding_json,a.binding_sha256,c.grant_id,
   ROW(t.launch_id,t.scenario_id,t.generation,t.original_platform_owner_id,t.original_platform_session_id)
    =ROW($2::uuid,$3::uuid,$4::bigint,$5::integer,$6::integer) AS scene_storage_matches,
   c.target_id=a.target_id AND c.binding_sha256=a.binding_sha256
    AND c.merchant_id=(a.binding_json::jsonb#>>'{persona,id}')::integer
    AND g.target_id=a.target_id AND g.original_platform_owner_id=t.original_platform_owner_id
    AND ROW(g.launch_id,g.scenario_id,g.generation,g.original_platform_owner_id,g.original_platform_session_id)
     =ROW((a.binding_json::jsonb#>>'{scope,launchId}')::uuid,(a.binding_json::jsonb#>>'{scope,scenarioId}')::uuid,
      (a.binding_json::jsonb#>>'{scope,generation}')::bigint,(a.binding_json::jsonb#>>'{scope,platformOwnerId}')::integer,
      (a.binding_json::jsonb#>>'{scope,platformSessionId}')::integer) AS scene_execution_matches
   FROM secureshop_review.owned_listing_admissions a
   LEFT JOIN secureshop_review.owned_listing_scene_admissions c USING(operation_id)
   LEFT JOIN secureshop_review.scene_execution_grants g ON g.grant_id=c.grant_id
   JOIN secureshop_review.product_targets t ON t.target_id=a.target_id
   WHERE a.target_id=$1 AND a.action='import'`,[targetId,scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId])).rows;
  const modes=new Set();for(const row of rows){let b;try{b=JSON.parse(row.binding_json);}catch{throw fail('LISTINGS_CLEANUP_BINDING');}
   if(crypto.createHash('sha256').update(row.binding_json).digest('hex')!==row.binding_sha256||b.targetId!==targetId||(row.grant_id!=null?(row.scene_storage_matches!==true||row.scene_execution_matches!==true):JSON.stringify(createLaunchScope(b.scope))!==JSON.stringify(scope))||!['vuln','fixed'].includes(b.mode))throw fail('LISTINGS_CLEANUP_BINDING');modes.add(b.mode);}
  if(!modes.size)return;
  let completed=false;
  for(const selected of modes){const binding={scope,targetId,mode:selected};
   try{await manager.acknowledgeRetirement(binding,options);completed=true;break;}catch{}
   try{await manager.retire(binding,options);await manager.acknowledgeRetirement(binding,options);completed=true;break;}catch{}
  }
  if(!completed)throw fail('LISTINGS_CLEANUP_UNAVAILABLE');
  for(const mode of modes)for(const listener of retirementListeners)await listener({scope,targetId,mode},{operationId:options.operationId});
 }
 const lifecycle=Object.freeze({
  async cleanup(input,options){const result=await products.cleanup(input,options);await reconcile(input,options);return result;},
  async readCleanupReceipt(input,options){const result=await products.readCleanupReceipt(input,options);if(result)await reconcile(input,options);return result;},
  onRetired(listener){if(typeof listener!=='function')throw TypeError('Retirement callback required');retirementListeners.add(listener);return()=>retirementListeners.delete(listener);}
 });
 return Object.freeze({admissions:value.enabled,manager,lifecycle,mode,modeAuthority,capabilityKey,configuration:value});
}
async function assertNoUnmanagedListingsDebt(reviewPool){const present=(await reviewPool.query("SELECT to_regclass('secureshop_review.owned_listing_admissions') IS NOT NULL AS present")).rows[0]?.present;if(!present)return;const debt=(await reviewPool.query("SELECT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_admissions WHERE action='import') AS present")).rows[0]?.present;if(debt)throw fail('LISTINGS_RUNTIME_CLEANUP_CONFIGURATION_REQUIRED');}
module.exports={loadConfiguration,createListingsRuntime,assertNoUnmanagedListingsDebt};
