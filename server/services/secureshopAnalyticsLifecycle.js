'use strict';
const services=new WeakMap();
const {createLaunchScope}=require('./secureshopConversationBinding');
// Only canonical reset/deletion journals can retire a private target after logout.
function createAnalyticsLifecycle({cleanupAuthority,service,agentsPool,reviewPool}){
 if(typeof cleanupAuthority?.getOperation!=='function'||(service?typeof service.retire!=='function':typeof agentsPool?.query!=='function'))throw TypeError('Canonical Analytics cleanup dependencies required');
 async function authority(resetId){const value=await cleanupAuthority.getOperation(resetId);if(value?.resetId!==resetId||!['fenced','committed','aborted'].includes(value.status))throw Error('Analytics cleanup authority unavailable');return createLaunchScope(value.binding);}
 async function retireGeneration(resetId,{signal}={}){
  signal?.throwIfAborted();const scope=await authority(resetId);let receipt;
  if(service)receipt=await service.retire(scope,{signal});
  else {
   const relation=(await agentsPool.query("SELECT to_regclass('secureshop_agents.analytics_request_admissions') AS relation")).rows[0]?.relation;
   const known=relation&&(await agentsPool.query('SELECT 1 FROM secureshop_agents.analytics_request_admissions WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3 AND platform_owner_id=$4 AND platform_session_id=$5 LIMIT 1',[scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId])).rows.length>0;
   let couponDebt=false;
   if(reviewPool){const exists=(await reviewPool.query("SELECT to_regclass('secureshop_review.bound_commerce_operations') AS relation")).rows[0]?.relation;if(exists)couponDebt=(await reviewPool.query("SELECT 1 FROM secureshop_review.bound_commerce_operations o JOIN secureshop_review.product_targets t USING(target_id) WHERE o.kind='coupon' AND t.launch_id=$1 AND t.scenario_id=$2 AND t.generation=$3 AND t.original_platform_owner_id=$4 AND t.original_platform_session_id=$5 LIMIT 1",[scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId])).rows.length>0;}
   const probeRelation=(await agentsPool.query("SELECT to_regclass('secureshop_agents.turn_requests') AS relation")).rows[0]?.relation;
   const probeDebt=probeRelation&&(await agentsPool.query(`SELECT 1
    FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
    WHERE s.authority_mode='launch_bound' AND s.conversation_purpose IN ('secureshop_coupon_probe','secureshop_product_search_union','secureshop_order_status_error')
      AND s.platform_launch_id=$1 AND s.platform_scenario_id=$2 AND s.platform_launch_generation=$3
      AND s.original_platform_owner_id=$4 AND s.original_platform_session_id=$5 LIMIT 1`,
   [scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId])).rows.length>0;
   if(known||couponDebt||probeDebt)throw Object.assign(Error('Analytics private configuration required for cleanup'),{code:'ANALYTICS_CLEANUP_UNAVAILABLE'});
   // POST preparation requires an admission first; no admission means no owned target.
   receipt={retired:true};
  }
  if(receipt?.retired!==true)throw Error('Analytics target retirement incomplete');signal?.throwIfAborted();
  if(JSON.stringify(await authority(resetId))!==JSON.stringify(scope))throw Error('Analytics cleanup authority changed');return Object.freeze({resetId,retired:true});
 }
 const lifecycle=Object.freeze({retireGeneration,async destroyForDeletion({resetIds,subjectId,check,signal}){
  if(!Array.isArray(resetIds)||resetIds.length>256||new Set(resetIds).size!==resetIds.length||!Number.isSafeInteger(subjectId)||subjectId<1||typeof check!=='function')throw TypeError('Canonical Analytics deletion mapping required');
  for(const resetId of resetIds){signal?.throwIfAborted();await check();const scope=await authority(resetId);if(scope.platformOwnerId!==subjectId)throw Error('Analytics deletion owner mismatch');await retireGeneration(resetId,{signal});await check();}
  // retire drops the database/login/credentials and redacts result payloads.
  // Non-content immutable operation hashes and scope tombstones are retained.
  return Object.freeze({completed:true});
 }});services.set(lifecycle,service);return lifecycle;
}
module.exports={createAnalyticsLifecycle,isAnalyticsLifecycleFor:(value,service)=>services.get(value)===service};
