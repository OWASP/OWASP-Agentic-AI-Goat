'use strict';
const {createLaunchScope}=require('./secureshopConversationBinding');
const fail=()=>Object.assign(new Error('Owned MCP registry cleanup verification unavailable'),{code:'MCP_REGISTRY_CLEANUP_UNVERIFIED'});
function createOwnedMcpRegistryLifecycle({pool,cleanupAuthority,invocationLifecycle,registrationLifecycle}={}){
 if(typeof pool?.query!=='function'||typeof cleanupAuthority?.getOperation!=='function')throw new TypeError('Canonical MCP cleanup authority required');
 async function verify(resetId){
  const operation=await cleanupAuthority.getOperation(resetId);if(operation?.resetId!==resetId||!['fenced','committed','aborted'].includes(operation.status))throw fail();
  const s=createLaunchScope(operation.binding);
  const result=await pool.query(`SELECT c.cleanup_id IS NOT NULL AND c.cleanup_kind='retirement'
   AND c.original_platform_owner_id=$4 AND c.platform_launch_id=$2 AND c.platform_generation=$3
   AND c.receipt_sha256=sha256(convert_to(jsonb_build_array('owned-mcp-registry-cleanup-v1',c.cleanup_id,c.cleanup_kind,c.original_platform_owner_id,c.platform_launch_id,c.platform_generation,c.deleted_entries,c.redacted_records)::text,'UTF8'))
   AND EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements r WHERE r.reset_id=$1 AND r.platform_launch_id=$2 AND r.from_generation=$3 AND r.original_platform_owner_id=$4 AND r.platform_scenario_id=$5 AND r.original_platform_session_id=$6)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_entries e WHERE e.platform_launch_id=$2 AND e.platform_launch_generation=$3 AND e.original_platform_owner_id=$4 AND e.platform_scenario_id=$5 AND e.original_platform_session_id=$6)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_operations o WHERE o.platform_launch_id=$2 AND o.platform_launch_generation=$3 AND o.original_platform_owner_id=$4 AND o.original_platform_session_id=$6 AND (o.redacted_at IS NULL OR o.request_json IS NOT NULL OR o.receipt_json IS NOT NULL))
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_revisions v WHERE v.platform_launch_id=$2 AND v.platform_launch_generation=$3 AND v.original_platform_owner_id=$4 AND v.platform_scenario_id=$5 AND v.original_platform_session_id=$6 AND (v.redacted_at IS NULL OR v.endpoint_text IS NOT NULL OR v.tools_json IS NOT NULL OR v.effect_json IS NOT NULL)) AS verified
   FROM secureshop_agents.bound_mcp_registry_cleanup_receipts c WHERE c.cleanup_id=$1`,[resetId,s.launchId,s.generation,s.platformOwnerId,s.scenarioId,s.platformSessionId]);
  if(result.rows.length!==1||result.rows[0].verified!==true)throw fail();
  const current=await cleanupAuthority.getOperation(resetId);if(JSON.stringify(current.binding)!==JSON.stringify(operation.binding))throw fail();
 }
 function decorateConversation(base){return Object.freeze({...base,
  async retireGeneration(id,options){await invocationLifecycle?.beforeRetirement(id,options);await registrationLifecycle?.beforeRetirement(id,options);const receipt=await base.retireGeneration(id,options);await verify(id);return receipt;},
  async readReceipt(id,options){const receipt=await base.readReceipt(id,options);await verify(id);return receipt;}
 });}
 async function verifyDeletion({jobId,subjectId,check,signal}){
  signal?.throwIfAborted();await check();
  const result=await pool.query(`SELECT c.cleanup_kind='owner_deletion' AND c.original_platform_owner_id=$2
   AND c.platform_launch_id IS NULL AND c.platform_generation IS NULL
   AND c.receipt_sha256=sha256(convert_to(jsonb_build_array('owned-mcp-registry-cleanup-v1',c.cleanup_id,c.cleanup_kind,c.original_platform_owner_id,c.platform_launch_id,c.platform_generation,c.deleted_entries,c.redacted_records)::text,'UTF8'))
   AND EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts a WHERE a.deletion_job_id=$1 AND a.original_platform_owner_id=$2)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_entries WHERE original_platform_owner_id=$2)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$2)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_revisions WHERE original_platform_owner_id=$2)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_mcp_registry_heads WHERE original_platform_owner_id=$2) AS verified
   FROM secureshop_agents.bound_mcp_registry_cleanup_receipts c WHERE c.cleanup_id=$1`,[jobId,subjectId]);
  if(result.rows.length!==1||result.rows[0].verified!==true)throw fail();await check();signal?.throwIfAborted();
 }
 return Object.freeze({decorateConversation,verifyDeletion,async beforeDeletion(input){await invocationLifecycle?.beforeDeletion(input);await registrationLifecycle?.beforeDeletion(input);}});
}
module.exports={createOwnedMcpRegistryLifecycle};
