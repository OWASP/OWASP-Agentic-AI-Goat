'use strict';
const PRIMARY_TRACE_SQL=`SELECT id,event_id,session_id,kind,actor,step,agent_ns,tool_name,params_json,result_json,provider
  FROM secureshop_agents.agent_trace WHERE session_id=ANY($1::text[]) ORDER BY id`;
const EFFECT_STATUS_SQL=`SELECT effect_key,status FROM graph_runtime.effects
  WHERE effect_key LIKE ANY($1::text[])`;
function findPacketInvocation(evidence,invocations){
  const current=evidence?.currentInvocation;
  if(!current||!Array.isArray(invocations))return null;
  const matches=invocations.filter(row=>row.invocation_id===current.invocationId
    &&row.operation_id===current.operationId&&row.run_id===evidence.runId
    &&row.request_id===evidence.requestId&&row.call_id===evidence.callId
    &&row.target_id===evidence.targetId&&row.remote_receipt_sha256===evidence.remoteReceiptSha256
    &&row.result_sha256===evidence.resultSha256);
  return matches.length===1?matches[0]:null;
}
async function validateSecureShopMcpTrustQualifierSchema({identityMigration,identity,agentsMigration,agents}={}){
  for(const pool of [identityMigration,identity,agentsMigration,agents])if(typeof pool?.query!=='function')throw new TypeError('Qualifier schema pools required');
  await identityMigration.query('SELECT name FROM dvaia_migrations.ledger ORDER BY name DESC LIMIT 0');
  await agentsMigration.query('SELECT name FROM dvaia_migrations.ledger ORDER BY name DESC LIMIT 0');
  await identity.query('SELECT workshop_key,catalog_active,is_visible FROM workshop_platform.exercises LIMIT 0');
  await identity.query('SELECT workshop_key,objective_id,catalog_active,is_enabled FROM workshop_platform.objectives LIMIT 0');
  await identity.query('SELECT user_id,workshop_key,mode FROM workshop_platform.user_modes LIMIT 0');
  await identity.query('SELECT run_id,owner_key,generation,status FROM graph_runtime.runs LIMIT 0');
  await identity.query(`SELECT owner_key,generation,effect_key,run_id,status,updated_at FROM graph_runtime.effects
    WHERE effect_key LIKE ANY($1::text[]) LIMIT 0`,[['00000000-0000-4000-8000-000000000000:%']]);
  await identity.query(EFFECT_STATUS_SQL,[['00000000-0000-4000-8000-000000000000:%']]);
  await identity.query('SELECT evaluation_id,objective_id,run_id,verdict,disposition,result_json FROM workshop_platform.objective_judgments LIMIT 0');
  await identity.query('SELECT objective_id,platform_launch_id,platform_launch_generation FROM workshop_platform.objective_contributions LIMIT 0');
  await agents.query(`SELECT invocation_id,operation_id,target_id,run_id,request_id,call_id,schema_version,trust_scenario,
    behavior_class,approved,server_approved,schema_approved,schema_sha256,remote_receipt_sha256,result_sha256,completed_at
    FROM secureshop_agents.bound_mcp_invocations LIMIT 0`);
  await agents.query(`SELECT target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,
    server_identity,trust_scenario,lifecycle,current_schema_version,created_at FROM secureshop_agents.bound_mcp_targets LIMIT 0`);
  await agents.query('SELECT target_id,version,schema_sha256,discovery_receipt_sha256 FROM secureshop_agents.bound_mcp_schema_versions LIMIT 0');
  await agents.query('SELECT target_id,version,tools_json FROM secureshop_agents.bound_mcp_tool_payloads LIMIT 0');
  await agents.query(`SELECT operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,
    original_platform_session_id,deleted_payload_count,retained_invocation_count,receipt_sha256,completed_at
    FROM secureshop_agents.bound_mcp_cleanup_receipts LIMIT 0`);
  await agents.query('SELECT id,event_id,session_id,kind,actor,step,agent_ns,tool_name,params_json,result_json,provider FROM secureshop_agents.agent_trace LIMIT 0');
  await agents.query(PRIMARY_TRACE_SQL,[['00000000-0000-4000-8000-000000000000']]);
  return true;
}
module.exports={validateSecureShopMcpTrustQualifierSchema,PRIMARY_TRACE_SQL,EFFECT_STATUS_SQL,findPacketInvocation};
