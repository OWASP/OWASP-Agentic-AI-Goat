'use strict';
const crypto=require('node:crypto');
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
function unavailable(message='Bound MCP repository unavailable'){return Object.assign(new Error(message),{code:'BOUND_MCP_UNAVAILABLE'});}
function personaUnavailable(){return Object.assign(new Error('Shop authentication required'),{code:'SHOP_AUTH_INVALID'});}
const scopeArgs=value=>[value.targetId,value.launchId,value.scenarioId,value.generation,value.platformOwnerId,value.platformSessionId];
function createSecureShopBoundMcpRepository(pool,{checkCurrent,checkRotation,checkCleanup,auditStore}={}){
  if(typeof pool?.query!=='function'||typeof pool?.connect!=='function'||typeof checkCurrent!=='function'
    ||typeof checkRotation!=='function'||typeof checkCleanup!=='function')throw unavailable();
  if(auditStore!==undefined&&typeof auditStore?.append!=='function')throw unavailable('Bound MCP audit store unavailable');
  async function auditInvocation(client,value,input,actor){
      if(auditStore)await auditStore.append(client,{eventId:input.operationId,scope:value,
        persona:{id:actor.shopUserId,role:actor.role},actor:actor.role,action:'mcp_invocation_recorded',
        target:`mcp:${value.serverIdentity}`,paramsJson:JSON.stringify({runId:input.runId,requestId:input.requestId,
          callId:input.callId,toolName:input.toolName,schemaVersion:input.schemaVersion,schemaSha256:input.schemaSha256,
          argumentsSha256:input.argumentsSha256,remoteReceiptSha256:input.remoteReceiptSha256,
          trustPolicySha256:input.trustPolicySha256,approved:input.approved,serverApproved:input.serverApproved,
          schemaApproved:input.schemaApproved,trustScenario:input.trustScenario,behaviorClass:input.behaviorClass,
          resultSha256:input.resultSha256}),outcome:'completed',sourceKind:'bound_mcp_invocation',sourceId:input.operationId});
  }
  async function tx(work){const client=await pool.connect();try{await client.query('BEGIN');const out=await work(client);await client.query('COMMIT');return out;}
    catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}}
  const personaScopeKeys=['launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
  function assertPersonaFence(value,fence,actor,authority=fence?.binding){
    if(!fence||typeof fence.withPersonaEffect!=='function'||!fence.binding||!authority
      ||personaScopeKeys.some(key=>fence.binding[key]!==value[key]||authority[key]!==value[key])
      ||!Number.isSafeInteger(fence.binding.personaId)||fence.binding.personaId<1
      ||authority.personaId!==fence.binding.personaId||authority.role!==fence.binding.role
      ||(value.shopUserId!==undefined&&value.shopUserId!==fence.binding.personaId)
      ||(value.role!==undefined&&value.role!==fence.binding.role)
      ||(actor&&(actor.shopUserId!==fence.binding.personaId||actor.role!==fence.binding.role)))throw personaUnavailable();
  }
  async function write(value,fence,actor,work){
    if(fence===undefined){await checkCurrent(value);return tx(work);}
    assertPersonaFence(value,fence,actor);
    return fence.withPersonaEffect(async(client,authority)=>{
      assertPersonaFence(value,fence,actor,authority);
      if(typeof client?.query!=='function')throw personaUnavailable();
      await checkCurrent(value,client);return work(client);
    });
  }
  async function active(client,value,lock='FOR SHARE'){const row=(await client.query(`SELECT target_id,server_identity,trust_scenario,current_schema_version,lifecycle
    FROM secureshop_agents.bound_mcp_targets WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
    AND original_platform_owner_id=$5 AND original_platform_session_id=$6 ${lock}`,scopeArgs(value))).rows[0];
    if(!row||row.lifecycle!=='active'||row.server_identity!==value.serverIdentity||row.trust_scenario!==value.trustScenario)throw unavailable();return row;}
  return Object.freeze({
    async provision(value,fence){return write(value,fence,null,async client=>{await client.query(`INSERT INTO secureshop_agents.bound_mcp_targets
      (target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,server_identity,trust_scenario)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(launch_id,generation,trust_scenario) DO NOTHING`,[...scopeArgs(value),value.serverIdentity,value.trustScenario]);
      await active(client,value);return value;});},
    async currentSchema(value,fence){return write(value,fence,null,async client=>{const target=await active(client,value);
      if(target.current_schema_version===0)return null;const row=(await client.query(`SELECT v.version,encode(v.schema_sha256,'hex') AS schema_sha256,
        p.tools_json FROM secureshop_agents.bound_mcp_schema_versions v JOIN secureshop_agents.bound_mcp_tool_payloads p USING(target_id,version)
        WHERE v.target_id=$1 AND v.version=$2`,[value.targetId,target.current_schema_version])).rows[0];
      if(!row)throw unavailable();return Object.freeze({serverIdentity:value.serverIdentity,version:row.version,schemaSha256:row.schema_sha256,tools:row.tools_json});});},
    async recordDiscovery(value,input,inputPersona,fence){const actor=auditStore||fence?createConversationBinding(value,inputPersona):null;
      return write(value,fence,actor,async client=>{if(input.expectedVersion>0)await checkRotation({...value,...input},client);const target=await active(client,value,'FOR UPDATE');if(target.current_schema_version!==input.expectedVersion)throw unavailable('Bound MCP schema conflict');
        const version=input.expectedVersion+1;await client.query(`INSERT INTO secureshop_agents.bound_mcp_schema_versions
          (target_id,version,schema_sha256,discovery_receipt_sha256) VALUES($1,$2,decode($3,'hex'),decode($4,'hex'))`,
        [value.targetId,version,input.schemaSha256,input.discoveryReceiptSha256]);
        await client.query('INSERT INTO secureshop_agents.bound_mcp_tool_payloads(target_id,version,tools_json) VALUES($1,$2,$3::jsonb)',
          [value.targetId,version,JSON.stringify(input.tools)]);await client.query('UPDATE secureshop_agents.bound_mcp_targets SET current_schema_version=$2 WHERE target_id=$1',[value.targetId,version]);
        if(auditStore)await auditStore.append(client,{eventId:crypto.randomUUID(),scope:value,
          persona:{id:actor.shopUserId,role:actor.role},actor:actor.role,
          action:input.expectedVersion===0?'mcp_schema_discovered':'mcp_schema_rotated',target:`mcp:${value.serverIdentity}`,
          paramsJson:JSON.stringify({previousVersion:input.expectedVersion,version,schemaSha256:input.schemaSha256,
            discoveryReceiptSha256:input.discoveryReceiptSha256,trustScenario:value.trustScenario}),
          outcome:'completed',sourceKind:'bound_mcp_schema_version',sourceId:`${value.targetId}:${version}`});
        await checkCurrent(value,client);
        return Object.freeze({serverIdentity:value.serverIdentity,version,schemaSha256:input.schemaSha256,tools:input.tools});});},
    async recordInvocation(value,input,inputPersona,fence){
      const actor=auditStore||fence?createConversationBinding(value,inputPersona):null;
      return write(value,fence,actor,async client=>{await active(client,value,'FOR UPDATE');
      if(input.trustScenario!==value.trustScenario)throw unavailable('Bound MCP invocation scenario mismatch');
      const prior=(await client.query(`SELECT *,encode(schema_sha256,'hex') AS schema_hex,encode(arguments_sha256,'hex') AS arguments_hex,
        encode(remote_receipt_sha256,'hex') AS remote_hex,encode(trust_policy_sha256,'hex') AS trust_hex,
        encode(result_sha256,'hex') AS result_hex FROM secureshop_agents.bound_mcp_invocations WHERE operation_id=$1`,[input.operationId])).rows[0];
        if(prior){if(prior.target_id!==value.targetId||prior.schema_version!==input.schemaVersion||prior.schema_hex!==input.schemaSha256
        ||prior.run_id!==input.runId||prior.request_id!==input.requestId||prior.call_id!==input.callId||prior.tool_name!==input.toolName
        ||prior.arguments_hex!==input.argumentsSha256||prior.remote_hex!==input.remoteReceiptSha256||prior.trust_hex!==input.trustPolicySha256
        ||prior.approved!==input.approved||prior.server_approved!==input.serverApproved||prior.schema_approved!==input.schemaApproved
        ||prior.trust_scenario!==input.trustScenario||prior.behavior_class!==input.behaviorClass||prior.result_hex!==input.resultSha256)
        throw unavailable('Bound MCP operation conflict');await auditInvocation(client,value,input,actor);await checkCurrent(value,client);return Object.freeze({...prior,invocationId:prior.invocation_id,
          operationId:prior.operation_id,targetId:prior.target_id,runId:prior.run_id,
          requestId:prior.request_id,callId:prior.call_id,toolName:prior.tool_name,serverIdentity:value.serverIdentity,
          schemaVersion:prior.schema_version,schemaSha256:prior.schema_hex,remoteReceiptSha256:prior.remote_hex,
          trustPolicySha256:prior.trust_hex,resultSha256:prior.result_hex,trustScenario:prior.trust_scenario,
          serverApproved:prior.server_approved,schemaApproved:prior.schema_approved,behaviorClass:prior.behavior_class,
          completedAt:new Date(prior.completed_at).toISOString()});}
      const row=(await client.query(`INSERT INTO secureshop_agents.bound_mcp_invocations(invocation_id,operation_id,target_id,schema_version,schema_sha256,
        run_id,request_id,call_id,tool_name,arguments_sha256,remote_receipt_sha256,trust_policy_sha256,approved,server_approved,
        schema_approved,trust_scenario,behavior_class,result_sha256)
        VALUES($1,$1,$2,$3,decode($4,'hex'),$5,$6,$7,$8,decode($9,'hex'),decode($10,'hex'),decode($11,'hex'),$12,$13,$14,$15,$16,decode($17,'hex')) RETURNING *,
        encode(schema_sha256,'hex') AS schema_hex,encode(remote_receipt_sha256,'hex') AS remote_hex,
        encode(trust_policy_sha256,'hex') AS trust_hex,encode(result_sha256,'hex') AS result_hex`,
      [input.operationId,value.targetId,input.schemaVersion,input.schemaSha256,input.runId,input.requestId,input.callId,input.toolName,
        input.argumentsSha256,input.remoteReceiptSha256,input.trustPolicySha256,input.approved,input.serverApproved,input.schemaApproved,
        input.trustScenario,input.behaviorClass,input.resultSha256])).rows[0];
      await auditInvocation(client,value,input,actor);
      await checkCurrent(value,client);
      return Object.freeze({...row,
        invocationId:row.invocation_id,operationId:row.operation_id,targetId:row.target_id,runId:row.run_id,
        requestId:row.request_id,callId:row.call_id,toolName:row.tool_name,serverIdentity:value.serverIdentity,schemaVersion:row.schema_version,
        schemaSha256:row.schema_hex,remoteReceiptSha256:row.remote_hex,trustPolicySha256:row.trust_hex,resultSha256:row.result_hex,
        trustScenario:input.trustScenario,approved:input.approved,
        serverApproved:input.serverApproved,schemaApproved:input.schemaApproved,behaviorClass:input.behaviorClass,
        completedAt:new Date(row.completed_at).toISOString()});});},
    async readInvocation(value,id){await checkCurrent(value);const row=(await pool.query(`SELECT i.*,t.server_identity,encode(i.schema_sha256,'hex') AS schema_hex,
      encode(i.remote_receipt_sha256,'hex') AS remote_hex,encode(i.trust_policy_sha256,'hex') AS trust_hex,
      encode(i.result_sha256,'hex') AS result_hex FROM secureshop_agents.bound_mcp_invocations i
      JOIN secureshop_agents.bound_mcp_targets t USING(target_id) WHERE i.invocation_id=$1 AND i.target_id=$2 AND t.launch_id=$3 AND t.scenario_id=$4
      AND t.generation=$5 AND t.original_platform_owner_id=$6 AND t.original_platform_session_id=$7`,[id,...scopeArgs(value)])).rows[0];
      if(!row)throw unavailable();return Object.freeze({...row,invocationId:row.invocation_id,operationId:row.operation_id,
        targetId:row.target_id,runId:row.run_id,requestId:row.request_id,callId:row.call_id,
        toolName:row.tool_name,serverIdentity:row.server_identity,schemaVersion:row.schema_version,schemaSha256:row.schema_hex,
        remoteReceiptSha256:row.remote_hex,trustPolicySha256:row.trust_hex,resultSha256:row.result_hex,
        trustScenario:row.trust_scenario,approved:row.approved,serverApproved:row.server_approved,
        schemaApproved:row.schema_approved,behaviorClass:row.behavior_class,
        completedAt:new Date(row.completed_at).toISOString()});},
    async readPriorSchema(value,invocation){await checkCurrent(value);const row=(await pool.query(`SELECT v.version,encode(v.schema_sha256,'hex') AS schema_sha256,
      i.target_id,i.invocation_id,i.operation_id,i.run_id,i.request_id,i.call_id,i.completed_at,
      encode(i.remote_receipt_sha256,'hex') AS remote_receipt_sha256,encode(i.result_sha256,'hex') AS result_sha256,
      i.behavior_class,i.server_approved,i.schema_approved FROM secureshop_agents.bound_mcp_schema_versions v JOIN secureshop_agents.bound_mcp_invocations i
      ON i.target_id=v.target_id AND i.schema_version=v.version WHERE v.target_id=$1 AND v.version<$2
      AND EXISTS (SELECT 1 FROM secureshop_agents.bound_mcp_invocations current_invocation
        WHERE current_invocation.invocation_id=$3 AND current_invocation.target_id=v.target_id
        AND current_invocation.schema_version=$2
        AND i.completed_at<current_invocation.completed_at)
      AND i.behavior_class='public_forecast_lookup' AND i.server_approved AND i.schema_approved
      AND i.trust_scenario='rug_pull' ORDER BY v.version DESC,i.completed_at DESC LIMIT 1`,
    [value.targetId,invocation.schemaVersion,invocation.invocationId])).rows[0];return row?Object.freeze({...row,serverIdentity:value.serverIdentity,
      targetId:row.target_id,invocationId:row.invocation_id,operationId:row.operation_id,runId:row.run_id,
      requestId:row.request_id,callId:row.call_id,completedAt:new Date(row.completed_at).toISOString(),
      schemaSha256:row.schema_sha256,remoteReceiptSha256:row.remote_receipt_sha256,resultSha256:row.result_sha256,
      behaviorClass:row.behavior_class,serverApproved:row.server_approved,schemaApproved:row.schema_approved}):null;},
    async retire(value,input){await checkCleanup({...value,...input});const rows=(await pool.query(
      'SELECT * FROM secureshop_agents.retire_bound_mcp_target($1,$2,$3,$4,$5,$6,$7,decode($8,\'hex\'))',
      [input.operationId,...scopeArgs(value),input.receiptSha256])).rows;if(rows.length!==1)throw unavailable();return rows[0];},
    async readCleanupReceipt(value,input){await checkCleanup({...value,...input});const row=(await pool.query(`SELECT r.*,
      t.trust_scenario,encode(r.receipt_sha256,'hex') AS receipt_hex FROM secureshop_agents.bound_mcp_cleanup_receipts r
      JOIN secureshop_agents.bound_mcp_targets t USING(target_id) WHERE r.operation_id=$1 AND r.target_id=$2
      AND r.launch_id=$3 AND r.scenario_id=$4 AND r.generation=$5 AND r.original_platform_owner_id=$6
      AND r.original_platform_session_id=$7`,[input.operationId,...scopeArgs(value)])).rows[0];
      if(!row||row.trust_scenario!==value.trustScenario)throw unavailable('Bound MCP cleanup receipt unavailable');
      return Object.freeze({targetId:row.target_id,launchId:row.launch_id,scenarioId:row.scenario_id,
        fromGeneration:Number(row.generation),platformOwnerId:Number(row.original_platform_owner_id),
        platformSessionId:Number(row.original_platform_session_id),operationId:row.operation_id,
        targetReceiptVersion:1,targetReceiptSha256:row.receipt_hex,targetCompletedAt:new Date(row.completed_at).toISOString()});},
  });
}
module.exports={createSecureShopBoundMcpRepository};
