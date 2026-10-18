'use strict';
// Unwired private recovery repository. No grant issuance or execution method.
const C=require('../../services/secureshopOwnedMcpInvocationContract');
const W=require('../../services/secureshopOwnedMcpInvocationWire');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail=()=>Object.assign(Error('Invocation recovery unavailable'),{code:'MCP_INVOCATION_RECOVERY_DENIED'});
function createInvocationRecoveryRepository({pool,recoveryAuthority,personaAuthority,launches}={}){
 if(typeof pool?.query!=='function'||typeof recoveryAuthority?.assertCurrent!=='function')throw TypeError('Canonical private recovery authority required');
 const canonical=personaAuthority!==undefined||launches!==undefined;
 if(canonical&&(typeof personaAuthority?.capture!=='function'||typeof launches?.settleOwnedMcpRecovery!=='function'))throw TypeError('Complete canonical recovery composition required');
 const handles=new WeakMap(),check=recoveryAuthority.assertCurrent.bind(recoveryAuthority);
 function rowValue(row,query){
  if(!row||row.redacted_at!==null||typeof row.worker_token!=='string'||!UUID.test(row.worker_token)||row.invocation_id!==query.invocationId)throw fail();
  const stored=C.bounded(row.request_json,196608),snapshot=C.snapshot(stored.snapshot),request=stored.request;
  if(C.digest(C.request({snapshot,runId:request?.runId,requestId:request?.requestId,callId:request?.callId,toolIndex:snapshot.tools.findIndex(t=>t.name===request?.toolName),args:request?.args,mode:request?.mode}))!==C.digest(request))throw fail();
  const scope=createLaunchScope(request.binding),rowScope=createLaunchScope({launchId:row.platform_launch_id,scenarioId:row.platform_scenario_id,generation:Number(row.platform_launch_generation),platformOwnerId:row.original_platform_owner_id,platformSessionId:row.original_platform_session_id});
  if(C.digest(scope)!==C.digest(query.scope)||C.digest(scope)!==C.digest(rowScope)||stored.invocationId!==row.invocation_id||stored.requestSha256!==C.digest(request)||row.request_sha256?.toString('hex')!==stored.requestSha256||stored.managerInstanceId!==row.manager_instance_id||stored.runtimeSha256!==row.runtime_sha256?.toString('hex')||stored.effectKey!==row.effect_key||request.runId!==row.run_id||request.entryId!==row.entry_id||request.registryVersion!==String(row.registry_version)||request.binding.shopUserId!==row.persona_id||stored.personaSession?.sessionId!==row.persona_session_id||stored.personaSession?.authorityVersion!==String(row.authority_version))throw fail();
  return{scope,identity:W.lookup({invocationId:row.invocation_id,requestSha256:stored.requestSha256,managerInstanceId:row.manager_instance_id,runtimeSha256:stored.runtimeSha256}),worker:row.worker_token,persona:{scope,personaId:request.binding.shopUserId,role:request.binding.role,sessionId:stored.personaSession.sessionId,authorityVersion:stored.personaSession.authorityVersion}};
 }
 async function prepare(raw){
  const input=C.bounded(raw,2048);if(Object.keys(input).sort().join()!=='invocationId,scope'||typeof input.invocationId!=='string'||!UUID.test(input.invocationId))throw fail();
  const query=C.freeze({invocationId:input.invocationId,scope:createLaunchScope(input.scope)});if(C.digest(query.scope)!==C.digest(input.scope))throw fail();
  await check(query);const s=query.scope;
  const row=(await pool.query('SELECT * FROM secureshop_agents.read_owned_mcp_invocation_recovery($1,$2,$3,$4,$5,$6)',[query.invocationId,s.platformOwnerId,s.launchId,s.scenarioId,s.generation,s.platformSessionId])).rows[0];
  const value=rowValue(row,query);await check(query);
  if(canonical){value.fence=personaAuthority.capture(value.persona);if(C.digest(value.fence?.binding)!==C.digest({...value.scope,...Object.fromEntries(Object.entries(value.persona).filter(([k])=>k!=='scope'))})||typeof value.fence.withPersonaEffect!=='function')throw fail();await value.fence.assertRemoteAdmission();}
  const handle=Object.freeze({});handles.set(handle,{...value,query});return handle;
 }
 function identity(handle){const value=handles.get(handle);if(!value)throw fail();return value.identity;}
 function scopeOf(handle){const value=handles.get(handle);if(!value)throw fail();return value.scope;}
 async function settle(handle,raw){if(canonical)return launches.settleOwnedMcpRecovery(handle,C.bounded(raw,196608));return settlePrepared(handle,raw);}
 async function settlePrepared(handle,raw){const value=handles.get(handle);if(!value)throw fail();const receipt=C.bounded(raw,196608);if(Object.entries(value.identity).some(([k,v])=>receipt[k]!==v)||!['completed','failed_before_effect','uncertain'].includes(receipt.state)||typeof receipt.drained!=='boolean'||receipt.state!=='uncertain'&&!receipt.drained)throw fail();await check(value.query);
  const write=async client=>{await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");return(await client.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[value.identity.invocationId,value.worker,receipt.state,JSON.stringify(receipt)])).rows[0];};
  const row=canonical?await value.fence.withPersonaEffect(write):(await pool.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[value.identity.invocationId,value.worker,receipt.state,JSON.stringify(receipt)])).rows[0];
  if(!row||row.invocation_id!==value.identity.invocationId||row.state!==receipt.state||row.request_sha256?.toString('hex')!==value.identity.requestSha256)throw fail();return C.freeze({...value.identity,state:row.state});
 }
 return Object.freeze({prepare,identity,settle,scopeOf,settlePrepared});
}
module.exports={createInvocationRecoveryRepository};
