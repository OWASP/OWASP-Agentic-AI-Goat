'use strict';
const {randomUUID}=require('node:crypto');
const C=require('../../services/secureshopOwnedMcpInvocationContract');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {currentEffectAdmission}=require('../../agent-runtime/effectAdmissionContext');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,SHA=/^[0-9a-f]{64}$/;
const fail=()=>Object.assign(Error('Owned invocation journal unavailable'),{code:'MCP_INVOCATION_DENIED'});
const uuid=v=>{if(typeof v!=='string'||!UUID.test(v))throw fail();return v;};
const sha=v=>{if(typeof v!=='string'||!SHA.test(v))throw fail();return v;};
function createOwnedMcpInvocationJournal({pool,personaAuthority,makeId=randomUUID}={}){
 if(typeof pool?.query!=='function')throw new TypeError('Invocation journal pool required');
 const prepared=new WeakMap();
 function prepare(raw,execution){
  const x=C.bounded(raw,196608),snapshot=C.snapshot(x.snapshot),request=C.request({...x,snapshot});
  const effect=currentEffectAdmission(execution);if(execution.runId!==request.runId)throw fail();
  uuid(x.personaSession?.sessionId);if(typeof x.personaSession.authorityVersion!=='string'||! /^[1-9][0-9]{0,18}$/.test(x.personaSession.authorityVersion)||BigInt(x.personaSession.authorityVersion)>9223372036854775807n)throw fail();
  const value=C.freeze({invocationId:uuid(x.invocationId),snapshot,request,requestSha256:C.digest(request),personaSession:x.personaSession,
   managerInstanceId:uuid(x.managerInstanceId),runtimeSha256:sha(x.runtimeSha256),policySha256:sha(x.policySha256),
   effectKey:effect.ledgerEffectKey});
  const handle=Object.freeze({});prepared.set(handle,{value,execution:Object.freeze({...execution}),worker:uuid(makeId())});return handle;
 }
 function scopeOf(handle){const p=prepared.get(handle);if(!p)throw fail();return createLaunchScope(p.value.request.binding);}
 async function admitPrepared(handle){
  const p=prepared.get(handle);if(!p||typeof personaAuthority?.capture!=='function')throw fail();currentEffectAdmission(p.execution);
  const v=p.value,b=v.request.binding,scope=scopeOf(handle);
  const fence=personaAuthority.capture({scope,personaId:b.shopUserId,role:b.role,sessionId:v.personaSession.sessionId,authorityVersion:v.personaSession.authorityVersion});
  if(C.digest(fence?.binding)!==C.digest({...scope,personaId:b.shopUserId,role:b.role,sessionId:v.personaSession.sessionId,authorityVersion:v.personaSession.authorityVersion})||typeof fence?.withPersonaEffect!=='function')throw fail();
  const row=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   return(await client.query('SELECT * FROM secureshop_agents.admit_owned_mcp_invocation($1::jsonb,$2)',[JSON.stringify(v),p.worker])).rows[0];
  });
  if(!row||row.invocation_id!==v.invocationId||row.request_sha256?.toString('hex')!==v.requestSha256)throw fail();
  // This returns to the private launch helper, still before its identity COMMIT.
  // No capability is minted and no transport is reachable in this repository.
  return C.freeze({invocationId:v.invocationId,requestSha256:v.requestSha256,state:row.state,managerInstanceId:v.managerInstanceId});
 }
 async function settlePrepared(handle,raw){
  const p=prepared.get(handle);if(!p)throw fail();const v=p.value,r=C.bounded(raw,196608);
  if(r.invocationId!==v.invocationId||r.requestSha256!==v.requestSha256||r.managerInstanceId!==v.managerInstanceId||r.runtimeSha256!==v.runtimeSha256
   ||!['completed','failed_before_effect','uncertain'].includes(r.state)||typeof r.drained!=='boolean'||(r.state!=='uncertain'&&!r.drained))throw fail();
  // Private worker handle only. Authentication of raw receipt remains the
  // manager client's obligation; this repository is not a public receipt API.
  const row=(await pool.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[v.invocationId,p.worker,r.state,JSON.stringify(r)])).rows[0];
  if(!row||row.invocation_id!==v.invocationId||row.state!==r.state||row.request_sha256?.toString('hex')!==v.requestSha256)throw fail();
  return C.freeze({invocationId:v.invocationId,state:row.state,requestSha256:v.requestSha256});
 }
 async function existing(scope,{ownerOnly=false}={}){
  const available=(await pool.query("SELECT to_regclass('secureshop_agents.owned_mcp_invocation_journal')::text AS invocation_table")).rows[0];
  if(available?.invocation_table===null)return[];if(available?.invocation_table!=='secureshop_agents.owned_mcp_invocation_journal')throw fail();
  const s=ownerOnly?scope:createLaunchScope(scope);
  return(await pool.query(`SELECT invocation_id::text,manager_instance_id::text,encode(runtime_sha256,'hex') AS runtime_sha256,drained,state
   FROM secureshop_agents.owned_mcp_invocation_journal WHERE original_platform_owner_id=$1 ${ownerOnly?'':'AND platform_launch_id=$2 AND platform_scenario_id=$3 AND platform_launch_generation=$4 AND original_platform_session_id=$5'} ORDER BY invocation_id`,ownerOnly?[s.platformOwnerId]:[s.platformOwnerId,s.launchId,s.scenarioId,s.generation,s.platformSessionId])).rows;
 }
 async function recordFence(receipt){const value=C.bounded(receipt,65536);await pool.query('SELECT secureshop_agents.record_owned_mcp_invocation_fence($1::jsonb)',[JSON.stringify(value)]);}
 return Object.freeze({prepare,scopeOf,admitPrepared,settlePrepared,existing,recordFence});
}
module.exports={createOwnedMcpInvocationJournal};
