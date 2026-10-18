'use strict';
const {randomUUID}=require('node:crypto');
const C=require('../../services/secureshopOwnedMcpInvocationContract');
const P=require('../../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {currentEffectAdmission}=require('../../agent-runtime/effectAdmissionContext');
const {createOwnedMcpInvocationJournal}=require('./secureshopOwnedMcpInvocationJournal');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const fail=()=>Object.assign(Error('Registry invocation journal unavailable'),{code:'MCP_INVOCATION_DENIED'});

function validateEnvelope(raw){
 const v=C.bounded(raw,196608),snapshot=C.snapshot(v.snapshot),request=C.request({snapshot,...v.request,
  toolIndex:snapshot.tools.findIndex(t=>t.name===v.request?.toolName)});
 const m=v.executorMapping,q=P.request(m?.request);
 if(m.version!==1||m.instanceId!==q.instanceId||m.runtimeSha256!==v.runtimeSha256
  ||m.instanceId!==v.managerInstanceId||q.operationId!==v.invocationId||m.requestSha256!==P.digest(q)
  ||v.requestSha256!==C.digest(request)||C.digest(request)!==C.digest(v.request)
  ||q.entry.entryId!==request.entryId||q.entry.registryVersion!==request.registryVersion
  ||q.entry.schemaSha256!==request.schemaSha256||C.digest(q.entry.tools)!==C.digest(snapshot.tools)
  ||q.toolName!==request.toolName||C.digest(q.args)!==C.digest(request.args)
  ||!UUID.test(v.invocationId)||!UUID.test(v.personaSession?.sessionId)
  ||! /^[1-9][0-9]{0,18}$/.test(v.personaSession?.authorityVersion||'')
  ||!SHA.test(v.runtimeSha256)||!SHA.test(v.policySha256)||typeof v.effectKey!=='string'||!v.effectKey)throw fail();
 return C.freeze(v);
}
function createRegistryInvocationJournal({pool,personaAuthority,makeId=randomUUID}={}){
 if(typeof pool?.query!=='function'||typeof personaAuthority?.capture!=='function')throw TypeError('Canonical journal dependencies required');
 const handles=new WeakMap(),base=createOwnedMcpInvocationJournal({pool});
 function prepare(raw,execution){
  const effect=currentEffectAdmission(execution),v=validateEnvelope({...raw,effectKey:effect.ledgerEffectKey});
  if(v.request.runId!==execution.runId)throw fail();
  const h=Object.freeze({});handles.set(h,{v,worker:makeId(),execution});return h;
 }
 function get(h){const value=handles.get(h);if(!value)throw fail();return value;}
 function scopeOf(h){return createLaunchScope(get(h).v.request.binding);}
 function identity(h){const v=get(h).v,m=v.executorMapping;return C.freeze({instanceId:m.instanceId,operationId:v.invocationId,requestSha256:m.requestSha256});}
 async function admitPrepared(h){
  const {v,worker,execution}=get(h);currentEffectAdmission(execution);
  const b=v.request.binding,scope=scopeOf(h),expected={...scope,personaId:b.shopUserId,role:b.role,
   sessionId:v.personaSession.sessionId,authorityVersion:v.personaSession.authorityVersion};
  const fence=personaAuthority.capture({scope,...Object.fromEntries(Object.entries(expected).filter(([key])=>!Object.hasOwn(scope,key)))});
  if(C.digest(fence?.binding)!==C.digest(expected)||typeof fence.withPersonaEffect!=='function')throw fail();
  const row=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   return(await client.query('SELECT * FROM secureshop_agents.admit_owned_mcp_invocation($1::jsonb,$2)',[JSON.stringify(v),worker])).rows[0];
  });
  if(row?.invocation_id!==v.invocationId||row.request_sha256?.toString('hex')!==v.requestSha256||row.state!=='admitted')throw fail();
  return C.freeze({invocationId:v.invocationId,requestSha256:v.requestSha256,managerInstanceId:v.managerInstanceId,state:row.state});
 }
 async function settlePrepared(h,{receipt,status}={}){
  const {v,worker}=get(h);let proof,state,drained;
  if(receipt){proof=P.receipt(receipt,v.executorMapping.request);state='completed';drained=true;}
  else {
   proof=C.bounded(status,2048);const id=identity(h);
   if(!proof||Object.keys(proof).sort().join()!=='drained,instanceId,operationId,requestSha256,state,version'
    ||proof.version!==1||Object.entries(id).some(([k,value])=>proof[k]!==value)
    ||!['running','completed','retired','unknown'].includes(proof.state)
    ||proof.drained!==['completed','retired'].includes(proof.state))throw fail();
   // Status proves retirement only; it cannot reconstruct a lost result.
   state='uncertain';drained=proof.drained;
  }
  const body={invocationId:v.invocationId,requestSha256:v.requestSha256,managerInstanceId:v.managerInstanceId,
   runtimeSha256:v.runtimeSha256,state,drained,executorProof:proof};
  const row=(await pool.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[v.invocationId,worker,state,JSON.stringify(body)])).rows[0];
  if(row?.invocation_id!==v.invocationId||row.state!==state||row.request_sha256?.toString('hex')!==v.requestSha256)throw fail();
  return C.freeze({state,drained});
 }
 // Only the live bridge may assert that its exact private handle never dispatched.
 async function settleNotDispatched(h){
  const {v,worker}=get(h);
  const existing=(await pool.query('SELECT invocation_id FROM secureshop_agents.owned_mcp_invocation_journal WHERE invocation_id=$1',[v.invocationId])).rows;
  if(existing.length===0)return C.freeze({state:'absent',drained:true});
  if(existing.length!==1||existing[0].invocation_id!==v.invocationId)throw fail();
  const body={invocationId:v.invocationId,requestSha256:v.requestSha256,managerInstanceId:v.managerInstanceId,
   runtimeSha256:v.runtimeSha256,state:'failed_before_effect',drained:true,
   localNotDispatched:{version:1,...identity(h)}};
  const row=(await pool.query('SELECT * FROM secureshop_agents.settle_owned_mcp_invocation($1,$2,$3,$4::jsonb)',[v.invocationId,worker,'failed_before_effect',JSON.stringify(body)])).rows[0];
  if(row?.invocation_id!==v.invocationId||row.state!=='failed_before_effect'||row.request_sha256?.toString('hex')!==v.requestSha256)throw fail();
  return C.freeze({state:'failed_before_effect',drained:true});
 }
 async function mappings(scope,{ownerOnly=false}={}){
  const rows=await base.existing(scope,{ownerOnly}),s=ownerOnly?scope:createLaunchScope(scope),out=[];
  for(const row of rows){
   if(row.drained===true){out.push({...row,mapping:null});continue;}
   const full=(await pool.query('SELECT request_json FROM secureshop_agents.owned_mcp_invocation_journal WHERE invocation_id=$1 AND original_platform_owner_id=$2 AND redacted_at IS NULL',[row.invocation_id,s.platformOwnerId])).rows[0];
   const v=validateEnvelope(full?.request_json),b=v.request.binding;
   if(v.invocationId!==row.invocation_id||v.managerInstanceId!==row.manager_instance_id||v.runtimeSha256!==row.runtime_sha256
    ||b.platformOwnerId!==s.platformOwnerId||(!ownerOnly&&C.digest(createLaunchScope(b))!==C.digest(s)))throw fail();
   out.push({...row,mapping:v.executorMapping});
  }
  return C.freeze(out);
 }
 async function readCompleted({scope,invocationId}){
  const s=createLaunchScope(scope);if(!UUID.test(invocationId||''))throw fail();
  const row=(await pool.query(`SELECT invocation_id,request_json,receipt_json,request_sha256,run_id,effect_key,
   manager_instance_id,runtime_sha256,state,drained FROM secureshop_agents.owned_mcp_invocation_journal
   WHERE invocation_id=$1 AND original_platform_owner_id=$2 AND platform_launch_id=$3
    AND platform_scenario_id=$4 AND platform_launch_generation=$5 AND original_platform_session_id=$6
    AND redacted_at IS NULL`,[invocationId,s.platformOwnerId,s.launchId,s.scenarioId,s.generation,s.platformSessionId])).rows[0];
  if(!row||row.state!=='completed'||row.drained!==true)throw fail();
  const v=validateEnvelope(row.request_json),r=row.receipt_json;
  if(C.digest(createLaunchScope(v.request.binding))!==C.digest(s)||v.invocationId!==invocationId
   ||row.invocation_id!==invocationId||row.request_sha256?.toString('hex')!==v.requestSha256
   ||row.run_id!==v.request.runId||row.effect_key!==v.effectKey||row.manager_instance_id!==v.managerInstanceId
   ||row.runtime_sha256?.toString('hex')!==v.runtimeSha256||r?.state!=='completed'||r.drained!==true
   ||r.invocationId!==invocationId||r.requestSha256!==v.requestSha256
   ||r.managerInstanceId!==v.managerInstanceId||r.runtimeSha256!==v.runtimeSha256)throw fail();
  const receipt=P.receipt(r.executorProof,v.executorMapping.request);
  return C.freeze({envelope:v,receipt});
 }
 return Object.freeze({prepare,scopeOf,identity,admitPrepared,settlePrepared,settleNotDispatched,mappings,readCompleted,
  existing:base.existing,recordFence:base.recordFence});
}
module.exports={createRegistryInvocationJournal,validateEnvelope};
