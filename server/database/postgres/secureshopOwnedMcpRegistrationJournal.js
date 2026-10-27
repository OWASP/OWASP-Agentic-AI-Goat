'use strict';
const {randomUUID}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {createLaunchScope,createConversationBinding}=require('../../services/secureshopConversationBinding');
const {canonicalDigest}=require('../../services/mcp/protocolContext');
const {normalizeRegistryRequest,registryRequestDigest}=require('../../services/secureshopMcpRegistryContract');
const {currentEffectAdmission}=require('../../agent-runtime/effectAdmissionContext');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const fail=()=>Object.assign(Error('Owned registration journal unavailable'),{code:'MCP_REGISTRATION_ADMISSION_REQUIRED',executionBoundary:true});
function envelope(raw){
 const v=structuredClone(raw),scope=createLaunchScope(v.scope),binding=createConversationBinding(scope,v.persona);
 const keys=['version','scope','persona','personaSession','runId','callId','step','tool','args','argsSha256','request','requestSha256','instanceId','runtimeDigest','mode','effectKey'];
 if(!v||Object.keys(v).sort().join()!==keys.sort().join()||v.version!==1||binding.role!=='admin'
  ||!UUID.test(v.runId)||!UUID.test(v.instanceId)||!SHA.test(v.runtimeDigest)||!UUID.test(v.personaSession?.sessionId)
  ||! /^[1-9][0-9]{0,18}$/.test(v.personaSession?.authorityVersion||'')||!['vuln','fixed'].includes(v.mode)
  ||v.tool!=='mcp-registry.register'||! /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v.callId||'')
  ||!Number.isSafeInteger(v.step)||v.step<0||v.step>100||typeof v.effectKey!=='string'||!v.effectKey||Buffer.byteLength(v.effectKey)>256
  ||!v.args||Object.getPrototypeOf(v.args)!==Object.prototype||canonicalDigest(v.args)!==v.argsSha256)throw fail();
 const request=normalizeRegistryRequest(v.request);
 if(request.action!=='register'||request.transport!=='stdio'||request.stdio_cmd!==v.args.stdio_cmd
  ||request.name!==v.args.name||v.args.transport!=='stdio'||registryRequestDigest(request)!==v.requestSha256
  ||Buffer.byteLength(JSON.stringify(v))>65536)throw fail();
 return Object.freeze({...v,scope,persona:Object.freeze({id:binding.shopUserId,role:binding.role}),request});
}
function createOwnedMcpRegistrationJournal({pool,personaAuthority,makeId=randomUUID}={}){
 if(typeof pool?.query!=='function')throw TypeError('Registration journal pool required');
 const handles=new WeakMap();
 const get=h=>{const p=handles.get(h);if(!p)throw fail();return p;};
 function prepare(raw,execution){
  const effect=currentEffectAdmission(execution),v=envelope({...raw,effectKey:effect.ledgerEffectKey});
  if(v.runId!==execution.runId)throw fail();
  const h=Object.freeze({});handles.set(h,{v,execution,worker:makeId()});return h;
 }
 const scopeOf=h=>get(h).v.scope;
 const identity=h=>{const v=get(h).v;return Object.freeze({instanceId:v.instanceId,operationId:v.request.operationId,requestSha256:v.requestSha256});};
 async function admitPrepared(h){
  const {v,execution,worker}=get(h);currentEffectAdmission(execution);
  if(typeof personaAuthority?.capture!=='function')throw fail();
  const expected={...v.scope,personaId:v.persona.id,role:'admin',sessionId:v.personaSession.sessionId,authorityVersion:v.personaSession.authorityVersion};
  const fence=personaAuthority.capture({scope:v.scope,personaId:v.persona.id,role:'admin',...v.personaSession});
  if(!isDeepStrictEqual(fence?.binding,expected)||typeof fence.withPersonaEffect!=='function')throw fail();
  const row=await fence.withPersonaEffect(async client=>(await client.query('SELECT * FROM secureshop_agents.admit_owned_mcp_registration($1::jsonb,$2)',[JSON.stringify(v),worker])).rows[0]);
  if(row?.operation_id!==v.request.operationId||row.state!=='admitted'||row.request_sha256?.toString('hex')!==v.requestSha256)throw fail();
  return Object.freeze({...identity(h),state:'admitted'});
 }
 async function settlePrepared(h,{receipt,status,notDispatched=false}={}){
  const {v,worker}=get(h),id=identity(h);let proof,state,drained;
  if(notDispatched){if(receipt||status)throw fail();proof={version:1,...id,state:'not_dispatched',drained:true};state='failed_before_effect';drained=true;}
  else{
   proof=structuredClone(receipt||status);
   if(!proof||proof.version!==1||Object.entries(id).some(([key,value])=>proof[key]!==value))throw fail();
   if(receipt){if(proof.state!=='completed'||proof.drained!==true||!Array.isArray(proof.changes))throw fail();state='completed';drained=true;}
   else{if(!['running','completed','retired','unknown'].includes(proof.state)||proof.drained!==['completed','retired'].includes(proof.state))throw fail();state='uncertain';drained=proof.drained;}
  }
  const settlement={version:1,...id,runtimeDigest:v.runtimeDigest,state,drained,proof};
  const row=(await pool.query('SELECT * FROM secureshop_agents.settle_owned_mcp_registration($1,$2,$3::jsonb)',[id.operationId,worker,JSON.stringify(settlement)])).rows[0];
  if(row?.operation_id!==id.operationId||row.state!==state||row.drained!==drained)throw fail();
  return Object.freeze(settlement);
 }
 async function existing(scope,{ownerOnly=false}={}){
  const exists=(await pool.query("SELECT to_regclass('secureshop_agents.owned_mcp_registration_journal')::text AS registration_table")).rows[0];
  if(exists?.registration_table===null)return [];
  if(exists?.registration_table!=='secureshop_agents.owned_mcp_registration_journal')throw fail();
  const s=ownerOnly?scope:createLaunchScope(scope);
  return(await pool.query(`SELECT operation_id::text,instance_id::text,encode(runtime_sha256,'hex') AS runtime_digest,
   encode(request_sha256,'hex') AS request_sha256,state,drained FROM secureshop_agents.owned_mcp_registration_journal
   WHERE original_platform_owner_id=$1 ${ownerOnly?'':'AND platform_launch_id=$2 AND platform_scenario_id=$3 AND platform_launch_generation=$4 AND original_platform_session_id=$5'} ORDER BY operation_id`,ownerOnly?[s.platformOwnerId]:[s.platformOwnerId,s.launchId,s.scenarioId,s.generation,s.platformSessionId])).rows;
 }
 async function recordFence(receipt){await pool.query('SELECT secureshop_agents.record_owned_mcp_registration_fence($1::jsonb)',[JSON.stringify(receipt)]);}
 async function unsettled(){
  return(await pool.query(`SELECT operation_id::text,instance_id::text,encode(runtime_sha256,'hex') AS runtime_digest,
   encode(request_sha256,'hex') AS request_sha256,state,drained FROM secureshop_agents.owned_mcp_registration_journal
   WHERE NOT drained ORDER BY operation_id`)).rows;
 }
 async function recordDrain(receipt){await pool.query('SELECT secureshop_agents.record_owned_mcp_registration_drain($1::jsonb)',[JSON.stringify(receipt)]);}
 async function readCompleted({scope,operationId}){
  const s=createLaunchScope(scope);if(!UUID.test(operationId))throw fail();
  const row=(await pool.query(`SELECT request_json,receipt_json FROM secureshop_agents.owned_mcp_registration_journal
   WHERE operation_id=$1 AND original_platform_owner_id=$2 AND platform_launch_id=$3 AND platform_scenario_id=$4
   AND platform_launch_generation=$5 AND original_platform_session_id=$6 AND state='completed' AND drained AND redacted_at IS NULL`,[operationId,s.platformOwnerId,s.launchId,s.scenarioId,s.generation,s.platformSessionId])).rows[0];
  if(!row)throw fail();const v=envelope(row.request_json),r=row.receipt_json;
  if(v.request.operationId!==operationId||!isDeepStrictEqual(v.scope,s)||r?.state!=='completed'||r.drained!==true
   ||r.operationId!==operationId||r.requestSha256!==v.requestSha256||r.instanceId!==v.instanceId||r.runtimeDigest!==v.runtimeDigest)throw fail();
  return Object.freeze({envelope:v,receipt:r});
 }
 return Object.freeze({prepare,scopeOf,identity,admitPrepared,settlePrepared,existing,unsettled,recordDrain,recordFence,readCompleted});
}
module.exports={createOwnedMcpRegistrationJournal,validateRegistrationEnvelope:envelope};
