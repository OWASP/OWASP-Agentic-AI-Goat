'use strict';
// Unmounted candidate: origin, target authority and transport are constructor-
// supplied trusted services. This repository never executes a tool or grades.
// withTargetAuthority must hold the target lease and check current authority both
// before work and after work, suppressing publication on a failed return fence.
// A persisted decision digest is not a reconstructable model-credit witness.
const {canonical,canonicalDigest}=require('../../../sidecars/sandbox-runner/owned-http/canonical');
const {isTrustedProtectedReceipt}=require('../../services/mcp/ownedTargetClient');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=code=>{throw Object.assign(Error(code),{code});};
function exact(v,keys){return v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');}
function freeze(v){if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
function requestSnapshot(request){
 if(!exact(request,['operationId','runId','operation','arguments','binding'])||!UUID.test(request.operationId)||!UUID.test(request.runId)
  ||!exact(request.binding,['targetId','platformOwnerId','platformSessionId','generation'])||!UUID.test(request.binding.targetId))fail('PROTECTED_INTENT_INVALID');
 const b=request.binding;if(!Number.isSafeInteger(b.platformOwnerId)||b.platformOwnerId<1||!Number.isSafeInteger(b.platformSessionId)||b.platformSessionId<1||!Number.isSafeInteger(b.generation)||b.generation<0)fail('PROTECTED_INTENT_INVALID');
 const a=request.arguments;if(!(request.operation==='read_configuration'&&exact(a,[])
  ||request.operation==='rotate_keys'&&exact(a,['labRole','enforceAuthorization'])&&['unprivileged','privileged'].includes(a.labRole)&&typeof a.enforceAuthorization==='boolean'
  ||request.operation==='set_audit_logging'&&exact(a,['action'])&&['disable','clear','enable'].includes(a.action)))fail('PROTECTED_INTENT_INVALID');
 return freeze(JSON.parse(canonical(request)));
}
function createMcpProtectedReceiptRepository({pool,resolveOrigin,withTargetAuthority,readReceipt}={}){
 if(typeof pool?.query!=='function'||typeof resolveOrigin!=='function'||typeof withTargetAuthority!=='function'||typeof readReceipt!=='function')throw TypeError('Trusted protected admission and readback dependencies required');
 return Object.freeze({
 async checkReadiness(){
  for(const table of ['mcp_protected_intents','mcp_protected_reconciliations']){
   const p=(await pool.query(`SELECT has_table_privilege(current_user,$1,'SELECT') AS read,has_table_privilege(current_user,$1,'INSERT,UPDATE,DELETE,TRUNCATE') AS write`,['workshop_conversations.'+table])).rows[0];if(!p?.read||p.write)fail('PROTECTED_RECEIPT_UNAVAILABLE');
  }
  const p=(await pool.query("SELECT has_function_privilege(current_user,'workshop_conversations.admit_mcp_protected(integer,bigint,bigint,uuid,uuid,text,text,text,text,text)','EXECUTE') AS admit,has_function_privilege(current_user,'workshop_conversations.append_mcp_protected_reconciliation(uuid,integer,bigint,text,text)','EXECUTE') AS append,has_function_privilege(current_user,'workshop_conversations.mcp_protected_current(integer,bigint,bigint,uuid,text,text)','EXECUTE') AS internal")).rows[0];if(!p?.admit||!p.append||p.internal)fail('PROTECTED_RECEIPT_UNAVAILABLE');return {ready:true};
 },
 async begin({request,execution,ledgerEffectKey,sdkEffectKey}={}){
  const selected=requestSnapshot(request),b=selected.binding;
  if(execution?.ownerKey!==JSON.stringify(['MCP',String(b.platformOwnerId)])||execution.runId!==selected.runId||String(execution.durableGeneration)!==String(b.generation)||typeof execution.check!=='function'
   ||typeof sdkEffectKey!=='string'||!sdkEffectKey||Buffer.byteLength(sdkEffectKey)>512||typeof ledgerEffectKey!=='string'||!ledgerEffectKey.endsWith(':'+sdkEffectKey)||Buffer.byteLength(ledgerEffectKey)>1024)fail('PROTECTED_INTENT_SCOPE_INVALID');
  await execution.check();
  const resolvedOrigin=await resolveOrigin({request:selected,execution,sdkEffectKey,ledgerEffectKey});
  const origin=exact(resolvedOrigin,['origin','decisionDigest'])?Object.freeze({origin:resolvedOrigin.origin,decisionDigest:resolvedOrigin.decisionDigest}):null;
  if(!exact(origin,['origin','decisionDigest'])||!['model','manual','controlled'].includes(origin.origin)||(origin.origin==='model'?!/^[a-f0-9]{64}$/.test(origin.decisionDigest||''):origin.decisionDigest!==null))fail('PROTECTED_ORIGIN_UNAVAILABLE');
  return withTargetAuthority(b,async()=>{
   await execution.check();const row=(await pool.query('SELECT workshop_conversations.admit_mcp_protected($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS value',[b.platformOwnerId,b.platformSessionId,b.generation,selected.runId,b.targetId,ledgerEffectKey,sdkEffectKey,origin.origin,origin.decisionDigest,canonical(selected)])).rows[0].value;
   await execution.check();return freeze(row);
  });
 },
 async reconcile({operationId,ownerId,platformSessionId}={}){
  if(!UUID.test(operationId)||!Number.isSafeInteger(ownerId)||!Number.isSafeInteger(platformSessionId))fail('PROTECTED_RECONCILIATION_SCOPE_INVALID');
  const intent=(await pool.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE operation_id=$1 AND user_id=$2 AND platform_session_id=$3',[operationId,ownerId,platformSessionId])).rows[0];if(!intent)fail('PROTECTED_INTENT_UNAVAILABLE');
  const request=requestSnapshot(JSON.parse(intent.request_canonical));if(canonicalDigest(request)!==intent.request_digest)fail('PROTECTED_INTENT_CORRUPT');
  return withTargetAuthority(request.binding,async()=>{
   // Before private readback, verify current SQL authority without publishing a
   // reconciliation. Same checks are repeated atomically by the append routine.
   const current=(await pool.query(`SELECT 1 FROM identity.users u JOIN identity.user_sessions s ON s.user_id=u.id JOIN graph_runtime.owners o ON o.owner_key=$3 JOIN graph_runtime.runs r ON r.run_id=$5 AND r.owner_key=o.owner_key AND r.generation=o.generation JOIN graph_runtime.effects e ON e.run_id=r.run_id AND e.owner_key=o.owner_key AND e.generation=o.generation AND e.effect_key=$6 WHERE u.id=$1 AND u.is_active=1 AND s.id=$2 AND s.is_active=1 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND o.generation=$4 AND e.status='uncertain'`,[ownerId,platformSessionId,intent.owner_key,intent.generation,intent.run_id,intent.ledger_effect_key])).rowCount;if(!current)fail('PROTECTED_RECONCILIATION_STALE');
   const observed=await readReceipt({request,intent:freeze({...intent})});
   if(!observed||!['completed','uncertain','absent'].includes(observed.state)||observed.requestDigest!==intent.request_digest)fail('PROTECTED_READBACK_INVALID');
   let digest=null;
   if(observed.state==='completed'){
    const result=observed.result;if(!isTrustedProtectedReceipt(result)||result.runId!==request.runId||result.operation!==request.operation||Object.entries(request.binding).some(([k,v])=>result[k]!==v))fail('PROTECTED_READBACK_UNTRUSTED');
    if(request.operation==='rotate_keys'&&(result.labRole!==request.arguments.labRole||result.policy!==(request.arguments.enforceAuthorization?'enforced':'vulnerable')))fail('PROTECTED_READBACK_UNTRUSTED');
    if(request.operation==='set_audit_logging'&&result.action!==request.arguments.action)fail('PROTECTED_READBACK_UNTRUSTED');
    digest=result.receiptSha256;
   }else if(observed.result!==undefined)fail('PROTECTED_READBACK_INVALID');
   const row=(await pool.query('SELECT workshop_conversations.append_mcp_protected_reconciliation($1,$2,$3,$4,$5) AS value',[operationId,ownerId,platformSessionId,observed.state,digest])).rows[0].value;
   return freeze({...row,originalEffectStatus:'uncertain',origin:intent.origin,creditGranted:false});
  });
 }
 });
}
module.exports={createMcpProtectedReceiptRepository};
