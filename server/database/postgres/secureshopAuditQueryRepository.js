'use strict';
const {withTransaction}=require('./index');
const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {canonicalDigest}=require('../../services/mcp/protocolContext');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const fail=code=>{throw Object.assign(Error(code),{code});};
function validate(request,execution){
 if(!request||Object.keys(request).sort().join(',')!=='binding,operationId,payloadSha256,runId,sourceSha256,target,username'||!uuid.test(request.operationId)||!uuid.test(request.runId)||!/^audit_[a-f0-9]{32}$/.test(request.target)||!sha.test(request.payloadSha256)||!sha.test(request.sourceSha256)||typeof request.username!=='string'||Buffer.byteLength(request.username)>8192||execution?.runId!==request.runId||typeof execution.ownerKey!=='string'||!execution.ownerKey||!/^\d+$/.test(String(execution.durableGeneration))||typeof execution.check!=='function')fail('AUDIT_QUERY_INVALID');
 return createLaunchScope(request.binding);
}
async function current(client,binding,execution){
 // Launch coordinates identify canonical authority in either realm. A shop
 // owner/session must never require a matching workshop account or session.
 const user=(await client.query('SELECT is_active,account_locked_until FROM identity.secureshop_authority_owners WHERE id=$1 FOR UPDATE',[binding.platformOwnerId])).rows[0];
 const session=(await client.query('SELECT user_id,is_active,expires_at FROM identity.secureshop_authority_sessions WHERE id=$1 FOR UPDATE',[binding.platformSessionId])).rows[0];
 const launch=(await client.query('SELECT * FROM identity.secureshop_launches WHERE launch_id=$1 FOR UPDATE',[binding.launchId])).rows[0];
 const owner=execution&&(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1 FOR UPDATE',[execution.ownerKey])).rows[0];
 const run=execution&&(await client.query('SELECT owner_key,generation,status FROM graph_runtime.runs WHERE run_id=$1 FOR UPDATE',[execution.runId])).rows[0];
 const now=(await client.query('SELECT clock_timestamp() AS now')).rows[0].now;
 if(!user?.is_active||(user.account_locked_until&&user.account_locked_until>now)||!session?.is_active||Number(session.user_id)!==binding.platformOwnerId||session.expires_at<=now||!launch||launch.status!=='active'||launch.expires_at<=now||Number(launch.original_platform_owner_id)!==binding.platformOwnerId||Number(launch.platform_session_id)!==binding.platformSessionId||launch.scenario_id!==binding.scenarioId||Number(launch.generation)!==binding.generation||(execution&&(!owner||String(owner.generation)!==String(execution.durableGeneration)||!run||run.owner_key!==execution.ownerKey||String(run.generation)!==String(owner.generation)||run.status!=='running')))fail('AUDIT_QUERY_STALE');
}
function verifyReceipt(receipt,request){
 const expected=createLaunchScope(request.binding);
 const result=receipt?.result;const expectedSql=`SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events WHERE actor LIKE '%${request.username}%' OR target LIKE '%${request.username}%' ORDER BY ts DESC LIMIT 200`;
 if(typeof result?.ok!=='boolean'||result.sql!==expectedSql||!Array.isArray(result.events)||result.count!==result.events.length||!Number.isFinite(result.durationMs)||result.durationMs<0||(result.ok?result.error!==null:typeof result.error!=='string'))fail('AUDIT_QUERY_RECEIPT_INVALID');
 if(receipt?.extraction&&(![1,2].includes(receipt.extraction.version)||(receipt.extraction.version===2&&(!sha.test(receipt.extraction.planSha256)||typeof receipt.extraction.sourceRelationPlanned!=='boolean'))||receipt.extraction.kind!=='synthetic_audit_canary'||typeof receipt.extraction.extracted!=='boolean'||!sha.test(receipt.extraction.canarySha256)))fail('AUDIT_QUERY_RECEIPT_INVALID');
 if(receipt?.timing!==undefined){
  const timing=receipt.timing,keys=['baselineDurationMs','baselineSql','clock','planSha256','queryDurationMs','sleepFunctionPlanned','statementTimeoutMs','version'];
  if(!timing||typeof timing!=='object'||Array.isArray(timing)||Object.keys(timing).sort().join(',')!==keys.sort().join(',')
   ||timing.version!==1||timing.clock!=='process.hrtime.bigint'||timing.baselineSql!=='SELECT 1'
   ||timing.statementTimeoutMs!==1000||typeof timing.sleepFunctionPlanned!=='boolean'
   ||![timing.baselineDurationMs,timing.queryDurationMs].every(value=>typeof value==='number'&&Number.isFinite(value)&&value>=0&&value<=15000)
   ||result.ok!==true||receipt.extraction?.version!==2||timing.planSha256!==receipt.extraction.planSha256)fail('AUDIT_QUERY_RECEIPT_INVALID');
 }
 const rawDigest=require('node:crypto').createHash('sha256').update(JSON.stringify([expected,request.target,request.operationId,request.username])).digest('hex');
 if(receipt?.version!==1||receipt.operationId!==request.operationId||receipt.target!==request.target||canonicalDigest(receipt.binding)!==canonicalDigest(expected)||receipt.requestSha256!==rawDigest||receipt.sourceSha256!==request.sourceSha256||receipt.payloadSha256!==request.payloadSha256||receipt.result?.username!==request.username||receipt.resultSha256!==canonicalDigest(receipt.result)||Buffer.byteLength(JSON.stringify(receipt))>17*1024*1024)fail('AUDIT_QUERY_RECEIPT_INVALID');
 return receipt;
}
function createAuditQueryRepository({pool,checkExecutionBinding}){
 if(typeof checkExecutionBinding!=='function')throw TypeError('Trusted conversation execution binding check required');
 async function transaction(request,execution,work){const binding=validate(request,execution);await execution.check();await checkExecutionBinding(binding,execution);return withTransaction(pool,async client=>{await current(client,binding,execution);return work(client,binding);});}
 return Object.freeze({
  async checkReadiness(){
   const exists=(await pool.query("SELECT to_regclass('identity.secureshop_audit_query_operations') AS relation")).rows[0];if(!exists?.relation)fail('AUDIT_QUERY_UNAVAILABLE');
   const acl=(await pool.query("SELECT has_table_privilege(current_user,'identity.secureshop_audit_query_operations','SELECT') AS readable,has_table_privilege(current_user,'identity.secureshop_audit_query_operations','INSERT') AS appendable,has_column_privilege(current_user,'identity.secureshop_audit_query_operations','receipt_json','UPDATE') AS publish,has_table_privilege(current_user,'identity.secureshop_audit_query_operations','UPDATE,DELETE,TRUNCATE') AS broad_write")).rows[0];
   if(!acl?.readable||!acl.appendable||!acl.publish||acl.broad_write)fail('AUDIT_QUERY_UNAVAILABLE');return{ready:true};
  },
  async begin({request,execution}){return transaction(request,execution,async(client,binding)=>{
   // The canonical owner lock above serializes both admission kinds. A manual
   // operation can never be replayed as a newly model-selected SQL effect.
   // user_id is a retained workshop FK; only platform_user_id belongs there.
   // original_platform_owner_id keeps the canonical owner for both realms.
   if((await client.query('SELECT 1 FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1',[request.operationId])).rowCount)fail('AUDIT_QUERY_CONFLICT');
   const digest=canonicalDigest({request,ownerKey:execution.ownerKey,durableGeneration:String(execution.durableGeneration)});
   const row=(await client.query('SELECT * FROM identity.secureshop_audit_query_operations WHERE operation_id=$1 FOR UPDATE',[request.operationId])).rows[0];
   if(row){if(row.request_sha256!==digest)fail('AUDIT_QUERY_CONFLICT');if(row.receipt_json){if(canonicalDigest(row.receipt_json)!==row.receipt_sha256)fail('AUDIT_QUERY_CORRUPT');return{state:'completed',receipt:verifyReceipt(row.receipt_json,request)};}return{state:'pending'};}
   await client.query('INSERT INTO identity.secureshop_audit_query_operations(operation_id,user_id,original_platform_owner_id,launch_id,run_id,request_sha256,request_json) VALUES($1,(SELECT platform_user_id FROM identity.secureshop_authority_owners WHERE id=$2),$2,$3,$4,$5,$6)',[request.operationId,binding.platformOwnerId,binding.launchId,request.runId,digest,{request,ownerKey:execution.ownerKey,durableGeneration:String(execution.durableGeneration)}]);return{state:'admitted'};
  });},
  async complete({request,execution,receipt}){verifyReceipt(receipt,request);return transaction(request,execution,async client=>{
   const row=(await client.query('SELECT * FROM identity.secureshop_audit_query_operations WHERE operation_id=$1 FOR UPDATE',[request.operationId])).rows[0];
   if(!row||row.request_sha256!==canonicalDigest({request,ownerKey:execution.ownerKey,durableGeneration:String(execution.durableGeneration)}))fail('AUDIT_QUERY_CONFLICT');
   const digest=canonicalDigest(receipt);if(row.receipt_json){if(row.receipt_sha256!==digest)fail('AUDIT_QUERY_CONFLICT');return row.receipt_json;}
   await client.query('UPDATE identity.secureshop_audit_query_operations SET receipt_json=$2,receipt_sha256=$3,completed_at=clock_timestamp() WHERE operation_id=$1',[request.operationId,receipt,digest]);return receipt;
  });},
 });
}
module.exports={createAuditQueryRepository,verifyReceipt,assertCurrentAuditScope:current};
