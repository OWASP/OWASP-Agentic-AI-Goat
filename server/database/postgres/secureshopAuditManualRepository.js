'use strict';
const {withTransaction}=require('./index');const {createLaunchScope}=require('../../services/secureshopConversationBinding');
const {canonicalDigest}=require('../../services/mcp/protocolContext');const {assertCurrentAuditScope,verifyReceipt}=require('./secureshopAuditQueryRepository');
const fail=code=>{throw Object.assign(Error(code),{code});};
function createAuditManualRepository({pool,personaAuth}){
 if(typeof personaAuth?.authenticateBoundToken!=='function')throw TypeError('Canonical persona authentication required');
 async function transaction(request,token,work){
  if(!request||Object.keys(request).sort().join(',')!=='binding,operationId,payloadSha256,persona,sourceSha256,target,username'||! /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(request.operationId)||!/^audit_[a-f0-9]{32}$/.test(request.target)||!['payloadSha256','sourceSha256'].every(k=>/^[a-f0-9]{64}$/.test(request[k]))||typeof request.username!=='string'||Buffer.byteLength(request.username)>8192)fail('AUDIT_MANUAL_INVALID');
  const binding=createLaunchScope(request.binding);const authenticated=await personaAuth.authenticateBoundToken({token,scope:binding});
  if(authenticated.user?.role!=='admin'||request.persona?.role!=='admin'||request.persona.id!==authenticated.user.id)fail('AUDIT_MANUAL_FORBIDDEN');
  return withTransaction(pool,async client=>{await assertCurrentAuditScope(client,binding,null);return work(client,binding);});
 }
 return Object.freeze({
  async read({binding:input,persona,operationId,token}){
   const binding=createLaunchScope(input);
   if(typeof operationId!=='string'||! /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(operationId))fail('AUDIT_MANUAL_INVALID');
   const authenticated=await personaAuth.authenticateBoundToken({token,scope:binding});
   if(authenticated.user?.role!=='admin'||persona?.role!=='admin'||persona.id!==authenticated.user.id)fail('AUDIT_MANUAL_FORBIDDEN');
   return withTransaction(pool,async client=>{
    await assertCurrentAuditScope(client,binding,null);
    const row=(await client.query('SELECT request_json,request_sha256,receipt_json,receipt_sha256 FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1 AND launch_id=$2 AND original_platform_owner_id=$3',[operationId,binding.launchId,binding.platformOwnerId])).rows[0];
    if(!row)return{state:'not_found'};
    const request=row.request_json;
    if(!request||Object.keys(request).sort().join(',')!=='binding,operationId,payloadSha256,persona,sourceSha256,target,username'
      ||request.operationId!==operationId||canonicalDigest(request.binding)!==canonicalDigest(binding)
      ||request.persona?.id!==persona.id||request.persona?.role!=='admin')fail('AUDIT_MANUAL_FORBIDDEN');
    if(row.request_sha256!==canonicalDigest(request)||!/^audit_[a-f0-9]{32}$/.test(request.target)
      ||!['payloadSha256','sourceSha256'].every(key=>/^[a-f0-9]{64}$/.test(request[key]))
      ||typeof request.username!=='string'||Buffer.byteLength(request.username)>8192)fail('AUDIT_QUERY_CORRUPT');
    if(row.receipt_json){
     if(row.receipt_sha256!==canonicalDigest(row.receipt_json))fail('AUDIT_QUERY_CORRUPT');
     return{state:'completed',request,receipt:verifyReceipt(row.receipt_json,request)};
    }
    if(row.receipt_sha256!==null)fail('AUDIT_QUERY_CORRUPT');
    return{state:'pending',request};
   });
  },
  async checkReadiness(){const row=(await pool.query("SELECT has_table_privilege(current_user,'identity.secureshop_audit_manual_operations','SELECT') AS readable,has_table_privilege(current_user,'identity.secureshop_audit_manual_operations','INSERT') AS appendable,has_column_privilege(current_user,'identity.secureshop_audit_manual_operations','receipt_json','UPDATE') AS publish,has_table_privilege(current_user,'identity.secureshop_audit_manual_operations','UPDATE,DELETE,TRUNCATE') AS broad_write")).rows[0];if(!row?.readable||!row.appendable||!row.publish||row.broad_write)fail('AUDIT_QUERY_UNAVAILABLE');return{ready:true};},
  assertCurrent:({request,token})=>transaction(request,token,async()=>true),
  begin:({request,token})=>transaction(request,token,async(client,binding)=>{
   if((await client.query('SELECT 1 FROM identity.secureshop_audit_query_operations WHERE operation_id=$1',[request.operationId])).rowCount)fail('AUDIT_QUERY_CONFLICT');
   const digest=canonicalDigest(request);const row=(await client.query('SELECT * FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1 FOR UPDATE',[request.operationId])).rows[0];
   if(row){if(row.request_sha256!==digest)fail('AUDIT_QUERY_CONFLICT');if(row.receipt_json){if(row.receipt_sha256!==canonicalDigest(row.receipt_json))fail('AUDIT_QUERY_CORRUPT');return{state:'completed',receipt:verifyReceipt(row.receipt_json,request)};}return{state:'pending'};}
   await client.query('INSERT INTO identity.secureshop_audit_manual_operations(operation_id,user_id,original_platform_owner_id,launch_id,request_sha256,request_json) VALUES($1,(SELECT platform_user_id FROM identity.secureshop_authority_owners WHERE id=$2),$2,$3,$4,$5)',[request.operationId,binding.platformOwnerId,binding.launchId,digest,request]);return{state:'admitted'};
  }),
  complete:({request,token,receipt})=>transaction(request,token,async client=>{
   verifyReceipt(receipt,request);const row=(await client.query('SELECT * FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1 FOR UPDATE',[request.operationId])).rows[0];if(!row||row.request_sha256!==canonicalDigest(request))fail('AUDIT_QUERY_CONFLICT');const digest=canonicalDigest(receipt);if(row.receipt_json){if(row.receipt_sha256!==digest)fail('AUDIT_QUERY_CONFLICT');return row.receipt_json;}
   await client.query('UPDATE identity.secureshop_audit_manual_operations SET receipt_json=$2,receipt_sha256=$3,completed_at=clock_timestamp() WHERE operation_id=$1',[request.operationId,receipt,digest]);return receipt;
  }),
 });
}
module.exports={createAuditManualRepository};
