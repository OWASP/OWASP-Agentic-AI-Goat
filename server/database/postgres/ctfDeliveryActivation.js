'use strict';
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const keys=['activation_id','authority_sha256','bootstrap_operation_id','ctf_store_id','identity_store_id','manifest_sha256','protocol_version','source_revision'];
function tuple(value){if(!value||JSON.stringify(Object.keys(value).sort())!==JSON.stringify(keys)||!['activation_id','bootstrap_operation_id','ctf_store_id','identity_store_id'].every(k=>UUID.test(value[k]))||!/^[a-f0-9]{64}$/.test(value.manifest_sha256)||!/^[a-f0-9]{64}$/.test(value.authority_sha256)||value.protocol_version!==1||typeof value.source_revision!=='string'||!/^(0|[1-9][0-9]*)$/.test(value.source_revision)||BigInt(value.source_revision)>9223372036854775807n)throw TypeError('Invalid CTF activation tuple');return Object.freeze({...value});}
const select=schema=>`SELECT a.activation_id::text,a.identity_store_id::text,a.ctf_store_id::text,a.bootstrap_operation_id::text,a.source_revision::text,a.manifest_sha256,a.protocol_version,a.authority_sha256 FROM ${schema}.${schema==='ctf'?'delivery':'ctf_delivery'}_control c JOIN ${schema}.${schema==='ctf'?'delivery':'ctf_delivery'}_activations a USING(activation_id) WHERE c.singleton`;
function same(a,b){return keys.every(k=>a?.[k]===b?.[k]);}
function unavailable(){return Object.assign(Error('CTF_DELIVERY_ACTIVATION_UNAVAILABLE'),{code:'CTF_DELIVERY_ACTIVATION_UNAVAILABLE'});}
function createCtfDeliveryActivation({identityPool,ctfPool}){
 const read=async(pool,schema,options)=>withCtfTransaction(pool,async client=>{
  const row=(await client.query(select(schema))).rows[0];if(!row)throw unavailable();
  const value=tuple(row);
  // Identity readiness predicate intentionally remains unavailable to the runtime
  // directly; verify the same prepared tuple with SELECT-only grants.
  const sql=schema==='ctf'?`SELECT 1 FROM ctf.bootstrap_control WHERE singleton AND state='prepared' AND store_id=$1 AND identity_store_id=$2 AND operation_id=$3 AND revision=$4 AND manifest_sha256=$5`:`SELECT 1 FROM identity.ctf_bootstrap_sessions b CROSS JOIN identity.ctf_bootstrap_store s WHERE s.singleton AND b.state='prepared' AND b.source_store_id=$1 AND s.store_id=$2 AND b.operation_id=$3 AND b.source_revision=$4 AND b.manifest_sha256=$5`;
  if(!(await client.query(sql,[value.ctf_store_id,value.identity_store_id,value.bootstrap_operation_id,value.source_revision,value.manifest_sha256])).rows.length)throw unavailable();return value;
 },options);
 const loadCurrent=async options=>{const first=await read(ctfPool,'ctf',options);const identity=await read(identityPool,'identity',options);const last=await read(ctfPool,'ctf',options);if(!same(first,identity)||!same(identity,last))throw unavailable();options?.signal?.throwIfAborted();return first;};
 return Object.freeze({loadCurrent,async verify(expected,options){const bound=tuple(expected);const current=await loadCurrent(options);if(!same(bound,current))throw unavailable();return bound;}});
}
module.exports={validateCtfDeliveryTuple:tuple,createCtfDeliveryActivation};
