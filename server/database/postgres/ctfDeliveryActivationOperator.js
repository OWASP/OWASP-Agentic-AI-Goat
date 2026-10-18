'use strict';
// Migration-pool-only cutover. Caller pauses ingress/worker before invoking;
// this module never starts traffic or promises arbitrary privileged SQL safety.
const {createHash}=require('node:crypto');
const {canonicalCtfJson}=require('../../services/ctfLifecycleCommands');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {validateCtfDeliveryTuple,createCtfDeliveryActivation}=require('./ctfDeliveryActivation');
const hash=text=>createHash('sha256').update(text).digest('hex');
function createCtfDeliveryActivationOperator({identityMigrationPool,ctfMigrationPool}){
 const tx=(pool,work,options)=>withCtfTransaction(pool,work,options);
 const exportScopes=async(activationId,pageBudget,options)=>{
  if(!Number.isInteger(pageBudget)||pageBudget<1||pageBudget>64)throw TypeError('Invalid activation page budget');
  const checkpoints=[];
  for(const [pool,schema,prefix] of [[identityMigrationPool,'identity','ctf_delivery'],[ctfMigrationPool,'ctf','delivery']])checkpoints.push(await tx(pool,async c=>(await c.query(`SELECT next_page,last_scope,chain_sha256 FROM ${schema}.${prefix}_scope_transfer WHERE activation_id=$1`,[activationId])).rows[0]||{next_page:0,last_scope:null,chain_sha256:'0'.repeat(64)},options));
  checkpoints.sort((a,b)=>a.next_page-b.next_page);
  if(checkpoints[1].next_page-checkpoints[0].next_page>1||(checkpoints[0].next_page===checkpoints[1].next_page&&(checkpoints[0].last_scope!==checkpoints[1].last_scope||checkpoints[0].chain_sha256!==checkpoints[1].chain_sha256)))throw Error('CTF_ACTIVATION_PAGE_CONFLICT');
  let after=checkpoints[0].last_scope,page=checkpoints[0].next_page,chain=checkpoints[0].chain_sha256;
  for(let processed=0;;processed++){
   if(processed===pageBudget)return Object.freeze({staged:true,activationId,nextPage:page,trafficStarted:false,ready:false});
   // Keyset pages keep memory bounded independently of historical owner count.
   const rows=await tx(identityMigrationPool,async c=>(await c.query(`SELECT scope_key,revision::text,owner_generation::text FROM identity.ctf_authority WHERE ($1::text IS NULL OR scope_key COLLATE "C">$1 COLLATE "C") ORDER BY scope_key COLLATE "C" LIMIT 128`,[after])).rows,options);
   if(!rows.length)break;
   const canonical=canonicalCtfJson(rows),digest=hash(canonical);if(Buffer.byteLength(canonical)>262144)throw Error('CTF_ACTIVATION_PAGE_OVERFLOW');
   chain=hash(chain+digest);
   for(const [pool,schema] of [[identityMigrationPool,'identity'],[ctfMigrationPool,'ctf']]){
    const result=await tx(pool,async c=>(await c.query(`SELECT ${schema}.stage_ctf_delivery_scopes($1,$2,$3,$4) AS chain`,[activationId,page,canonical,digest])).rows[0],options);
    if(result?.chain!==chain)throw Error('CTF_ACTIVATION_PAGE_CONFLICT');
   }
   after=rows.at(-1).scope_key;page++;
  }
  return {chain};
 };
 return Object.freeze({async activate({activationId,bootstrapOperationId,pageBudget=16},options){
  const prepared=await tx(identityMigrationPool,async c=>{
   const b=(await c.query(`SELECT b.source_store_id::text AS ctf_store_id,s.store_id::text AS identity_store_id,b.source_revision::text,b.manifest_sha256 FROM identity.ctf_bootstrap_sessions b CROSS JOIN identity.ctf_bootstrap_store s WHERE s.singleton AND b.operation_id=$1 AND b.state='prepared'`,[bootstrapOperationId])).rows[0];if(!b)throw Error('CTF_BOOTSTRAP_NOT_PREPARED');return b;
  },options);
  const exported=await exportScopes(activationId,pageBudget,options);if(exported.staged)return exported;
  const chain=exported.chain;
  const t=validateCtfDeliveryTuple({activation_id:activationId,bootstrap_operation_id:bootstrapOperationId,...prepared,protocol_version:1,authority_sha256:chain});
  const args=[t.activation_id,t.identity_store_id,t.ctf_store_id,t.bootstrap_operation_id,t.source_revision,t.manifest_sha256,t.authority_sha256];
  // No simultaneous store leases; ambiguous failure is surfaced, never replayed.
  await tx(ctfMigrationPool,c=>c.query('SELECT ctf.activate_delivery($1,$2,$3,$4,$5,$6,$7)',args),options);
  await tx(identityMigrationPool,c=>c.query('SELECT identity.activate_ctf_delivery($1,$2,$3,$4,$5,$6,$7)',args),options);
  await createCtfDeliveryActivation({identityPool:identityMigrationPool,ctfPool:ctfMigrationPool}).verify(t,options);
  return Object.freeze({activation:t,trafficStarted:false});
 },async resumeAfterMaintenance({activationId,transferId,pageBudget=16},options){
  if(transferId===activationId)throw TypeError('Distinct maintenance transfer required');
  const t=await tx(identityMigrationPool,async c=>validateCtfDeliveryTuple((await c.query('SELECT activation_id::text,authority_sha256,bootstrap_operation_id::text,ctf_store_id::text,identity_store_id::text,manifest_sha256,protocol_version,source_revision::text FROM identity.ctf_delivery_activations WHERE activation_id=$1',[activationId])).rows[0]),options);
  const head=await tx(identityMigrationPool,async c=>(await c.query(`SELECT a.applied_sequence::text AS sequence,e.operation_id::text,e.command_hash,e.result_hash FROM identity.ctf_authority a LEFT JOIN identity.ctf_outbox e ON e.sequence=a.applied_sequence WHERE a.scope_key='global' AND a.applied_sequence=a.next_sequence`)).rows[0],options);
  if(!head)throw Error('CTF_DELIVERY_NOT_DRAINED');
  const exported=await exportScopes(transferId,pageBudget,options);if(exported.staged)return {...exported,activationId,transferId};
  const args=[activationId,transferId,exported.chain,head.sequence,head.operation_id,head.command_hash,head.result_hash];
  await tx(ctfMigrationPool,c=>c.query('SELECT ctf.resume_delivery($1,$2,$3,$4,$5,$6,$7)',args),options);
  await tx(identityMigrationPool,c=>c.query('SELECT identity.resume_ctf_delivery($1,$2,$3,$4,$5,$6,$7)',args),options);
  await createCtfDeliveryActivation({identityPool:identityMigrationPool,ctfPool:ctfMigrationPool}).verify(t,options);
  return Object.freeze({activation:t,resumed:true,trafficStarted:false});
 },async revokeForMaintenance(options){
  // Publication also locks global first: decisions published before this commit
  // are historically authorized; subsequent current publication is denied.
  await tx(identityMigrationPool,async c=>{await c.query("SELECT 1 FROM identity.ctf_authority WHERE scope_key='global' FOR UPDATE");await c.query('UPDATE identity.ctf_delivery_control SET activation_id=NULL WHERE singleton');},options);
  await tx(ctfMigrationPool,async c=>{await c.query('SELECT pg_advisory_xact_lock(1886610804,44)');await c.query('SELECT 1 FROM ctf.bootstrap_control WHERE singleton FOR UPDATE');await c.query('UPDATE ctf.delivery_control SET activation_id=NULL WHERE singleton');},options);
  return Object.freeze({revoked:true,trafficStarted:false});
 }});
}
module.exports={createCtfDeliveryActivationOperator};
