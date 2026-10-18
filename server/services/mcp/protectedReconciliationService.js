'use strict';
const {withTransaction}=require('../../database/postgres');
const {createMcpProtectedReceiptRepository}=require('../../database/postgres/mcpProtectedReceiptRepository');
const {createMcpResourceRepository}=require('../../database/postgres/mcpResourceRepository');
const {createMcpPlatformSessionResolver}=require('./platformSessionBinding');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=()=>{throw Object.assign(Error('Current original protected intent is unavailable'),{code:'PROTECTED_RECONCILIATION_STALE'});};
function bounded(pool){return pool&&Number.isInteger(pool.options?.max)&&pool.options.max>=1&&pool.options.max<=4&&pool.options.connectionTimeoutMillis>0&&pool.options.connectionTimeoutMillis<=5000;}
function createProtectedReconciliationService({validateSession,identityLeasePool,resourceLeasePool,targets}={}){
 if(!bounded(identityLeasePool)||!bounded(resourceLeasePool)||identityLeasePool===resourceLeasePool||typeof targets?.readProtectedOperationReceipt!=='function')throw TypeError('Dedicated bounded recovery pools and private readback client required');
 const sessions=createMcpPlatformSessionResolver({validateSession}),resources=createMcpResourceRepository(resourceLeasePool);
 return Object.freeze({async reconcile(request,operationId){
  if(!UUID.test(operationId||''))fail();
  const principal=await sessions.resolveRequest(request);
  const result=await withTransaction(identityLeasePool,async client=>{
   await client.query("SET LOCAL lock_timeout='3s'");
   await client.query("SET LOCAL statement_timeout='5s'");
   await client.query("SET LOCAL idle_in_transaction_session_timeout='35s'");
   const intent=(await client.query('SELECT * FROM workshop_conversations.mcp_protected_intents WHERE operation_id=$1 AND user_id=$2 AND platform_session_id=$3',[operationId,principal.platformOwnerId,principal.platformSessionId])).rows[0];if(!intent)fail();
   // Canonical lock order: identity user/session, owner/run/effect, resource.
   // This caller has no live original graph process or in-memory model witness.
   for(const [sql,args] of [
    ['SELECT id FROM identity.users WHERE id=$1 AND is_active=1 FOR SHARE',[principal.platformOwnerId]],
    ['SELECT id FROM identity.user_sessions WHERE id=$1 AND user_id=$2 AND is_active=1 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE',[principal.platformSessionId,principal.platformOwnerId]],
    ['SELECT owner_key FROM graph_runtime.owners WHERE owner_key=$1 AND generation=$2 FOR SHARE',[intent.owner_key,intent.generation]],
    ['SELECT run_id FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2 AND generation=$3 FOR SHARE',[intent.run_id,intent.owner_key,intent.generation]],
    ["SELECT effect_key FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4 AND status='uncertain' FOR SHARE",[intent.run_id,intent.owner_key,intent.generation,intent.ledger_effect_key]],
   ])if((await client.query(sql,args)).rowCount!==1)fail();
   const check=async()=>{request.signal?.throwIfAborted?.();await principal.assertCurrent();};
   const repository=createMcpProtectedReceiptRepository({pool:client,resolveOrigin:async()=>{throw Error('Readback cannot admit effects');},
    withTargetAuthority:(scope,work)=>resources.withActiveRunnerTarget(scope,check,work),
    readReceipt:async({request:original})=>targets.readProtectedOperationReceipt({request:original,check})});
   await repository.checkReadiness();await check();
   const metadata=await repository.reconcile({operationId,ownerId:principal.platformOwnerId,platformSessionId:principal.platformSessionId});
   await check();return {metadata,ownerKey:intent.owner_key,generation:intent.generation,scope:JSON.parse(intent.request_canonical).binding};
  });
  await principal.assertCurrent();request.signal?.throwIfAborted?.();
  const current=(await identityLeasePool.query('SELECT 1 FROM graph_runtime.owners WHERE owner_key=$1 AND generation=$2',[result.ownerKey,result.generation])).rowCount;
  const active=await resources.readActiveRunnerTarget(result.scope);
  if(!current||active?.targetId!==result.scope.targetId)fail();
  return result.metadata;
 }});
}
module.exports={createProtectedReconciliationService};
