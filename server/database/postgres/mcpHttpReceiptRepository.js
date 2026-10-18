'use strict';
const {withTransaction}=require('./index');
const {canonicalDigest}=require('../../../sidecars/sandbox-runner/owned-http/canonical');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=code=>{throw Object.assign(Error(code),{code});};
function coordinates(identity,execution){
 if(!identity||Object.keys(identity).sort().join(',')!=='binding,invocationId,mcpSessionId,mode,operationId,runId,url'
  ||!['operationId','runId','invocationId'].every(key=>UUID.test(identity[key]||''))
  ||!identity.binding||Object.keys(identity.binding).sort().join(',')!=='generation,ownerId,platformSessionId,targetId'
  ||!UUID.test(identity.binding.targetId||'')||!['fixed','vuln'].includes(identity.mode)
  ||typeof identity.url!=='string'||!identity.url||Buffer.byteLength(identity.url)>2048)fail('HTTP_RECEIPT_SCOPE_INVALID');
 const b=identity.binding;const owner=Number(b.ownerId),session=Number(b.platformSessionId),generation=Number(b.generation);
 if(!Number.isSafeInteger(owner)||owner<1||owner>2147483647||String(owner)!==b.ownerId
  ||!Number.isSafeInteger(session)||session<1||String(session)!==b.platformSessionId
  ||!Number.isSafeInteger(generation)||generation<0||String(generation)!==b.generation
  ||identity.mcpSessionId!==`mcp_${owner}`||execution?.ownerKey!==JSON.stringify(['MCP',String(owner)])
  ||execution.runId!==identity.runId||String(execution.durableGeneration)!==b.generation||typeof execution.check!=='function')fail('HTTP_RECEIPT_SCOPE_INVALID');
 return {owner,session,generation,digest:canonicalDigest(identity)};
}
async function current(client,execution){
 const owner=(await client.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1 FOR UPDATE',[execution.ownerKey])).rows[0];
 if(!owner||String(owner.generation)!==String(execution.durableGeneration))fail('STALE_GENERATION');
 const run=(await client.query('SELECT owner_key,generation,status FROM graph_runtime.runs WHERE run_id=$1 FOR UPDATE',[execution.runId])).rows[0];
 if(!run||run.owner_key!==execution.ownerKey||String(run.generation)!==String(owner.generation)||run.status!=='running')fail('STALE_RUN');
}
function verifyPrior(row,identity,digest){
 if(!row||row.request_digest!==digest||canonicalDigest(row.request_json)!==digest)fail('HTTP_RECEIPT_CONFLICT');
 if(row.receipt_json&&canonicalDigest(row.receipt_json)!==row.receipt_sha256)fail('HTTP_RECEIPT_CORRUPT');
}
function createMcpHttpReceiptRepository(pool){
 return Object.freeze({
  async checkReadiness(){const exists=(await pool.query("SELECT to_regclass('workshop_conversations.mcp_http_operations')::text AS name")).rows[0]?.name;if(!exists)fail('HTTP_RECEIPT_UNAVAILABLE');const p=(await pool.query("SELECT has_table_privilege(current_user,'workshop_conversations.mcp_http_operations','SELECT') AS read,has_table_privilege(current_user,'workshop_conversations.mcp_http_operations','INSERT') AS insert,has_column_privilege(current_user,'workshop_conversations.mcp_http_operations','receipt_json','UPDATE') AS publish,has_table_privilege(current_user,'workshop_conversations.mcp_http_operations','DELETE') AS delete")).rows[0];if(!p?.read||!p.insert||!p.publish||p.delete)fail('HTTP_RECEIPT_UNAVAILABLE');return {ready:true};},
  async begin({identity,execution}){
   const c=coordinates(identity,execution);await execution.check();
   return withTransaction(pool,async client=>{
    await current(client,execution);
    const prior=(await client.query('SELECT * FROM workshop_conversations.mcp_http_operations WHERE operation_id=$1 FOR UPDATE',[identity.operationId])).rows[0];
    if(prior){verifyPrior(prior,identity,c.digest);if(!prior.receipt_json)fail('HTTP_OPERATION_UNCERTAIN');return {state:'replay',receipt:prior.receipt_json};}
    await client.query(`INSERT INTO workshop_conversations.mcp_http_operations(operation_id,user_id,owner_key,run_id,generation,target_id,platform_session_id,invocation_id,request_digest,request_json)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,[identity.operationId,c.owner,execution.ownerKey,identity.runId,c.generation,identity.binding.targetId,c.session,identity.invocationId,c.digest,JSON.stringify(identity)]);
    return {state:'admitted'};
   });
  },
  async complete({identity,execution,receipt}){
   const c=coordinates(identity,execution);
   if(!receipt||receipt.version!=='mcp-owned-http-operation.v1'||receipt.requestDigest!==c.digest
    ||canonicalDigest(receipt.identity)!==c.digest||Buffer.byteLength(JSON.stringify(receipt))>131072)fail('HTTP_RECEIPT_INVALID');
   require('../../services/mcp/ownedHttpReceipt').verifyOwnedHttpReceipt(receipt,identity);
   const receiptDigest=canonicalDigest(receipt);await execution.check();
   return withTransaction(pool,async client=>{
    await current(client,execution);
    const row=(await client.query('SELECT * FROM workshop_conversations.mcp_http_operations WHERE operation_id=$1 FOR UPDATE',[identity.operationId])).rows[0];
    verifyPrior(row,identity,c.digest);
    if(row.receipt_json){if(row.receipt_sha256!==receiptDigest)fail('HTTP_RECEIPT_CONFLICT');return {replayed:true,receipt:row.receipt_json};}
    await client.query('UPDATE workshop_conversations.mcp_http_operations SET receipt_json=$2::jsonb,receipt_sha256=$3,completed_at=clock_timestamp() WHERE operation_id=$1',[identity.operationId,JSON.stringify(receipt),receiptDigest]);
    return {replayed:false,receipt};
   });
  },
 });
}
module.exports={createMcpHttpReceiptRepository};
