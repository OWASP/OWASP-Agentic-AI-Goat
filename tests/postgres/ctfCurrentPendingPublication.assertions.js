'use strict';
// Native SQL contract check on a genuinely pending decision in an owned,
// disposable Stage 9 store. A row lock holds the projection window while
// rollback-only savepoints probe stale authority and session variants.
const assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const sha=value=>createHash('sha256').update(value).digest('hex');

async function assertControlledSqlGates({identityRuntime,identityMigration,decisionId,actorId,sessionId,rawToken,stageId,ownerGeneration}){
 assert(identityRuntime&&identityMigration&&typeof rawToken==='string'&&rawToken.length);
 const values=[decisionId,actorId,sessionId,sha(rawToken)];
 const probe=async client=>{
  const result=await client.query('SELECT identity.ctf_current_decision_pending($1,$2,$3,$4) AS pending',values);
  assert.equal(result.rows.length,1);
  assert.equal(typeof result.rows[0].pending,'boolean','pending probe returns no decision result');
  return result.rows[0].pending;
 };
 const client=await identityMigration.connect();
 try{
  await client.query('BEGIN');
  const current=(await client.query('SELECT owner_id,session_id,stage_id,owner_generation FROM identity.ctf_decisions WHERE decision_id=$1',[decisionId])).rows[0];
  assert(current,'pending decision required');
  assert.equal(String(current.owner_id),String(actorId));
  assert.equal(String(current.session_id),String(sessionId));
  assert.equal(String(current.stage_id),String(stageId));
  assert.equal(String(current.owner_generation),String(ownerGeneration));
  // Match publication/ACK order so a concurrent worker can either finish
  // first or wait for this bounded read-only qualification transaction.
  await client.query("SELECT 1 FROM identity.ctf_authority WHERE scope_key='global' FOR UPDATE");
  await client.query('SELECT 1 FROM identity.ctf_authority WHERE scope_key=$1 FOR UPDATE',['stage:'+stageId]);
  await client.query('SELECT 1 FROM identity.ctf_authority WHERE scope_key=$1 FOR UPDATE',['owner:'+actorId]);
  await client.query('SELECT 1 FROM identity.users WHERE id=$1 FOR UPDATE',[actorId]);
  await client.query('SELECT 1 FROM identity.user_sessions WHERE id=$1 FOR UPDATE',[sessionId]);
  await client.query('SELECT 1 FROM graph_runtime.owners WHERE owner_key=$1 FOR UPDATE',[JSON.stringify(['CTF',String(actorId)])]);
  await client.query('SELECT 1 FROM graph_runtime.runs WHERE run_id=(SELECT run_id FROM identity.ctf_decisions WHERE decision_id=$1) FOR UPDATE',[decisionId]);
  const outbox=(await client.query('SELECT state FROM identity.ctf_outbox WHERE operation_id=$1 FOR UPDATE',[decisionId])).rows[0];
  if(outbox?.state!=='pending')return false; // Worker won; caller must try another controlled decision.
  assert.equal(await probe(client),true,'exact pending decision and owner operation are recognized');
  const wrong=async(name,statement,args=[],code=null)=>{
   await client.query('SAVEPOINT pending_gate_case');
   try{
    await client.query(statement,args);
    if(code)await assert.rejects(probe(client),{code},name);
    else assert.equal(await probe(client),false,name);
   }finally{await client.query('ROLLBACK TO SAVEPOINT pending_gate_case');await client.query('RELEASE SAVEPOINT pending_gate_case');}
   assert.equal(await probe(client),true,name+' must leave the pending baseline intact');
  };
  const checkArgs=async(name,args,code=null)=>{
   await client.query('SAVEPOINT pending_gate_case');
   try{
    const call=()=>client.query('SELECT identity.ctf_current_decision_pending($1,$2,$3,$4) AS pending',args);
    if(code)await assert.rejects(call(),{code},name);
    else assert.equal((await call()).rows[0].pending,false,name);
   }finally{await client.query('ROLLBACK TO SAVEPOINT pending_gate_case');await client.query('RELEASE SAVEPOINT pending_gate_case');}
  };
  await checkArgs('wrong decision ID',[randomUUID(),actorId,sessionId,sha(rawToken)]);
  await checkArgs('wrong actor',[decisionId,Number(actorId)+1,sessionId,sha(rawToken)]);
  await checkArgs('wrong session',[decisionId,actorId,Number(sessionId)+1,sha(rawToken)]);
  await checkArgs('wrong token',[decisionId,actorId,sessionId,sha('wrong-token')],'28000');
  await wrong('global revision changed',"UPDATE identity.ctf_authority SET revision=revision+1 WHERE scope_key='global'");
  await wrong('stage revision changed','UPDATE identity.ctf_authority SET revision=revision+1 WHERE scope_key=$1',['stage:'+stageId]);
  await wrong('owner generation changed','UPDATE identity.ctf_authority SET owner_generation=owner_generation+1 WHERE scope_key=$1',['owner:'+actorId]);
  await wrong('owner no longer pending',"UPDATE identity.ctf_authority SET lifecycle_state='ready',pending_operation_id=NULL WHERE scope_key=$1",['owner:'+actorId]);
  await wrong('owner pending operation changed','UPDATE identity.ctf_authority SET pending_operation_id=$1 WHERE scope_key=$2',[randomUUID(),'owner:'+actorId]);
  await wrong('owner banned','UPDATE identity.ctf_authority SET banned=true WHERE scope_key=$1',['owner:'+actorId]);
  await wrong('graph owner generation changed','UPDATE graph_runtime.owners SET generation=generation+1 WHERE owner_key=$1',[JSON.stringify(['CTF',String(actorId)])]);
  await wrong('graph run cancelled',"UPDATE graph_runtime.runs SET status='cancelled' WHERE run_id=(SELECT run_id FROM identity.ctf_decisions WHERE decision_id=$1)",[decisionId]);
  await wrong('outbox no longer pending',"UPDATE identity.ctf_outbox SET state='blocked' WHERE operation_id=$1",[decisionId]);
  await wrong('pending outbox contains a result',"UPDATE identity.ctf_outbox SET canonical_result='{}',result_hash=$1 WHERE operation_id=$2",[sha('{}'),decisionId]);
  await wrong('participant inactive','UPDATE identity.ctf_participant_bindings SET active=false WHERE owner_id=$1',[actorId]);
  await wrong('progress not in progress',"UPDATE identity.ctf_progress_bindings SET status='not_started' WHERE progress_id=(SELECT progress_id FROM identity.ctf_decisions WHERE decision_id=$1)",[decisionId]);
  await wrong('stage digest changed','UPDATE identity.ctf_stage_bindings SET stage_digest=$1 WHERE stage_id=$2',['0'.repeat(64),stageId]);
  await wrong('stage inactive','UPDATE identity.ctf_stage_bindings SET active=false WHERE stage_id=$1',[stageId]);
  await wrong('configuration disabled','UPDATE identity.ctf_config_binding SET enabled=false WHERE singleton');
  await wrong('original session revoked','UPDATE identity.user_sessions SET is_active=0 WHERE id=$1',[sessionId],'28000');
  assert.equal(await probe(client),true,'all stale variants rolled back');
  return true;
 }finally{await client.query('ROLLBACK');client.release();}
}
async function assertApplied({identityRuntime,decisionId,actorId,sessionId,rawToken}){
 const result=await identityRuntime.query('SELECT identity.ctf_current_decision_pending($1,$2,$3,$4) AS pending',[decisionId,actorId,sessionId,sha(rawToken)]);
 assert.deepEqual(result.rows,[{pending:false}],'applied decision cannot use pending-only gate');
}
module.exports={assertControlledSqlGates,assertApplied};
