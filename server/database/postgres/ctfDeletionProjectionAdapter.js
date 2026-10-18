'use strict';
const {validateEvent,receiptFor,validateReceipt,countKeys}=require('../../services/ctfDeletionContract');
async function projectCtfDeletion(client,event){
 validateEvent(event);const c=event.command;
 await client.query('SELECT pg_advisory_xact_lock(1886610804,44)');
 const prior=(await client.query('SELECT * FROM ctf.projection_receipts WHERE operation_id=$1',[c.operationId])).rows[0];
 if(prior)return validateReceipt(event,prior.canonical_result,prior.result_hash);
 const cursor=(await client.query('SELECT * FROM ctf.projection_cursor WHERE singleton FOR UPDATE')).rows[0];
 if(!cursor?.initialized||BigInt(cursor.applied_sequence)+1n!==BigInt(event.sequence))throw Error('CTF_DELETION_CURSOR_UNAVAILABLE');
 const scopes=(await client.query("SELECT * FROM ctf.projection_scopes WHERE scope_key IN ('global',$1) ORDER BY scope_key FOR UPDATE",['owner:'+c.subjectId])).rows;
 const global=scopes.find(x=>x.scope_key==='global'),owner=scopes.find(x=>x.scope_key==='owner:'+c.subjectId);
 if(String(global?.revision)!==c.globalRevision||(owner&&(String(owner.revision)!==c.ownerRevision||String(owner.owner_generation)!==c.generationBefore)))throw Error('CTF_DELETION_SCOPE_DRIFT');
 const participant=(await client.query('SELECT id FROM ctf.ctf_participants WHERE user_id=$1 FOR UPDATE',[c.subjectId])).rows[0];
 if((participant?String(participant.id):null)!==c.participantId)throw Error('CTF_DELETION_PARTICIPANT_DRIFT');
 const removed=Object.fromEntries(countKeys.map(k=>[k,0]));
 removed.bans=(await client.query('DELETE FROM ctf.ctf_bans WHERE user_id=$1',[c.subjectId])).rowCount;
 if(participant){
  const tables={judgments:'ctf_judgments',attempts:'ctf_attempts',progress:'ctf_progress',techniques:'ctf_technique_blocklist',leaderboard:'ctf_leaderboard',events:'ctf_events',sessions:'ctf_sessions'};
  for(const [key,table] of Object.entries(tables))removed[key]=(await client.query(`DELETE FROM ctf.${table} WHERE participant_id=$1`,[participant.id])).rowCount;
  // Global payload memory persists; its existing FK clears the winner link.
  removed.participants=(await client.query('DELETE FROM ctf.ctf_participants WHERE id=$1 AND user_id=$2',[participant.id,c.subjectId])).rowCount;
 }
 await client.query('SELECT ctf.refresh_authorized_leaderboard($1::timestamptz)',[c.occurredAt]);
 const receipt=receiptFor(event,removed);
 await client.query('INSERT INTO ctf.projection_receipts(sequence,operation_id,kind,command_hash,canonical_result,result_hash) VALUES($1,$2,$3,$4,$5,$6)',[event.sequence,c.operationId,c.kind,event.commandHash,receipt.canonicalResult,receipt.resultHash]);
 await client.query('INSERT INTO ctf.projection_scopes(scope_key,revision,owner_generation,applied_operation_id) VALUES($1,$2,$3,$4) ON CONFLICT(scope_key) DO UPDATE SET revision=EXCLUDED.revision,owner_generation=EXCLUDED.owner_generation,applied_operation_id=EXCLUDED.applied_operation_id',['owner:'+c.subjectId,c.ownerRevision,c.generationAfter,c.operationId]);
 await client.query('UPDATE ctf.projection_cursor SET applied_sequence=$1,last_operation_id=$2 WHERE singleton',[event.sequence,c.operationId]);
 return receipt;
}
module.exports={projectCtfDeletion};
