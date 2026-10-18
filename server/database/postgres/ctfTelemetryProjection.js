'use strict';
const {validateHeartbeatEvent,heartbeatReceipt,validateHeartbeatReceipt}=require('../../services/ctfTelemetryContract');
async function applyCtfHeartbeat(client,input){
 const event=validateHeartbeatEvent(input),c=event.command,s=c.scope;
 await client.query('SELECT pg_advisory_xact_lock(1886610804,44)');
 const cursor=(await client.query('SELECT * FROM ctf.projection_cursor WHERE singleton FOR UPDATE')).rows[0];
 if(!cursor?.initialized)throw Error('CTF_PROJECTION_UNINITIALIZED');
 const prior=(await client.query('SELECT * FROM ctf.projection_receipts WHERE operation_id=$1 OR sequence=$2',[c.operationId,event.sequence])).rows[0];
 if(prior){if(prior.operation_id!==c.operationId||String(prior.sequence)!==event.sequence||prior.command_hash!==event.commandHash)throw Error('CTF_HEARTBEAT_REPLAY_CONFLICT');return validateHeartbeatReceipt(event,prior.canonical_result,prior.result_hash);}
 if(BigInt(event.sequence)!==BigInt(cursor.applied_sequence)+1n)throw Error('CTF_PROJECTION_OUT_OF_ORDER');
 const scopes=(await client.query('SELECT * FROM ctf.projection_scopes WHERE scope_key=ANY($1::text[])',[['global','owner:'+s.ownerId]])).rows;
 const global=scopes.find(r=>r.scope_key==='global'),owner=scopes.find(r=>r.scope_key==='owner:'+s.ownerId);
 if(String(global?.revision)!==s.globalRevision||String(owner?.owner_generation)!==s.ownerGeneration)throw Error('CTF_HEARTBEAT_SCOPE_DRIFT');
 const effect=await client.query(`UPDATE ctf.ctf_sessions s SET last_heartbeat=GREATEST(s.last_heartbeat,$4::timestamptz),total_active_time=s.total_active_time+1000
 FROM ctf.ctf_participants p WHERE s.session_token=$1 AND s.is_active=1 AND p.id=s.participant_id AND p.id=$2 AND p.user_id=$3`,[c.registrationToken,s.participantId,s.ownerId,c.occurredAt]);
 if(![0,1].includes(effect.rowCount))throw Error('CTF_HEARTBEAT_EFFECT_INVALID');
 const receipt=heartbeatReceipt(event,effect.rowCount===1);
 await client.query('INSERT INTO ctf.projection_receipts(sequence,operation_id,kind,command_hash,canonical_result,result_hash) VALUES($1,$2,$3,$4,$5,$6)',[event.sequence,c.operationId,'heartbeat',event.commandHash,receipt.canonicalResult,receipt.resultHash]);
 // Transport only: do not update scope revisions, generations, progress or clocks.
 await client.query('UPDATE ctf.projection_cursor SET applied_sequence=$1,last_operation_id=$2 WHERE singleton',[event.sequence,c.operationId]);
 return receipt;
}
module.exports={applyCtfHeartbeat};
