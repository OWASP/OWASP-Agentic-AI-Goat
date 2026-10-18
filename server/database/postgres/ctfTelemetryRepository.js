'use strict';
const {createHash}=require('node:crypto');
const {encodeHeartbeat,validateHeartbeatEvent,validateHeartbeatReceipt}=require('../../services/ctfTelemetryContract');
// Lazy boundary import avoids a lifecycle-repository import cycle.
const transaction=(...args)=>require('./ctfLifecycleRepository').withCtfTransaction(...args);
function readHeartbeatEvent(row){const event=validateHeartbeatEvent({command:JSON.parse(row.canonical_command),canonicalCommand:row.canonical_command,commandHash:row.command_hash,sequence:String(row.sequence)});if(event.command.operationId!==row.operation_id||event.command.actorId!==String(row.actor_id)||event.command.sessionId!==String(row.session_id)||event.command.scope.ownerGeneration!==String(row.owner_generation_after))throw Error('CTF_HEARTBEAT_BINDING_INVALID');return event;}
async function acknowledgeHeartbeat(client,event,receipt){validateHeartbeatReceipt(event,receipt.canonicalResult,receipt.resultHash);return(await client.query('SELECT * FROM identity.ack_ctf_heartbeat($1,$2,$3,$4,$5)',[event.command.operationId,event.sequence,event.commandHash,receipt.canonicalResult,receipt.resultHash])).rows[0];}
function createCtfTelemetryRepository(pool){return Object.freeze({async admit({session,operationId,registrationToken},options){
 const {actorId,sessionId,rawToken}=session||{};
 if(typeof rawToken!=='string'||!rawToken.length||rawToken.length>16384||!rawToken.isWellFormed())throw TypeError('Canonical admitted session required');
 // Retain the old optional/falsy-token no-op without allowing an unauthenticated shortcut.
 const token=registrationToken?registrationToken:null;
 if(token!==null&&(typeof token!=='string'||!token.isWellFormed()||token.includes('\0')||Buffer.byteLength(token)>256))throw TypeError('Invalid CTF registration locator');
 const tokenHash=createHash('sha256').update(rawToken,'utf8').digest('hex');
 return transaction(pool,async client=>{
  const args=[actorId,sessionId,tokenHash,operationId,token];
  const prepared=(await client.query('SELECT identity.prepare_ctf_heartbeat($1,$2,$3,$4,$5) AS value',args)).rows[0]?.value;
  if(prepared?.state==='noop')return{state:'noop',operationId:null};
  if(!prepared?.command)throw Error('CTF_HEARTBEAT_PREPARATION_INVALID');
  const encoded=encodeHeartbeat(prepared.command);
  if(encoded.command.operationId!==operationId||encoded.command.actorId!==String(actorId)||encoded.command.sessionId!==String(sessionId)||encoded.command.registrationToken!==token)throw Error('CTF_HEARTBEAT_PREPARATION_INVALID');
  const admitted=(await client.query('SELECT identity.enqueue_ctf_heartbeat($1,$2,$3,$4,$5,$6,$7) AS value',[...args,encoded.canonicalCommand,encoded.commandHash])).rows[0]?.value;
  if(!admitted||admitted.operationId!==operationId||!['pending','applied'].includes(admitted.state))throw Error('CTF_HEARTBEAT_ADMISSION_INVALID');
  return admitted;
 },options);
 }});}
module.exports={createCtfTelemetryRepository,readHeartbeatEvent,acknowledgeHeartbeat};
