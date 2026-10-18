'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {canonicalCtfJson,validateCtfLifecycleCommand}=require('../../services/ctfLifecycleCommands');
const sha=x=>createHash('sha256').update(x).digest('hex');
function createCtfBlockedPredefenseRepository(pool){return Object.freeze({enqueueFromClaim({runId,session},{signal}={}){
 if(!session||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384)throw TypeError('Original platform session required');
 const auth=[session.actorId,session.sessionId,sha(session.rawToken),runId];
 return withCtfTransaction(pool,async client=>{
  // Locks remain held across both statements. No model or second store here.
  const prepared=(await client.query('SELECT identity.prepare_ctf_blocked_predefense($1,$2,$3,$4) AS value',auth)).rows[0].value;
  const raw=canonicalCtfJson(prepared.command),hash=sha(raw);
  const command=validateCtfLifecycleCommand({...prepared.command,commandHash:hash});
  if(command.kind!=='record_blocked_attempt'||command.actorId!==String(session.actorId)||command.operationId!==prepared.operationId||prepared.currentState!==false||prepared.replayed&&prepared.canonicalCommand!==raw)throw Error('CTF_BLOCKED_PREPARATION_INVALID');
  return(await client.query('SELECT identity.enqueue_ctf_blocked_predefense($1,$2,$3,$4,$5,$6) AS value',[...auth,raw,hash])).rows[0].value;
 },{signal});
}});}
module.exports={createCtfBlockedPredefenseRepository};
