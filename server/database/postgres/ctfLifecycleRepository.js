'use strict';
const {createHash}=require('node:crypto');
const {buildCtfLifecycleCommand,canonicalCtfJson,validateCtfLifecycleCommand}=require('../../services/ctfLifecycleCommands');
const {validateCtfProjectionResult}=require('../../services/ctfProjectionResults');
const {readCtfDecisionEvent,acknowledgeCtfDecision}=require('./ctfDecisionProjectionRepository');
const {readHeartbeatEvent,acknowledgeHeartbeat}=require('./ctfTelemetryRepository');
const deletionDeferrals=new WeakSet();
const isCtfDeletionDeferred=value=>Boolean(value&&typeof value==='object'&&deletionDeferrals.has(value));
const abort=()=>Object.assign(new Error('CTF bounded transaction interrupted; reconcile operation before retry'),{code:'CTF_TRANSACTION_UNCERTAIN'});
// A finite client-acquisition and transaction boundary. No callback may invoke a
// model or acquire another store. Lost/ambiguous COMMIT is never replayed here.
async function withCtfTransaction(pool,work,{signal,timeoutMs=3000,acquireMs=500}={}){
 if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>5000||!Number.isInteger(acquireMs)||acquireMs<1||acquireMs>1000)throw new TypeError('Invalid CTF transaction bounds');
 if(signal?.aborted)throw abort();
 let client,expired=false,released=false,timer,acquireTimer,listener;
 let rejectDeadline;const deadline=new Promise((_,reject)=>{rejectDeadline=reject;});
 const release=discard=>{if(client&&!released){released=true;client.release(discard);}};
 const stop=()=>{expired=true;release(true);rejectDeadline(abort());};
 signal?.addEventListener('abort',listener=stop,{once:true});timer=setTimeout(stop,timeoutMs);
 // Late acquisition is destroyed rather than leaked into a completed request.
 const pending=Promise.resolve().then(()=>pool.connect()).then(c=>{if(expired){c.release(true);throw abort();}client=c;return c;});
 const acquireLimit=new Promise((_,reject)=>{acquireTimer=setTimeout(()=>{expired=true;reject(abort());},Math.min(acquireMs,timeoutMs));});
 try{
  await Promise.race([pending,acquireLimit,deadline]);clearTimeout(acquireTimer);
  const bounded={query:async(...args)=>{if(expired||signal?.aborted)throw abort();return client.query(...args);},release(){throw new Error('Transaction client release is owned by boundary');}};
  const transaction=(async()=>{
   await bounded.query('BEGIN');
   await bounded.query("SET LOCAL lock_timeout='250ms'");await bounded.query("SET LOCAL statement_timeout='2000ms'");
   await bounded.query("SET LOCAL idle_in_transaction_session_timeout='3000ms'");
   const value=await work(bounded);await bounded.query('COMMIT');return value;
  })();
  return await Promise.race([transaction,deadline]);
 }catch(error){
  if(client&&!released){try{await Promise.race([client.query('ROLLBACK'),deadline]);}catch{release(true);}}
  throw error;
 }finally{
  clearTimeout(timer);clearTimeout(acquireTimer);signal?.removeEventListener('abort',listener);release(expired);
 }
}
function createCtfLifecycleRepository(pool){
 return Object.freeze({
  async enqueue({actorId,sessionId,rawToken,operationId,kind,body,scope},options){
   if(typeof rawToken!=='string'||rawToken.length<1||rawToken.length>16384||!rawToken.isWellFormed())throw new TypeError('Canonical admitted session required');
   const tokenHash=createHash('sha256').update(rawToken,'utf8').digest('hex');
   return withCtfTransaction(pool,async client=>{
    const time=(await client.query("SELECT to_char(date_trunc('milliseconds',transaction_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS occurred_at")).rows[0].occurred_at;
    const command=buildCtfLifecycleCommand(kind,body,{actorId,operationId,occurredAt:time,scope});
    const {commandHash,...content}=command;
    return (await client.query('SELECT * FROM identity.enqueue_ctf_user_command($1,$2,$3,$4,$5,$6)',[actorId,sessionId,tokenHash,operationId,canonicalCtfJson(content),commandHash])).rows[0];
   },options);
  },
  async next(options){
   return withCtfTransaction(pool,async client=>{
    const row=(await client.query("SELECT o.* FROM identity.ctf_authority a JOIN identity.ctf_outbox o ON o.sequence=a.applied_sequence+1 WHERE a.scope_key='global' AND a.lifecycle_state IN ('ready','pending') AND o.state='pending' ORDER BY o.sequence LIMIT 1")).rows[0];
    if(!row)return null;
    if(!row.canonical_command)throw new Error('CTF_LEGACY_EVENT_REQUIRES_RECOVERY');
    if(row.kind==='student_delete'){
     const command=JSON.parse(row.canonical_command);
     require('../../services/ctfDeletionContract').validateEvent({command,canonicalCommand:row.canonical_command,commandHash:row.command_hash,sequence:String(row.sequence)});
     if(command.operationId!==row.operation_id)throw new Error('CTF_DELETION_IDENTITY_MISMATCH');
     const deferred=Object.freeze({deferred:'student_delete',operationId:row.operation_id,sequence:String(row.sequence)});deletionDeferrals.add(deferred);return deferred;
    }
    if(row.kind==='decision')return readCtfDecisionEvent(client,row);
    if(row.kind==='heartbeat')return readHeartbeatEvent(row);
    const command=validateCtfLifecycleCommand({...JSON.parse(row.canonical_command),commandHash:row.command_hash});
    const {commandHash,...content}=command;
    if(canonicalCtfJson(content)!==row.canonical_command)throw new Error('CTF_COMMAND_ENCODING_MISMATCH');
    return {sequence:String(row.sequence),command,ownerGenerationAfter:row.owner_generation_after==null?null:String(row.owner_generation_after),registrationDisposition:row.registration_disposition,registrationParticipantBefore:row.registration_participant_before==null?null:String(row.registration_participant_before)};
   },options);
  },
  async acknowledge(event,receipt,options){
   if(event.command?.kind==='heartbeat')return withCtfTransaction(pool,client=>acknowledgeHeartbeat(client,event,receipt),options);
   if(event.command?.kind==='decision')return withCtfTransaction(pool,client=>acknowledgeCtfDecision(client,event,receipt),options);
   validateCtfProjectionResult(event.command,event.sequence,receipt.canonicalResult,receipt.resultHash);
   return withCtfTransaction(pool,async client=>(await client.query('SELECT * FROM identity.ack_ctf_projection($1,$2,$3,$4,$5)',[event.command.operationId,event.sequence,event.command.commandHash,receipt.canonicalResult,receipt.resultHash])).rows[0],options);
  }
 });
}
module.exports={createCtfLifecycleRepository,withCtfTransaction,isCtfDeletionDeferred};
