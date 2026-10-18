'use strict';
const {createHash}=require('node:crypto');
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {canonicalCtfJson,validateCtfLifecycleCommand}=require('../../services/ctfLifecycleCommands');
const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const states=new Set(['not_found','in_progress','outcome_indeterminate','outcome_stored','admission_pending','blocked_ready_to_enqueue','blocked_pending','blocked_publishable','guardian_not_started_or_unknown','proposal_staged','decision_available','recovery_required']);
const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');
function auth({runId,session}){
 if(typeof runId!=='string'||!uuid.test(runId)||!session||!['actorId','sessionId'].every(key=>typeof session[key]==='string'&&/^[1-9][0-9]*$/.test(session[key])&&BigInt(session[key])<=2147483647n)||typeof session.rawToken!=='string'||!session.rawToken.isWellFormed()||!session.rawToken.length||session.rawToken.length>16384)throw TypeError('Original CTF recovery session and run required');
 return Object.freeze([session.actorId,session.sessionId,sha(session.rawToken),runId]);
}
function validateState(value,runId){
 const keys=['version','state','runId','admissionId','blockedOperationId','decisionId','currentCompletion'];
 if(typeof runId!=='string'||!uuid.test(runId)||!value||Array.isArray(value)||Object.keys(value).length!==keys.length||Object.keys(value).some(k=>!keys.includes(k))||value.version!==1||value.runId!==runId||!states.has(value.state)||value.currentCompletion!==false||!['admissionId','blockedOperationId','decisionId'].every(key=>value[key]===null||typeof value[key]==='string'&&uuid.test(value[key])))throw Error('CTF_RECOVERY_STATE_INVALID');
 if(value.state==='not_found'&&['admissionId','blockedOperationId','decisionId'].some(key=>value[key]!==null)||value.state!=='not_found'&&(!value.admissionId||!value.blockedOperationId)||value.state==='decision_available'&&!value.decisionId||value.state!=='decision_available'&&value.decisionId!==null)throw Error('CTF_RECOVERY_STATE_INVALID');
 return Object.freeze({...value});
}
function createCtfPredefenseRecoveryRepository(pool){
 return Object.freeze({
  read(input,options){const args=auth(input);return withCtfTransaction(pool,async c=>validateState((await c.query('SELECT identity.read_ctf_predefense_recovery($1,$2,$3,$4) AS value',args)).rows[0]?.value,args[3]),options);},
  consume(input,options){const args=auth(input);return withCtfTransaction(pool,async c=>{
   const value=(await c.query('SELECT identity.consume_ctf_predefense_recovery($1,$2,$3,$4) AS value',args)).rows[0]?.value;
   if(!value||value.currentState!==false||typeof value.consumed!=='boolean'||value.consumed===true&&(!uuid.test(value.operationId)||!uuid.test(value.blockedOperationId)||!['input','category','payload','continue'].includes(value.disposition)))throw Error('CTF_RECOVERY_CONSUMPTION_INVALID');
   return Object.freeze({consumed:value.consumed,currentState:false});
  },options);},
  enqueueBlocked(input,options){const args=auth(input);return withCtfTransaction(pool,async c=>{
   const prepared=(await c.query('SELECT identity.prepare_ctf_blocked_recovery($1,$2,$3,$4) AS value',args)).rows[0]?.value;
   const raw=canonicalCtfJson(prepared?.command),hash=sha(raw),command=validateCtfLifecycleCommand({...prepared.command,commandHash:hash});
   if(prepared.currentState!==false||typeof prepared.replayed!=='boolean'||command.kind!=='record_blocked_attempt'||command.actorId!==args[0]||command.operationId!==prepared.operationId||prepared.replayed&&prepared.canonicalCommand!==raw)throw Error('CTF_RECOVERY_BLOCKED_PREPARATION_INVALID');
   const value=(await c.query('SELECT identity.enqueue_ctf_blocked_recovery($1,$2,$3,$4,$5,$6) AS value',[...args,raw,hash])).rows[0]?.value;
   if(value?.operationId!==command.operationId||value.currentState!==false||typeof value.replayed!=='boolean')throw Error('CTF_RECOVERY_BLOCKED_RESULT_INVALID');
   return Object.freeze({operationId:value.operationId,replayed:value.replayed,currentState:false});
  },options);},
 });
}
module.exports={createCtfPredefenseRecoveryRepository,validateCtfPredefenseRecoveryState:validateState};
