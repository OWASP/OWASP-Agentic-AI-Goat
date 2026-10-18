'use strict';
const {withCtfTransaction}=require('./ctfLifecycleRepository');
const {authenticateCtfRead}=require('./ctfPredefenseRequestLoader');
const {inputDocument}=require('../../services/ctfPredefenseContract');
const {stageDigest}=require('../../agent-runtime/ctfStageJudge');
const {validateCtfLifecycleCommand,canonicalCtfJson}=require('../../services/ctfLifecycleCommands');
const {validateCtfProjectionResult}=require('../../services/ctfProjectionResults');
const fail=()=>{throw Object.assign(Error('CTF admitted attempt unavailable'),{code:'CTF_ADMITTED_ATTEMPT_UNAVAILABLE'});};
const freeze=x=>{if(x&&typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}return x;};
function createCtfAdmittedAttemptRepository(identityPool){
 return Object.freeze({async loadAdmittedAttempt(admissionId,session,options){
  if(!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(admissionId))throw TypeError('Invalid admission reference');
  const original=structuredClone(session);
  return withCtfTransaction(identityPool,async client=>{
   await authenticateCtfRead(client,original);
   const row=(await client.query(`SELECT row_to_json(c) AS claim,row_to_json(d) AS consumption,
    jsonb_build_object('ownerId',a.owner_id::text,'ownerGeneration',a.owner_generation::text,'participantId',a.participant_id::text,'progressId',a.progress_id::text,'stageId',a.stage_id::text,'attemptNumber',a.attempt_number,'failed',a.failed_counter_increment,'sequence',a.applied_sequence::text) AS admission,
    o.canonical_command,o.command_hash,o.canonical_result,o.result_hash,o.sequence::text,o.state,o.kind,o.actor_id::text,o.session_id::text
    FROM identity.ctf_predefense_claims c
    JOIN identity.ctf_predefense_consumptions d ON d.run_id=c.run_id AND d.operation_id=c.admission_operation_id
    JOIN identity.ctf_attempt_admissions a ON a.operation_id=c.admission_operation_id
    JOIN identity.ctf_outbox o ON o.operation_id=a.operation_id
    WHERE c.admission_operation_id=$1`,[admissionId])).rows[0];
   if(!row||row.state!=='applied'||row.kind!=='admit_attempt'||row.consumption.final_disposition!=='continue'||row.consumption.failed!==false||row.consumption.matched_payload_hash!==null)fail();
   const c=row.claim,a=row.admission;
   if(String(c.owner_id)!==String(original.actorId)||String(c.session_id)!==String(original.sessionId)||c.admission_operation_id!==admissionId||row.actor_id!==String(original.actorId)||row.session_id!==String(original.sessionId))fail();
   const parsed=JSON.parse(c.canonical_input),checked=inputDocument(parsed,c.stage_snapshot),b=checked.document.binding;
   if(checked.canonicalDocument!==c.canonical_input||checked.documentHash!==c.input_hash||b.runId!==c.run_id||b.ownerId!==String(original.actorId)||b.sessionId!==String(original.sessionId))fail();
   const stage=Object.fromEntries(JSON.parse(c.stage_snapshot));
   if(stageDigest(stage)!==b.stageDigest||String(stage.id)!==b.stageId||!Number.isSafeInteger(stage.stage_number)||stage.stage_number<1||stage.stage_number>2147483647)fail();
   const command=validateCtfLifecycleCommand({...JSON.parse(row.canonical_command),commandHash:row.command_hash});const {commandHash,...content}=command;
   if(canonicalCtfJson(content)!==row.canonical_command||command.kind!=='admit_attempt'||command.operationId!==admissionId||command.actorId!==b.ownerId||command.body.failed!==false||a.failed!==false||a.sequence!==row.sequence)fail();
   for(const key of ['ownerId','ownerGeneration','participantId','progressId','stageId'])if(a[key]!==b[key])fail();
   for(const key of ['ownerId','ownerGeneration','globalRevision','stageRevision','participantId','progressId','stageId'])if(command.scope[key]!==b[key])fail();
   const receipt=validateCtfProjectionResult(command,row.sequence,row.canonical_result,row.result_hash).value;
   if(receipt.outcome!=='applied'||receipt.data.progressId!==b.progressId||receipt.data.attemptNumber!==a.attemptNumber)fail();
   const {ownerRevision,...decisionBinding}=b;
   // Capture rechecks live authority after this read transaction releases.
   return freeze({binding:{...decisionBinding,admissionId,stageNumber:stage.stage_number},stage,payload:checked.document.payload,techniqueTag:checked.document.techniqueTag});
  },options);
 }});
}
module.exports={createCtfAdmittedAttemptRepository};
