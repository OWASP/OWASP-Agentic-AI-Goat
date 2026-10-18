'use strict';
const {createHash}=require('node:crypto');
const {normalize}=require('./secureshopBoundMailRepository');
const {operationId}=require('../../services/secureshopBoundMailGraph');
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const mailScene=require('../../services/secureshopMailSceneBinding');
const hash=value=>createHash('sha256').update(value).digest('hex');
const fail=()=>Object.assign(Error('Canonical mail evidence unavailable'),{code:'MAIL_EVIDENCE_UNAVAILABLE'});
function createMailEvidenceRepository({personaAuthority,mailRepository}={}){
 if(typeof personaAuthority?.capture!=='function'||typeof mailRepository?.recover!=='function'||typeof mailRepository?.read!=='function')throw TypeError('Mail evidence dependencies required');
 return Object.freeze({async readReply(raw){
  const {threadId,...input}=raw,b=normalize(input);if(!Number.isSafeInteger(threadId)||threadId<1)throw fail();
  return mailScene.withLease(b,async()=>{
  const fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};if(!fence?.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k]))throw fail();
  const binding=createConversationBinding(b.scope,b.persona),message=JSON.stringify({version:1,targetId:b.targetId,threadId,mode:b.mode,operationId:b.operationId,personaSession:b.personaSession});
  const turn=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   await mailScene.assertGrant(client,b);
   const rows=(await client.query(`SELECT tr.session_id,tr.request_id,tr.request_hash,tr.request_version,tr.status,tr.result_json
    FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
    WHERE tr.request_id=$1 AND s.conversation_purpose='secureshop_mail_reply' AND s.authority_mode='launch_bound' AND s.binding_state='active'
    AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3 AND s.platform_launch_generation=$4
    AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6 AND s.user_id=$7 AND s.role=$8`,
    [b.operationId,b.scope.launchId,b.scope.scenarioId,b.scope.generation,b.scope.platformOwnerId,b.scope.platformSessionId,b.persona.id,b.persona.role])).rows;
   if(rows.length!==1||rows[0].status!=='completed')throw fail();const row=rows[0];
   if(createTurnRequest({sessionId:row.session_id,requestId:b.operationId,binding,message,version:row.request_version}).hash!==row.request_hash)throw fail();
   const m=row.result_json?.taskMetadata?.mail;
   if(row.result_json?.stopReason!=='end_turn'||![1,2].includes(m?.version)||m.operationId!==b.operationId||m.targetId!==b.targetId||m.threadId!==threadId||m.mode!==b.mode||m.decision!=='saved'
    ||m.sendOperationId!==operationId(b.operationId,'reply')||m.readOperationId!==operationId(b.operationId,'snapshot')
    ||!m.decisionModel||m.decisionModel.mocked!==false||m.decisionModel.fallback!==false||typeof m.decisionModel.callId!=='string'
    ||typeof m.decisionModel.provider!=='string'||/mock|fixture|fallback|scripted/i.test(m.decisionModel.provider))throw fail();
   await mailScene.assertGrant(client,b);
   return {sessionId:row.session_id,requestId:row.request_id,requestHash:row.request_hash,metadata:structuredClone(m)};
  });
  const m=turn.metadata,receipt=await mailRepository.recover({...b,operationId:m.sendOperationId});
  if(!receipt.found||receipt.action!=='send'||JSON.stringify(receipt.receipt)!==JSON.stringify(m.sendReceipt))throw fail();
  if(m.version===2){
   const digest=await fence.withPersonaEffect(async client=>{await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");await mailScene.assertGrant(client,b);const value=(await client.query("SELECT encode(sha256(convert_to($1::jsonb::text,'UTF8')),'hex') AS payload_sha256",[JSON.stringify(m.sendPayload)])).rows[0]?.payload_sha256;await mailScene.assertGrant(client,b);return value;});
   if(digest!==receipt.receipt.contentSha256)throw fail();
  }
  // Exact original snapshot replay; new mail cannot change this evidence.
  const snapshot=await mailRepository.read({...b,operationId:m.readOperationId},b.persona.id),messages=snapshot.emails.filter(row=>row.thread_id===threadId);
  if(!messages.length||hash(JSON.stringify(messages))!==m.sourceSha256)throw fail();
  await fence.assertRemoteAdmission();return Object.freeze({binding:b,threadId,turn,source:messages,send:receipt.receipt});
  });
 }});
}
module.exports={createMailEvidenceRepository};
