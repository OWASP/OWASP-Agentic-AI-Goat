'use strict';
const {normalize}=require('./secureshopBoundMailRepository');
const {createConversationBinding}=require('../../services/secureshopConversationBinding');
const {createTurnRequest}=require('../../services/secureshopTurnRequest');
const mailScene=require('../../services/secureshopMailSceneBinding');
function createMailRecoveryRepository({personaAuthority}={}){
 if(typeof personaAuthority?.capture!=='function')throw TypeError('Mail recovery authority required');
 return Object.freeze({async readTerminal(raw){
  const b=normalize(raw),fence=personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};if(!fence?.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k]))throw Error('Mail recovery authority mismatch');
  return mailScene.withLease(b,async()=>{
  const result=await fence.withPersonaEffect(async client=>{
   await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
   await mailScene.assertGrant(client,b);
   const rows=(await client.query(`SELECT tr.session_id,tr.request_hash,tr.request_version,tr.status,tr.result_json
    FROM secureshop_agents.turn_requests tr JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
    WHERE tr.request_id=$1 AND s.conversation_purpose='secureshop_mail_reply' AND s.authority_mode='launch_bound' AND s.binding_state='active'
    AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3 AND s.platform_launch_generation=$4
    AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6 AND s.user_id=$7 AND s.role=$8`,
    [b.operationId,b.scope.launchId,b.scope.scenarioId,b.scope.generation,b.scope.platformOwnerId,b.scope.platformSessionId,b.persona.id,b.persona.role])).rows;
   if(!rows.length)return null;if(rows.length!==1)throw Error('Mail recovery ambiguous');const row=rows[0];if(row.status!=='completed')return null;
   const m=row.result_json?.taskMetadata?.mail;if(!m||m.operationId!==b.operationId||m.targetId!==b.targetId||m.mode!==b.mode||!Number.isSafeInteger(m.threadId)||!['saved','declined'].includes(m.decision))throw Error('Mail recovery receipt mismatch');
   if(Object.hasOwn(m,'expectedSource')&&(!m.expectedSource
    ||Object.getPrototypeOf(m.expectedSource)!==Object.prototype
    ||Object.keys(m.expectedSource).sort().join(',')!=='messageId,sha256,threadId'
    ||m.expectedSource.threadId!==m.threadId
    ||!Number.isSafeInteger(m.expectedSource.messageId)||m.expectedSource.messageId<1
    ||typeof m.expectedSource.sha256!=='string'||! /^[0-9a-f]{64}$/.test(m.expectedSource.sha256)))
    throw Error('Mail recovery receipt mismatch');
   const request=createTurnRequest({sessionId:row.session_id,requestId:b.operationId,binding:createConversationBinding(b.scope,b.persona),version:row.request_version,message:JSON.stringify({version:1,targetId:b.targetId,threadId:m.threadId,mode:b.mode,operationId:b.operationId,personaSession:b.personaSession})});
   if(request.hash!==row.request_hash||row.result_json.stopReason!=='end_turn')throw Error('Mail recovery request mismatch');
   const terminalNoSend=m.version===2&&m.decision==='declined'
    &&Object.hasOwn(m,'sendPayload')&&m.sendPayload===null
    &&Object.hasOwn(m,'sendOperationId')&&m.sendOperationId===null
    &&Object.hasOwn(m,'sendReceipt')&&m.sendReceipt===null;
   const modeCapability=require('./secureshopTurnModeProjection').projectSavedMode(row.result_json.modeCapability,'mail');
   await mailScene.assertGrant(client,b);
   return Object.freeze({decision:m.decision,threadId:m.threadId,terminalNoSend,
    ...(Object.hasOwn(m,'expectedSource')?{expectedSource:m.expectedSource}:{}),
    ...(modeCapability?{modeCapability}:{})});
  });
  if(typeof fence.assertRemoteAdmission==='function')await fence.assertRemoteAdmission();
  return result;
  });
 }});
}
module.exports={createMailRecoveryRepository};
