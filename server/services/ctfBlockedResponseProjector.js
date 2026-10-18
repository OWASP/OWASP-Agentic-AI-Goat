'use strict';
const {createCtfLessonReceipt}=require('../agent-runtime/ctfLessonState');
function createCtfBlockedResponseProjector({current}){
 if(typeof current?.readAuthorized!=='function')throw TypeError('Current blocked-response authority required');
 return Object.freeze({async project({runId,session},options){
  const value=await current.readAuthorized({runId,session},options);
  if(value?.current!==true||value.runId!==runId||value.ownerId!==String(session.actorId)||value.sessionId!==String(session.sessionId)||value.command?.kind!=='record_blocked_attempt'||!['input','category','payload'].includes(value.disposition))throw Error('CTF_BLOCKED_RESPONSE_INVALID');
  const body=value.command.body,lesson=createCtfLessonReceipt({ownerId:value.ownerId,participantId:value.participantId,stageId:value.stageId,stageNumber:value.stageNumber});lesson.bindAttempt(body.attemptNumber);
  if(value.disposition==='input')lesson.observeInputGuard();else if(value.disposition==='category')lesson.observeCategoryReuseBlock();else lesson.observeSharedSimilarityBlock();
  const lessonState=lesson.project({ownerId:value.ownerId,participantId:value.participantId,stageId:value.stageId,attemptNumber:body.attemptNumber});
  const response={success:false,blocked:true,reason:body.reason,attemptNumber:body.attemptNumber};
  if(value.disposition==='category')response.techniqueTag=body.techniqueTag;
  if(value.disposition==='input'&&value.feedbackMode!=='silent'&&value.languageStatus)response.languageStatus=value.languageStatus;
  if(lessonState)response.lessonState=lessonState;
  return{status:200,body:response};
 }});
}
module.exports={createCtfBlockedResponseProjector};
