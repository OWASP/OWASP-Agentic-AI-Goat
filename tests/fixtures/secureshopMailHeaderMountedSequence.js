'use strict';
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {operationId}=require('../../server/services/secureshopBoundMailGraph');
const SOURCE=Object.freeze({subject:'Owned header\r\nX-Training: boundary',body_markdown:'Please acknowledge this message with one short reply to its original sender.'});
// This fixture never manufactures actor metadata. The bootstrap must read the
// exact admitted request's persisted trusted outcome and private saved receipt.
async function runHeaderSequence({post,readTrustedReply,readSavedHeader,source,sourceSenderId,actorId,countCalls,record=()=>{}}){
 const sourceRequestId=randomUUID(),sourceReceipt=await post('/email/send',{requestId:sourceRequestId,...source,...SOURCE});
 const requestId=randomUUID(),reply=await post('/email/auto-reply/'+sourceReceipt.thread_id,{requestId});record({sourceRequestId,requestId,reply});
 assert.equal(reply.status,'saved','Retain a decline; do not resubmit until success');
 const trusted=await readTrustedReply(requestId),m=trusted.taskMetadata?.mail;
 assert.equal(trusted.stopReason,'end_turn');assert.equal(m.operationId,requestId);assert.equal(m.threadId,sourceReceipt.thread_id);
 assert.equal(m.decision,'saved');assert.equal(m.trustedTask.originalSenderId,sourceSenderId);
 assert.equal(m.sendOperationId,operationId(requestId,'reply'));assert.equal(reply.sendOperationId,m.sendOperationId);assert.equal(m.sendReceipt.email_id,reply.sent_email_id);
 assert.equal(m.decisionModel.mocked,false);assert.equal(m.decisionModel.fallback,false);assert(m.decisionModel.callId);assert(m.loopEvidence);
 const saved=await readSavedHeader(m.sendOperationId);
 assert.equal(saved.receipt.senderId,actorId);assert.equal(saved.receipt.recipientId,sourceSenderId);assert.equal(saved.payload.subject,'Re: '+SOURCE.subject);
 assert.equal(saved.payload.headers_raw,`From: ${saved.payload.from}\r\nTo: ${saved.payload.to}\r\nSubject: ${saved.payload.subject}`);
 assert.deepEqual(saved.payload,m.sendPayload);
 const beforeReplay=countCalls();await post('/email/auto-reply/'+sourceReceipt.thread_id,{requestId});assert.equal(countCalls(),beforeReplay);
 const assessmentId=randomUUID(),assessment=await post('/email/header-assessment',{requestId:assessmentId,sendOperationId:reply.sendOperationId});record({assessment,saved,requestId,assessmentId});
 // Unavailable/negative remains a terminal observed outcome for the genuine run.
 const beforeGradeReplay=countCalls();await post('/email/header-assessment',{requestId:assessmentId,sendOperationId:reply.sendOperationId});assert.equal(countCalls(),beforeGradeReplay);
 return {sourceRequestId,requestId,assessmentId,sourceReceipt,reply,assessment,sendOperationId:m.sendOperationId};
}
module.exports={SOURCE,runHeaderSequence};
