'use strict';
const {createHash}=require('node:crypto');
function createReviewDecisionOperation({runId,fence}={}) {
 if(typeof runId!=='string'||! /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(runId)||!fence?.binding)throw new TypeError('Admitted review run required');
 return invocation=>{
  if(!invocation||!Number.isSafeInteger(invocation.step)||invocation.step<0||typeof invocation.callId!=='string'||!invocation.callId||invocation.callId.length>128||!['review-moderator.approve','review-moderator.reject'].includes(invocation.tool))throw Object.assign(Error('Actual review tool invocation required'),{code:'REVIEW_OPERATION_CONFLICT',executionBoundary:true});
  const identity=JSON.stringify([invocation.step,invocation.callId,invocation.tool]);const hash=createHash('sha256').update(JSON.stringify(['review-decision-v1',runId,identity])).digest();hash[6]=(hash[6]&15)|0x50;hash[8]=(hash[8]&63)|0x80;const hex=hash.subarray(0,16).toString('hex');const operationId=[hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-');
  return Object.freeze({operationId,kind:'agent',runId,toolInvocationId:identity,personaSessionId:fence.binding.sessionId,authorityVersion:fence.binding.authorityVersion});
 };
}
module.exports={createReviewDecisionOperation};
