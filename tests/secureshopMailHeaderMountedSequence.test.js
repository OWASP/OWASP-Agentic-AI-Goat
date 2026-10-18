'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {runHeaderSequence,SOURCE}=require('./fixtures/secureshopMailHeaderMountedSequence');
const {operationId}=require('../server/services/secureshopBoundMailGraph');
function fixture(mutate=()=>{}){
 let calls=0,requestId;const posts=[];
 const payload={from:'merchant@lab',to:'customer@lab',subject:'Re: '+SOURCE.subject};payload.headers_raw=`From: ${payload.from}\r\nTo: ${payload.to}\r\nSubject: ${payload.subject}`;
 return {posts,options:{source:{from:'customer@lab',to:'merchant@lab'},sourceSenderId:1,actorId:2,countCalls:()=>calls,
 async post(route,body){posts.push({route,body});if(route==='/email/send')return {thread_id:5};if(route.includes('/auto-reply/')){requestId=body.requestId;return {status:'saved',sent_email_id:8,sendOperationId:operationId(requestId,'reply')};}return {completed:false,judgment:{verdict:'unavailable'}};},
 async readTrustedReply(id){const m={operationId:id,threadId:5,decision:'saved',trustedTask:{originalSenderId:1},sendOperationId:operationId(id,'reply'),sendReceipt:{email_id:8},decisionModel:{mocked:false,fallback:false,callId:'controlled-call'},loopEvidence:{controlled:true},sendPayload:payload};mutate(m);return {stopReason:'end_turn',taskMetadata:{mail:m}};},
 async readSavedHeader(){return {receipt:{senderId:2,recipientId:1},payload};}}};
}
test('sequence uses returned public opaque ID and retains unavailable without retry',async()=>{const f=fixture(),r=await runHeaderSequence(f.options);assert.equal(r.assessment.judgment.verdict,'unavailable');const grades=f.posts.filter(p=>p.route==='/email/header-assessment');assert.equal(grades.length,2);assert.deepEqual(grades[0].body,grades[1].body);assert.equal(grades[0].body.sendOperationId,operationId(r.requestId,'reply'));});
for(const [name,mutate] of [['substituted operation',m=>m.sendOperationId='wrong'],['mocked actor',m=>m.decisionModel.mocked=true],['wrong original sender',m=>m.trustedTask.originalSenderId=9]])test(name+' blocks grading',async()=>{const f=fixture(mutate);await assert.rejects(runHeaderSequence(f.options));assert.equal(f.posts.some(p=>p.route==='/email/header-assessment'),false);});

test('wrong saved recipient cannot be described as reply to original sender',async()=>{const f=fixture();const read=f.options.readSavedHeader;f.options.readSavedHeader=async()=>{const r=await read();r.receipt.recipientId=3;return r;};await assert.rejects(runHeaderSequence(f.options));assert.equal(f.posts.some(p=>p.route==='/email/header-assessment'),false);});
