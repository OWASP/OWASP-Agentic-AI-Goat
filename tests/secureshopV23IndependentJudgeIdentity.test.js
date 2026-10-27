'use strict';
// Permanent controlled tests of actual qualification sources; no native calls.
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const V=require('./postgres/secureshopV23Original.integration.test');
const T=require('./postgres/secureshopMailActualTransport');
const sha=x=>createHash('sha256').update(x).digest('hex');
function call(kind,model){const request=JSON.stringify({model,messages:[]}),response=JSON.stringify({model,done:true,message:{content:'controlled only'}});return{kind,model,status:200,responseComplete:true,responseCaptureTruncated:false,request,response,requestSha256:sha(request),responseSha256:sha(response)};}
test('V23 default remains Llama and explicit Judge configuration is closed',()=>{
 const actor=V.v23JudgeIdentity(),judge=V.v23JudgeIdentity('qwen25-v1');
 assert.equal(actor.model,'llama3.1:8b');assert.equal(judge.model,'qwen2.5:7b-instruct-q4_K_M');
 assert.equal(V.v23ConfiguredIdentity({provider:'ollama',model:actor.model}),actor);
 assert.throws(()=>V.v23ConfiguredIdentity({provider:'ollama',model:judge.model}));
 assert.equal(V.v23ConfiguredIdentity({provider:'ollama',model:judge.model},'qwen25-v1'),judge);
 for(const profile of ['unknown','qwen3-v1','__proto__'])assert.throws(()=>V.v23JudgeIdentity(profile));
});
test('V23 actual physical role validator rejects actor replacement and forged frames',()=>{
 const a=V.v23JudgeIdentity(),j=V.v23JudgeIdentity('qwen25-v1');
 V.assertPhysical(call('actor',a.model),'actor');V.assertPhysical(call('judge',j.model),'judge','qwen25-v1');
 assert.throws(()=>V.assertPhysical(call('actor',j.model),'actor','qwen25-v1'));
 for(const change of [c=>c.kind='actor',c=>c.model=a.model,c=>c.requestSha256='0'.repeat(64),c=>{c.response=JSON.stringify({model:a.model,done:true,message:{content:''}});c.responseSha256=sha(c.response);},c=>c.responseComplete=false]){const c=call('judge',j.model);change(c);assert.throws(()=>V.assertPhysical(c,'judge','qwen25-v1'));}
});
test('V23 actual two-call Judge budget cannot spend actor calls or third Judge call',()=>{
 const b=T.createActualCallBudget({protocol:'v23-independent-judge-v1',maxHttpCalls:2});
 assert.equal(b.reserve('actor'),false);assert.equal(b.reserve('judge'),true);assert.equal(b.reserve('judge'),true);assert.equal(b.reserve('judge'),false);
 assert.deepEqual(b.snapshot(),{total:2,actor:0,judge:2});
 assert.throws(()=>T.createActualCallBudget({protocol:'v23-independent-judge-v1',maxHttpCalls:3}));
});
