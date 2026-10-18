'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const trace=require('../server/agent-runtime/runTraceStore');
const snapshot=()=>({version:'workshop-result-presentation-v1',narrativeSource:'model',errorCode:null,narrativeSha256:'a'.repeat(64),responseSha256:'b'.repeat(64),blocks:[{index:0,tool:'search_products',effectKey:'run:tool:0',resultSha256:'c'.repeat(64),displaySha256:'d'.repeat(64)}]});
test('closed presentation envelope survives repeated ledger projection without retaining content',()=>{
 const input=snapshot(),out=trace.traceData({presentationSnapshot:input,rawNarrative:'secret',rows:['private']});
 assert.deepEqual(out,{presentationSnapshot:input});assert.deepEqual(trace.traceData(out),out);
 input.blocks[0].resultSha256='e'.repeat(64);assert.equal(out.presentationSnapshot.blocks[0].resultSha256,'c'.repeat(64));
});
test('malformed, oversized, duplicate and content-bearing presentation envelopes are omitted',()=>{
 const cases=[p=>p.text='private',p=>p.blocks[0].result=['private'],p=>p.blocks[0].index=1,p=>p.blocks[0].resultSha256='x',p=>p.version='unknown',p=>p.narrativeSource='fallback',p=>p.errorCode='raw private error',p=>p.blocks[0].effectKey='x\nsecret',p=>p.blocks.push({...p.blocks[0],index:1}),p=>p.blocks=Array.from({length:5},(_,index)=>({...p.blocks[0],index,effectKey:`k${index}`}))];
 for(const mutate of cases){const p=snapshot();mutate(p);assert.deepEqual(trace.traceData({presentationSnapshot:p}),{});}
});
