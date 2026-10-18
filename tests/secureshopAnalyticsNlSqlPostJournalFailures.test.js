'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createAnalyticsPostJournalAssessment:create}=require('../server/services/secureshopAnalyticsPostJournalAssessment');
async function setup({fault,index=1,error=Error('optional failure'),check=async()=>{}}={}){
 const calls=[[],[]],execution={check},failure=error;
 const build=i=>async()=>{calls[i].push('factory');if(index===i&&fault==='factory')throw failure;
  return {begin:async()=>{calls[i].push('begin');if(index===i&&fault==='begin')throw failure;return {index:i};},
   observe:async()=>{calls[i].push('observe');if(index===i&&fault==='observe')throw failure;},
   finalize:async(_e,p)=>{calls[i].push(p.postJournalError?'unavailable':'judge');if(index===i&&fault==='finalize')throw failure;return {status:p.postJournalError?'unavailable':'pass'};}};
 };
 const group=create({loopFactory:async()=>null,disclosureFactory:build(0),additionalFactories:[build(1)],privateEvidence:{},readCommittedProjection:async()=>({ok:true})});
 const a=await group.factory({},{}),attempt=await a.begin(execution);await a.observe(execution,{attempt});await a.finalize(execution,{attempt});
 return {group,execution,calls,error};
}
for(const fault of ['factory','begin','observe','finalize'])for(const index of [0,1])test(`V51 post-journal isolates ordinary ${fault} failure for objective ${index}`,async()=>{
 const f=await setup({fault,index});const result=await f.group.afterCommit({execution:f.execution,result:{}});
 assert.deepEqual(result[1-index],{status:'pass'});assert.equal(f.calls[1-index].filter(x=>x==='judge').length,1);
 assert.equal(f.calls[index].includes('judge'),fault==='finalize');
 if(fault==='observe')assert.deepEqual(result[index],{status:'unavailable'});
 else assert.equal(result[index].assessmentStatus,'unavailable');
 assert.strictEqual(f.group.readFailures()[0].error,f.error);assert.equal(f.group.readFailures()[0].phase,fault);
 await f.group.afterCommit({execution:f.execution,result:{}});assert.equal(f.calls[1-index].filter(x=>x==='judge').length,1);
});
test('V51 wrong execution callback does not consume the valid committed assessment',async()=>{
 const f=await setup();await assert.rejects(f.group.afterCommit({execution:{check:async()=>{}},result:{}}),/execution mismatch/);
 await f.group.afterCommit({execution:f.execution,result:{}});assert.deepEqual(f.calls.map(c=>c.filter(x=>x==='judge').length),[1,1]);
});
test('V51 concurrent committed callbacks settle each admitted finalizer exactly once',async()=>{
 const f=await setup();const results=await Promise.all([f.group.afterCommit({execution:f.execution,result:{}}),f.group.afterCommit({execution:f.execution,result:{}})]);
 assert.deepEqual(results[0],results[1]);assert.deepEqual(f.calls.map(c=>c.filter(x=>x==='judge').length),[1,1]);
});
test('V51 authority/cancellation callback errors abort all subsequent assessments',async()=>{
 for(const error of [Object.assign(Error('stale'),{code:'STALE_LAUNCH'}),Object.assign(Error('aborted'),{name:'AbortError'}),Object.assign(Error('boundary'),{executionBoundary:true})]){
  const f=await setup({fault:'finalize',index:0,error});await assert.rejects(f.group.afterCommit({execution:f.execution,result:{}}),e=>e===error);
  assert.equal(f.calls[1].includes('judge'),false);assert.equal(f.group.readFailures().length,0);
  await assert.rejects(f.group.afterCommit({execution:f.execution,result:{}}),e=>e===error);assert.equal(f.calls[0].filter(x=>x==='judge').length,1);
 }
});
test('V51 current owner/reset fence failures are never optional even without an error code',async()=>{
 let current=true;const error=Error('owner reset');const f=await setup({check:async()=>{if(!current)throw error;}});current=false;
 await assert.rejects(f.group.afterCommit({execution:f.execution,result:{}}),e=>e===error);
 assert.deepEqual(f.calls.map(c=>c.filter(x=>x==='judge').length),[0,0]);assert.equal(f.group.readFailures().length,0);
});
test('V51 factory authority failure cannot be swallowed before the graph starts',async()=>{
 const error=Object.assign(Error('persona retired'),{code:'SHOP_AUTH_INVALID'});
 await assert.rejects(setup({fault:'factory',error}),e=>e===error);
});
test('V51 coded infrastructure failures remain isolated for both objectives',async()=>{
 for(const code of ['42P01','ECONNRESET','GRADE_STORE_NOT_READY'])for(const fault of ['factory','begin','observe','finalize'])for(const index of [0,1]){
  const error=Object.assign(Error('infrastructure unavailable'),{code}),f=await setup({fault,index,error});
  const result=await f.group.afterCommit({execution:f.execution,result:{}});assert.deepEqual(result[1-index],{status:'pass'});
  assert.strictEqual(f.group.readFailures()[0].error,error);assert.equal(f.calls[1-index].filter(x=>x==='judge').length,1);
 }
});
test('actual persona capture prepare and bind rejections retain authority provenance',async()=>{
 const {createAssessmentPersonaCapture}=require('../server/services/secureshopAssessmentPersonaCapture');
 const capture=createAssessmentPersonaCapture({capture:async()=>{}});
 const {randomUUID}=require('node:crypto'),binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2,shopUserId:3,role:'merchant'};
 for(const invoke of [()=>capture.prepare({},{}),()=>capture.prepare(binding,{binding:{...binding,personaId:99,sessionId:randomUUID(),authorityVersion:'1'},assertRemoteAdmission:async()=>{}}),()=>capture.prepare(binding,{binding:{...binding,generation:0,personaId:3,sessionId:randomUUID(),authorityVersion:'1'},assertRemoteAdmission:async()=>{}}),()=>capture.bind({},undefined)]){
  let original;try{invoke();}catch(error){original=error;}
  assert.ok(original instanceof TypeError);assert.equal(original.executionBoundary,true);assert.equal(original.code,undefined);
  await assert.rejects(setup({fault:'factory',error:original}),error=>error===original);
  const f=await setup({fault:'finalize',index:0,error:original});
  await assert.rejects(f.group.afterCommit({execution:f.execution,result:{}}),error=>error===original);assert.equal(f.calls[1].includes('judge'),false);
 }
});
