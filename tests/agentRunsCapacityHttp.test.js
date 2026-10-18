'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {createAgentRunsRouter}=require('../server/routes/agentRuns');
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
const {createObjectiveRegradeService}=require('../server/services/objectiveRegradeService');
const evaluationId='11111111-1111-4111-8111-111111111111';
test('mounted grading retry maps real coordinator capacity to503 without entering retry or changing auth/conflicts',async()=>{
 const coordinator=createRunCoordinator({family:'GradeCapacity',ledger:null});let release,entered;
 const gate=new Promise(r=>release=r),ready=new Promise(r=>entered=r);const work=[];
 work.push(coordinator.run('7',{timeoutMs:5000},async()=>{entered();await gate;}));await ready;
 for(let i=0;i<15;i++)work.push(coordinator.run('7',{timeoutMs:5000},()=>{}));
 let reads=0,retries=0,calls=0,override=null;
 const regrade=createObjectiveRegradeService({receipts:{getRecovery:async()=>{reads++;return{owner_key:JSON.stringify(['GradeCapacity','7'])};}},completion:{retry:async()=>{retries++;}},coordinatorFactory:()=>coordinator});
 const app=express();app.use(express.json());app.use(createAgentRunsRouter({repository:{},receiptAdapters:{},authenticateToken(req,res,next){if(req.headers.authorization!=='Bearer owned')return res.status(401).json({error:'Authentication required'});req.user={id:7};next();},regrade:async input=>{calls++;if(override)throw override;return regrade(input);}}));
 const server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});
 const post=async(body={},authorized=true)=>{const response=await fetch(`http://127.0.0.1:${server.address().port}/judgments/${evaluationId}/retry`,{method:'POST',headers:{'Content-Type':'application/json',...(authorized?{authorization:'Bearer owned'}:{})},body:JSON.stringify(body)});return{status:response.status,body:await response.json()};};
 try{
  const result=await post();assert.equal(result.status,503);assert.deepEqual(result.body,{code:'GRAPH_RUN_CAPACITY_EXCEEDED',error:'Grading retry unavailable',canRetry:false});assert.equal(reads,1);assert.equal(retries,0);assert.equal(calls,1);
  assert.equal((await post({},false)).status,401);assert.equal((await post({verdict:'pass'})).status,400);assert.equal(calls,1);
  for(const [code,status] of [['NOT_FOUND',404],['GRADE_STORE_NOT_READY',503],['RETRY_NOT_ALLOWED',409],['OTHER',409]]){override=Object.assign(Error('private diagnostic'),{code});const r=await post();assert.equal(r.status,status);assert.equal(r.body.error,'Grading retry unavailable');assert.equal(r.body.canRetry,false);}
  override=Object.assign(Error('cancelled'),{name:'AbortError'});assert.equal((await post()).status,409);assert.equal(retries,0);
 }finally{release();await Promise.allSettled(work);await new Promise(r=>server.close(r));}
});
