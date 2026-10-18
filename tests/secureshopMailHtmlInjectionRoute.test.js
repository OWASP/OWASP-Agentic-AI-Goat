'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const express=require('express');
const {randomUUID}=require('node:crypto');
const {createBoundMailRouter}=require('../server/routes/secureshop/boundMail');

test('HTML-injection assessment POST and saved GET expose only original IDs through authenticated mail route',async()=>{
 const calls=[];
 const evaluationId=randomUUID(),privateJudgment={verdict:'fail',evaluationId,canRetry:true,objectiveId:'ss_mail_agent_html_injection',
  rubricVersion:'secureshop-mail-agent-html-injection-v1',evidenceDigest:'a'.repeat(64),criteria:[{id:'private'}],provider:'ollama',model:'private'};
 let terminal=false;
 const application={readiness(){},read(){},send(){},reply(){},recover(){},
  async assessHtmlInjection(context,value){if(context.persona.id===9)throw Object.assign(Error('foreign saved source'),{code:'MAIL_EVIDENCE_UNAVAILABLE'});calls.push(['post',value]);return {ok:true,completed:false,judgment:privateJudgment,replayed:false};},
  async readHtmlInjectionAssessment(_context,value){calls.push(['get',value]);return terminal
   ?{ok:true,completed:false,judgment:privateJudgment,replayed:true}
   :{ok:true,completed:false,status:'unconfirmed',modelEvaluated:false};}};
 const app=express();app.use(express.json());app.use(createBoundMailRouter({application,authenticatePersona(req,_res,next){
  req.ssLaunch={};req.ssUser={id:req.headers['x-test-peer']==='1'?9:8,role:'merchant'};req.ssPersonaSession={sessionId:randomUUID(),authorityVersion:'1'};next();}}));
 const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
 try{
  const origin=`http://127.0.0.1:${server.address().port}`;
  const value={requestId:randomUUID(),sourceSessionId:randomUUID(),sourceRequestId:randomUUID(),sendOperationId:randomUUID(),messageId:19};
  let response=await fetch(origin+'/email/html-injection-assessment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)});
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{ok:true,completed:false,
   judgment:{verdict:'fail',evaluationId,canRetry:true},replayed:false});
  const path=[value.requestId,value.sourceSessionId,value.sourceRequestId,value.sendOperationId,value.messageId].join('/');
  response=await fetch(origin+'/email/html-injection-assessment/'+path);assert.equal(response.status,200);assert.deepEqual(await response.json(),
   {ok:true,completed:false,status:'unconfirmed',modelEvaluated:false});
  terminal=true;response=await fetch(origin+'/email/html-injection-assessment/'+path);assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{ok:true,completed:false,judgment:{verdict:'fail',evaluationId,canRetry:true},replayed:true});
  assert.deepEqual(calls,[['post',value],['get',value],['get',value]]);
  response=await fetch(origin+'/email/html-injection-assessment',{method:'POST',headers:{'content-type':'application/json','x-test-peer':'1'},body:JSON.stringify(value)});assert.equal(response.status,503);assert.deepEqual(await response.json(),{ok:false,error:'Bound mail unavailable'});assert.equal(calls.length,3);
  privateJudgment.evaluationId='private';response=await fetch(origin+'/email/html-injection-assessment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(value)});
  assert.equal(response.status,503);assert.deepEqual(await response.json(),{ok:false,error:'Bound mail unavailable'});privateJudgment.evaluationId=evaluationId;
  for(const extra of ['evaluationId','scope','evidence','html','verdict','completed']){
   response=await fetch(origin+'/email/html-injection-assessment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...value,[extra]:'forged'})});assert.equal(response.status,400);
  }
  assert.equal((await fetch(origin+'/email/html-injection-assessment/'+path+'?retry=1')).status,400);
  assert.equal(calls.length,4);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
