'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const express=require('express');
const {createBoundRoleChatRouter}=require('../server/routes/secureshop/boundRoleChat');

test('policy instruction retry is bound to the original saved IDs and authenticated admin authority',async t=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:2,platformSessionId:3};
 const personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const source={sessionId:randomUUID(),requestId:randomUUID()};
 let role='admin',authenticated=true,launchAvailable=true,failure;
 const calls=[];
 const runtime=Object.fromEntries(['createSession','run','readRequest','confirmUserAdministration',
  'confirmPolicy','confirmMcpRegistry','confirmSystemRestart','confirmAcl','runAuditJob',
  'readAuditJob','readAuditOperation','readSystemConfigOperation'].map(name=>[name,async()=>{
  assert.fail(`Protected retry must not call ${name}`);
 }]));
 runtime.retryPolicyInstructionAssessment=async input=>{calls.push(input);if(failure)throw failure;
  return{completed:false,status:'ineligible',modelEvaluated:false}};
 const app=express();app.use(express.json());app.use(createBoundRoleChatRouter({role:'admin',runtime,
  launches:{resolveCapability:async()=>launchAvailable?scope:null},
  authenticatePersona(req,res,next){if(!authenticated)return res.status(401).json({error:'Authentication required'});
   req.ssUser={id:7,role};req.ssPersonaSession=personaSession;next();}}));
 const server=app.listen(0,'127.0.0.1');
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 await new Promise(resolve=>server.once('listening',resolve));
 const url=`http://127.0.0.1:${server.address().port}/agents/admin/assistant/policy/instruction/assessment-retry`;
 const headers={'content-type':'application/json','x-dvaia-secureshop-launch':'a'.repeat(43)};
 const post=(body=source,suffix='',provided=headers)=>fetch(url+suffix,{method:'POST',headers:provided,body:JSON.stringify(body)});
 const response=await post({sessionId:source.sessionId.toUpperCase(),requestId:source.requestId.toUpperCase()});
 assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');
 assert.deepEqual(await response.json(),{completed:false,status:'ineligible',modelEvaluated:false});
 assert.equal(calls.length,1);assert.deepEqual(calls[0].scope,scope);
 assert.deepEqual(calls[0].persona,{id:7,role:'admin'});assert.equal(calls[0].personaSession,personaSession);
 assert.equal(calls[0].sessionId,source.sessionId);assert.equal(calls[0].requestId,source.requestId);
 assert.ok(calls[0].signal instanceof AbortSignal);
 for(const body of [{...source,mode:'vuln'},{...source,persona:{id:99}},
  {...source,completed:true},{...source,requestId:'invalid'},{sessionId:source.sessionId}])
  assert.equal((await post(body)).status,400);
 assert.equal((await post(source,'?mode=vuln')).status,400);
 assert.equal((await post(source,'',{...headers,'content-type':'text/plain'})).status,400);
 role='merchant';assert.equal((await post()).status,403);
 role='admin';authenticated=false;assert.equal((await post()).status,401);
 authenticated=true;launchAvailable=false;assert.equal((await post()).status,401);
 assert.equal(calls.length,1);
 launchAvailable=true;failure=Object.assign(Error('private diagnostic'),{code:'SHOP_AUTH_INVALID'});
 const revoked=await post();assert.equal(revoked.status,401);
 assert.deepEqual(await revoked.json(),{error:'Shop session unavailable'});
 failure=Error('private diagnostic');const unavailable=await post();assert.equal(unavailable.status,503);
 assert.deepEqual(await unavailable.json(),{error:'Role assistant unavailable'});
 assert.equal(calls.length,3);
});
