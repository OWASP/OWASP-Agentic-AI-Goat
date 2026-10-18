'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
test('conversation HTTP adapter scopes requests, replays responses, rejects authority overrides and redacts failures',async()=>{
 const app=require('express')();
 // Test principal injection only; actual JWT/session middleware is qualified separately.
 app.use((req,_res,next)=>{if(req.headers['x-test-user'])req.user={id:Number(req.headers['x-test-user'])};next();});
 const coordinator=require('../server/agent-runtime/runCoordinator').createRunCoordinator({family:'MCP',ledger:{begin:async()=>({durableGeneration:'0'})}});
 const records=new Map();let effects=0,clearOwner,unavailable=false;
 const conversations={list:async userId=>[{userText:`owner ${userId}`,assistantText:'saved answer'}],clearBeforeCurrentGeneration:async userId=>{
  clearOwner=userId;if(unavailable)throw Object.assign(Error('secret SQL password'),{code:'42501'});return {removedTurns:1};
 }};
 const requests={admit:async args=>{
  const key=`${args.userId}:${args.requestId}`,prior=records.get(key);
  if(prior){if(prior.message!==args.userText)throw Object.assign(Error('conflict'),{code:'IDEMPOTENCY_CONFLICT'});return {state:'replay',response:prior.response};}
  records.set(key,{message:args.userText});return {state:'admitted'};
 },complete:async args=>{records.get(`${args.userId}:${args.requestId}`).response=args.response;}};
 const service=require('../server/services/mcp/conversationService').createMcpConversationService({requests,conversations,coordinator});
 app.use(require('../server/routes/mcpConversationRoutes').createMcpConversationRouter({coordinator,service,conversations,admit:async()=>({}),perform:async({userId,message,execution})=>{
  assert.equal(require('../server/agent-runtime/ownerWorkflowRoutes').getOwnerExecution(),execution);effects++;return {response:message,userId};
 }}));
 const server=await new Promise(resolve=>{const server=app.listen(0,'127.0.0.1',()=>resolve(server));});
 try{
  const base=`http://127.0.0.1:${server.address().port}`;
  const post=(route,body,user='7')=>fetch(base+route,{method:'POST',headers:{'content-type':'application/json',...(user?{'x-test-user':user}:{})},body:JSON.stringify(body)});
  const body={requestId:randomUUID(),message:'read training data'};
  assert.equal((await post('/chat',body,null)).status,401);
  assert.equal((await post('/chat',{...body,userId:8})).status,400);
  assert.equal((await post('/chat',{...body,history:[]})).status,400);
  assert.equal((await post('/chat',{...body,requestId:'invalid'})).status,400);
  assert.equal((await post('/chat',{...body,requestId:[body.requestId]})).status,400);
  const first=await post('/chat',body);assert.equal(first.status,200);assert.equal(first.headers.get('cache-control'),'no-store');
  assert.deepEqual(await first.json(),{response:body.message,userId:7});
  assert.deepEqual(await (await post('/chat',body)).json(),{response:body.message,userId:7});assert.equal(effects,1);
  assert.equal((await post('/chat',{...body,message:'changed'})).status,409);
  const history=await fetch(base+'/history', {headers:{'x-test-user':'8'}});
  assert.equal((await history.json()).turns[0].userText,'owner 8');
  assert.equal((await fetch(base+'/history?userId=7',{headers:{'x-test-user':'8'}})).status,400);
  assert.equal((await post('/clear',{})).status,200);assert.equal(clearOwner,7);
  unavailable=true;const failed=await post('/clear',{});assert.equal(failed.status,503);assert.equal((await failed.text()).includes('secret'),false);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
