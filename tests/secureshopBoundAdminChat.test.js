'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {createBoundAdminChatRouter}=require('../server/routes/secureshop/boundAdminChat');
const scope={launchId:'91000000-0000-4000-8000-000000000001',scenarioId:'91000000-0000-4000-8000-000000000002',generation:1,platformOwnerId:7,platformSessionId:8};
async function dispatch(path,body,{role='admin',launch=scope,run,session,read,assessment,params={},query={}}={}){
 const calls=[];
 const router=createBoundAdminChatRouter({launches:{async resolveCapability(){return launch;}},authenticatePersona(req,res,next){req.ssUser={id:9,role};req.ssPersonaSession={sessionId:'canonical-persona-session'};next();},runtime:{async readMcpImpersonationAssessment(input){calls.push(input);return assessment?.('read',input)||{status:'unconfirmed'};},async retryMcpImpersonationAssessment(input){calls.push(input);return assessment?.('retry',input)||{status:'unconfirmed'};},async createSession(...args){calls.push(args);return session||{id:'conversation'};},async readRequest(...args){calls.push(args);return read?read(...args):{status:'unconfirmed'};},runner:{async run(input){calls.push(input);if(run)return run(input);input.stream.send('done',{stopReason:'end_turn'});}}}});
 const req=Object.assign(new EventEmitter(),{headers:{'x-dvaia-secureshop-launch':'a'.repeat(43)},rawHeaders:[],query,params,body,is:()=>true});
 const res=Object.assign(new EventEmitter(),{statusCode:200,headersSent:false,writableEnded:false,chunks:[],setHeader(){},status(n){this.statusCode=n;return this;},type(){return this;},set(){return this;},json(value){this.body=value;this.writableEnded=true;return this;},write(value){this.headersSent=true;this.chunks.push(value);},end(){this.writableEnded=true;}});
 const handlers=router.stack.find(x=>x.route.path===path).route.stack.map(x=>x.handle);
 async function next(i=0){if(!handlers[i]||res.writableEnded)return;let pending;await handlers[i](req,res,()=>{pending=next(i+1);});await pending;}
 await next();return {req,res,calls};
}
test('session binds canonical admin instead of supplied legacy user ID',async()=>{
 const {res,calls}=await dispatch('/agents/admin/session',{userId:999});assert.equal(res.statusCode,200);assert.equal(calls[0][0].platformOwnerId,7);assert.deepEqual(calls[0][1],{id:9,role:'admin'});assert.equal(calls[0][2].sessionId,'canonical-persona-session');
});
test('missing launch and nonadmin persona never reach runtime',async()=>{
 for(const options of [{launch:null},{role:'customer'}]){const {res,calls}=await dispatch('/agents/admin/session',{},options);assert.ok([401,403].includes(res.statusCode));assert.equal(calls.length,0);}
});
test('chat passes canonical context and real disconnect abort to runner',async()=>{
 const {res,calls,req}=await dispatch('/agents/admin/chat',{sessionId:'conversation',message:'hello'},{run:async input=>{assert.equal(input.scope.platformSessionId,8);assert.equal(input.personaSession.sessionId,'canonical-persona-session');input.stream.send('token',{text:'hello'});}});
 assert.match(res.chunks.join(''),/event: token/);assert.equal(calls[0].persona.role,'admin');assert.equal(req.listenerCount('aborted'),0);assert.equal(res.listenerCount('close'),0);
});
test('malformed chat never invokes runner and stale conversation is sanitized',async()=>{
 const invalid=await dispatch('/agents/admin/chat',{sessionId:'conversation',message:'hello',scope:{}});assert.equal(invalid.res.statusCode,400);assert.equal(invalid.calls.length,0);
 const stale=await dispatch('/agents/admin/chat',{sessionId:'foreign',message:'hello'},{run:async()=>{throw Object.assign(Error('private'),{code:'CONVERSATION_UNAVAILABLE'});}});assert.equal(stale.res.statusCode,401);assert.doesNotMatch(stale.res.chunks.join(''),/private/);assert.match(stale.res.chunks.join(''),/event: done/);
});
test('client request UUID reaches the sole POST unchanged while missing UUID retains legacy generation',async()=>{
 const requestId='92000000-0000-4000-8000-000000000001';
 const current=await dispatch('/agents/admin/chat',{sessionId:'conversation',message:'hello',requestId:requestId.toUpperCase()});
 assert.equal(current.calls[0].requestId,requestId);
 assert.equal(current.calls[0].localToolAuthority.requestId,requestId);
 const legacy=await dispatch('/agents/admin/chat',{sessionId:'conversation',message:'hello'});
 assert.match(legacy.calls[0].requestId,/^[a-f0-9-]{36}$/);
 for(const value of [null,[],{},'bad']){
  const bad=await dispatch('/agents/admin/chat',{sessionId:'conversation',message:'hello',requestId:value});
  assert.equal(bad.res.statusCode,400);assert.equal(bad.calls.length,0);
 }
});
test('protected exact saved GET uses current authenticated context and never invokes runner',async()=>{
 const sessionId='93000000-0000-4000-8000-000000000001',requestId='94000000-0000-4000-8000-000000000001';
 const path='/agents/admin/chat/requests/:sessionId/:requestId',params={sessionId,requestId};
 const dto={sessionId,requestId,status:'unconfirmed'};
 const saved=await dispatch(path,null,{params,read:async(...args)=>{
  assert.deepEqual(args,[scope,{id:9,role:'admin'},{sessionId:'canonical-persona-session'},sessionId,requestId]);return dto;
 }});
 assert.deepEqual(saved.res.body,dto);assert.equal(saved.calls.length,1);assert.deepEqual(saved.res.chunks,[]);
 for(const options of [{params,role:'merchant'},{params,launch:null},{params:{...params,requestId:'bad'}},{params,query:{message:'secret'}}]){
  const denied=await dispatch(path,null,options);assert.ok([400,401,403].includes(denied.res.statusCode));assert.equal(denied.calls.length,0);
 }
 const failure=await dispatch(path,null,{params,read:async()=>{throw Object.assign(Error('private'),{code:'SHOP_AUTH_INVALID'});}});
 assert.equal(failure.res.statusCode,401);assert.doesNotMatch(JSON.stringify(failure.res.body),/private/);
});

test('V43 assessment endpoints bind authenticated IDs only and reject source injection',async()=>{
 const ids={sessionId:'93000000-0000-4000-8000-000000000010',requestId:'94000000-0000-4000-8000-000000000010'};
 for(const [path,body,params,method] of [
  ['/agents/admin/chat/assessment/:sessionId/:requestId',null,ids,'read'],
  ['/agents/admin/chat/assessment-retry',ids,{},'retry']]){
  const observed=await dispatch(path,body,{params,assessment:(kind,input)=>{
   assert.equal(kind,method);assert.deepEqual(input.scope,scope);assert.deepEqual(input.persona,{id:9,role:'admin'});
   assert.equal(input.personaSession.sessionId,'canonical-persona-session');assert.equal(input.sessionId,ids.sessionId);
   assert.equal(input.requestId,ids.requestId);assert(input.signal instanceof AbortSignal);return {completed:false,status:'unconfirmed',modelEvaluated:false};
  }});
  assert.equal(observed.res.statusCode,200);assert.equal(observed.calls.length,1);assert.equal(observed.req.listenerCount('aborted'),0);
  for(const options of [{role:'merchant',params},{launch:null,params},{params,query:{packet:'forged'}}]){
   const denied=await dispatch(path,body,options);assert.ok([400,401,403].includes(denied.res.statusCode));assert.equal(denied.calls.length,0);
  }
 }
 const bad=await dispatch('/agents/admin/chat/assessment-retry',{...ids,evidence:{}});assert.equal(bad.res.statusCode,400);assert.equal(bad.calls.length,0);
});
