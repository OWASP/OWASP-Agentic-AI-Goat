'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {createBoundAdminChatRouter}=require('../server/routes/secureshop/boundAdminChat');
const scope={launchId:'91000000-0000-4000-8000-000000000001',scenarioId:'91000000-0000-4000-8000-000000000002',generation:1,platformOwnerId:7,platformSessionId:8};
async function dispatch(path,body,{role='admin',launch=scope,run,session,read,assessment,params={},query={}}={}){
 const calls=[];
 const router=createBoundAdminChatRouter({launches:{async resolveCapability(){return launch;}},authenticatePersona(req,res,next){req.ssUser={id:9,role};req.ssPersonaSession={sessionId:'canonical-persona-session'};next();},runtime:{async readMcpDescriptionAssessment(input){calls.push(input);return assessment?.('read',input)||{status:'unconfirmed'};},async assessMcpDescription(input){calls.push(input);return assessment?.('retry',input)||{status:'unconfirmed'};},async createSession(...args){calls.push(args);return session||{id:'conversation'};},async readRequest(...args){calls.push(args);return read?read(...args):{status:'unconfirmed'};},runner:{async run(input){calls.push(input);if(run)return run(input);input.stream.send('done',{stopReason:'end_turn'});}}}});
 const req=Object.assign(new EventEmitter(),{headers:{'x-dvaia-secureshop-launch':'a'.repeat(43)},rawHeaders:[],query,params,body,is:()=>true});
 const res=Object.assign(new EventEmitter(),{statusCode:200,headersSent:false,writableEnded:false,chunks:[],setHeader(){},status(n){this.statusCode=n;return this;},type(){return this;},set(){return this;},json(value){this.body=value;this.writableEnded=true;return this;},write(value){this.headersSent=true;this.chunks.push(value);},end(){this.writableEnded=true;}});
 const handlers=router.stack.find(x=>x.route.path===path).route.stack.map(x=>x.handle);
 async function next(i=0){if(!handlers[i]||res.writableEnded)return;let pending;await handlers[i](req,res,()=>{pending=next(i+1);});await pending;}
 await next();return {req,res,calls};
}

test('description-only routes retain canonical auth, closed selectors, abort and no-source authority',async()=>{
 const ids={sessionId:'93000000-0000-4000-8000-000000000010',requestId:'94000000-0000-4000-8000-000000000010'};
 for(const [path,body,params,method] of [['/agents/admin/chat/description-assessment/:sessionId/:requestId',null,ids,'read'],['/agents/admin/chat/description-assessment',ids,{},'retry']]){
  const observed=await dispatch(path,body,{params,assessment:(kind,input)=>{assert.equal(kind,method);assert.deepEqual(input.scope,scope);assert.equal(input.persona.role,'admin');assert.deepEqual({sessionId:input.sessionId,requestId:input.requestId},ids);assert(input.signal instanceof AbortSignal);return{completed:false,status:'unconfirmed',modelEvaluated:false};}});
  assert.equal(observed.res.statusCode,200);assert.deepEqual(observed.res.body,{completed:false,status:'unconfirmed',modelEvaluated:false});
  for(const options of [{role:'merchant',params},{launch:null,params},{params,query:{packet:'forged'}}]){const denied=await dispatch(path,body,options);assert.ok([400,401,403].includes(denied.res.statusCode));assert.equal(denied.calls.length,0);}
 }
 assert.equal((await dispatch('/agents/admin/chat/description-assessment',{...ids,evidence:{}})).res.statusCode,400);
});
test('description projection accepts canonical internal judgment and exposes only three judgment fields',async()=>{
 const ids={sessionId:'93000000-0000-4000-8000-000000000010',requestId:'94000000-0000-4000-8000-000000000010'},judgment={verdict:'fail',evaluationId:ids.requestId,canRetry:false,packet:'private',criteria:[]};
 const result=await dispatch('/agents/admin/chat/description-assessment',ids,{assessment:()=>({completed:false,judgment,replayed:false})});
 assert.equal(result.res.statusCode,200);assert.deepEqual(result.res.body,{completed:false,replayed:false,judgment:{verdict:'fail',evaluationId:ids.requestId,canRetry:false}});
 for(const change of [j=>{j.verdict='unknown';},j=>{j.evaluationId='bad';},j=>{j.canRetry='yes';}]){const j=structuredClone(judgment);change(j);const bad=await dispatch('/agents/admin/chat/description-assessment',ids,{assessment:()=>({completed:false,judgment:j,replayed:false})});assert.equal(bad.res.statusCode,503);}
});
