'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { EventEmitter } = require('node:events');
const events = () => { const e=new EventEmitter(); return { once:e.once.bind(e),
  removeListener:e.removeListener.bind(e),emit:e.emit.bind(e),listenerCount:e.listenerCount.bind(e) }; };
const { createBoundSearchEchoAssessmentRouter, publicSearchEchoAssessment, sourceIds } =
  require('../server/routes/secureshop/boundSearchEchoAssessment');
const ids = { sessionId: randomUUID(), requestId: randomUUID(), step: 2 };
const response = () => ({ ...events(),statusCode: 0, headers: {}, status(n) { this.statusCode=n; return this; },
  set(k,v) { this.headers[k]=v; return this; }, setHeader(k,v) { this.headers[k]=v; },
  json(body) { this.body=body; return this; } });
function fixture(assessment) {
  const calls=[];
  const service=assessment || Object.fromEntries(['readOutcome','runAttempt'].map(method=>[method,async input=>{
    calls.push({method,input});return {completed:false,status:'unconfirmed',modelEvaluated:false};
  }]));
  const router=createBoundSearchEchoAssessmentRouter({launches:{resolveCapability:async()=>({})},
    authenticatePersona:(_req,_res,next)=>next(),assessment:service});
  const route=method=>router.stack.find(layer=>layer.route?.methods[method]).route.stack;
  const req={...events(),body:ids,params:{...ids,step:'2'},query:{},is:()=>true,ssLaunch:{launchId:randomUUID()},
    ssUser:{id:17,role:'customer'},ssPersonaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
  return {calls,req,post:route('post'),get:route('get')};
}
test('search assessment selects exact protected source IDs and keeps GET read only',async()=>{
  const f=fixture(),res=response();await f.post.at(-1).handle(f.req,res);
  assert.equal(res.statusCode,200);assert.equal(f.calls[0].method,'runAttempt');
  assert.deepEqual(f.calls[0].input,{scope:f.req.ssLaunch,persona:{id:17,role:'customer'},
    personaSession:f.req.ssPersonaSession,...ids,signal:f.calls[0].input.signal});
  assert.equal(f.calls[0].input.signal.aborted,false);
  await f.get.at(-1).handle({...f.req,body:undefined},res);
  assert.equal(f.calls[1].method,'readOutcome');assert.equal(res.headers['Cache-Control'],'no-store');
  for(const body of [{...ids,html:'untrusted'},{...ids,step:'2'},{...ids,step:0},{...ids,step:5}]){
    await f.post.at(-1).handle({...f.req,body},res);assert.equal(res.statusCode,400);
  }
  await f.get.at(-1).handle({...f.req,body:undefined,query:{mode:'vuln'}},res);assert.equal(res.statusCode,400);
  await f.get.at(-1).handle(f.req,res);assert.equal(res.statusCode,400);
  assert.equal(f.calls.length,2);
  for(const step of ['02','2.0','-1','5','2x'])assert.equal(sourceIds({...ids,step},true),null);
});
test('disconnect aborts ongoing assessment and removes request listeners',async()=>{
  let entered,release,signal;
  const started=new Promise(resolve=>{entered=resolve;});
  const work=new Promise(resolve=>{release=resolve;});
  const f=fixture({readOutcome:async()=>{},runAttempt:async input=>{
    signal=input.signal;entered();await work;return {completed:false,status:'unconfirmed',modelEvaluated:false};
  }}),res=response();
  const pending=f.post.at(-1).handle(f.req,res);await started;
  res.emit('close');assert.equal(signal.aborted,true);release();await pending;
  assert.equal(res.body,undefined);assert.equal(f.req.listenerCount('aborted'),0);
  assert.equal(res.listenerCount('close'),0);
});
test('real Express GET parameters preserve the exact read-only source contract',async()=>{
  const express=require('express'),app=express(),f=fixture();
  let prototype;
  app.get('/sessions/:sessionId/requests/:requestId/search-echo/:step/assessment',(req,res)=>{
    prototype=Object.getPrototypeOf(req.params);
    Object.assign(req,{ssLaunch:f.req.ssLaunch,ssUser:f.req.ssUser,ssPersonaSession:f.req.ssPersonaSession});
    return f.get.at(-1).handle(req,res);
  });
  const server=await new Promise(resolve=>{const server=app.listen(0,'127.0.0.1',()=>resolve(server));});
  try{
    const url=`http://127.0.0.1:${server.address().port}/sessions/${ids.sessionId}/requests/${ids.requestId}/search-echo/2/assessment`;
    const result=await fetch(url);
    assert.equal(prototype,null);assert.equal(result.status,200);
    assert.deepEqual(await result.json(),{completed:false,status:'unconfirmed',modelEvaluated:false});
    assert.equal(f.calls.length,1);assert.equal(f.calls[0].method,'readOutcome');
    assert.equal(f.calls[0].input.sessionId,ids.sessionId);assert.equal(f.calls[0].input.step,2);
    assert.equal((await fetch(url+'?step=1')).status,400);assert.equal(f.calls.length,1);
    const params=Object.assign(Object.create(null),{...ids,step:'2'});
    assert.deepEqual(sourceIds(params,true),ids);assert.equal(sourceIds(params),null);
    params.extra='no';assert.equal(sourceIds(params,true),null);
  }finally{await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}
});
test('customer guard denies other roles and duplicate launch headers do not select assessment',()=>{
  const f=fixture(),res=response();let next;
  f.post[0].handle({rawHeaders:['X-DVAIA-SecureShop-Launch','a','X-DVAIA-SecureShop-Launch','b']},res,x=>{next=x;});
  assert.equal(next,'route');
  for(const role of ['admin','merchant',undefined]){
    f.post.at(-2).handle({...f.req,ssUser:{id:17,role}},res,()=>assert.fail('unauthorized continuation'));
    assert.equal(res.statusCode,403);
  }
});
test('search assessment hides private evidence and never accepts contradictory completion',async()=>{
  const judgment={evaluationId:randomUUID(),verdict:'pass',canRetry:false,packet:'private'};
  assert.deepEqual(publicSearchEchoAssessment({completed:true,judgment,replayed:false}),
    {completed:true,judgment:{evaluationId:judgment.evaluationId,verdict:'pass',canRetry:false},replayed:false});
  assert.throws(()=>publicSearchEchoAssessment({completed:true,judgment:{...judgment,verdict:'fail'},replayed:false}));
  for(const status of ['disabled','pending']) assert.throws(()=>publicSearchEchoAssessment({completed:false,status,modelEvaluated:false}));
  const f=fixture({runAttempt:async()=>{throw Error('private SQL');},readOutcome:async()=>{
    throw Object.assign(Error('private owner'),{code:'CONVERSATION_UNAVAILABLE'});
  }}),res=response();
  await f.post.at(-1).handle(f.req,res);assert.equal(res.statusCode,503);
  assert.deepEqual(res.body,{error:'Search assessment unavailable'});
  await f.get.at(-1).handle({...f.req,body:undefined},res);assert.equal(res.statusCode,401);
  assert.deepEqual(res.body,{error:'Shop session unavailable'});
});
