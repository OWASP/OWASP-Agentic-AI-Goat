'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const {createBoundV01AuditLessonRouter}=require('../server/routes/secureshop/boundV01AuditLesson');
const id='30000000-0000-4000-8000-000000000091';

function fixture(work) {
  const calls=[];
  const runtime=Object.fromEntries(['createSession','issueToken','readRequest','run']
    .map(name=>[name,async (...args)=>{calls.push({name,args});return work(name,args);} ]));
  const assessment=Object.fromEntries(['runAttempt','readOutcome']
    .map(name=>[name,async (...args)=>{calls.push({name,args});return work(name,args);} ]));
  const router=createBoundV01AuditLessonRouter({
    launches:{resolveCapability(){}},authenticatePersona(_req,_res,next){next();},runtime,assessment});
  const handler=(method,tail)=>{
    const found=router.stack.find(row=>row.route?.path===`/agents/customer/checkout-audit${tail}`
      &&row.route.methods[method]);
    assert.ok(found);return found.route.stack.at(-1).handle;
  };
  return {calls,handler};
}
function request(body={},params={}){
  return Object.assign(new EventEmitter(),{aborted:false,body,params,query:{},
    ssLaunch:{},boundPersona:{id:12,role:'customer'},ssPersonaSession:{sessionId:id,authorityVersion:'1'},
    is:()=>true});
}
function response(){
  const result=Object.assign(new EventEmitter(),{writableEnded:false,destroyed:false,
    writes:[],set(){return this;},status(code){this.code=code;return this;},
    json(value){this.writes.push(value);this.writableEnded=true;return this;},
    write(value){this.writes.push(value);return true;},
    end(){this.writes.push('end');this.writableEnded=true;}});
  return result;
}
const paths=[['post','/session',{}],['post','/practice-token',{checkoutOperationId:id}],
  ['get',`/operations/:sessionId/:requestId`,null,{sessionId:id,requestId:id}],
  ['post','/assess',{sessionId:id,requestId:id}],
  ['get','/assess/:sessionId/:requestId',null,{sessionId:id,requestId:id}],
  ['post','/chat',{sessionId:id,requestId:id,checkoutOperationId:id,
    teachingToken:'practice',message:'Read this checkout audit.'}]];
for(const [method,route,body,params] of paths){
  for(const kind of ['pre-aborted','pre-destroyed'])test(`${route} ${kind} performs no work`,async()=>{
    const f=fixture(()=>assert.fail('runtime called'));
    const req=request(body||{},params||{}),res=response();
    if(kind==='pre-aborted')req.aborted=true;else res.destroyed=true;
    await f.handler(method,route)(req,res);
    assert.equal(f.calls.length,0);assert.deepEqual(res.writes,[]);
    assert.equal(req.listenerCount('aborted'),0);assert.equal(res.listenerCount('close'),0);
  });
}
for(const [method,route,body,params] of paths)test(`${route} late abort suppresses output`,async()=>{
  let finish;const pending=new Promise(resolve=>{finish=resolve;});
  const f=fixture(()=>pending),req=request(body||{},params||{}),res=response();
  const running=f.handler(method,route)(req,res);
  assert.equal(f.calls.length,1);
  req.emit('aborted');finish({id,sessionId:id,requestId:id});
  await running;
  assert.deepEqual(res.writes,[]);
  assert.equal(req.listenerCount('aborted'),0);assert.equal(res.listenerCount('close'),0);
});
test('practice token projection rejects UTF-8 bytes beyond the request bound',async()=>{
  const f=fixture(()=>({orderId:1,operationId:id,token:'😀'.repeat(1500),
    modeCapability:{version:1,featureId:'checkout_audit_jwt',
      policyVersion:'owned-checkout-admin-audit-practice-jwt-v1',effectiveMode:'vuln',
      scope:{kind:'launch_feature',id:'checkout_audit_jwt'}}}));
  const res=response();
  await f.handler('post','/practice-token')(request({checkoutOperationId:id}),res);
  assert.equal(f.calls.length,1);
  assert.deepEqual(res.writes,[{error:'Checkout audit lesson unavailable'}]);
});
test('assessment routes publish only canonical bounded saved outcomes',async()=>{
  const evaluationId='30000000-0000-4000-8000-000000000092';
  const f=fixture(name=>name==='runAttempt'
    ? {completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false,
      privateEvidence:'never publish'},replayed:false}
    : {completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:true});
  const post=response(),get=response();
  await f.handler('post','/assess')(request({sessionId:id,requestId:id}),post);
  await f.handler('get','/assess/:sessionId/:requestId')(
    request({}, {sessionId:id,requestId:id}),get);
  assert.deepEqual(post.writes,[{completed:true,judgment:{verdict:'pass',
    evaluationId,canRetry:false},replayed:false}]);
  assert.deepEqual(get.writes,[{completed:true,judgment:{verdict:'pass',
    evaluationId,canRetry:false},replayed:true}]);
  assert.deepEqual(f.calls.map(x=>x.name),['runAttempt','readOutcome']);
});
test('assessment routes retain pending and deny inconsistent completion',async()=>{
  const evaluationId='30000000-0000-4000-8000-000000000092';
  const pending=fixture(()=>({completed:false,status:'unconfirmed',modelEvaluated:false}));
  const res=response();
  await pending.handler('get','/assess/:sessionId/:requestId')(
    request({}, {sessionId:id,requestId:id}),res);
  assert.deepEqual(res.writes,[{completed:false,status:'unconfirmed',modelEvaluated:false}]);
  const inconsistent=fixture(()=>({completed:true,judgment:{verdict:'fail',
    evaluationId,canRetry:false},replayed:true}));
  const denied=response();
  await inconsistent.handler('post','/assess')(request({sessionId:id,requestId:id}),denied);
  assert.deepEqual(denied.writes,[{error:'Checkout audit lesson unavailable'}]);
});
