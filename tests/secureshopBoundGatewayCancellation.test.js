'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {EventEmitter}=require('node:events');
const source=fs.readFileSync(path.join(__dirname,'../server/routes/secureshop/boundGateway.js'),'utf8');
const helper=source.slice(source.indexOf('const PRODUCT_REQUEST_ABORTED'),source.indexOf('\nfunction productNotFound'));
const routes=source.slice(source.indexOf('  const ownedAuditSearch ='),source.indexOf("  for (const [url,method]"));
function fixture(operation){
 const handlers=new Map();
 const context={AbortController,DOMException,Buffer,SESSION_UUID:/^[a-f0-9-]{36}$/,
  plain:v=>v!==null&&typeof v==='object'&&!Array.isArray(v),handle:f=>f,
  persona:()=>[],context:()=>({}),readBearer:()=>null,
  auditSearch:{search:operation,runAgent:operation},auditTimingReady:false,
  router:{post(url,...chain){handlers.set(url,chain.at(-1));}}};
 vm.createContext(context);vm.runInContext(helper+'\n'+routes,context);
 return handlers;
}
const id='30000000-0000-4000-8000-000000000091';
for(const route of ['/admin/audit/search','/admin/audit/search-by-user','/admin/audit/agent-search']){
 for(const phase of ['pre-aborted','late-success','late-rejection','success'])test(`${route} ${phase} response lifecycle`,async()=>{
  const sent=[];let calls=0,finish,fail,signal;
  const deferred=new Promise((resolve,reject)=>{finish=resolve;fail=reject;});
  const handlers=fixture(input=>{calls++;signal=input.signal;return deferred;});
  const body=route.endsWith('agent-search')?{message:'owned',requestId:id,sessionId:id}:{username:'owned',operationId:id};
  const req=Object.assign(new EventEmitter(),{aborted:phase==='pre-aborted',body});
  const res=Object.assign(new EventEmitter(),{writableEnded:false,destroyed:false,json(value){sent.push(value);}});
  const running=handlers.get(route)(req,res);
  const result={owned:true};
  if(phase==='late-success'||phase==='late-rejection')req.emit('aborted');
  if(phase==='late-rejection')fail(Error('controlled late failure'));else finish(result);
  await running;
  assert.equal(calls,phase==='pre-aborted'?0:1);
  assert.deepEqual(sent,phase==='success'?[result]:[]);
  if(phase.startsWith('late'))assert.equal(signal.aborted,true);
  assert.equal(req.listenerCount('aborted'),0);assert.equal(res.listenerCount('close'),0);
 });
}
