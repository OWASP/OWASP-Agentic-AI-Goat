'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {createCtfAuthorityAttemptRoute}=require('../server/services/ctfAuthorityAttemptRoute');
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
async function fixture(t){const calls=[],runtime={};for(const name of ['attempt','recoverOperation','recoverDecision','publishDecision','publishBlocked','recoverPredefense','resumePredefense'])runtime[name]=async args=>{calls.push({name,args});if(name==='recoverDecision')return{state:'historical_receipt',private:'never expose',currentCompletion:true};return{status:202,body:{success:false,runId:args.runId??null}};};let admissions=0;const actual=createRunCoordinator({family:'CTF',ledger:null}),coordinator={run(...args){admissions++;return actual.run(...args);}};const handlers=createCtfAuthorityAttemptRoute({runtime,coordinator}),app=express();app.use(express.json());app.use((req,res,next)=>{req.user={id:Number(req.headers['x-owner']||7)};req.identitySession={id:8};next();});app.post('/attempt/:stageId',handlers.attempt);app.post('/operation/:operationId',handlers.recoverOperation);app.post('/recovery/:admissionId',handlers.recoverDecision);app.post('/authorize/:admissionId',handlers.authorizeDecision);app.post('/publish/:decisionId',handlers.publishDecision);app.post('/blocked/:runId',handlers.publishBlocked);app.post('/predefense/:runId',handlers.recoverPredefense);app.post('/predefense/:runId/resume',handlers.resumePredefense);const server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});t.after(()=>new Promise(r=>server.close(r)));return{calls,runtime,get admissions(){return admissions;},post:async(path,body={},owner=7)=>fetch(`http://127.0.0.1:${server.address().port}`+path,{method:'POST',headers:{'content-type':'application/json','x-owner':String(owner)},body:JSON.stringify(body)})};}
test('real coordinator supplies exact run identity; learner bytes retained and authority overrides ignored',async t=>{const f=await fixture(t),payload='  \"attack\"\n🌍  ';const r=await f.post('/attempt/1',{payload,sessionToken:'teaching',runId:'forged',execution:{},diagnostics:{},stageId:'9'});assert.equal(r.status,202);assert.equal(f.admissions,1);const a=f.calls[0].args;assert.equal(a.runId,a.execution.runId);assert.match(a.runId,/^[a-f0-9-]{36}$/);assert.deepEqual(a.request,{runId:a.runId,stageId:'1',payload,registrationToken:'teaching'});assert.equal(a.execution.ownerKey,'["CTF","7"]');assert.equal(a.signal,a.execution.signal);});
test('malformed references and payload reject before admission; limiter remains owner/stage scoped',async t=>{const f=await fixture(t);for(const [path,body] of [['/attempt/0',{payload:'x'}],['/attempt/1',{payload:' '}],['/attempt/1',{payload:'x',sessionToken:{}}],['/operation/bad',{}],['/recovery/bad',{}],['/publish/bad',{}]])assert.equal((await f.post(path,body)).status,400);assert.equal(f.admissions,0);for(let i=0;i<10;i++)assert.equal((await f.post('/attempt/1',{payload:'x'})).status,202);assert.equal((await f.post('/attempt/1',{payload:'x'})).status,429);assert.equal((await f.post('/attempt/2',{payload:'x'})).status,202);assert.equal((await f.post('/attempt/1',{payload:'x'},9)).status,202);});
test('recovery uses exact references outside coordinator and never repeats attempt or exposes historical credit',async t=>{const f=await fixture(t),id='00000000-0000-0000-0000-000000000001';await f.post('/operation/'+id);const r=await f.post('/recovery/'+id,{resumeAuthorization:true,runId:'forged'});assert.deepEqual(await r.json(),{state:'historical_receipt',admissionId:id,currentCompletion:false});await f.post('/publish/'+id);assert.equal(f.admissions,0);assert.deepEqual(f.calls.map(x=>x.name),['recoverOperation','recoverDecision','publishDecision']);assert.equal(f.calls[1].args.resumeAuthorization,undefined);});
test('runtime errors do not retry or expose internal messages',async t=>{const f=await fixture(t);let n=0;f.runtime.attempt=async()=>{n++;throw Object.assign(Error('private database details'),{statusCode:503});};const r=await f.post('/attempt/1',{payload:'x'});assert.equal(r.status,503);assert(!JSON.stringify(await r.json()).includes('private'));assert.equal(n,1);});
test('authenticated stale publication is 409 without recasting foreign or revoked sessions',async t=>{
 const f=await fixture(t),id='00000000-0000-0000-0000-000000000001';
 for(const [code,status,body] of [
  ['PCT01',409,{error:'CTF request is no longer current'}],
  ['42501',403,{error:'CTF service temporarily unavailable'}],
  ['28000',401,{error:'Session is no longer current'}],
 ]){
  f.runtime.publishDecision=async args=>{f.calls.push({name:'publishDecision',args});throw Object.assign(Error('private owner and generation'),{code});};
  const response=await f.post('/publish/'+id);assert.equal(response.status,status);assert.deepEqual(await response.json(),body);
 }
 assert.equal(f.calls.length,3);assert.equal(f.admissions,0);
});
test('explicit authorization recovery carries only bound reference and never creates another model run',async t=>{
 const f=await fixture(t),id='00000000-0000-0000-0000-000000000001';
 f.runtime.recoverDecision=async args=>{f.calls.push({name:'recoverDecision',args});return{state:'authorized_receipt',decisionId:id,accepted:true,private:'do not expose'};};
 const response=await f.post('/authorize/'+id,{runId:'forged',resumeAuthorization:false});
 assert.equal(response.status,200);assert.deepEqual(await response.json(),{state:'authorized_receipt',admissionId:id,decisionId:id,currentCompletion:false});
 assert.equal(f.calls[0].args.resumeAuthorization,true);assert.equal(f.calls[0].args.runId,undefined);assert.equal(f.admissions,0);
});

test('blocked publication uses exact run reference outside coordinator and never admits an attempt',async t=>{
 const f=await fixture(t),runId='00000000-0000-0000-0000-000000000001';
 f.runtime.publishBlocked=async args=>{f.calls.push({name:'publishBlocked',args});return{status:200,body:{success:false,blocked:true,reason:'Current blocked result',attemptNumber:1}};};
 const response=await f.post('/blocked/'+runId,{payload:'replacement',operationId:'forged'});
 assert.equal(response.status,200);assert.equal((await response.json()).blocked,true);
 assert.equal(f.admissions,0);assert.equal(f.calls.length,1);assert.equal(f.calls[0].args.runId,runId);
 assert.equal(f.calls[0].args.payload,undefined);assert.equal(f.calls[0].args.operationId,undefined);
 assert.equal((await f.post('/blocked/not-a-uuid')).status,400);assert.equal(f.calls.length,1);
});

test('predefense read/resume stays outside coordinator, closes POST body and rate limits explicit resumes',async t=>{
 const f=await fixture(t),id='00000000-0000-0000-0000-000000000001';
 assert.equal((await f.post('/predefense/'+id)).status,202);
 assert.equal((await f.post('/predefense/'+id+'/resume',{outcome:'forged'})).status,400);
 for(let n=0;n<10;n++)assert.equal((await f.post('/predefense/'+id+'/resume')).status,202);
 assert.equal((await f.post('/predefense/'+id+'/resume')).status,429);assert.equal(f.admissions,0);
 f.runtime.recoverPredefense=async()=>{throw Object.assign(Error('private reset details'),{code:'42501'});};
 assert.equal((await f.post('/predefense/'+id)).status,403);
});
