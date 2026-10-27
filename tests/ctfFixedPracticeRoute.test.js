'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
const {createCtfFixedPracticeRoute}=require('../server/services/ctfFixedPracticeRoute');

async function fixture(t,{generate,capture,revalidate,timeoutMs=1000,drainMs=30}={}){
 const calls=[],lease={};
 const runtime={async practiceCapture(args){calls.push('capture');assert.equal(args.stageId,1);await capture?.(args);return{lease,stage:{stageName:'PRIVATE STAGE',system_prompt:'PRIVATE SYSTEM',success_criteria:'PRIVATE SECRET'}};},async practiceRevalidate(args){calls.push('revalidate');assert.equal(args.lease,lease);await revalidate?.();}};
 const model={async generateResponse(prompt,options){calls.push('model');return generate?generate(prompt,options):{response:'Helpful answer',provider:'ollama',model:'llama3.1:8b',mocked:false};}};
 const handler=createCtfFixedPracticeRoute({runtime,coordinator:createRunCoordinator({family:'CTF',ledger:null}),model,timeoutMs,drainMs});
 const app=express();app.use(express.json());app.use((req,res,next)=>{req.user={id:7};req.identitySession={id:8};next();});app.post('/:stageId',handler);
 const server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});t.after(async()=>{await new Promise(r=>server.close(r));await handler.close();});
 return{calls,close:handler.close,status:handler.status,post:(body={payload:'hello'})=>fetch(`http://127.0.0.1:${server.address().port}/1`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})};
}
test('fixed practice accepts controlled provider metadata with public prompt and reports unscored capability',async t=>{
 const f=await fixture(t,{generate(prompt){assert(!prompt.includes('PRIVATE STAGE'));assert(!prompt.includes('PRIVATE SYSTEM'));assert(!prompt.includes('PRIVATE SECRET'));assert(prompt.includes('User: hello'));return{response:'Helpful answer',provider:'ollama',model:'llama3.1:8b',mocked:false};}});
 const r=await f.post({payload:'hello',sessionToken:'locator'});assert.equal(r.status,200);assert.deepEqual(await r.json(),{response:'Helpful answer',mode:'fixed',practice:true,unscored:true,scoringEligible:false,protectedContextIncluded:false,serverSecretProvided:false});assert.deepEqual(f.calls,['capture','model','revalidate']);
});
test('practice rejects mock provider and never publishes model bytes after stale lease',async t=>{
 const f=await fixture(t,{generate:()=>({response:'PRIVATE SECRET',provider:'mock',model:'mock',mocked:true})});const r=await f.post();assert.equal(r.status,503);assert(!JSON.stringify(await r.json()).includes('PRIVATE SECRET'));assert.deepEqual(f.calls,['capture','model','revalidate']);
 const g=await fixture(t,{generate:()=>({response:'PRIVATE SECRET',provider:'ollama',model:'llama3.1:8b',mocked:false}),revalidate(){throw Object.assign(Error('private'),{statusCode:409});}});const stale=await g.post();assert.equal(stale.status,409);assert(!JSON.stringify(await stale.json()).includes('PRIVATE SECRET'));
});
test('invalid input is rejected before owner admission and close drains abortable provider',async t=>{
 let entered;const ready=new Promise(r=>entered=r);
 const f=await fixture(t,{generate(_prompt,{signal}){entered();return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(signal.reason),{once:true}));}});
 assert.equal((await f.post({payload:' '})).status,400);assert.equal((await f.post({payload:'x',sessionToken:{}})).status,400);assert.deepEqual(f.calls,[]);
 const pending=f.post();await ready;const stopped=await f.close();assert.equal(stopped.drained,true);assert.equal((await pending).status,409);assert.equal((await f.post()).status,503);assert.equal(f.status().active,0);
});

test('stale practice capture denies before provider dispatch without leaking internal errors',async t=>{
 const f=await fixture(t,{capture(){throw Object.assign(Error('PRIVATE CAPTURE DETAIL'),{statusCode:409});},generate(){assert.fail('stale capture must not call the provider');}});
 const r=await f.post();assert.equal(r.status,409);
 assert.deepEqual(await r.json(),{error:'CTF practice is no longer current'});
 assert.deepEqual(f.calls,['capture']);
});

test('provider failure still revalidates authority before publishing an unavailable response',async t=>{
 const f=await fixture(t,{generate(){throw Error('PRIVATE PROVIDER DETAIL');}});
 const r=await f.post();assert.equal(r.status,503);
 assert.deepEqual(await r.json(),{error:'Practice model temporarily unavailable',retryable:true});
 assert.deepEqual(f.calls,['capture','model','revalidate']);
 const g=await fixture(t,{generate(){throw Error('PRIVATE PROVIDER DETAIL');},revalidate(){throw Object.assign(Error('PRIVATE STALE DETAIL'),{statusCode:409});}});
 const stale=await g.post();assert.equal(stale.status,409);
 assert.deepEqual(await stale.json(),{error:'CTF practice is no longer current'});
 assert.deepEqual(g.calls,['capture','model','revalidate']);
});
