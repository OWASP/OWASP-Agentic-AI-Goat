'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {randomUUID}=require('node:crypto');
const {createBoundRoleChatRouter}=require('../server/routes/secureshop/boundRoleChat');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:4,platformSessionId:5};
const session={sessionId:randomUUID(),authorityVersion:'2'};
const ids={sessionId:randomUUID(),requestId:randomUUID()};
const headers={'content-type':'application/json','x-owasp-ai-goat-secureshop-launch':'a'.repeat(43),authorization:'Bearer controlled'};
async function fixture(t){
 const calls=[];let output={completed:false,status:'unconfirmed',modelEvaluated:false};
 const runtime=Object.fromEntries(['createSession','run','readRequest','confirmInventory','confirmPricing','confirmListing','readListing',
  'confirmListingCreate','readListingCreate','confirmMail','readMailOperation'].map(k=>[k,async()=>{throw Error('source replay forbidden');}]));
 const app=express();app.use(express.json());
 app.use('/api/secureshop',createBoundRoleChatRouter({role:'merchant',runtime,
  launches:{resolveCapability:async()=>scope},authenticatePersona(req,res,next){req.ssUser={id:7,role:'merchant'};req.ssPersonaSession=session;next();},
  mailAgentReadAssessment:{async runAttempt(input){calls.push(['post',input]);return output;},async readOutcome(input){calls.push(['get',input]);return output;}}}));
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 t.after(()=>new Promise(r=>{server.closeAllConnections();server.close(r);}));
 const base=`http://127.0.0.1:${server.address().port}/api/secureshop/agents/merchant/assistant/mail-read`;
 return {calls,setOutput:value=>{output=value;},post:(body=ids)=>fetch(base+'/assess',{method:'POST',headers,body:JSON.stringify(body)}),
  get:()=>fetch(`${base}/assessment/${ids.sessionId}/${ids.requestId}`,{headers})};
}
test('V11 mounted POST and saved GET admit exact IDs and never invoke source runtime',async t=>{
 const f=await fixture(t);for(const method of ['post','get']){const response=await f[method]();assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');await response.json();}
 assert.deepEqual(f.calls.map(c=>c[0]),['post','get']);for(const [,input] of f.calls){assert.deepEqual(input.persona,{id:7,role:'merchant'});assert.deepEqual(input.personaSession,session);assert.equal(input.sessionId,ids.sessionId);assert.ok(input.signal instanceof AbortSignal);}
 for(const extra of [{traceEventIds:[]},{mode:'vuln'},{body:'copied'},{readOperationId:randomUUID()}]){const r=await f.post({...ids,...extra});assert.equal(r.status,400);await r.text();}assert.equal(f.calls.length,2);
});
test('V11 closed public projection keeps private provenance out and preserves size limitation',async t=>{
 const f=await fixture(t);f.setOutput({completed:false,replayed:true,judgment:{verdict:'fail',evaluationId:randomUUID(),canRetry:false,packet:'private',traceIds:['private']}});
 let r=await f.get();assert.equal(r.status,200);assert.deepEqual(Object.keys((await r.json()).judgment).sort(),['canRetry','evaluationId','verdict']);
 const unavailable={completed:false,status:'unavailable',modelEvaluated:false,reason:'evidence_size_limit'};f.setOutput(unavailable);r=await f.post();assert.equal(r.status,200);assert.deepEqual(await r.json(),unavailable);
 f.setOutput({...unavailable,privatePacket:{}});r=await f.post();assert.equal(r.status,503);assert.doesNotMatch(JSON.stringify(await r.json()),/privatePacket/);
});
