'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID,createHash}=require('node:crypto');
const {createOwnedListingsClient}=require('../server/services/secureshopOwnedListingsClient');
const {prepareListingAdmission}=require('../server/services/secureshopListingJournalContract');
const sha=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
function fixture(change=()=>{},fetchOverride,clientOptions={}){
 const admission=prepareListingAdmission({scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},targetId:randomUUID(),mode:'vuln',catalogRevision:'0',request:{version:1,action:'import',operationId:randomUUID(),json_url:'http://supplier.training/catalog.json',xml_url:null}});
 const health={version:1,ready:true,identity:'a'.repeat(64),runtimeDigest:'b'.repeat(64),mode:'vuln',isolation:'owned-listings.v1'};
 const body={version:1,identity:health.identity,mode:'vuln',operationId:admission.request.operationId,requestSha256:admission.requestSha256,status:'completed',result:{version:1,operationId:admission.request.operationId,requestSha256:admission.requestSha256,mode:'vuln',products:[],sources:[]}};
 const receipt={...body,receiptSha256:sha(body)}; const calls=[];
 const client=createOwnedListingsClient({origin:'http://127.0.0.1:1234',token:'x'.repeat(43),runtimeIdentity:health.identity,runtimeDigest:health.runtimeDigest,mode:'vuln',executorId:randomUUID(),timeoutMs:30,fetchImpl:fetchOverride|| (async(url,options)=>{calls.push({url,options});const value=structuredClone(url.endsWith('/health')?health:receipt);change(value,url);return new Response(JSON.stringify(value));}),...clientOptions});
 client.registerAdmission(admission);
 const expected={operationId:admission.request.operationId,requestSha256:admission.requestSha256,bindingSha256:admission.bindingSha256,targetId:admission.binding.targetId,mode:'vuln'};
 return{client,admission,expected,calls};
}
test('attested context derives only from registered admission and authenticated result GET',async()=>{
 const f=fixture();const value=await f.client.readVerifiedResult(f.expected.operationId,f.expected);
 assert.equal(value.context.bindingSha256,f.admission.bindingSha256);assert.equal(JSON.parse(value.bytes).operationId,f.expected.operationId);
 assert.equal(f.calls.length,2);assert.ok(f.calls.every(c=>c.options.headers.authorization==='Bearer '+'x'.repeat(43)));
 await assert.rejects(f.client.readVerifiedResult(f.expected.operationId,{...f.expected,targetId:randomUUID()}),{code:'LISTINGS_ATTESTATION_MISMATCH'});
 assert.equal(f.calls.length,2);
 await assert.rejects(f.client.readVerifiedResult(randomUUID(),f.expected),{code:'LISTINGS_UNREGISTERED'});
});
test('health runtime drift, changed receipt digest, extra raw fields and changed operation are denied',async()=>{
 for(const change of [(v,u)=>{if(u.endsWith('/health'))v.runtimeDigest='c'.repeat(64);},(v,u)=>{if(!u.endsWith('/health'))v.result.products.push({name:'forged'});},(v,u)=>{if(!u.endsWith('/health'))v.debug='secret';},(v,u)=>{if(!u.endsWith('/health'))v.operationId=randomUUID();}]){
  const f=fixture(change);await assert.rejects(f.client.get(f.expected.operationId));
 }
});
test('whole request deadlines bound noncooperative headers and body readers',async()=>{
 for(const fetchImpl of [()=>new Promise(()=>{}),async()=>({ok:true,body:{getReader:()=>({read:()=>new Promise(()=>{}),cancel:async()=>{},releaseLock(){}})}})]){
  const f=fixture(undefined,fetchImpl),start=Date.now();await assert.rejects(f.client.health(),{code:'LISTINGS_TIMEOUT'});assert.ok(Date.now()-start<500);
 }
});
test('already aborted request never dispatches; oversized JSON fails boundedly',async()=>{
 const f=fixture(),abort=new AbortController();abort.abort();await assert.rejects(f.client.health({signal:abort.signal}),{code:'LISTINGS_ABORTED'});assert.equal(f.calls.length,0);
 const big=fixture(undefined,async()=>new Response('x'.repeat(2097153)));await assert.rejects(big.client.health(),{code:'LISTINGS_LIMIT'});
});
test('registered operation cannot be rebound to another target',()=>{
 const f=fixture();assert.throws(()=>f.client.registerAdmission({...f.admission,binding:{...f.admission.binding,targetId:randomUUID()}}),{code:'LISTINGS_ADMISSION_CONFLICT'});
});
test('retired tombstone verifies hash but cannot become completed attestation',async()=>{
 const f=fixture((value,url)=>{if(!url.endsWith('/health')){const body={version:1,status:'retired',operationId:value.operationId,identity:value.identity,requestSha256:value.requestSha256,receiptSha256:value.receiptSha256};for(const key of Object.keys(value))delete value[key];Object.assign(value,body,{tombstoneSha256:sha(body)});}});
 assert.equal((await f.client.retire(f.expected.operationId)).status,'retired');
 await assert.rejects(f.client.readVerifiedResult(f.expected.operationId,f.expected),{code:'LISTINGS_RESULT_UNAVAILABLE'});
});
test('HTTP failure cancels its body without waiting on an uncooperative cancellation',async()=>{
 let cancelled=0;
 const f=fixture(undefined,async()=>({ok:false,body:{cancel(){cancelled++;return new Promise(()=>{});}}}));
 await assert.rejects(f.client.health(),{code:'LISTINGS_HTTP'});
 assert.equal(cancelled,1);
});
test('admission memory is bounded and explicit lifecycle release permits a new registration',()=>{
 const f=fixture(undefined,undefined,{maxAdmissions:1});
 assert.equal(f.client.registerAdmission(f.admission),f.admission.request.operationId);
 const next={...f.admission,request:{...f.admission.request,operationId:randomUUID()}};
 assert.throws(()=>f.client.registerAdmission(next),{code:'LISTINGS_ADMISSION_CAPACITY'});
 assert.equal(f.client.releaseAdmission(f.admission.request.operationId),true);
 assert.equal(f.client.registerAdmission(next),next.request.operationId);
 assert.equal(f.calls.length,0);
});
test('scoped admissions share concurrent registration and release only after the last user',async()=>{
 const f=fixture(undefined,undefined,{maxAdmissions:1});let release,entered;
 const gate=new Promise(resolve=>release=resolve),started=new Promise(resolve=>entered=resolve);
 const first=f.client.withAdmission(f.admission,async handle=>{entered();await gate;return f.client.get(handle);});await started;
 const next={...f.admission,request:{...f.admission.request,operationId:randomUUID()}};
 try{
  assert.equal(f.client.releaseAdmission(f.admission.request.operationId),false);
  await f.client.withAdmission(f.admission,handle=>f.client.get(handle));
  await assert.rejects(f.client.withAdmission(next,async()=>{}),{code:'LISTINGS_ADMISSION_CAPACITY'});
 }finally{release();}
 await first;
 assert.throws(()=>f.client.get(f.admission.request.operationId),{code:'LISTINGS_UNREGISTERED'});
 await f.client.withAdmission(next,async()=>{});
 // Canonical caller can restore the exact original admission for GET recovery.
 const before=f.calls.length;await f.client.withAdmission(f.admission,handle=>f.client.get(handle));
 assert.ok(f.calls.slice(before).every(call=>call.options.method==='GET'));
 await assert.rejects(f.client.withAdmission(next,async()=>{throw Error('lost response');}),/lost response/);
 await f.client.withAdmission(f.admission,async()=>{});
});
