'use strict';
// Actual-model qualification helper. No fallback provider and no synthetic identity.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const sha=value=>createHash('sha256').update(value).digest('hex');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
async function createActualListingsProvider({writeEvidence,maxCalls=10,maxHttpCalls=maxCalls,signal}={}){
 if(typeof writeEvidence!=='function'||!Number.isInteger(maxCalls)||maxCalls<1||maxCalls>12||!Number.isInteger(maxHttpCalls)||maxHttpCalls<maxCalls||maxHttpCalls>40)throw TypeError('Bounded actual qualification required');
 const origin='http://127.0.0.1:11434';
 const tags=await(await fetch(origin+'/api/tags',{signal:AbortSignal.timeout(5000)})).json();assert.equal(tags.models.find(m=>m.name===MODEL)?.digest,DIGEST);
 const provider=new(require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({baseUrl:origin,model:MODEL});
 const evidence={model:MODEL,digest:DIGEST,maxCalls,maxHttpCalls,calls:[],httpCalls:[],actual:true};
 const originalFetch=global.fetch;let phase='actor';
 global.fetch=async(url,options={})=>{
  const target=new URL(typeof url==='string'?url:url.url||String(url));
  if(target.origin!==origin)return originalFetch(url,options);
  if(target.pathname!=='/api/chat')return originalFetch(url,options);
  if(evidence.httpCalls.length>=maxHttpCalls)throw Object.assign(Error('Actual HTTP call budget exhausted'),{code:'QUALIFICATION_BUDGET_EXHAUSTED'});
  const request=String(options.body||''),call={index:evidence.httpCalls.length+1,phase,request,requestSha256:sha(request),status:'pending'};evidence.httpCalls.push(call);await writeEvidence(evidence);
  try{const response=await originalFetch(url,{...options,signal:AbortSignal.any([AbortSignal.timeout(120000),...(signal?[signal]:[]),...(options.signal?[options.signal]:[])])});const text=await response.clone().text();assert.ok(Buffer.byteLength(text)<=4*1024*1024);call.response=text;call.responseSha256=sha(text);call.httpStatus=response.status;call.status='returned';await writeEvidence(evidence);return response;}catch(error){call.status='failed';call.error={name:error.name,code:error.code};await writeEvidence(evidence);throw error;}
 }; await writeEvidence(evidence);
 const wrapped={};
 for(const method of['chat','finalResponse'])wrapped[method]=async args=>{
  if(evidence.calls.length>=maxCalls)throw Object.assign(Error('Actual Listings call budget exhausted'),{code:'QUALIFICATION_BUDGET_EXHAUSTED'});
  const call={index:evidence.calls.length+1,method,status:'pending',startedAt:new Date().toISOString()};evidence.calls.push(call);await writeEvidence(evidence);
  try{const result=await provider[method]({...args,signal:AbortSignal.any([AbortSignal.timeout(120000),...(signal?[signal]:[]),...(args.signal?[args.signal]:[])])});
   assert.equal(result.provider,'ollama');assert.equal(result.model,MODEL);assert.equal(result.mocked,false);assert.notEqual(result.fallback,true);
   call.status='returned';call.result=result;await writeEvidence(evidence);return result;
  }catch(error){call.status='failed';call.error={name:error.name,code:error.code};await writeEvidence(evidence);throw error;}
 };
 return{provider:Object.freeze(wrapped),evidence,async withJudgePhase(work){if(phase!=='actor')throw Error('Concurrent qualification phase');phase='judge';try{return await work();}finally{phase='actor';}},close(){global.fetch=originalFetch;}};
}
module.exports={createActualListingsProvider};
