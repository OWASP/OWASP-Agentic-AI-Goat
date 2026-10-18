'use strict';
// Diagnostic transport only: forwards unchanged model requests/responses and
// records owned raw wire evidence. It never supplies a model decision.
const assert=require('node:assert/strict');
const {installNetworkGuard,readModelDigest,REQUIRED_MODEL_DIGEST}=require('./ipiEmailRenderedFixture');
function installActualTransport({mailpitApiUrl,ollamaBaseUrl,fetchImpl=global.fetch,maxCalls=24}={}){
 const originalGlobalFetch=global.fetch;const axios=require('axios'),calls=[];let stage='initialization';
 const begin=(url,body)=>{const record={stage,url,request:typeof body==='string'?body:JSON.stringify(body),startedAt:new Date().toISOString()};calls.push(record);return {record,start:performance.now()};};
 const finish=(entry,response,error)=>{entry.record.durationMs=Math.round(performance.now()-entry.start);if(response!==undefined)entry.record.response=response;if(error)entry.record.error={name:error.name,code:error.code||null,message:error.message};};
 const rawFetch=async(input,init)=>{
  const url=typeof input==='string'?input:input instanceof URL?input.href:input?.url;assert.equal(typeof url,'string');init=init||{};const generation=/\/api\/(chat|generate)$/.test(url);if(!generation)return fetchImpl(input,init);
  const entry=begin(url,init.body),signal=AbortSignal.any([...(init.signal?[init.signal]:[]),AbortSignal.timeout(60000)]);
  try{const response=await fetchImpl(input,{...init,signal});const raw=await response.clone().text();assert.ok(Buffer.byteLength(raw)<=1048576);entry.record.status=response.status;finish(entry,raw);return response;}catch(e){finish(entry,undefined,e);throw e;}
 };
 const network=installNetworkGuard({mailpitApiUrl,ollamaBaseUrl,maxCalls,maxTransportCalls:400,fetchImpl:rawFetch});
 const interceptor=axios.interceptors.request.use(config=>{
  const url=new URL(config.url,config.baseURL);if(!['/api/chat','/api/generate'].includes(url.pathname))return config;
  config.timeout=Math.min(Number(config.timeout)>0?Number(config.timeout):60000,60000);
  config.signal=AbortSignal.any([...(config.signal?[config.signal]:[]),AbortSignal.timeout(60000)]);
  const adapter=axios.getAdapter(config.adapter||axios.defaults.adapter);
  config.adapter=async actual=>{const entry=begin(url.href,actual.data);try{const response=await adapter(actual);entry.record.status=response.status;const raw=typeof response.data==='string'?response.data:JSON.stringify(response.data);assert.ok(Buffer.byteLength(raw)<=1048576);finish(entry,raw);return response;}catch(e){finish(entry,e.response?.data,e);throw e;}};
  return config;
 });
 return {calls,counters:network.counters,setStage:value=>{assert.equal(typeof value,'string');stage=value;},readDigest:()=>readModelDigest({ollamaBaseUrl}),requiredDigest:REQUIRED_MODEL_DIGEST,close:()=>{axios.interceptors.request.eject(interceptor);network.restore();global.fetch=originalGlobalFetch;}};
}
module.exports={installActualTransport};
