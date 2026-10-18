'use strict';
const {createHash}=require('node:crypto');
const {ProviderRouter}=require('./secureshop/providerRouter');
const {OllamaProvider}=require('./secureshop/providers/ollamaProvider');
const {OpenAIProvider}=require('./secureshop/providers/openaiProvider');
const {AnthropicProvider}=require('./secureshop/providers/anthropicProvider');
const {BedrockProvider}=require('./secureshop/providers/bedrockProvider');
const {readJudgeProviderConfig}=require('../agent-runtime/judgeProviderConfiguration');
const TYPES={ollama:OllamaProvider,openai:OpenAIProvider,anthropic:AnthropicProvider,bedrock:BedrockProvider};
const exact=(value,Type)=>value instanceof Type&&Object.getPrototypeOf(value)===Type.prototype;
function actorConfigurations(provider){
 const entries=exact(provider,ProviderRouter)?provider._order().map(name=>[name,provider.providers[name]]):Object.entries(TYPES).filter(([,Type])=>exact(provider,Type)).map(([name])=>[name,provider]);
 return entries.map(([name,p])=>({instance:p,config:TYPES[name]&&exact(p,TYPES[name])?{provider:name,model:p.config?.model||p.model||p.modelId,baseURL:p.config?.baseURL||p.baseUrl,apiKey:p.config?.apiKey,region:p.config?.region}:null,mock:name==='mock'}));
}
function createMailCapabilities({provider,judge,fetchImpl=globalThis.fetch,now=Date.now,timeoutMs=2000,ttlMs=15000}={}){
 if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>2000||!Number.isInteger(ttlMs)||ttlMs<1||ttlMs>15000)throw TypeError('Invalid mail capability bounds');
 let cached=null,inflight=null;const ids=new WeakMap();let sequence=0;
 const identity=value=>{if(!value||!['object','function'].includes(typeof value))return null;if(!ids.has(value))ids.set(value,++sequence);return ids.get(value);};
 const state=(config,status,canAttempt)=>Object.freeze({provider:config?.provider||null,model:config?.model||null,status,canAttempt});
 async function inspect(config,signal){
  if(!config?.model)return state(config,'unknown_unprobed',false);
  if(config.provider!=='ollama')return state(config,config.provider==='bedrock'||config.apiKey?'configured_unprobed':'unconfigured',config.provider==='bedrock'||Boolean(config.apiKey));
  const response=await fetchImpl(new URL('/api/tags',config.baseURL),{signal,headers:{accept:'application/json'}});
  if(!response.ok)return state(config,'unavailable',false);
  const reader=response.body?.getReader();if(!reader)return state(config,'unavailable',false);
  let size=0;const parts=[];const cancel=()=>{void reader.cancel(signal.reason).catch(()=>{});};signal.addEventListener('abort',cancel,{once:true});
  try{while(true){signal.throwIfAborted();const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>65536)throw Error('Model list exceeds bound');parts.push(Buffer.from(value));}}finally{signal.removeEventListener('abort',cancel);await reader.cancel().catch(()=>{});reader.releaseLock();}signal.throwIfAborted();
  const data=JSON.parse(Buffer.concat(parts).toString('utf8'));const installed=Array.isArray(data.models)&&data.models.some(row=>row?.name===config.model||row?.model===config.model);
  return state(config,installed?'available':'model_missing',installed);
 }
 async function read(){
  const actors=actorConfigurations(provider);let judgeConfig=null;try{judgeConfig=readJudgeProviderConfig(judge);}catch{}
  const key=createHash('sha256').update(JSON.stringify({actors:actors.map(x=>[identity(x.instance),x.config,x.mock]),judge:identity(judge),judgeConfig})).digest('hex');
  if(cached?.key===key&&now()<cached.until)return cached.value;if(inflight?.key===key)return inflight.promise;
  const controller=new AbortController();let timer;
  const safe=async config=>{try{return await inspect(config,controller.signal);}catch{return state(config,'unavailable',false);}};
  const actorStates=actors.map(entry=>state(entry.config,entry.mock?'mock_only':entry.config?'unavailable':'unknown_unprobed',false));
  let judgeState=state(judgeConfig,judgeConfig?'unavailable':'unknown_unprobed',false);
  const result=()=>{
   const actor=actorStates.find(value=>value.canAttempt)||actorStates[0]||state(null,'unknown_unprobed',false);
   return Object.freeze({actor:Object.freeze({...actor,selection:'prospective_route',candidates:Object.freeze([...actorStates])}),judge:judgeState});
  };
  // Independent status probes share one wall-clock deadline. A slow local
  // candidate must not erase a configured cloud fallback or a fast Judge.
  const work=Promise.all([...actors.map(async(entry,index)=>{if(entry.config)actorStates[index]=await safe(entry.config);}),
   (async()=>{if(judgeConfig)judgeState=await safe(judgeConfig);})()]).then(result);
  const promise=Promise.race([work,new Promise(resolve=>{timer=setTimeout(()=>{controller.abort(Error('Mail capability probe deadline'));resolve(result());},timeoutMs);})]).then(value=>{cached={key,until:now()+ttlMs,value};return value;}).finally(()=>{clearTimeout(timer);if(inflight?.promise===promise)inflight=null;});
  inflight={key,promise};return promise;
 }
 async function assertAvailable(kind){if(!(await read())[kind]?.canAttempt)throw Object.assign(Error('Mail model capability unavailable'),{code:'MAIL_MODEL_UNAVAILABLE'});}
 return Object.freeze({read,assertAvailable});
}
function guardMailJudge(capabilities,judge){return async input=>{input.execution?.signal?.throwIfAborted();await capabilities.assertAvailable('judge');input.execution?.signal?.throwIfAborted();return judge(input);};}
module.exports={createMailCapabilities,actorConfigurations,guardMailJudge};
