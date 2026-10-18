'use strict';
const {OllamaProvider}=require('./secureshop/providers/ollamaProvider');
async function tags(baseUrl,signal){
 const response=await fetch(new URL('/api/tags',baseUrl),{signal,redirect:'error'});
 if(!response.ok)throw Error('provider unavailable');
 const reader=response.body.getReader();let size=0;const chunks=[];
 try{while(true){const{done,value}=await reader.read();if(done)break;size+=value.length;if(size>1048576)throw Error('provider response exceeds health limit');chunks.push(Buffer.from(value));}}
 finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
 return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function createSecureShopBoundRuntimeHealth({repository,provider,isServing,probeTags=tags}={}){
 if(typeof repository?.probe!=='function'||typeof isServing!=='function')throw new TypeError('Health dependencies required');
 return async scope=>{
  if(!isServing())throw Object.assign(Error('Bound service is draining'),{statusCode:503});
  // Real scoped store reads; launch/session and persona checks bracket this in
  // BoundAdmin. This is service readiness, not an inference success claim.
  await repository.probe(scope);
  const available=provider?.providers || (provider instanceof OllamaProvider?{ollama:provider}:{}),providers=[];
  for(const [name,p] of Object.entries(available)){
   if(!p)continue;
   if(name==='ollama'&&p instanceof OllamaProvider){
    let availability='unreachable';
    try{const value=await probeTags(p.baseUrl,AbortSignal.timeout(2000));availability=Array.isArray(value.models)&&value.models.some(row=>row.name===p.model||row.model===p.model)?'model_present':'model_missing';}catch{}
    providers.push({provider:'ollama',model:p.model,availability,model_execution:'not_tested'});
   }else if(['openai','anthropic','bedrock'].includes(name))providers.push({provider:name,availability:(p.apiKey||p.modelId)?'configured_unknown':'not_configured',model_execution:'not_tested'});
   else if(name==='mock')providers.push({provider:'mock',availability:'mock_not_genuine',model_execution:'not_tested'});
  }
  if(!isServing())throw Object.assign(Error('Bound service is draining'),{statusCode:503});
  return {ready:true,status:'SERVICE_READY',basis:'scoped_store_reads',providers,model_execution:'not_tested'};
 };
}
module.exports={createSecureShopBoundRuntimeHealth};
