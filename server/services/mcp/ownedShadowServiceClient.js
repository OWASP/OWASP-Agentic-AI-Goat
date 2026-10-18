'use strict';
function createOwnedShadowServiceClient({baseUrl,token,fetch:requestFetch=globalThis.fetch}={}){
 const parsed=new URL(baseUrl);if(parsed.protocol!=='http:'||parsed.username||parsed.password||parsed.search||parsed.hash||!['127.0.0.1','localhost','mcp-owned-shadow'].includes(parsed.hostname)||parsed.pathname!=='/'||!/^[A-Za-z0-9_-]{43,128}$/.test(token||''))throw TypeError('Private local HTTP endpoint required');
 async function request(path,body,{signal}={}){
  const response=await requestFetch(new URL(path,baseUrl),{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(body),signal:signal?AbortSignal.any([signal,AbortSignal.timeout(25000)]):AbortSignal.timeout(25000),redirect:'error'});
  let size=0;const chunks=[];for await(const chunk of response.body){size+=chunk.length;if(size>131072)throw Object.assign(Error('SHADOW_RESPONSE_LIMIT'),{code:'SHADOW_RESPONSE_LIMIT'});chunks.push(chunk);}
  const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!response.ok)throw Object.assign(Error(value.error||'SHADOW_SERVICE_UNAVAILABLE'),{code:value.error||'SHADOW_SERVICE_UNAVAILABLE'});return value;
 }
 return Object.freeze({readSource:capability=>request('/owned-shadow/source/read',{capability}),writeSource:(capability,value)=>request('/owned-shadow/source/write',{capability,request:value}),readReceipt:(capability,{operationId,requestDigest})=>request('/owned-shadow/receipt',{capability,operationId,requestDigest}),execute:(capability,operation,options)=>request('/owned-shadow/execute',{capability,request:operation},options),recoverRegistration:(capability,{operationId,registrationId})=>request('/owned-shadow/registration',{capability,operationId,registrationId}),readiness:()=>request('/owned-shadow/readiness',{}),admit:scope=>request('/owned-shadow/admit',{scope}),retire:({operationId,...scope})=>request('/owned-shadow/retire',{scope,operationId}),readRetirement:({operationId,...scope})=>request('/owned-shadow/retirement',{scope,operationId})});
}
module.exports={createOwnedShadowServiceClient};
