'use strict';
function createOwnedHttpServiceClient({baseUrl,token,fetch:requestFetch=globalThis.fetch}={}){
 const parsed=new URL(baseUrl);if(parsed.protocol!=='http:'||parsed.username||parsed.password||parsed.search||parsed.hash||!['127.0.0.1','localhost','mcp-owned-http'].includes(parsed.hostname)||parsed.pathname!=='/'||!/^[A-Za-z0-9_-]{43,128}$/.test(token||''))throw TypeError('Private local HTTP endpoint required');
 async function request(path,body,{signal}={}){
  const response=await requestFetch(new URL(path,baseUrl),{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(body),signal:signal?AbortSignal.any([signal,AbortSignal.timeout(25000)]):AbortSignal.timeout(25000),redirect:'error'});
  let size=0;const chunks=[];for await(const chunk of response.body){size+=chunk.length;if(size>131072)throw Object.assign(Error('HTTP_RESPONSE_LIMIT'),{code:'HTTP_RESPONSE_LIMIT'});chunks.push(chunk);}
  const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!response.ok)throw Object.assign(Error(value.error||'HTTP_SERVICE_UNAVAILABLE'),{code:value.error||'HTTP_SERVICE_UNAVAILABLE'});return value;
 }
 return Object.freeze({request,readiness:()=>request('/owned-http/readiness',{}),admit:scope=>request('/owned-http/admit',{scope}),retire:({operationId,...scope})=>request('/owned-http/retire',{scope,operationId}),readRetirement:({operationId,...scope})=>request('/owned-http/retirement',{scope,operationId})});
}
module.exports={createOwnedHttpServiceClient};
