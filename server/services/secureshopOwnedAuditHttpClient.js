'use strict';
function createOwnedAuditHttpClient({url,token}){
 const base=new URL(url);if(base.protocol!=='http:'||base.hostname!=='127.0.0.1'||base.pathname!=='/'||base.search||base.hash||base.username||base.password||Number(base.port)<1024||!/^[-_A-Za-z0-9]{43,128}$/.test(token))throw TypeError('Private local audit service required');
 async function request(route,body){
  const response=await fetch(new URL(route,base),{method:'POST',redirect:'error',headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
  const chunks=[];let bytes=0;for await(const chunk of response.body){bytes+=chunk.length;if(bytes>17*1024*1024)throw Error('Audit response exceeds limit');chunks.push(Buffer.from(chunk));}
  const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if(!response.ok){const code=['AUDIT_QUERY_UNCERTAIN','AUDIT_QUERY_CONFLICT','AUDIT_QUERY_RETIRED'].includes(result?.error)?result.error:'AUDIT_SERVICE_UNAVAILABLE';throw Object.assign(Error(code),{code});}return result;
 }
 return Object.freeze(Object.fromEntries(['readiness','target','provision','search','receipt','retire','destroy'].map(name=>[name,body=>request('/'+name,body||{})])));
}
module.exports={createOwnedAuditHttpClient};
