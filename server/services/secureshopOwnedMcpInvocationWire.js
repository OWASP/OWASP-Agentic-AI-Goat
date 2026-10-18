'use strict';
// Private, unwired invocation protocol. A receipt digest is not authentication.
const crypto=require('node:crypto');
const C=require('./secureshopOwnedMcpInvocationContract');
const VERSION='owned-mcp-invocation-wire-v1';
// Fixed issuer-clock allowance only. Expiry has no grace and signed lifetime
// remains bounded independently of this one-second future-clock allowance.
const FUTURE_CLOCK_SKEW_MS=1000;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const fail=()=>{throw Object.assign(Error('Invalid private invocation message'),{code:'MCP_INVOCATION_WIRE_INVALID'});};
const uuid=v=>typeof v==='string'&&UUID.test(v),sha=v=>typeof v==='string'&&SHA.test(v);
function exact(v,keys){if(!v||Array.isArray(v)||Object.keys(v).sort().join()!==keys.slice().sort().join())fail();}
function scope(v,ownerOnly=false){
 exact(v,ownerOnly?['platformOwnerId']:['platformOwnerId','platformSessionId','launchId','scenarioId','generation']);
 if(!Number.isSafeInteger(v.platformOwnerId)||v.platformOwnerId<1||v.platformOwnerId>2147483647)fail();
 if(!ownerOnly&&(!Number.isSafeInteger(v.platformSessionId)||v.platformSessionId<1||v.platformSessionId>2147483647||!Number.isSafeInteger(v.generation)||v.generation<1||!uuid(v.launchId)||!uuid(v.scenarioId)))fail();return v;
}
function claim(raw){
 const v=C.bounded(raw,196608);exact(v,['invocationId','snapshot','request','personaSession','managerInstanceId','runtimeSha256','policySha256','effectKey','assetId']);
 const s=C.snapshot(v.snapshot),q=v.request,index=s.tools.findIndex(t=>t.name===q?.toolName);
 const expected=C.request({snapshot:s,runId:q?.runId,requestId:q?.requestId,callId:q?.callId,toolIndex:index,args:q?.args,mode:q?.mode});
 if(C.digest(q)!==C.digest(expected)||!uuid(v.invocationId)||!uuid(v.managerInstanceId)||!sha(v.runtimeSha256)||!sha(v.policySha256)||typeof v.effectKey!=='string'||!v.effectKey||v.effectKey.length>512||typeof v.assetId!=='string'||!/^[a-z][a-z0-9-]{0,63}$/.test(v.assetId))fail();
 exact(v.personaSession,['sessionId','authorityVersion']);if(!uuid(v.personaSession.sessionId)||typeof v.personaSession.authorityVersion!=='string'||!/^[1-9][0-9]{0,18}$/.test(v.personaSession.authorityVersion)||BigInt(v.personaSession.authorityVersion)>9223372036854775807n)fail();return C.freeze(v);
}
function lookup(raw){const v=C.bounded(raw,1024);exact(v,['invocationId','requestSha256','managerInstanceId','runtimeSha256']);if(!uuid(v.invocationId)||!sha(v.requestSha256)||!uuid(v.managerInstanceId)||!sha(v.runtimeSha256))fail();return C.freeze(v);}
function fence(raw){
 const v=C.bounded(raw,65536),ownerOnly=v.kind==='owner_deletion';
 exact(v,['version','kind','fenceId','platformOwnerId','managerInstanceId','runtimeSha256','invocationIds',...(ownerOnly?[]:['launchId','scenarioId','generation','platformSessionId'])]);
 if(v.version!=='owned-mcp-invocation-fence-v1'||!['retirement','owner_deletion'].includes(v.kind)||!uuid(v.fenceId)||!uuid(v.managerInstanceId)||!sha(v.runtimeSha256)||!Array.isArray(v.invocationIds)||v.invocationIds.length>256||v.invocationIds.some(x=>!uuid(x))||new Set(v.invocationIds).size!==v.invocationIds.length||v.invocationIds.join()!==[...v.invocationIds].sort().join())fail();
 scope(Object.fromEntries((ownerOnly?['platformOwnerId']:['platformOwnerId','platformSessionId','launchId','scenarioId','generation']).map(k=>[k,v[k]])),ownerOnly);return C.freeze(v);
}
function createInvocationSigner({key,keyId,now=Date.now,maxAgeMs=15000}={}){
 if(!Buffer.isBuffer(key)||key.length!==32||typeof keyId!=='string'||!/^[a-zA-Z0-9_-]{1,32}$/.test(keyId)||typeof now!=='function'||!Number.isSafeInteger(maxAgeMs)||maxAgeMs<1||maxAgeMs>15000)throw TypeError('Private invocation signing configuration required');
 const secret=Buffer.from(key),domains=new Set(['claim','status','retire','receipt']);
 function sign(domain,payload){if(!domains.has(domain))fail();const issuedAt=now(),body=C.bounded({version:VERSION,keyId,domain,issuedAt,expiresAt:issuedAt+maxAgeMs,payload},262144);const mac=crypto.createHmac('sha256',secret).update(JSON.stringify(body)).digest('hex');return C.freeze({...body,mac});}
 function verify(domain,raw){const current=now(),v=C.bounded(raw,262144);exact(v,['version','keyId','domain','issuedAt','expiresAt','payload','mac']);if(!domains.has(domain)||v.version!==VERSION||v.keyId!==keyId||v.domain!==domain||!sha(v.mac)||!Number.isSafeInteger(v.issuedAt)||!Number.isSafeInteger(v.expiresAt)||v.expiresAt-v.issuedAt<1||v.expiresAt-v.issuedAt>maxAgeMs||v.issuedAt>current+FUTURE_CLOCK_SKEW_MS||current>=v.expiresAt)fail();const {mac,...body}=v,expected=crypto.createHmac('sha256',secret).update(JSON.stringify(C.bounded(body,262144))).digest();if(!crypto.timingSafeEqual(Buffer.from(mac,'hex'),expected))fail();return C.freeze(v.payload);}
 return Object.freeze({sign,verify});
}
module.exports={claim,lookup,fence,scope,createInvocationSigner,FUTURE_CLOCK_SKEW_MS};
