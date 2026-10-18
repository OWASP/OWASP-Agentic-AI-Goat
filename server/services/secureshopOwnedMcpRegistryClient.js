'use strict';
const {MCP_REGISTRY_CAPABILITY}=require('../../sidecars/sandbox-runner/owned-mcp-registry/http-handler');
const MAX=512*1024,uncertain=new WeakSet(),fail=code=>Object.assign(new Error('Owned MCP registry executor unavailable'),{code});
const notDispatched=new WeakMap();
function isOwnedMcpRegistryNotDispatched(error,request){
 try{return notDispatched.get(error)===require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol').digest(request);}catch{return false;}
}
async function bounded(response,signal){const reader=response.body?.getReader?.();if(!reader)throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');let size=0,parts=[];const cancel=()=>Promise.resolve(reader.cancel()).catch(()=>{});signal.addEventListener('abort',cancel,{once:true});try{while(true){signal.throwIfAborted();const item=await reader.read();if(item.done)break;size+=item.value.byteLength;if(size>MAX){cancel();throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');}parts.push(Buffer.from(item.value));}return JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(Buffer.concat(parts)));}finally{signal.removeEventListener('abort',cancel);reader.releaseLock?.();}}
function createOwnedMcpRegistryClient({baseURL,token,fetchImpl=fetch,timeoutMs=18000,expectedRuntimeDigest}={}){
 if(expectedRuntimeDigest!==undefined&&!/^[0-9a-f]{64}$/.test(expectedRuntimeDigest))throw new TypeError('Exact MCP registry runtime digest required');
 let origin;try{origin=new URL(baseURL);}catch{throw new TypeError('Private MCP registry origin required');}if(!['http:','https:'].includes(origin.protocol)||origin.pathname!=='/'||origin.username||origin.password||origin.search||origin.hash||!/^[A-Za-z0-9_-]{43,128}$/.test(token||'')||typeof fetchImpl!=='function'||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>20000)throw new TypeError('Private MCP registry transport required');
 async function call(path,{method='GET',body,signal,onDispatch,onRejection}={}){
  const controller=new AbortController(),abort=()=>controller.abort(),timer=setTimeout(abort,timeoutMs);
  signal?.addEventListener('abort',abort,{once:true});
  let rejectInterrupted;
  const interrupted=new Promise((_,reject)=>{rejectInterrupted=()=>reject(fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE'));controller.signal.addEventListener('abort',rejectInterrupted,{once:true});});
  try{
   signal?.throwIfAborted();
   const pending=(async()=>{
    onDispatch?.();
    const response=await fetchImpl(new URL(path,origin),{method,redirect:'error',credentials:'omit',signal:controller.signal,headers:{authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
    if(!controller.signal.aborted&&!response.ok&&onRejection){const rejection=await bounded(response,controller.signal);onRejection(response.status,rejection);}
    if(controller.signal.aborted||!response.ok){Promise.resolve(response.body?.cancel?.()).catch(()=>{});throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');}
    return await bounded(response,controller.signal);
   })();
   return await Promise.race([pending,interrupted]);
  }catch(cause){const e=fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');Object.defineProperty(e,'cause',{value:cause});throw e;}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',rejectInterrupted);}
 }

 async function health({signal}={}){const value=await call('/secureshop/mcp-registry/health',{signal}),keys=['version','ready','isolation','registryCapability','runtimeDigest'];if(!value||Object.keys(value).sort().join(',')!==keys.sort().join(',')||value.version!==1||value.ready!==true||value.isolation!=='owned-mcp-registry-v1'||value.registryCapability!==MCP_REGISTRY_CAPABILITY||!/^[0-9a-f]{64}$/.test(value.runtimeDigest||'')||(expectedRuntimeDigest!==undefined&&value.runtimeDigest!==expectedRuntimeDigest))throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');return Object.freeze(value);}
 async function execute(request,{signal,activeEntries,mode,assertCurrent}={}){
  if(typeof assertCurrent!=='function')throw new TypeError('Trusted MCP registry authority required');
  // Freeze the original command before asynchronous health/authority reads.
  const original=require('./secureshopMcpRegistryContract').normalizeRegistryRequest(request);
  await assertCurrent();await health({signal});await assertCurrent();let denied=null;
  try{
   const value=await call('/secureshop/mcp-registry/execute',{method:'POST',body:{request:original,activeEntries,mode},signal,
    onRejection:(status,body)=>{if(status===403)denied=require('./secureshopMcpRegistryDiscoveryContract').validateDiscoveryDenial(body,{request:original,mode});}});
   if(!value||Object.keys(value).sort().join(',')!=='changes,version'||value.version!==1||!Array.isArray(value.changes))throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');
   await assertCurrent();return value.changes;
  }catch(cause){
   if(denied){await assertCurrent();const error=Object.assign(Error('MCP registry destination denied before discovery'),{
    code:denied.error,effectNotStarted:true,drained:true,operationId:denied.operationId,
    registryRequestSha256:denied.registryRequestSha256,policySha256:denied.policySha256});
    Object.defineProperty(error,'cause',{value:cause});throw error;}
   const error=Object.assign(new Error('MCP registry executor outcome unknown; read back before continuing'),{code:'MCP_REGISTRY_EXECUTOR_OUTCOME_UNCERTAIN',automaticRetry:false});
   uncertain.add(error);Object.defineProperty(error,'cause',{value:cause});throw error;
  }
 }
 async function invocationHealth({signal}={}){
  const value=await call('/secureshop/mcp-registry/invoke/health',{signal});
  if(!value||Object.keys(value).sort().join()!=='instanceId,runtimeDigest,version'||value.version!==1
    ||typeof value.instanceId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.instanceId)
    ||!/^[a-f0-9]{64}$/.test(value.runtimeDigest||'')||(expectedRuntimeDigest!==undefined&&value.runtimeDigest!==expectedRuntimeDigest))throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');
  return Object.freeze(value);
 }
 async function invocationState(raw,{drain=false,signal}={}){
  const q=require('./secureshopOwnedMcpInvocationContract').bounded(raw,1024);
  if(!q||Object.keys(q).sort().join()!=='instanceId,operationId,requestSha256'
    ||!['instanceId','operationId'].every(key=>typeof q[key]==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(q[key]))
    ||!/^[a-f0-9]{64}$/.test(q.requestSha256||''))throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');
  const value=await call('/secureshop/mcp-registry/invoke/'+(drain?'drain':'status'),{method:'POST',body:q,signal});
  if(!value||Object.keys(value).sort().join()!=='drained,instanceId,operationId,requestSha256,state,version'
    ||value.version!==1||Object.keys(q).some(key=>value[key]!==q[key])
    ||!['running','completed','retired','unknown'].includes(value.state)
    ||value.drained!==['completed','retired'].includes(value.state))throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');
  return Object.freeze(value);
 }
 async function invoke(raw,{signal}={}){
  const protocol=require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
  const request=protocol.request(raw),identity={instanceId:request.instanceId,operationId:request.operationId,
    requestSha256:require('./mcp/protocolContext').canonicalDigest(request)};
  try{
   signal?.throwIfAborted();
   const ready=await invocationHealth({signal});
   if(ready.instanceId!==request.instanceId)throw fail('MCP_REGISTRY_INSTANCE_CHANGED');
   signal?.throwIfAborted();
  }catch(cause){
   const error=fail(cause?.code==='MCP_REGISTRY_INSTANCE_CHANGED'?'MCP_REGISTRY_INSTANCE_CHANGED':'MCP_REGISTRY_NOT_DISPATCHED');
   Object.defineProperty(error,'cause',{value:cause});notDispatched.set(error,protocol.digest(request));throw error;
  }
  let postMayStart=false,rejectedBeforeAdmission=false;
  try{
   const value=await call('/secureshop/mcp-registry/invoke',{method:'POST',body:request,signal,
    onDispatch:()=>{postMayStart=true;},onRejection:(status,body)=>{
     // These closed responses occur before the executor records or starts work.
     // Operation conflicts are deliberately excluded: another call may exist.
     rejectedBeforeAdmission=body&&Object.keys(body).join()==='error'&&
       ((status===429&&body.error==='MCP_REGISTRY_HTTP_CAPACITY')
        ||(status===409&&body.error==='MCP_REGISTRY_INSTANCE_CHANGED'));
    }});
   if(!value||Object.keys(value).sort().join()!=='receipt,version'||value.version!==1)throw fail('MCP_REGISTRY_EXECUTOR_UNAVAILABLE');
   return require('./secureshopOwnedMcpInvocationContract').freeze(protocol.receipt(value.receipt,request));
  }catch(cause){
   if(!postMayStart||rejectedBeforeAdmission){const error=fail('MCP_REGISTRY_NOT_DISPATCHED');Object.defineProperty(error,'cause',{value:cause});notDispatched.set(error,protocol.digest(request));throw error;}
   // Parent cancellation ends publication, not retirement. Use a separate
   // bounded authenticated request and wait for the exact worker to drain.
   let retirement=null;
   try{retirement=await invocationState(identity,{drain:true});}catch{}
   const error=Object.assign(new Error('Registered tool outcome uncertain'),{
    code:'MCP_REGISTRY_INVOCATION_UNCERTAIN',executionBoundary:true,automaticRetry:false,
    drained:retirement?.drained===true,retirement});
   Object.defineProperty(error,'cause',{value:cause});uncertain.add(error);throw error;
  }
 }
 return Object.freeze({health,execute,invocationHealth,invocationState,invoke});
}
module.exports={createOwnedMcpRegistryClient,isOwnedMcpRegistryOutcomeUncertain:error=>uncertain.has(error),isOwnedMcpRegistryNotDispatched};
