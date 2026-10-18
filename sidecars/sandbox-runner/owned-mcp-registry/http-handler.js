'use strict';
const crypto=require('node:crypto');
const fail=code=>Object.assign(new Error(code),{code});
const CAPABILITY='secureshop-owned-mcp-registry.v1';
function createOwnedMcpRegistryHttpHandler({token,executor,maxConcurrent=2,now=Date.now}={}){
 if(!/^[A-Za-z0-9_-]{43,128}$/.test(token||'')||typeof executor?.checkReadiness!=='function'||typeof executor?.assertReady!=='function'||typeof executor?.execute!=='function'||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>4)throw new TypeError('Owned MCP registry HTTP dependencies required');
 let active=0,closed=false;const invocations=new Map(),instanceId=crypto.randomUUID();
 const prune=()=>{for(const [id,r]of invocations)if(['completed','retired'].includes(r.state)&&now()-r.finishedAt>=60000)invocations.delete(id);};
 const protocol=require('./invoke-protocol'),digest=protocol.digest;
 const authorized=req=>{const supplied=Buffer.from(req.headers.authorization||''),expected=Buffer.from('Bearer '+token);return supplied.length===expected.length&&crypto.timingSafeEqual(supplied,expected);};
 async function body(req){let size=0,parts=[];for await(const chunk of req){size+=chunk.length;if(size>196608)throw fail('MCP_REGISTRY_HTTP_LIMIT');parts.push(chunk);}let value;try{value=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{throw fail('MCP_REGISTRY_HTTP_INVALID');}return value;}
 const send=(res,status,value)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(value));};
 async function handle(req,res){
  prune();if(closed){send(res,503,{error:'MCP_REGISTRY_HTTP_CLOSED'});return true;}if(!authorized(req)){send(res,401,{error:'MCP_REGISTRY_HTTP_UNAUTHORIZED'});return true;}
  if(req.method==='GET'&&req.url==='/secureshop/mcp-registry/health'){const ready=await executor.checkReadiness();await executor.assertReady();send(res,200,{version:1,ready:true,isolation:'owned-mcp-registry-v1',registryCapability:CAPABILITY,runtimeDigest:ready.runtimeDigest});return true;}
  if(req.method==='GET'&&req.url==='/secureshop/mcp-registry/invoke/health'){const ready=await executor.checkReadiness();await executor.assertReady();send(res,200,{version:1,instanceId,runtimeDigest:ready.runtimeDigest});return true;}
  if(req.method==='POST'&&['/secureshop/mcp-registry/invoke/status','/secureshop/mcp-registry/invoke/drain'].includes(req.url)){
   const q=await body(req);if(!q||Object.keys(q).sort().join()!=='instanceId,operationId,requestSha256'||!/^[a-f0-9-]{36}$/.test(q.instanceId)||!/^[a-f0-9-]{36}$/.test(q.operationId)||!/^[a-f0-9]{64}$/.test(q.requestSha256)){send(res,400,{error:'MCP_REGISTRY_HTTP_INVALID'});return true;}
   const record=q.instanceId===instanceId?invocations.get(q.operationId):null;if(!record){send(res,200,{version:1,...q,state:'unknown',drained:false});return true;}
   if(record.requestSha256!==q.requestSha256){send(res,409,{error:'MCP_REGISTRY_OPERATION_CONFLICT'});return true;}
   if(req.url.endsWith('/drain')){record.controller.abort();await record.settled.catch(()=>{});}
   send(res,200,{version:1,...q,state:record.state,drained:['completed','retired'].includes(record.state)});return true;
  }
  if(req.method==='POST'&&req.url==='/secureshop/mcp-registry/invoke'){
   const q=protocol.request(await body(req)),requestSha256=digest(q);
   if(q.instanceId!==instanceId){send(res,409,{error:'MCP_REGISTRY_INSTANCE_CHANGED'});return true;}
   if(invocations.has(q.operationId)){send(res,409,{error:'MCP_REGISTRY_OPERATION_CONFLICT'});return true;}
   // Retain drained outcomes for 60 seconds; never evict running/unknown work.
   // Host durable admission prevents replay. Expired/restarted IDs are unknown;
   // this short-lived transport cache makes no exactly-once claim.
   if(active>=maxConcurrent||invocations.size>=128){send(res,429,{error:'MCP_REGISTRY_HTTP_CAPACITY'});return true;}
   const controller=new AbortController(),record={controller,requestSha256,state:'running',settled:null};
   const abort=()=>controller.abort();const timer=setTimeout(abort,15000);
   req.once('aborted',abort);res.once('close',abort);if(req.aborted||res.destroyed)abort();invocations.set(q.operationId,record);active++;
   record.settled=(async()=>{try{const receipt=await executor.execute({invocation:q},{signal:controller.signal});record.state='completed';return receipt;}catch(error){record.state=error?.drained===true?'retired':'unknown';throw error;}finally{record.finishedAt=now();clearTimeout(timer);req.removeListener('aborted',abort);res.removeListener('close',abort);active--;}})();
   // A drain request waits for executor settlement, which follows supervisor
   // child close/descendant retirement. Disconnect alone is not that proof.
   record.settled.catch(()=>{});
   try{const receipt=await record.settled;send(res,200,{version:1,receipt});}catch{if(!res.destroyed)send(res,503,{error:'MCP_REGISTRY_INVOCATION_UNCERTAIN'});}return true;
  }
  if(req.method==='POST'&&req.url==='/secureshop/mcp-registry/execute'){
   if(active>=maxConcurrent){send(res,429,{error:'MCP_REGISTRY_HTTP_CAPACITY'});return true;}const input=await body(req);if(!input||Object.keys(input).sort().join(',')!=='activeEntries,mode,request'){send(res,400,{error:'MCP_REGISTRY_HTTP_INVALID'});return true;}
   active++;try{const changes=await executor.execute(input,{signal:AbortSignal.timeout(15000)});send(res,200,{version:1,changes});}
   catch(error){
    if(error?.code!=='MCP_REGISTRY_FIXED_DESTINATION_DENIED'||error.effectNotStarted!==true||error.drained!==true)throw error;
    const value=require('../../../server/services/secureshopMcpRegistryDiscoveryContract').validateDiscoveryDenial({version:1,
     error:error.code,effectNotStarted:true,operationId:error.operationId,registryRequestSha256:error.registryRequestSha256,
     policySha256:error.policySha256},input);
    send(res,403,value);
   }finally{active--;}return true;
  }
  return false;
 }
 return Object.freeze({handle,async close(){closed=true;for(const record of invocations.values())record.controller.abort();while(active)await new Promise(resolve=>setTimeout(resolve,10));}});
}
module.exports={createOwnedMcpRegistryHttpHandler,MCP_REGISTRY_CAPABILITY:CAPABILITY};
