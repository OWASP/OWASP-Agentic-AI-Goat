'use strict';
const http=require('node:http'),crypto=require('node:crypto');
const {createMcpTargetStore}=require('../mcpTargets');
const {createOwnedHttpExecutor}=require('./executor');
const {createOwnedHttpOperationStore}=require('./operationStore');
function createOwnedHttpService({token,root,profile,maxActive=2,maxPending=32}={}){
 if(!/^[A-Za-z0-9_-]{43,128}$/.test(token||'')||!root||!Number.isSafeInteger(maxActive)||maxActive<1||maxActive>4||!Number.isSafeInteger(maxPending)||maxPending<0||maxPending>64)throw TypeError('Private HTTP service configuration required');
 const targets=createMcpTargetStore({root,fixtureRoot:'/opt/lab-template'}),executor=createOwnedHttpExecutor({expectedProfile:profile});
 const operations=createOwnedHttpOperationStore({targetStore:targets,executor:executor.execute,checkReadiness:executor.checkReadiness});
 const authority=async()=>true;let active=0;const queue=[],inflight=new Set(),controllers=new Set();
 function failure(code){return Object.assign(Error(code),{code});}
 async function slot(signal,work){
  if(signal.aborted)throw failure('HTTP_OPERATION_ABORTED');
  if(active>=maxActive){if(queue.length>=maxPending)throw failure('HTTP_CAPACITY_EXCEEDED');await new Promise((resolve,reject)=>{
   const item={resolve:()=>{cleanup();resolve();}};const remove=()=>{const index=queue.indexOf(item);if(index>=0)queue.splice(index,1);};
   const abort=()=>{remove();cleanup();reject(failure('HTTP_OPERATION_ABORTED'));};
   const timer=setTimeout(()=>{remove();cleanup();reject(failure('HTTP_QUEUE_TIMEOUT'));},10000);
   const cleanup=()=>{clearTimeout(timer);signal.removeEventListener('abort',abort);};signal.addEventListener('abort',abort,{once:true});queue.push(item);
  });}else active++;
  try{if(signal.aborted)throw failure('HTTP_OPERATION_ABORTED');return await work();}
  finally{const next=queue.shift();if(next)next.resolve();else active--;}
 }
 const exact=(body,keys)=>{if(!body||Object.keys(body).sort().join(',')!==keys.sort().join(','))throw failure('HTTP_REQUEST_INVALID');};
 const internal=scope=>{exact(scope,['targetId','platformOwnerId','platformSessionId','generation']);return {targetId:scope.targetId,ownerId:scope.platformOwnerId,platformSessionId:scope.platformSessionId,generation:scope.generation};};
 const server=http.createServer(async(req,res)=>{
  let finish;const done=new Promise(resolve=>{finish=resolve;});inflight.add(done);
  const controller=new AbortController();controllers.add(controller);res.once('close',()=>{if(!res.writableEnded)controller.abort();});
  try{
   const supplied=Buffer.from(req.headers.authorization||''),expected=Buffer.from('Bearer '+token);
   if(supplied.length!==expected.length||!crypto.timingSafeEqual(supplied,expected))throw failure('HTTP_UNAUTHORIZED');
   if(req.method!=='POST')throw failure('HTTP_REQUEST_INVALID');let size=0,chunks=[];
   for await(const chunk of req){size+=chunk.length;if(size>8192)throw failure('HTTP_REQUEST_INVALID');chunks.push(chunk);}
   const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));let value;
   if(req.url==='/owned-http/readiness'){exact(body,[]);await targets.checkReadiness();value=await executor.checkReadiness();}
   else if(req.url==='/owned-http/admit'){exact(body,['scope']);await executor.checkReadiness();const binding=internal(body.scope);let owned;try{owned=await targets.recoverTarget(binding,{authorize:authority});}catch(error){if(error.code!=='TARGET_INCOMPLETE')throw error;try{owned=await targets.provisionTarget(binding,{authorize:authority});}catch(provisionError){if(provisionError.code!=='TARGET_ALREADY_EXISTS')throw provisionError;owned=await targets.recoverTarget(binding,{authorize:authority});}}value={scope:body.scope,capability:owned.capability};}
   else if(req.url==='/owned-http/retire'||req.url==='/owned-http/retirement'){exact(body,['scope','operationId']);const binding=internal(body.scope);value=req.url.endsWith('/retire')?await targets.retireTarget(binding,{operationId:body.operationId,authorize:authority}):await targets.readRetirementReceipt(binding,{operationId:body.operationId,authorize:authority});}
   else if(req.url==='/owned-http/execute'){exact(body,['capability','request']);value=await slot(controller.signal,()=>operations.execute(body.capability,authority,body.request,{signal:controller.signal}));}
   else if(req.url==='/owned-http/receipt'){exact(body,['capability','operationId','requestDigest']);value=await operations.readReceipt(body.capability,authority,body);}
   else throw failure('HTTP_REQUEST_INVALID');
   if(!res.destroyed){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(value));}
  }catch(error){if(!res.destroyed){res.writeHead(error.code==='HTTP_UNAUTHORIZED'?401:409,{'content-type':'application/json'});res.end(JSON.stringify({error:error.code||'HTTP_SERVICE_FAILED'}));}}finally{controllers.delete(controller);inflight.delete(done);finish();}
 });server.maxConnections=64;server.requestTimeout=15000;server.headersTimeout=5000;
 server.shutdown=async()=>{for(const controller of controllers)controller.abort();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await Promise.allSettled([...inflight]);};
 return server;
}
if(require.main===module){const server=createOwnedHttpService({token:process.env.MCP_OWNED_HTTP_TOKEN,root:process.env.MCP_OWNED_HTTP_ROOT,profile:process.env.MCP_OWNED_TARGET_APPARMOR_PROFILE});server.listen(Number(process.env.MCP_OWNED_HTTP_PORT||8091),'0.0.0.0');for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{server.shutdown().catch(()=>{process.exitCode=1;});});}
module.exports={createOwnedHttpService};
