'use strict';
// Foundation only: deliberately no production factory or HTTP route installs it.
const C=require('./secureshopOwnedMcpInvocationContract');
const uncertain=new WeakSet();
const denied=()=>Object.assign(new Error('Owned MCP invocation unavailable'),{code:'MCP_INVOCATION_DENIED'});
function createOwnedMcpInvocationAdapter({snapshot,runId,requestId,mode,signal,assertAuthority,readCurrent,readApproval,assertEffectAuthorized,validateArguments,transport,timeoutMs=15000}={}){
 if(![assertAuthority,readCurrent,readApproval,assertEffectAuthorized,validateArguments,transport?.invoke].every(fn=>typeof fn==='function')||!['vuln','fixed'].includes(mode)||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000)throw denied();
 // Capture caller data synchronously, before any authority/read awaits.
 const invokeTransport=transport.invoke.bind(transport);
 const admitted=C.snapshot(snapshot),snapshotSha256=C.digest(admitted),namespace='owned_'+admitted.entryId.replaceAll('-',''),calls=new Set();
 C.request({snapshot:admitted,runId,requestId,callId:'admission',toolIndex:0,args:{},mode});
 const tools=C.freeze(admitted.tools.map((tool,index)=>({agent:namespace,tool:'tool_'+index,description:tool.description,inputSchema:tool.inputSchema,isExternalMcp:true})));
 async function current(){signal?.throwIfAborted();await assertAuthority(admitted.binding);signal?.throwIfAborted();const found=C.snapshot(await readCurrent(admitted.binding,admitted.entryId));if(C.digest(found)!==snapshotSha256)throw denied();await assertAuthority(admitted.binding);signal?.throwIfAborted();}
 async function policy(){const p=C.bounded(await readApproval(admitted),1024);if(!p||Object.keys(p).sort().join()!=='approved,policySha256'||typeof p.approved!=='boolean'||typeof p.policySha256!=='string'||!/^[0-9a-f]{64}$/.test(p.policySha256))throw denied();if(mode==='fixed'&&!p.approved)throw denied();return C.freeze(p);}
 function callTool(agent,alias,args,context){
  const index=tools.findIndex(tool=>tool.tool===alias);if(agent!==namespace||index<0)throw denied();
  const req=C.request({snapshot:admitted,runId,requestId,callId:context?.callId,toolIndex:index,args,mode});
  if(calls.has(req.callId)||calls.size>=64)throw denied();calls.add(req.callId);
  return invoke(req,index);
 }
 async function invoke(req,index){
  await current();const approval=await policy();
  // Trusted synthetic-asset schema validator must reject, not rewrite arguments.
  const validated=await validateArguments(admitted,admitted.tools[index].name,req.args);if(validated!==true)throw denied();
  if(await assertEffectAuthorized(req)!==true)throw denied();await current();if(C.digest(await policy())!==C.digest(approval))throw denied();await current();
  const controller=new AbortController(),abort=()=>controller.abort(),timer=setTimeout(abort,timeoutMs);signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  let onAbort;const interrupted=new Promise((_,reject)=>{onAbort=()=>reject(denied());controller.signal.addEventListener('abort',onAbort,{once:true});});
  try{
   controller.signal.throwIfAborted();
   const raw=await Promise.race([invokeTransport(req,{signal:controller.signal}),interrupted]);
   controller.signal.throwIfAborted();const receipt=C.receipt(raw,req,approval);await current();
   const latest=await policy();if(C.digest(latest)!==C.digest(approval)||await assertEffectAuthorized(req)!==true)throw denied();await current();controller.signal.throwIfAborted();
   // A future durable observer must join this receipt to a completed graph
   // effect. Returning it here is not persisted evidence or objective credit.
   return C.freeze({content:[{type:'text',text:JSON.stringify(receipt.result)}],_meta:{ownedRegistryInvocation:{request:req,receipt}}});
  }catch(cause){const error=Object.assign(new Error('Owned MCP invocation outcome requires authoritative readback'),{code:'MCP_INVOCATION_OUTCOME_UNCERTAIN',automaticRetry:false});Object.defineProperty(error,'cause',{value:cause});uncertain.add(error);throw error;}
  finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',onAbort);}
 }
 return Object.freeze({snapshotSha256,manifest:Object.freeze({getForRole:role=>role==='admin'?tools:Object.freeze([])}),pool:Object.freeze({callTool}),assertCurrent:current});
}
module.exports={createOwnedMcpInvocationAdapter,isOwnedMcpInvocationUncertain:error=>uncertain.has(error)};
