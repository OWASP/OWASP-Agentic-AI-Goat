'use strict';
// Dependency-injected private HTTP boundary only; no listener/route is installed.
const crypto=require('node:crypto');
const C=require('./secureshopOwnedMcpInvocationContract');
const W=require('./secureshopOwnedMcpInvocationWire');
const fail=()=>Object.assign(Error('Private invocation transport unavailable'),{code:'MCP_INVOCATION_TRANSPORT_UNAVAILABLE'});
const routes=Object.freeze({claim:'/secureshop/mcp-invocation/v1/claim',status:'/secureshop/mcp-invocation/v1/status',retire:'/secureshop/mcp-invocation/v1/retire'});
function response(value,request,operation){
 const v=C.bounded(value,196608);
 if(operation==='retire'){if(C.digest(v)!==C.digest({...request,retired:true,drained:true}))throw fail();return C.freeze(v);}
 const q=operation==='claim'?{invocationId:request.invocationId,requestSha256:C.digest(request.request),managerInstanceId:request.managerInstanceId,runtimeSha256:request.runtimeSha256}:request;
 if(Object.entries(q).some(([k,x])=>v[k]!==x)||!['absent','running','completed','failed_before_effect','uncertain'].includes(v.state)||typeof v.drained!=='boolean'||(['completed','failed_before_effect'].includes(v.state)&&!v.drained))throw fail();
 const keys=['invocationId','requestSha256','managerInstanceId','runtimeSha256','state','drained',...(Object.hasOwn(v,'result')?['result','resultSha256']:[])];
 if(['running','absent'].includes(v.state)&&(v.drained||Object.hasOwn(v,'result')))throw fail();
 if(Object.keys(v).sort().join()!==keys.sort().join()||Object.hasOwn(v,'result')&&C.digest(v.result)!==v.resultSha256||v.state==='completed'&&!Object.hasOwn(v,'result'))throw fail();return C.freeze(v);
}
function createInvocationClient({exchange,signer,timeoutMs=15000}={}){
 if(typeof exchange!=='function'||typeof signer?.sign!=='function'||typeof signer?.verify!=='function'||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000)throw TypeError('Private pinned exchange and signer required');
 async function send(operation,raw,{signal}={}){const request=W[operation==='status'?'lookup':operation==='retire'?'fence':'claim'](raw);signal?.throwIfAborted();const envelope=signer.sign(operation,request);const controller=new AbortController();const abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});let timer;let wire;try{wire=await Promise.race([exchange(routes[operation],envelope,{signal:controller.signal}),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(fail());},timeoutMs);})]);}finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}signal?.throwIfAborted();const receipt=signer.verify('receipt',wire);if(receipt.operation!==operation||receipt.envelopeSha256!==C.digest(envelope)||Object.keys(receipt).sort().join()!=='envelopeSha256,operation,value')throw fail();return response(receipt.value,request,operation);}
 return Object.freeze({claim:(q,o)=>send('claim',q,o),status:(q,o)=>send('status',q,o),retire:(q,o)=>send('retire',q,o)});
}
function createInvocationHttpHandler({token,signer,manager,maxConcurrent=2}={}){
 if(typeof token!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(token)||typeof signer?.verify!=='function'||typeof signer?.sign!=='function'||!['claim','status','retire'].every(k=>typeof manager?.[k]==='function')||!Number.isInteger(maxConcurrent)||maxConcurrent<1||maxConcurrent>4)throw TypeError('Private invocation HTTP dependencies required');
 let active=0;const expected=Buffer.from('Bearer '+token);
 const send=(res,status,value)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(value));};
 async function handle(req,res){const operation=Object.keys(routes).find(k=>req.url===routes[k]);if(!operation)return false;
  const supplied=typeof req.headers?.authorization==='string'&&req.headers.authorization.length<=135?Buffer.from(req.headers.authorization):Buffer.alloc(0);if(supplied.length!==expected.length||!crypto.timingSafeEqual(supplied,expected)){send(res,401,{error:'MCP_INVOCATION_UNAUTHORIZED'});return true;}
  if(req.method!=='POST'){send(res,405,{error:'MCP_INVOCATION_METHOD'});return true;}if(active>=maxConcurrent){send(res,429,{error:'MCP_INVOCATION_CAPACITY'});return true;}active++;
  let timer;try{const bytes=await Promise.race([(async()=>{let size=0;const parts=[];for await(const chunk of req){size+=chunk.length;if(size>262144)throw fail();parts.push(chunk);}return Buffer.concat(parts);})(),new Promise((_,reject)=>{timer=setTimeout(()=>{req.destroy?.();reject(fail());},15000);})]);clearTimeout(timer);const envelope=JSON.parse(bytes.toString('utf8'));const raw=signer.verify(operation,envelope),request=W[operation==='status'?'lookup':operation==='retire'?'fence':'claim'](raw);const value=response(await manager[operation](request),request,operation);send(res,200,signer.sign('receipt',{operation,envelopeSha256:C.digest(envelope),value}));}
  catch{send(res,503,{error:'MCP_INVOCATION_UNAVAILABLE'});}finally{clearTimeout(timer);active--;}return true;
 }
 return Object.freeze({handle});
}
module.exports={createInvocationClient,createInvocationHttpHandler};
