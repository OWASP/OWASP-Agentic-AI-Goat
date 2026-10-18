'use strict';
// Unwired local-channel adapter. The injected channel must obtain peer metadata
// from OS credentials, never from worker-supplied JSON. No socket is opened here.
const C=require('./secureshopOwnedMcpInvocationContract');
const W=require('./secureshopOwnedMcpInvocationWire');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const isId=v=>typeof v==='string'&&UUID.test(v);
const fail=()=>Object.assign(Error('Owned supervisor proof unavailable'),{code:'MCP_INVOCATION_SUPERVISOR_UNAVAILABLE'});
const exact=(v,keys)=>v&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
function intent(raw){const q=C.bounded(raw,1024);if(!exact(q,['invocationId','workerId','bootId'])||!Object.values(q).every(isId))throw fail();return C.freeze(q);}
function createInvocationSupervisorChannel({channel,identity,timeoutMs=15000}={}){
 const expected=C.freeze(C.bounded(identity,2048));
 if(typeof channel?.exchange!=='function'||!exact(expected,['managerInstanceId','volumeId','supervisorEpoch','runtimeSha256','peerUid','peerPid'])||!['managerInstanceId','volumeId','supervisorEpoch'].every(k=>isId(expected[k]))||typeof expected.runtimeSha256!=='string'||!/^[a-f0-9]{64}$/.test(expected.runtimeSha256)||!Number.isSafeInteger(expected.peerUid)||expected.peerUid<0||!Number.isSafeInteger(expected.peerPid)||expected.peerPid<1||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>15000)throw TypeError('Pinned private supervisor channel required');
 const exchange=channel.exchange.bind(channel);
 async function request(operation,q,claim){const controller=new AbortController(),requestId=require('node:crypto').randomUUID();let timer;
  const message=C.freeze({version:'owned-mcp-supervisor-v1',operation,requestId,identity:expected,intent:q,...(claim?{claim}:{})});
  try{const raw=await Promise.race([exchange(message,{signal:controller.signal}),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(fail());},timeoutMs);})]);
   // peer is out-of-band, supplied only by the trusted socket adapter.
   const reply=C.bounded(raw,131072);if(!exact(reply,['peer','body'])||C.digest(reply.peer)!==C.digest(expected))throw fail();const b=reply.body;if(!exact(b,['version','requestId','operation','intent','state','drained',...(Object.hasOwn(b||{},'result')?['result']:[])])||b.version!==message.version||b.requestId!==requestId||b.operation!==operation||C.digest(b.intent)!==C.digest(q)||!['completed','failed_before_effect','uncertain'].includes(b.state)||b.drained!==true||b.state==='completed'&&!Object.hasOwn(b,'result'))throw fail();
   if(operation==='start')return C.freeze({state:b.state,result:C.bounded(b.result??null,65536),proof:{...q,drained:true}});
   // Drain/readback proves absence only. Without a manager-persisted outcome,
   // current manager recovery stays uncertain; it never manufactures success.
   return C.freeze({...q,drained:true});
  }finally{clearTimeout(timer);}
 }
 function start(raw){const value=C.bounded(raw,196608);if(!exact(value,['intent','claim']))throw fail();const q=intent(value.intent),claim=W.claim(value.claim);if(claim.invocationId!==q.invocationId||claim.managerInstanceId!==expected.managerInstanceId||claim.runtimeSha256!==expected.runtimeSha256)throw fail();return Object.freeze({completion:request('start',q,claim),stop:()=>request('drain',q)});}
 return Object.freeze({start,reconcile:raw=>request('status',intent(raw))});
}
module.exports={createInvocationSupervisorChannel};
