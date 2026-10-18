'use strict';
// Owned workload primitive. No retries, credentials or response bodies in metrics.
const {performance}=require('node:perf_hooks');
function createBoundedClient({request,maxOutstanding=200,maxRequests=12000,now=()=>performance.now()}){
 if(typeof request!=='function'||!Number.isSafeInteger(maxOutstanding)||maxOutstanding<1||maxOutstanding>1025||!Number.isSafeInteger(maxRequests)||maxRequests<1||maxRequests>12000)throw new TypeError('Invalid workload boundary');
 let active=0,peak=0,admitted=0;const owners=new Set(),metrics=[];
 async function call({owner,endpoint,operation,timeoutMs=10000,signal}){
  if(typeof owner!=='string'||!owner||typeof endpoint!=='string'||!/^\/[a-zA-Z0-9/_:-]+$/.test(endpoint)||typeof operation!=='function'||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000)throw new TypeError('Invalid declared request');
  if(owners.has(owner)||active>=maxOutstanding||admitted>=maxRequests)throw new Error('WORKLOAD_BOUND_EXCEEDED');
  signal?.throwIfAborted();const controller=new AbortController();let timer,listener;let rejectAbort;
  const aborted=new Promise((_,reject)=>{rejectAbort=reject;});
  const abort=()=>{controller.abort();rejectAbort(Object.assign(new Error('Owned request aborted'),{name:'AbortError'}));};
  if(signal){listener=abort;signal.addEventListener('abort',listener,{once:true});}
  admitted++;active++;peak=Math.max(peak,active);owners.add(owner);const start=now();let status=null,outcome='error';
  timer=setTimeout(()=>{controller.abort();rejectAbort(Object.assign(new Error('Owned request deadline'),{name:'TimeoutError'}));},timeoutMs);
  try{const result=await Promise.race([Promise.resolve().then(()=>{controller.signal.throwIfAborted();return request(operation,controller.signal);}),aborted]);
   if(!result||!Number.isInteger(result.status)||result.status<100||result.status>599)throw new Error('Invalid HTTP observation');status=result.status;outcome='response';return result;
  }catch(error){outcome=error.name==='TimeoutError'?'timeout':error.name==='AbortError'?'cancelled':'error';throw error;
  }finally{clearTimeout(timer);if(signal&&listener)signal.removeEventListener('abort',listener);controller.abort();owners.delete(owner);active--;metrics.push(Object.freeze({endpoint,status,outcome,elapsedMs:Math.max(0,now()-start)}));}
 }
 return Object.freeze({call,snapshot:()=>Object.freeze({active,peak,requests:metrics.map(x=>({...x}))})});
}
function summarize(samples){
 if(!Array.isArray(samples)||!samples.length||samples.some(x=>!Number.isFinite(x.elapsedMs)||x.elapsedMs<0))throw new Error('Capacity samples unavailable');
 const sorted=samples.map(x=>x.elapsedMs).sort((a,b)=>a-b),at=p=>sorted[Math.min(sorted.length-1,Math.ceil(p*sorted.length)-1)];
 return{count:sorted.length,p50:at(.5),p95:at(.95),p99:at(.99),max:sorted.at(-1)};
}
module.exports={createBoundedClient,summarize};
