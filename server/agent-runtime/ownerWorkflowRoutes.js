'use strict';
const {AsyncLocalStorage}=require('node:async_hooks');
const {OwnerWorkflowHttpError}=require('./ownerWorkflowHttpError');
const executionContext=new AsyncLocalStorage();
async function checkOwnerRun(){await executionContext.getStore()?.check?.();}
function ownerWorkflowRoute(coordinator,ownerFor,handler,{reset=false,beforePublish,scopeFor,withAdmission,timeoutFor}={}) {
 if(withAdmission!==undefined&&typeof withAdmission!=='function')throw new TypeError('Workflow admission must be a function');
 if(scopeFor!==undefined&&typeof scopeFor!=='function')throw new TypeError('Workflow scope mapper must be a function');
 if(timeoutFor!==undefined&&typeof timeoutFor!=='function')throw new TypeError('Workflow timeout mapper must be a function');
 if(reset&&timeoutFor!==undefined)throw new TypeError('Reset routes cannot use a workflow timeout mapper');
 if(reset&&scopeFor!==undefined)throw new TypeError('Reset routes cannot use a workflow scope mapper');
 return async function coordinatedRoute(req,res,next){
  const controller = new AbortController();
  const disconnected = () => {
   if (reset || res.writableEnded) return;
   const error = new Error('Client disconnected'); error.name = 'AbortError';
   controller.abort(error);
  };
  req.once?.('aborted', disconnected);
  res.once?.('close', disconnected);
  if (req.aborted || res.destroyed) disconnected();
  let payload,sent=false,sentMethod='json',checkPublication;
  let resolveResponse;
  const responseReady=new Promise(resolve=>{resolveResponse=resolve;});
  const buffered=new Proxy(res,{get(target,key){
   if(key==='json'||key==='send')return value=>{sentMethod=key;payload=value;sent=true;resolveResponse();return buffered;};
   if(key==='status')return code=>{target.status(code);return buffered;};
   const value=target[key];return typeof value==='function'? (...args)=>{const result=value.apply(target,args);return result===target?buffered:result;}:value;
  }});
  const execute=async execution=>executionContext.run(execution,async()=>{
   await handler(req,buffered,next);
   if(!sent) {
    const signal=execution?.signal;
    if(!signal)await responseReady;
    else {
     let aborted;
     try {
      await new Promise((resolve,reject)=>{
       aborted=()=>reject(signal.reason);
       signal.addEventListener('abort',aborted,{once:true});
       if(signal.aborted)aborted();
       else responseReady.then(resolve);
      });
     } finally { signal.removeEventListener('abort',aborted); }
    }
   }
   await checkOwnerRun();
   await beforePublish?.(req);
   await checkOwnerRun();
  });
  try{
   // Capture server-owned authority before coordinator admission performs any
   // asynchronous work. Request bodies are never forwarded implicitly.
   const owner=ownerFor(req);
   const scope=scopeFor?.(req);
   const timeoutMs=timeoutFor?.(req);
   if(timeoutMs!==undefined&&(!Number.isSafeInteger(timeoutMs)||timeoutMs<=0||timeoutMs>300000))throw new RangeError('Workflow timeout must be an integer between 1 and 300000');
   const coordinated=admission=>{
    if(withAdmission&&typeof admission?.check!=='function')throw new TypeError('Workflow admission guard required');
    if(admission?.checkPublication!==undefined){
     if(typeof admission.checkPublication!=='function')throw new TypeError('Publication admission check must be a function');
     // Only authority explicitly valid after admission release may opt in.
     const publication=admission.checkPublication;
     checkPublication=()=>Reflect.apply(publication,admission,[]);
    }
    if(admission?.wrapOwnsAdmission!==undefined&&typeof admission.wrapOwnsAdmission!=='boolean')throw new TypeError('Complete admission wrapper opt-in must be boolean');
    if(admission?.wrapOwnsAdmission===true&&typeof admission.wrap!=='function')throw new TypeError('Complete admission wrapper required');
    const admittedExecute=async execution=>{
     if(!admission)return execute(execution);
     // Server-owned opt-in: the complete wrapper already enforces this admission.
     // Distinct lifecycle guards keep the default layered path below.
     if(admission.wrapOwnsAdmission===true){
      const wrapped=admission.wrap(execution);
      const identities=['runId','ownerKey','generation','durableGeneration','signal'];
      const methods=['check','effect','effectWithReceipt','checkpoint','trace'];
      if(!wrapped||typeof wrapped.check!=='function'
       ||identities.some(key=>wrapped[key]!==execution?.[key])
       ||methods.some(key=>typeof execution?.[key]==='function'&&typeof wrapped[key]!=='function'))
       throw new TypeError('Complete admission wrapper must preserve run authority and methods');
      await wrapped.check();
      return execute(wrapped);
     }
     const check=async()=>{await admission.check();await execution?.check?.();await admission.check();};
     await check();
     const guarded={...execution,check};
     for(const method of ['effect','effectWithReceipt','checkpoint'])if(typeof execution?.[method]==='function'){
      guarded[method]=async(...args)=>{await check();const result=await execution[method](...args);await check();return result;};
     }
     const admittedExecution=typeof admission.wrap==='function'?admission.wrap(guarded):guarded;
     if(typeof admittedExecution?.check!=='function')throw new TypeError('Wrapped workflow admission guard required');
     return execute(admittedExecution);
    };
    return reset?coordinator.reset(owner,admittedExecute):coordinator.run(owner,{signal:controller.signal,
     ...(scope===undefined?{}:{scope}),...(timeoutMs===undefined?{}:{timeoutMs})},admittedExecute);
   };
   if(withAdmission)await withAdmission(owner,coordinated,req);
   else await coordinated();
   await checkPublication?.();
   if(!res.headersSent && !res.destroyed)res[sentMethod](payload);
  }catch(error){
   if(error?.code==='GRAPH_RUN_CAPACITY_EXCEEDED'){
    if(!res.headersSent&&!res.destroyed)res.status(503).json({error:'Agent capacity is unavailable.',code:'GRAPH_RUN_CAPACITY_EXCEEDED'});
    return;
   }
   if(error?.code==='SESSION_REVOKED'){
    if(!res.headersSent&&!res.destroyed)res.status(401).json({error:'Session is no longer current',code:'SESSION_REVOKED'});
    return;
   }
   if(error instanceof OwnerWorkflowHttpError){
    if(!res.headersSent && !res.destroyed){
     if(error.retryAfter)res.setHeader('Retry-After',String(error.retryAfter));
     res.status(error.status).json({error:error.message});
    }
    return;
   }
   if(!res.headersSent && !res.destroyed)res.status(error.name==='AbortError'?409:500).json({error:error.name==='AbortError'?'Request invalidated by reset':error.message});
  }finally{
   req.removeListener?.('aborted', disconnected);
   res.removeListener?.('close', disconnected);
  }
 };
}
module.exports={ownerWorkflowRoute,checkOwnerRun,withOwnerExecution:(execution,fn)=>executionContext.run(execution,fn),getOwnerExecution:()=>executionContext.getStore()};
