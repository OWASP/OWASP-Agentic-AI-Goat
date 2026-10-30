'use strict';
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {createSecureShopAuditRuntime}=require('./secureshopAuditRuntime');

async function createSecureShopAuditRuntimeLifecycle(options,{createRuntime=createSecureShopAuditRuntime,maxConcurrentRuns=2}={}){
  if(!Number.isSafeInteger(maxConcurrentRuns)||maxConcurrentRuns<1||maxConcurrentRuns>32)
    throw new TypeError('Audit concurrency must be an integer between 1 and 32');
  let activeRuns=0;
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-audit-runtime-'));
  const controller=new AbortController(),active=new Set();let closing;
  let runtime;
  try{await fs.chmod(root,0o700);runtime=createRuntime({...options,root});}
  catch(error){await fs.rm(root,{recursive:true,force:true});throw error;}
  const unavailable=()=>Object.assign(new Error('Audit runtime is closed'),{code:'AUDIT_RUNTIME_UNAVAILABLE'});
  const invoke=(method,input)=>{
    if(controller.signal.aborted)return Promise.reject(unavailable());
    const isRun=method==='run';
    if(isRun&&activeRuns>=maxConcurrentRuns)return Promise.reject(Object.assign(
      new Error('Audit summary capacity is busy; retry the same request'),{code:'AUDIT_RUNTIME_BUSY',statusCode:503}));
    const signal=input?.signal?AbortSignal.any([controller.signal,input.signal]):controller.signal;
    if(isRun)activeRuns++;
    const operation=Promise.resolve().then(()=>{
      signal.throwIfAborted();return runtime[method]({...input,signal});
    }).then(value=>{signal.throwIfAborted();return value;});
    const release=()=>{active.delete(operation);if(isRun)activeRuns--;};
    active.add(operation);operation.then(release,release);
    return operation;
  };
  return Object.freeze({
    createSession:input=>invoke('createSession',input),run:input=>invoke('run',input),
    close(){
      if(!closing){
        controller.abort(new DOMException('Audit runtime shutting down','AbortError'));
        closing=(async()=>{await Promise.allSettled([...active]);await fs.rm(root,{recursive:true,force:true});})();
      }
      return closing;
    },
  });
}
module.exports={createSecureShopAuditRuntimeLifecycle};
