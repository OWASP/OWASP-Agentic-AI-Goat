'use strict';
const {projectCtfBatch}=require('./ctfProjectionWorker');
const failureCodes=new Set(['CTF_DELIVERY_ACTIVATION_UNAVAILABLE','CTF_TRANSACTION_UNCERTAIN',
 'CTF_LEGACY_EVENT_REQUIRES_RECOVERY','CTF_DELETION_IDENTITY_MISMATCH','CTF_COMMAND_ENCODING_MISMATCH',
 '55P03','57014','53300','40P01','40001','42501','42P01','08001','08006']);
const literalFailureMessages=new Set(['CTF_LEGACY_EVENT_REQUIRES_RECOVERY','CTF_DELETION_IDENTITY_MISMATCH','CTF_COMMAND_ENCODING_MISMATCH']);
const failureCode=error=>{
 let code,message;
 try{code=error?.code;message=error?.message;}catch{return 'other';}
 if(failureCodes.has(code))return code;
 return literalFailureMessages.has(message)?message:'other';
};

// Internal process lifecycle only. Construction never activates authority, runs
// migrations, acquires a connection or calls a model. Readiness is supplied by
// trusted application composition, not a request or bootstrap PREPARED flag.
function createCtfProjectionWorkerLifecycle({identity,ctfPool,readiness,pollMs=250,maxEvents=4,batchTimeoutMs=10000,drainMs=5000}) {
 if(!identity||typeof identity.next!=='function'||typeof identity.acknowledge!=='function'||!ctfPool||typeof ctfPool.connect!=='function'||typeof readiness!=='function')throw new TypeError('CTF worker dependencies required');
 for(const [value,min,max] of [[pollMs,10,60000],[maxEvents,1,16],[batchTimeoutMs,1,30000],[drainMs,1,30000]])if(!Number.isInteger(value)||value<min||value>max)throw new TypeError('Invalid CTF lifecycle bounds');
 let state='paused',active=null,controller=null,timer=null,lastOutcome='not_started',lastFailurePhase=null,lastFailureCode=null;
 const status=()=>Object.freeze({state,active:active!==null,ready:state==='running'&&lastOutcome==='applied',lastOutcome,lastFailurePhase,lastFailureCode});
 function unschedule(){clearTimeout(timer);timer=null;}
 function schedule(delay=pollMs){
  if(state!=='running'||active||timer!==null)return;
  timer=setTimeout(()=>{timer=null;cycle();},delay);
 }
 function cycle(requestedMax=maxEvents){
  if(state!=='running'||active)return;
  controller=new AbortController();const owned=controller;
  const deadline=setTimeout(()=>{lastOutcome='deadline';if(state==='running')state='paused';owned.abort();},batchTimeoutMs);
  // Set active before invoking dependencies, including synchronous/reentrant
  // readiness callbacks. Cancellation never releases this slot early.
  let phase='readiness';
  active=Promise.resolve().then(async()=>{
   const ready=await readiness({signal:owned.signal});
   if(owned.signal.aborted||state!=='running')return;
   if(ready!==true){state='paused';lastOutcome='not_ready';return;}
   phase='projection';
   const outcomes=await projectCtfBatch({identity,ctfPool,signal:owned.signal,maxEvents:requestedMax,timeoutMs:batchTimeoutMs});
   if(owned.signal.aborted||state!=='running')return;
   if(outcomes.some(x=>x.state==='deferred')){lastOutcome='deferred';return;}
   if(outcomes.some(x=>x.state!=='applied')){state='paused';lastOutcome='blocked';return;}
   lastOutcome='applied';
  }).catch(error=>{
   // Closed diagnostics only: never retain arbitrary error text, SQL or event data.
   // An uncertain transaction requires explicit recovery, not a polling retry.
   if(!owned.signal.aborted){lastOutcome='failed';lastFailurePhase=phase;lastFailureCode=failureCode(error);if(state==='running')state='paused';}
  }).finally(()=>{
   clearTimeout(deadline);active=null;controller=null;schedule();
  });
 }
 async function halt(terminal){
  if(terminal)state='stopped';else if(state!=='stopped')state='paused';
  unschedule();controller?.abort();
  const pending=active;
  if(!pending)return Object.freeze({...status(),drained:true});
  let timeout;
  const drained=await Promise.race([pending.then(()=>true),new Promise(resolve=>{timeout=setTimeout(()=>resolve(false),drainMs);})]);
  clearTimeout(timeout);
  // A timed-out drain is not cleanup success. The caller must not close pools
  // or announce a restart until active has actually settled.
  return Object.freeze({...status(),drained});
 }
 return Object.freeze({status,start(){
  if(state==='stopped')throw new Error('CTF worker stopped');
  if(state==='running')return status();
  if(active)throw new Error('CTF worker still draining');
  state='running';lastOutcome='checking';lastFailurePhase=null;lastFailureCode=null;schedule(0);return status();
 },async pump({maxEvents:requestedMax=1,signal}={}){
  if(!Number.isInteger(requestedMax)||requestedMax<1||requestedMax>maxEvents)throw new TypeError('Invalid CTF pump bound');
  signal?.throwIfAborted();
  if(state!=='running')return status();
  unschedule();if(!active)cycle(requestedMax);const pending=active;
  let listener,waitTimer;
  const waitBound=new Promise(resolve=>{waitTimer=setTimeout(resolve,batchTimeoutMs+drainMs);});
  const cancelled=new Promise((_,reject)=>{if(!signal)return;listener=()=>reject(Object.assign(new Error('CTF pump wait cancelled'),{code:'CTF_REQUEST_CANCELLED'}));signal.addEventListener('abort',listener,{once:true});if(signal.aborted)listener();});
  try{await Promise.race([pending,cancelled,waitBound]);return status();}finally{clearTimeout(waitTimer);if(listener)signal.removeEventListener('abort',listener);}

 },wake(){if(state==='running'&&!active){unschedule();schedule(0);}return status();},pause:()=>halt(false),stop:()=>halt(true)});
}
module.exports={createCtfProjectionWorkerLifecycle};
