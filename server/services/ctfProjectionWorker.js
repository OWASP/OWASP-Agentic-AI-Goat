'use strict';
// Explicitly invoked internal batch only. No timer, startup hook or auto-retry.
const {withCtfTransaction,isCtfDeletionDeferred}=require('../database/postgres/ctfLifecycleRepository');
const {applyCtfProjection}=require('../database/postgres/ctfProjectionRepository');
const {applyCtfDecisionProjection}=require('../database/postgres/ctfDecisionProjectionAdapter');
const {applyCtfHeartbeat}=require('../database/postgres/ctfTelemetryProjection');
async function projectCtfBatch({identity,ctfPool,signal,maxEvents=4,timeoutMs=10000}){
 if(!Number.isInteger(maxEvents)||maxEvents<1||maxEvents>16||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000)throw new TypeError('Invalid CTF worker bounds');
 const controller=new AbortController();const cancel=()=>controller.abort();signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
 const timer=setTimeout(cancel,timeoutMs),outcomes=[];
 try{
  for(let i=0;i<maxEvents;i++){
   if(controller.signal.aborted)throw new Error('CTF_WORKER_CANCELLED');
   // Each call releases its store connection before the next one is acquired.
   const event=await identity.next({signal:controller.signal});if(!event)break;
   if(isCtfDeletionDeferred(event)){outcomes.push({operationId:event.operationId,sequence:event.sequence,state:'deferred'});break;}
   const receipt=await withCtfTransaction(ctfPool,client=>(event.command?.kind==='decision'?applyCtfDecisionProjection:event.command?.kind==='heartbeat'?applyCtfHeartbeat:applyCtfProjection)(client,event),{signal:controller.signal});
   const ack=await identity.acknowledge(event,receipt,{signal:controller.signal});
   outcomes.push({operationId:event.command.operationId,sequence:event.sequence,state:ack.state});
   if(ack.state!=='applied')break;
  }
  return outcomes;
 }finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);}
}
module.exports={projectCtfBatch};
