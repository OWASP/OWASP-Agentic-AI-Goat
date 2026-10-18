'use strict';
// Process-local scheduling only; PostgreSQL remains the owner authority.
const queues=new WeakMap();
function admissionFor(pool){
 if(queues.has(pool))return queues.get(pool);
 const capacity=pool.options?.max??1;
 if(!Number.isSafeInteger(capacity)||capacity<1)throw new TypeError('Bounded lease pool required');
 const pending={run:[],lifecycle:[]},owners=new Map(),totals={run:0,lifecycle:0},lastOwner={run:null,lifecycle:null};let active=0,next='run';
 const limits={run:1024,lifecycle:256},ownerLimits={run:16,lifecycle:4};
 function pump(){
  while(active<capacity&&(pending.run.length||pending.lifecycle.length)){
   const kind=pending[next].length?next:next==='run'?'lifecycle':'run';next=kind==='run'?'lifecycle':'run';
   const index=pending[kind].findIndex(job=>job.owner!==lastOwner[kind]);const job=pending[kind].splice(index<0?0:index,1)[0];lastOwner[kind]=job.owner;const cleanup=job.remove();if(cleanup||pool.ending||pool.ended){job.retire();job.reject(cleanup||new Error('Graph lease pool is closing'));continue;}if(job.signal?.aborted){job.retire();job.reject(job.signal.reason);continue;}
   active++;let released=false;job.resolve(()=>{if(released)return;released=true;active--;job.retire();pump();});
  }
 }
 const api={acquire(owner,signal,kind='run'){
  if(typeof owner!=='string'||!owner||!Object.hasOwn(limits,kind))throw new TypeError('Lease admission coordinates required');
  if(signal?.aborted)return Promise.reject(signal.reason);
  if(pool.ending||pool.ended)return Promise.reject(new Error('Graph lease pool is closing'));
  const key=JSON.stringify([kind,owner]),count=owners.get(key)||0;
  if(totals[kind]>=limits[kind]||count>=ownerLimits[kind])return Promise.reject(Object.assign(new Error('Graph admission is full'),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503}));
  owners.set(key,count+1);totals[kind]++;
  return new Promise((resolve,reject)=>{
   let retired=false;const job={owner,signal,resolve,reject,retire(){if(retired)return;retired=true;totals[kind]--;const n=owners.get(key)-1;if(n)owners.set(key,n);else owners.delete(key);},remove(){try{signal?.removeEventListener('abort',abort);}catch(error){return error;}}};
   const abort=()=>{const index=pending[kind].indexOf(job);if(index<0)return;pending[kind].splice(index,1);const cleanup=job.remove();job.retire();reject(cleanup?new AggregateError([signal.reason,cleanup],'Graph admission cancellation cleanup failed'):signal.reason);pump();};
   pending[kind].push(job);
   try{signal?.addEventListener('abort',abort,{once:true});}catch(error){pending[kind].splice(pending[kind].indexOf(job),1);job.remove();job.retire();reject(error);return;}
   if(signal?.aborted)abort();else pump();
  });
 },snapshot:()=>Object.freeze({capacity,active,queuedRuns:pending.run.length,queuedLifecycle:pending.lifecycle.length})};
 queues.set(pool,api);return api;
}
module.exports={admissionFor};
