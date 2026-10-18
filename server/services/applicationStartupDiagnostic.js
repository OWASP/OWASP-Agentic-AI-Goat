'use strict';
// Closed startup diagnostics only: never serialize an exception, message or stack.
const categories=new Map([
 ['CTF_DELIVERY_ACTIVATION_UNAVAILABLE','ctf_prerequisite'],
 ['ERR_POSTGRES_REQUIRED','postgres_configuration'],
 ['MIGRATION_HISTORY_MISMATCH','postgres_migration'],
 ...['APPLICATION_MAINTENANCE_DIRTY','APPLICATION_MAINTENANCE_CONTROL_UNAVAILABLE','APPLICATION_MAINTENANCE_CONTROL_INVALID','APPLICATION_MAINTENANCE_VERSION_MISMATCH','APPLICATION_MAINTENANCE_BUSY','APPLICATION_LEASE_CONNECT_TIMEOUT','APPLICATION_LEASE_QUERY_TIMEOUT','APPLICATION_LEASE_ACQUIRE_FAILED','APPLICATION_LEASE_ACQUIRE_AND_CLOSE_FAILED','APPLICATION_LEASE_LOST','APPLICATION_LEASE_NOT_HELD'].map(code=>[code,'postgres_readiness'])
]);
function ownData(value,key){
 try{const descriptor=Object.getOwnPropertyDescriptor(value,key);return descriptor&&Object.hasOwn(descriptor,'value')?descriptor.value:undefined;}catch{return undefined;}
}
function projectStartupDiagnostic(error){
 const queue=[{value:error,depth:0}],seen=new Set();
 for(let cursor=0;cursor<queue.length&&cursor<8;cursor++){
  const {value,depth}=queue[cursor];
  if(!value||(typeof value!=='object'&&typeof value!=='function')||seen.has(value))continue;
  seen.add(value);
  const code=ownData(value,'code');
  if(typeof code==='string'&&categories.has(code))return Object.freeze({code:'APPLICATION_START_FAILED',category:categories.get(code),reason:code});
  if(depth>=3)continue;
  if(queue.length<8)queue.push({value:ownData(value,'cause'),depth:depth+1});
  const errors=ownData(value,'errors');
  // Fixed indexed reads avoid custom iterators, length getters and unbounded lists.
  for(let i=0;i<4&&queue.length<8;i++)if(errors&&typeof errors==='object')queue.push({value:ownData(errors,String(i)),depth:depth+1});
 }
 return Object.freeze({code:'APPLICATION_START_FAILED',category:'unknown',reason:'UNCLASSIFIED_STARTUP_ERROR'});
}
function reportStartupDiagnostic(error,emit){
 try{emit('application_start_failed',projectStartupDiagnostic(error));}catch{/* Diagnostics must not interfere with shutdown or rejection. */}
}
module.exports={projectStartupDiagnostic,reportStartupDiagnostic};
