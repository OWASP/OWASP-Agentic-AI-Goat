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

const diagnosticFrames=Object.freeze(['server/index.js','server/applicationServer.js','server/services/ctfAuthorityProduction.js','server/services/applicationMaintenanceLease.js','server/database/postgres/applicationMaintenanceControl.js','server/database/postgres/ctfDeliveryActivation.js','server/database/postgres/ctfDeliveryPool.js']);
const diagnosticCodes=new Set(['MODULE_NOT_FOUND','ERR_MODULE_NOT_FOUND','ERR_INVALID_ARG_TYPE','ERR_INVALID_ARG_VALUE','ERR_ASSERTION','ENOENT','EACCES','EPERM','ECONNREFUSED','ECONNRESET','ETIMEDOUT','42P01','42703','42501','28P01','53300','23505','23503']);

const nativeErrorTypes=require('node:util').types;
const nativeStackGetter=Object.getOwnPropertyDescriptor(new Error(),'stack').get;
const nativeErrorNames=new Map([[Error.prototype,'Error'],[TypeError.prototype,'TypeError'],[ReferenceError.prototype,'ReferenceError'],[SyntaxError.prototype,'SyntaxError'],[RangeError.prototype,'RangeError'],[EvalError.prototype,'EvalError'],[URIError.prototype,'URIError'],[AggregateError.prototype,'AggregateError']]);
function nativeErrorFields(error){
 try{
  if(!nativeErrorTypes.isNativeError(error))return {};
  const prototype=Object.getPrototypeOf(error),name=nativeErrorNames.get(prototype);
  if(!name)return {};
  if(prototype!==Error.prototype&&Object.getPrototypeOf(prototype)!==Error.prototype)return {};
  for(const key of ['name','message']){
   const own=Object.getOwnPropertyDescriptor(error,key);
   if(own&&(!Object.hasOwn(own,'value')||typeof own.value!=='string'||own.value.length>4096))return {};
   for(const p of [prototype,Error.prototype]){
    const value=Object.getOwnPropertyDescriptor(p,key);
    if(value&&(!Object.hasOwn(value,'value')||typeof value.value!=='string'||value.value.length>4096))return {};
   }
  }
  const descriptor=Object.getOwnPropertyDescriptor(error,'stack');
  if(!descriptor||descriptor.get!==nativeStackGetter)return {name};
  const formatter=Object.getOwnPropertyDescriptor(Error,'prepareStackTrace');
  for(let p=Object.getPrototypeOf(Error);p;p=Object.getPrototypeOf(p))if(Object.getOwnPropertyDescriptor(p,'prepareStackTrace'))return {name};
  // Synchronous intrinsic formatting only. Never execute an installed formatter,
  // including the Node default hook, or an accessor supplied by application code.
  if(formatter&&!formatter.configurable)return {name};
  let stack;
  try{
   if(formatter)delete Error.prepareStackTrace;
   stack=Reflect.apply(nativeStackGetter,error,[]);
  }finally{
   if(formatter)Object.defineProperty(Error,'prepareStackTrace',formatter);
  }
  return {name,stack:typeof stack==='string'&&stack.length<=16384?stack:undefined};
 }catch{return {};}
}

function projectStartupDetail(error){
 if(nativeErrorTypes.isProxy(error))return {version:1,code:'OTHER',name:'OTHER',frames:[]};
 const native=nativeErrorFields(error);
 const code=ownData(error,'code'),name=ownData(error,'name')??native.name,stack=ownData(error,'stack')??native.stack;
 const result={version:1,code:diagnosticCodes.has(code)?code:'OTHER',name:['Error','TypeError','ReferenceError','SyntaxError','RangeError','AssertionError','AggregateError'].includes(name)?name:'OTHER',frames:[]};
 if(typeof stack==='string'&&stack.length<=16384){
  for(const line of stack.split('\n').slice(1,17)){
   if(!/^\s+at /.test(line))continue;
   const match=line.match(/(?:\(| )(?:[^\s]*\/)?(server\/[A-Za-z0-9_\/-]+\.js):(\d{1,6}):(\d{1,6})\)?$/);
   if(match&&diagnosticFrames.includes(match[1]))result.frames.push({file:match[1],line:Number(match[2]),column:Number(match[3])});
   if(result.frames.length===3)break;
  }
 }
 return result;
}


function projectStartupShape(error){
 const result={version:1,kind:'primitive',prototype:'none',code:'absent',name:'absent',stack:'absent',cause:'absent'};
 if(!error||(typeof error!=='object'&&typeof error!=='function'))return result;
 if(nativeErrorTypes.isProxy(error)){result.kind='proxy';return result;}
 result.kind=nativeErrorTypes.isNativeError(error)?'native':'object';
 try{
  const prototype=Object.getPrototypeOf(error);
  result.prototype=nativeErrorNames.has(prototype)?'builtin':'other';
  for(const key of ['code','name','stack','cause']){
   const descriptor=Object.getOwnPropertyDescriptor(error,key);
   result[key]=!descriptor?'absent':!Object.hasOwn(descriptor,'value')?'accessor':'data';
  }
 }catch{result.prototype='unavailable';}
 return result;
}

function reportStartupDiagnostic(error,emit){
 try{emit('application_start_failed',projectStartupDiagnostic(error));}catch{/* Diagnostics must not interfere with shutdown or rejection. */}
 try{emit('application_start_detail '+JSON.stringify(projectStartupDetail(error)));}catch{/* Primary failure unchanged. */}
 try{emit('application_start_shape '+JSON.stringify(projectStartupShape(error)));}catch{/* Primary failure unchanged. */}
}
module.exports={projectStartupDiagnostic,projectStartupDetail,projectStartupShape,reportStartupDiagnostic};
