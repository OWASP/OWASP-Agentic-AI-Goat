'use strict';
const {readBearerAuthorization}=require('../middleware/bearerToken');
const denied=()=>Object.assign(Error('Canonical session is no longer current'),{code:'SESSION_REVOKED',statusCode:401});
function identity(value){if(!['number','string'].includes(typeof value)||!/^[1-9][0-9]*$/.test(String(value))||!Number.isSafeInteger(Number(value)))throw denied();return String(value);}
function createAdmittedPlatformSessionFence(req,{validateSession}={}){
 const token=readBearerAuthorization(req).token,owner=identity(req?.user?.id),session=identity(req?.identitySession?.id);
 if(!token||typeof validateSession!=='function')throw denied();
 const check=async()=>{const current=await validateSession(token);if(!current||identity(current.user?.id)!==owner||identity(current.session?.id)!==session||identity(current.session?.user_id)!==owner)throw denied();};
 function wrap(execution){
  if(typeof execution?.check!=='function')throw TypeError('Execution check required');
  const guarded={...execution,check:async()=>{await execution.check.call(execution);await check();await execution.check.call(execution);}};
  for(const name of ['effect','effectWithReceipt','checkpoint'])if(typeof execution[name]==='function')guarded[name]=async(...args)=>{await guarded.check();const forwarded=[...args];if(['effect','effectWithReceipt'].includes(name)&&typeof args[1]==='function'){const callback=args[1];forwarded[1]=async function(...callbackArgs){await guarded.check();const value=await Reflect.apply(callback,this,callbackArgs);await guarded.check();return value;};}const value=await Reflect.apply(execution[name],execution,forwarded);await guarded.check();return value;};
  return Object.freeze(guarded);
 }
 return Object.freeze({check,wrap});
}
module.exports={createAdmittedPlatformSessionFence};
