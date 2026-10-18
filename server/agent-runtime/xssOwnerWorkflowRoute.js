'use strict';
const {ownerWorkflowRoute}=require('./ownerWorkflowRoutes');
const {OwnerWorkflowHttpError}=require('./ownerWorkflowHttpError');
const {configuredXssMutationAdmission,configuredXssProfileResetPendingCheck}=require('../services/xssMutationAdmission');

// The owner resolver is server-owned. Anonymous profile teaching sessions do
// not hold platform lifecycle authority and cannot receive canonical credit.
function createXssOwnerWorkflowRoute({coordinator,ownerFor,allowAnonymous=false,
 postgres=process.env.PLATFORM_DATABASE_ENGINE==='postgres',
 admit=configuredXssMutationAdmission,pendingProfileReset=configuredXssProfileResetPendingCheck,
 validateSession=token=>require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token)}={}){
 if(typeof ownerFor!=='function'||typeof admit!=='function'||typeof pendingProfileReset!=='function'||typeof validateSession!=='function')
  throw new TypeError('XSS route authority required');
 return (handler,options={})=>ownerWorkflowRoute(coordinator,ownerFor,handler,{
  ...options,
  ...(postgres?{withAdmission:async(owner,work,req)=>{
   if(allowAnonymous&&!req.user&&!req.identitySession&&typeof owner==='string'&&owner.startsWith('anon_')&&owner.length>5)
    return work(Object.freeze({check:async()=>{}}));
   if(String(req.user?.id)!==String(owner))throw Object.assign(new Error('Session owner mismatch'),{code:'SESSION_REVOKED'});
   const fence=require('./admittedPlatformSession').createAdmittedPlatformSessionFence(req,{validateSession});
   await fence.check();
   return admit(owner,async guard=>{
    await fence.check();
    if(options.reset===true)try{await pendingProfileReset(owner,guard);}
    catch(error){
     if(error?.code==='XSS_PROFILE_RESET_PENDING')
      throw new OwnerWorkflowHttpError(503,'Finish or recover the pending profile reset before resetting progress');
     throw error;
    }
    return work(Object.freeze({ownerId:guard.ownerId,check:()=>guard.check(),
     wrap:execution=>fence.wrap(execution),checkPublication:()=>fence.check()}));
   });
  }}:{}),
 });
}
module.exports={createXssOwnerWorkflowRoute};
