'use strict';
function createProtectedRecoveryHandler({getService}={}){
 if(typeof getService!=='function')throw TypeError('Current protected recovery service required');
 return async(req,res)=>{
  if(!req.body||Object.getPrototypeOf(req.body)!==Object.prototype||Object.keys(req.body).join(',')!=='operationId'||typeof req.body.operationId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(req.body.operationId))return res.status(400).json({error:'INVALID_PROTECTED_OPERATION_ID'});
  const service=getService();if(typeof service?.reconcile!=='function')return res.status(503).json({error:'MCP_PROTECTED_RECOVERY_UNAVAILABLE'});
  try{
   const value=await service.reconcile(req,req.body.operationId);
   return res.json({operationId:req.body.operationId,originalEffectStatus:'uncertain',outcome:value.outcome,receiptDigest:value.receipt_digest||null,observedAt:value.observed_at,origin:value.origin,creditGranted:false});
  }catch(error){const stale=['PROTECTED_RECONCILIATION_STALE','PROTECTED_INTENT_UNAVAILABLE','MCP_PLATFORM_SESSION_REQUIRED'].includes(error.code);return res.status(stale?404:503).json({error:stale?'PROTECTED_OPERATION_UNAVAILABLE':'MCP_PROTECTED_RECOVERY_UNAVAILABLE'});}
 };
}
module.exports={createProtectedRecoveryHandler};
