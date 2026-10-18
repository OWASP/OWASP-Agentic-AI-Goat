'use strict';
// Audit close drains its operations before removing the private spool. A
// subsequent filesystem error must not prevent release of the remaining pools.
async function closeSecureShopBoundResources({registeredInvocation,ownedMcpRegistry,mail,auditSummary,auditUnbounded,listings,inventory,closeBrowserAssessment,closeCleanup}){
  const failures=[];
  try{if(registeredInvocation)await registeredInvocation.close();}catch(error){failures.push(error);}
  try{if(ownedMcpRegistry)await ownedMcpRegistry.close();}catch(error){failures.push(error);}
  try{if(mail)await mail.close();}catch(error){failures.push(error);}
  try{await auditSummary?.close();}catch(error){failures.push(error);}
  try{await auditUnbounded?.close();}catch(error){failures.push(error);}
  try{await listings?.close();}catch(error){failures.push(error);}
  try{await inventory?.close();}catch(error){failures.push(error);}
  const results=await Promise.allSettled([closeBrowserAssessment,closeCleanup].map(close=>Promise.resolve().then(close)));
  failures.push(...results.filter(result=>result.status==='rejected').map(result=>result.reason));
  if(failures.length)throw new AggregateError(failures,'SecureShop bound review runtime cleanup failed');
}
module.exports={closeSecureShopBoundResources};
