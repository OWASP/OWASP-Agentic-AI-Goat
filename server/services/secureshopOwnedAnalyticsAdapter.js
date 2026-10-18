'use strict';
const {target:checkedTarget,request:checkedRequest,sameScope,fail}=require('../../sidecars/analytics-sql-target/contract');
// Internal dependency only. Private service transport/config never comes from HTTP.
function createOwnedAnalyticsAdapter({launches,personaAuthority,targetService,schema}){
 if(typeof launches?.assertCurrent!=='function'||typeof personaAuthority?.capture!=='function'||typeof targetService?.resolve!=='function'||typeof targetService?.execute!=='function'||typeof schema!=='string')throw TypeError('Owned Analytics authority required');
 async function authority(input){
  const {scope,persona,personaSession,signal,checkCurrent}=input;
  if(typeof checkCurrent!=='function')throw fail('ANALYTICS_TARGET_INVALID');
  const fence=await personaAuthority.capture({scope,personaId:persona.id,role:persona.role,...personaSession});
  if(!sameScope(fence?.binding,scope)||fence.binding.personaId!==persona.id||fence.binding.role!==persona.role||fence.binding.sessionId!==personaSession.sessionId||fence.binding.authorityVersion!==personaSession.authorityVersion||typeof fence.withCrossStoreEffect!=='function'||typeof fence.assertRemoteAdmission!=='function')throw fail('SHOP_AUTH_INVALID');
  const check=async()=>{signal?.throwIfAborted();await checkCurrent();await launches.assertCurrent(scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};
  await check();return {fence,check};
 }
 return Object.freeze({schema,async prepare(input){
  if(typeof targetService.provision!=='function')throw fail('ANALYTICS_TARGET_UNAVAILABLE');
  const {fence,check}=await authority(input);const result=await fence.withCrossStoreEffect(async()=>{input.signal?.throwIfAborted();await launches.assertCurrent(input.scope);const value=await targetService.provision(input.scope,{signal:input.signal});if(input.mode?.mode==='fixed'){if(typeof targetService.prepareFixed!=='function')throw fail('ANALYTICS_FIXED_CAPABILITY_UNAVAILABLE');await targetService.prepareFixed(input.scope,{signal:input.signal});}input.signal?.throwIfAborted();return value;});
  await check();const target=checkedTarget(result);if(!sameScope(target.scope,input.scope))throw fail('ANALYTICS_TARGET_INVALID');return target;
 },async resolve(input){
  const {check}=await authority(input);const target=checkedTarget(await targetService.resolve(input.scope,{signal:input.signal}));
  if(!sameScope(target.scope,input.scope))throw fail('ANALYTICS_TARGET_INVALID');await check();return target;
 },async topProducts(input){
  if(!['merchant','admin'].includes(input?.persona?.role))throw fail('SHOP_AUTH_INVALID');
  if(typeof targetService.provision!=='function'||typeof targetService.topProducts!=='function'||!Number.isSafeInteger(input.limit)||input.limit<1||input.limit>25)throw fail('ANALYTICS_TARGET_INVALID');
  const {fence,check}=await authority(input);
  const {expected,result}=await fence.withCrossStoreEffect(async()=>{input.signal?.throwIfAborted();await launches.assertCurrent(input.scope);
   const expected=checkedTarget(await targetService.provision(input.scope,{signal:input.signal}));
   if(!sameScope(expected.scope,input.scope))throw fail('ANALYTICS_TARGET_INVALID');
   input.signal?.throwIfAborted();await launches.assertCurrent(input.scope);
   const result=await targetService.topProducts(input.scope,input.limit,{signal:input.signal});
   input.signal?.throwIfAborted();await launches.assertCurrent(input.scope);return {expected,result};});
  await check();const actual=checkedTarget({targetId:result?.targetId,scope:result?.scope,sourceManifestSha256:result?.sourceManifestSha256});
  if(actual.targetId!==expected.targetId||actual.sourceManifestSha256!==expected.sourceManifestSha256||!sameScope(actual.scope,expected.scope)||!Array.isArray(result.rows)||result.rows.length>input.limit||result.rows.some(row=>!row||Object.keys(row).sort().join(',')!=='id,name,revenue'||!Number.isSafeInteger(row.id)||typeof row.name!=='string'||!Number.isFinite(Number(row.revenue))))throw fail('ANALYTICS_RECEIPT_MISMATCH');
  return Object.freeze({rows:structuredClone(result.rows)});
 },async execute(input){
  const {fence,check}=await authority(input);
  const request=checkedRequest({target:input.target,operationId:input.operationId,runId:input.runId,requestId:input.requestId,sessionId:input.sessionId,callId:input.callId,sql:input.sql,...(input.mode?{mode:input.mode}:{})});
  if(!sameScope(request.target.scope,input.scope))throw fail('ANALYTICS_TARGET_INVALID');
  // The canonical cross-store fence holds agents advisory locks and checks
  // persona authority on its own client before/after this callback. Re-entering
  // assertRemoteAdmission (including caller checkCurrent) here self-deadlocks.
  const lockedCheck=async()=>{input.signal?.throwIfAborted();await launches.assertCurrent(input.scope);input.signal?.throwIfAborted();};
  const result=await fence.withCrossStoreEffect(async()=>{
   await lockedCheck();const current=checkedTarget(await targetService.resolve(input.scope,{signal:input.signal}));
   if(current.targetId!==request.target.targetId||current.sourceManifestSha256!==request.target.sourceManifestSha256||!sameScope(current.scope,request.target.scope))throw fail('ANALYTICS_TARGET_INVALID');
   const value=await targetService.execute(request,{signal:input.signal});await lockedCheck();return value;
  });await check();return result;
 }});
}
module.exports={createOwnedAnalyticsAdapter};
