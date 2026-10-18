'use strict';
const {captureFeatureMode,guardFeatureFence,POLICIES}=require('./secureshopFeatureModeAuthority');
const c=require('./secureshopCouponContract');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {executionScope}=require('./secureshopSceneBinding');
function createBoundCoupon({repository,service,readCoupons,checkCurrent,mode,modeAuthority}={}){
 if(['recover','admitCoupon','completeCoupon'].some(k=>typeof repository?.[k]!=='function')||['provision','lookupCoupon'].some(k=>typeof service?.[k]!=='function')||typeof readCoupons!=='function'||typeof checkCurrent!=='function'||!['vuln','fixed'].includes(mode))throw TypeError('Bound coupon dependencies required');
 function originalToken(token,featureId,scope){
  if(!modeAuthority||typeof modeAuthority.assertToken!=='function')throw c.fail('COMMERCE_MODE_CHANGED');
  const owned=modeAuthority.assertToken(token),snapshot=owned.snapshot;
  if(snapshot?.featureId!==featureId||snapshot.policyVersion!==POLICIES[featureId]
    ||!['vuln','fixed'].includes(snapshot.mode)||JSON.stringify(snapshot.scope)!==JSON.stringify(scope)
    ||typeof owned.assertCurrent!=='function'||typeof owned.assertCurrentAtEffect!=='function')throw c.fail('COMMERCE_MODE_CHANGED');
  return owned;
 }
 async function apply(input,{fence,signal,customerMode,couponMode,checkCurrent:checkOriginal,withSelectedSceneEffect}={},confirmed=false){
  const readOnly=confirmed==='read';
  const scope=createLaunchScope(executionScope(input.target)),expected={...scope,personaId:input.persona.id,role:'customer',sessionId:input.personaSession?.sessionId,authorityVersion:input.personaSession?.authorityVersion};
  if(typeof fence?.assertRemoteAdmission!=='function'||typeof fence?.withCrossStoreEffect!=='function'||Object.keys(expected).some(k=>fence.binding?.[k]!==expected[k]))throw c.fail('SHOP_AUTH_INVALID');
  const modeToken=confirmed?originalToken(couponMode,'coupons',scope):await captureFeatureMode(modeAuthority,scope,'coupons',mode);
  const customerToken=confirmed?originalToken(customerMode,'customer_chat',scope):null;
  if(confirmed&&(typeof checkOriginal!=='function'||typeof withSelectedSceneEffect!=='function'))throw c.fail('SHOP_AUTH_INVALID');
  // Confirmed effects hold the selected-scene owner lease around the local
  // persona/review transactions. Regular mode reads belong outside that lease;
  // at-effect mode reads below are SELECT-only and safe within it.
  if(!confirmed)fence=guardFeatureFence(fence,modeToken);
  const atEffect=customerToken?async()=>{await customerToken.assertCurrentAtEffect();await modeToken.assertCurrentAtEffect();}:undefined;
  const local=confirmed?work=>withSelectedSceneEffect(work):work=>work();
  const localEffect=async work=>{let returned=false;try{return await local(async()=>{
   const value=await fence.withCrossStoreEffect(work);returned=true;return value;
  });}catch(cause){if(!returned)throw cause;throw Object.assign(c.fail('PERSONA_EFFECT_OUTCOME_UNCERTAIN'),
   {cause,executionBoundary:true});}};
  const raw={...input,mode:modeToken.snapshot.mode},check=async()=>{signal?.throwIfAborted();await checkCurrent(scope);
   await customerToken?.assertCurrent();await modeToken.assertCurrent();await checkOriginal?.();await fence.assertRemoteAdmission();signal?.throwIfAborted();};
  await check();let operation=await local(()=>repository.recover(raw,'coupon',atEffect));await check();
  if(readOnly){
   if(!operation)return null;
   if(operation.request.code!==input.code||operation.request.operationId!==input.operationId
    ||operation.request.mode!==raw.mode)throw c.fail('COMMERCE_OPERATION_CONFLICT');
   return operation.state==='completed'
    ?Object.freeze({state:'completed',request:operation.request,result:operation.result}):null;
  }
  if(operation){if(operation.request.code!==input.code||((modeAuthority!=null||operation.request.mode!==undefined)&&operation.request.mode!==raw.mode))throw c.fail('COMMERCE_OPERATION_CONFLICT');if(operation.state==='completed')return operation.result;}
  else{const coupons=c.bank(await readCoupons());await check();operation=await localEffect(()=>repository.admitCoupon({...raw,coupons},atEffect));await check();}
  // Durable application debt precedes any separate cluster target creation.
  await service.provision(scope,{signal});await check();const receipt=await service.lookupCoupon(operation.request,{signal});await check();
  const result=await localEffect(()=>repository.completeCoupon(raw,{request:operation.request,receipt,atEffect}));try{await check();}catch(cause){throw Object.assign(c.fail('PERSONA_EFFECT_OUTCOME_UNCERTAIN'),{cause,executionBoundary:true});}return result;
 }
 return Object.freeze({
  apply(input,options){return apply(input,options,false);},
  applyConfirmed(input,options){return apply(input,options,true);},
  readConfirmed(input,options){return apply(input,options,'read');},
 });
}
module.exports={createBoundCoupon};
