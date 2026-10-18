'use strict';
const {captureFeatureMode,guardFeatureFence}=require('./secureshopFeatureModeAuthority');
const contract=require('./secureshopInventoryContract');
const {executionScope}=require('./secureshopSceneBinding');
function createBoundInventory({repository,checkCurrent,mode,modeAuthority}={}){
 if(typeof repository?.execute!=='function'||typeof repository?.recover!=='function'||typeof checkCurrent!=='function'||!['vuln','fixed'].includes(mode))throw TypeError('Bound inventory dependencies required');
 async function invoke(input,{fence,signal}={},recoverOnly=false){
  const token=await captureFeatureMode(modeAuthority,executionScope(input.target),'inventory',mode);
  const raw={...input,mode:token.snapshot.mode},request=contract.request(raw),expected={...request.scope,personaId:request.persona.id,role:'merchant',...request.personaSession};
  if(typeof fence?.assertRemoteAdmission!=='function'||typeof fence?.withCrossStoreEffect!=='function'||Object.keys(expected).some(key=>fence.binding?.[key]!==expected[key]))throw contract.fail('SHOP_AUTH_INVALID');
  fence=guardFeatureFence(fence,token);
  const check=async()=>{signal?.throwIfAborted();await checkCurrent(request.scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};
  await check();
  // A missing receipt is an observation, not an uncertain cross-store mutation.
  const prior=await repository.recover(raw);await check();if(prior||recoverOnly)return prior;
  const receipt=await fence.withCrossStoreEffect(()=>repository.execute(raw));
  try{await check();}catch(cause){throw Object.assign(contract.fail('PERSONA_EFFECT_OUTCOME_UNCERTAIN'),{cause,executionBoundary:true});}
  return receipt;
 }
 return Object.freeze({mode,execute:(input,options)=>invoke(input,options),recover:(input,options)=>invoke(input,options,true)});
}
module.exports={createBoundInventory};
