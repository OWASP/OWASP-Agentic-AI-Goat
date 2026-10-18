'use strict';
// Canonical catalog capabilities stay server-private; immutable listing packets
// retain the execution scope they originally captured, not the target's birth.
const {createLaunchScope}=require('./secureshopConversationBinding');
const {executionScope,isSceneMerchant,withSceneLease,assertSceneGrant}=require('./secureshopSceneBinding');
const fail=()=>Object.assign(Error('Owned Listings target unavailable'),{code:'LISTING_TARGET_UNAVAILABLE'});
function validateListingTarget(target,binding){
 if(!target||typeof target.targetId!=='string'||(binding.targetId!==undefined&&target.targetId!==binding.targetId))throw fail();
 const current=createLaunchScope(executionScope(target));
 if(Object.keys(binding.scope).some(k=>binding.scope[k]!==current[k]))throw fail();
 if(target.scene!==undefined&&!isSceneMerchant(target,binding.persona.id))throw fail();
 return target;
}
async function resolveListingTarget(resolveTarget,binding){
 if(resolveTarget===undefined)return null; // Explicit unmapped legacy fixtures.
 return validateListingTarget(await resolveTarget(binding),binding);
}
function withListingTarget(target,work){return target?withSceneLease(target,work):work();}
async function assertListingTarget(client,target){if(target)await assertSceneGrant(client,target);}
// New scene operations have an immutable original grant. Existing legacy
// evidence remains readable but cannot acquire a new grant through replay.
async function assertListingOperation(client,target,operationId,bindingSha256){
 if(!target?.scene)return;
 const rows=(await client.query(`SELECT grant_id,target_id,merchant_id,binding_sha256
  FROM secureshop_review.owned_listing_scene_admissions WHERE operation_id=$1`,[operationId])).rows;
 if(rows.length>1||rows.length===1&&(rows[0].target_id!==target.targetId||rows[0].grant_id!==target.scene.grantId
  ||!isSceneMerchant(target,Number(rows[0].merchant_id))||rows[0].binding_sha256!==bindingSha256))throw fail();
}
module.exports={validateListingTarget,resolveListingTarget,withListingTarget,assertListingTarget,assertListingOperation};
