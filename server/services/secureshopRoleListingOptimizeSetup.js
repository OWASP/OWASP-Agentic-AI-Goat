'use strict';
const {createHash}=require('node:crypto');
const {canonicalDigest}=require('./mcp/protocolContext');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {normalizeListingRequest}=require('./secureshopListingRequestContract');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
const fail=(code='ROLE_LISTINGS_SETUP_INVALID')=>Object.assign(Error('Listing image setup unavailable'),{code});
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const positive=v=>Number.isSafeInteger(v)&&v>0&&v<=2147483647;
const bounded=(v,n)=>typeof v==='string'&&v.isWellFormed()&&!v.includes('\0')&&Buffer.byteLength(v,'utf8')<=n;
const sha=value=>createHash('sha256').update(value,'utf8').digest('hex');
const id=value=>typeof value==='string'&&UUID.test(value);
function uuidFrom(hash){return `${hash.slice(0,8)}-${hash.slice(8,12)}-5${hash.slice(13,16)}-a${hash.slice(17,20)}-${hash.slice(20,32)}`;}
function capability(v,featureId){return exact(v,['version','featureId','policyVersion','effectiveMode','scope'])&&v.version===1
 &&v.featureId===featureId&&v.policyVersion===(featureId==='listings'?'owned-listing-import-v1':'owned-merchant-read-and-confirmation-v1')
 &&['vuln','fixed'].includes(v.effectiveMode)&&exact(v.scope,['kind','id'])&&v.scope.kind==='launch_feature'&&v.scope.id===featureId;}
function createListingOptimizeSetup({context,source,origin,selected,modeCapability,listingsModeCapability,product}={}){
 const scene=context?.target?.scene;
 if(context?.persona?.role!=='merchant'||!positive(context.persona.id)||!id(context.personaSession?.sessionId)
  ||typeof context.personaSession.authorityVersion!=='string'||!/^[1-9]\d{0,15}$/.test(context.personaSession.authorityVersion)
  ||!id(context.target?.targetId)||!id(scene?.sceneId)||!positive(scene?.sceneGeneration)||!id(scene?.grantId)||!id(source?.sessionId)||!id(source?.requestId)
  ||!Number.isSafeInteger(origin?.step)||origin.step<1||origin.step>10||!bounded(origin.callId,128)||!origin.callId
  ||!exact(selected,['version','kind','choiceId','sourceId','snapshotSha256','card'])||selected.version!==1||selected.kind!=='merchant_product'
  ||!id(selected.choiceId)||!positive(selected.sourceId)||!SHA.test(selected.snapshotSha256)
  ||!capability(modeCapability,'merchant_assistant')||!capability(listingsModeCapability,'listings')
  ||!product||product.id!==selected.sourceId||product.retailer_id!==context.persona.id||product.status!=='active'
  ||!bounded(product.name,1024)||!bounded(product.imageUrl,4096))throw fail('ROLE_LISTINGS_CHOICE_STALE');
 const imageUrlSha256=sha(product.imageUrl),operationId=source.requestId.toLowerCase();
 normalizeListingRequest({version:1,action:'optimize',operationId,productId:product.id,imageUrl:product.imageUrl,imageUrlSha256,sceneId:scene.sceneId,sceneGeneration:scene.sceneGeneration,grantId:scene.grantId});
 const productSnapshotSha256=canonicalDigest(['listing-optimize-product-v1',{productId:product.id,merchantId:product.retailer_id,
  status:product.status,name:product.name,imageUrl:product.imageUrl,imageUrlSha256,choiceSnapshotSha256:selected.snapshotSha256}]);
 const base={version:1,kind:'listing_optimize_setup',action:'optimize',source:{sessionId:source.sessionId.toLowerCase(),requestId:operationId},
  origin:{step:origin.step,callId:origin.callId},scopeSha256:canonicalDigest(createLaunchScope(context.scope)),
  scene:{targetId:context.target.targetId.toLowerCase(),sceneId:scene.sceneId.toLowerCase(),sceneGeneration:scene.sceneGeneration,grantId:scene.grantId.toLowerCase()},
  persona:{id:context.persona.id,sessionId:context.personaSession.sessionId.toLowerCase(),authorityVersion:context.personaSession.authorityVersion},
  modeCapability,listingsModeCapability,choice:{choiceId:selected.choiceId.toLowerCase(),snapshotSha256:selected.snapshotSha256},
  product:{productId:product.id,name:product.name,imageUrl:product.imageUrl,imageUrlSha256,productSnapshotSha256}};
 const proposalId=uuidFrom(canonicalDigest(['merchant-listing-optimize-setup-v1',base]));
 return validateListingOptimizeSetup({...base,proposalId,operationId:proposalId});
}
function validateListingOptimizeSetup(v){
 if(!exact(v,['version','kind','action','proposalId','operationId','source','origin','scopeSha256','scene','persona','modeCapability','listingsModeCapability','choice','product'])
  ||v.version!==1||v.kind!=='listing_optimize_setup'||v.action!=='optimize'||!id(v.proposalId)||v.operationId!==v.proposalId
  ||!exact(v.source,['sessionId','requestId'])||!id(v.source.sessionId)||!id(v.source.requestId)
  ||!exact(v.origin,['step','callId'])||!Number.isSafeInteger(v.origin.step)||v.origin.step<1||v.origin.step>10||!bounded(v.origin.callId,128)||!v.origin.callId
  ||!SHA.test(v.scopeSha256)||!exact(v.scene,['targetId','sceneId','sceneGeneration','grantId'])||!id(v.scene.targetId)||!id(v.scene.sceneId)||!positive(v.scene.sceneGeneration)||!id(v.scene.grantId)
  ||!exact(v.persona,['id','sessionId','authorityVersion'])||!positive(v.persona.id)||!id(v.persona.sessionId)||!/^[1-9]\d{0,15}$/.test(v.persona.authorityVersion)
  ||!capability(v.modeCapability,'merchant_assistant')||!capability(v.listingsModeCapability,'listings')
  ||!exact(v.choice,['choiceId','snapshotSha256'])||!id(v.choice.choiceId)||!SHA.test(v.choice.snapshotSha256)
  ||!exact(v.product,['productId','name','imageUrl','imageUrlSha256','productSnapshotSha256'])||!positive(v.product.productId)
  ||!bounded(v.product.name,1024)||!bounded(v.product.imageUrl,4096)||!SHA.test(v.product.imageUrlSha256)||!SHA.test(v.product.productSnapshotSha256)
  ||sha(v.product.imageUrl)!==v.product.imageUrlSha256
  ||canonicalDigest(['listing-optimize-product-v1',{productId:v.product.productId,merchantId:v.persona.id,status:'active',name:v.product.name,
   imageUrl:v.product.imageUrl,imageUrlSha256:v.product.imageUrlSha256,choiceSnapshotSha256:v.choice.snapshotSha256}])!==v.product.productSnapshotSha256)throw fail();
 normalizeListingRequest({version:1,action:'optimize',operationId:v.operationId,productId:v.product.productId,imageUrl:v.product.imageUrl,imageUrlSha256:v.product.imageUrlSha256,sceneId:v.scene.sceneId,sceneGeneration:v.scene.sceneGeneration,grantId:v.scene.grantId});
 const {proposalId,operationId,...base}=v;
 if(proposalId!==uuidFrom(canonicalDigest(['merchant-listing-optimize-setup-v1',base])))throw fail('ROLE_LISTINGS_SETUP_MISMATCH');
 return v;
}
function projectListingOptimizeSetup(value){const v=validateListingOptimizeSetup(value);return Object.freeze({version:1,kind:v.kind,
 proposalId:v.proposalId,operationId:v.operationId,source:{...v.source},listingsModeCapability:v.listingsModeCapability,
 product:Object.freeze({choiceId:v.choice.choiceId,name:v.product.name,imageUrl:v.product.imageUrl,imageUrlSha256:v.product.imageUrlSha256})});}
module.exports={createListingOptimizeSetup,validateListingOptimizeSetup,projectListingOptimizeSetup};
