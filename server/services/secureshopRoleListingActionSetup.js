'use strict';
const {isDeepStrictEqual}=require('node:util');
const {createHash}=require('node:crypto');
const {canonicalDigest}=require('./mcp/protocolContext');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {captureFeatureMode,projectFeatureMode}=require('./secureshopFeatureModeAuthority');
const {normalizeListingRequest}=require('./secureshopListingRequestContract');
const {normalizeListingSaveRequest}=require('./secureshopListingsApplication');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA=/^[a-f0-9]{64}$/;
const fail=(code='ROLE_LISTINGS_SETUP_INVALID')=>Object.assign(Error('Listings chat setup unavailable'),{code});
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
const bounded=(v,n)=>typeof v==='string'&&v.isWellFormed()&&!v.includes('\0')&&Buffer.byteLength(v)<=n;
const id=v=>typeof v==='string'&&UUID.test(v);
const positive=v=>Number.isSafeInteger(v)&&v>0&&v<=2147483647;
const choiceDigest=(v,mode)=>{const keys=mode==='fixed'
 ?['id','name','description','price','category','status','stock_quantity']
 :['id','name','description','description_html','price','category','status','stock_quantity'];
 if(!exact(v,keys))throw fail('ROLE_LISTINGS_CHOICE_STALE');
 return createHash('sha256').update(JSON.stringify(Object.fromEntries(keys.map(k=>[k,v[k]])))).digest('hex');};
function uuidFrom(hash){return `${hash.slice(0,8)}-${hash.slice(8,12)}-5${hash.slice(13,16)}-a${hash.slice(17,20)}-${hash.slice(20,32)}`;}
function scene(context){const t=context?.target,s=t?.scene;
 if(!id(t?.targetId)||!id(s?.sceneId)||!positive(s?.sceneGeneration))throw fail('ROLE_LISTINGS_SCENE_STALE');
 return {targetId:t.targetId.toLowerCase(),sceneId:s.sceneId.toLowerCase(),sceneGeneration:s.sceneGeneration};}
function capability(v,featureId){return exact(v,['version','featureId','policyVersion','effectiveMode','scope'])&&v.version===1
 &&v.featureId===featureId&&v.policyVersion===(featureId==='listings'?'owned-listing-import-v1':'owned-merchant-read-and-confirmation-v1')
 &&['vuln','fixed'].includes(v.effectiveMode)&&exact(v.scope,['kind','id'])&&v.scope.kind==='launch_feature'&&v.scope.id===featureId;}
function fixedText(v,n){return typeof v==='string'?v.slice(0,n).replace(/[\u0000-\u001f]/g,'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])):null;}
function choiceSnapshot(p,mode){return mode==='fixed'?{id:p.id,name:fixedText(p.name,256),description:fixedText(p.description,1024),price:p.price,
 category:fixedText(p.category,128),status:p.status,stock_quantity:p.stock_quantity}
 :{id:p.id,name:p.name,description:p.description,description_html:p.description_html,price:p.price,
 category:p.category,status:p.status,stock_quantity:p.stock_quantity};}
function itemFromProduct(p){return {name:p.name,description:p.description,price:p.price,category:p.category,
 images:p.images,templateSource:p.template_source};}
function createListingActionSetup({context,source,origin,action,selected,input={},modeCapability,listingsModeCapability,product,retainedItem,retainedChoiceSnapshot}={}){
 if(context?.persona?.role!=='merchant'||!positive(context.persona.id)||!id(context.personaSession?.sessionId)
 ||typeof context.personaSession.authorityVersion!=='string'||!/^[1-9]\d{0,15}$/.test(context.personaSession.authorityVersion)
 ||!id(source?.sessionId)||!id(source?.requestId)||!Number.isSafeInteger(origin?.step)||origin.step<1||origin.step>10
 ||!bounded(origin.callId,128)||!origin.callId||!['import','rewrite'].includes(action)
 ||!capability(modeCapability,'merchant_assistant')||!capability(listingsModeCapability,'listings'))throw fail();
 const base={version:1,kind:action==='import'?'listing_import_setup':'listing_rewrite_setup',action,
  source:{sessionId:source.sessionId.toLowerCase(),requestId:source.requestId.toLowerCase()},origin:{step:origin.step,callId:origin.callId},
  scopeSha256:canonicalDigest(createLaunchScope(context.scope)),scene:scene(context),
  persona:{id:context.persona.id,sessionId:context.personaSession.sessionId.toLowerCase(),authorityVersion:context.personaSession.authorityVersion},
  modeCapability,listingsModeCapability,choice:null,choiceSnapshot:null,productId:null,item:null,sources:null};
 if(action==='import'){
  if(selected!==null&&selected!==undefined||!exact(input,['json_url','xml_url']))throw fail('INVALID_TOOL_ARGUMENTS');
  const checked=normalizeListingRequest({version:1,action:'import',operationId:source.requestId,json_url:input.json_url,xml_url:input.xml_url});
  base.sources={json_url:checked.json_url,xml_url:checked.xml_url};
 }else{
  if(!exact(input,[])||!exact(selected,['version','kind','choiceId','sourceId','snapshotSha256','card'])
   ||selected.kind!=='merchant_product'||selected.version!==1||!id(selected.choiceId)||!positive(selected.sourceId)
   ||!SHA.test(selected.snapshotSha256))throw fail('ROLE_LISTINGS_CHOICE_STALE');
  const snapshot=product?choiceSnapshot(product,modeCapability.effectiveMode):retainedChoiceSnapshot;
  if(product&&(product.id!==selected.sourceId||product.retailer_id!==context.persona.id||product.status!=='active')
   ||!snapshot||snapshot.id!==selected.sourceId||choiceDigest(snapshot,modeCapability.effectiveMode)!==selected.snapshotSha256)throw fail('ROLE_LISTINGS_CHOICE_STALE');
  const item=product?itemFromProduct(product):retainedItem;
  normalizeListingRequest({version:1,action:'rewrite',operationId:source.requestId,title:item.name,description:item.description});
  normalizeListingSaveRequest({rewriteOperationId:source.requestId,saveOperationId:source.requestId,productId:selected.sourceId,item});
  base.choice={choiceId:selected.choiceId.toLowerCase(),snapshotSha256:selected.snapshotSha256};base.choiceSnapshot=structuredClone(snapshot);
  base.productId=selected.sourceId;base.item=structuredClone(item);
 }
 return validateListingActionSetup({...base,proposalId:uuidFrom(canonicalDigest(['merchant-listings-setup-v1',base])),operationId:uuidFrom(canonicalDigest(['merchant-listings-setup-v1',base]))});
}
function validateListingActionSetup(v){
 if(!exact(v,['version','kind','action','proposalId','operationId','source','origin','scopeSha256','scene','persona','modeCapability','listingsModeCapability','choice','choiceSnapshot','productId','item','sources'])
  ||v.version!==1||v.kind!==(v.action==='import'?'listing_import_setup':'listing_rewrite_setup')||!id(v.proposalId)||v.operationId!==v.proposalId
  ||!exact(v.source,['sessionId','requestId'])||!id(v.source.sessionId)||!id(v.source.requestId)
  ||!exact(v.origin,['step','callId'])||!Number.isSafeInteger(v.origin.step)||v.origin.step<1||v.origin.step>10||!bounded(v.origin.callId,128)||!v.origin.callId
  ||!SHA.test(v.scopeSha256)||!exact(v.scene,['targetId','sceneId','sceneGeneration'])||!id(v.scene.targetId)||!id(v.scene.sceneId)||!positive(v.scene.sceneGeneration)
  ||!exact(v.persona,['id','sessionId','authorityVersion'])||!positive(v.persona.id)||!id(v.persona.sessionId)
  ||typeof v.persona.authorityVersion!=='string'||!/^[1-9]\d{0,15}$/.test(v.persona.authorityVersion)
  ||!capability(v.modeCapability,'merchant_assistant')||!capability(v.listingsModeCapability,'listings'))throw fail();
 try{
  if(v.action==='import'){
   if(v.choice!==null||v.choiceSnapshot!==null||v.productId!==null||v.item!==null||!exact(v.sources,['json_url','xml_url']))throw fail();
   normalizeListingRequest({version:1,action:'import',operationId:v.operationId,...v.sources});
  }else if(v.action==='rewrite'){
   if(!exact(v.choice,['choiceId','snapshotSha256'])||!id(v.choice.choiceId)||!SHA.test(v.choice.snapshotSha256)||!positive(v.productId)||v.sources!==null
    ||v.choiceSnapshot?.id!==v.productId||choiceDigest(v.choiceSnapshot,v.modeCapability.effectiveMode)!==v.choice.snapshotSha256)throw fail();
   normalizeListingRequest({version:1,action:'rewrite',operationId:v.operationId,title:v.item?.name,description:v.item?.description});
   normalizeListingSaveRequest({rewriteOperationId:v.operationId,saveOperationId:v.operationId,productId:v.productId,item:v.item});
  }else throw fail();
 }catch{throw fail();}
 const {proposalId,operationId,...base}=v;
 if(proposalId!==uuidFrom(canonicalDigest(['merchant-listings-setup-v1',base])))throw fail('ROLE_LISTINGS_SETUP_MISMATCH');
 return v;
}
function projectListingActionSetup(value){const v=validateListingActionSetup(value);
 return {version:1,kind:v.kind,proposalId:v.proposalId,operationId:v.operationId,source:{...v.source},listingsModeCapability:v.listingsModeCapability,
  ...(v.action==='import'?{sources:{...v.sources}}:{product:{choiceId:v.choice.choiceId,...structuredClone(v.item)},title:v.item.name,description:v.item.description})};
}
function createListingsChatSetup({getApplication}={}){
 if(typeof getApplication!=='function')throw TypeError('Listings application getter required');
 const application=()=>{const app=getApplication();if(typeof app?.prepareChatSetup!=='function')throw fail('ROLE_LISTINGS_SETUP_UNAVAILABLE');return app;};
 return Object.freeze({ready:true,
  async prepare(args){const app=application(),token=await captureFeatureMode(app.modeAuthority,args.context.scope,'listings');
   await args.beforeEffect?.();await token.assertCurrent();
   const value=await app.prepareChatSetup({context:args.context,action:args.action,selected:args.selected,signal:args.signal,beforeEffect:args.beforeEffect});
   await token.assertCurrent();await args.beforeEffect?.();
   if(args.action==='optimize'){const row=value.product;return require('./secureshopRoleListingOptimizeSetup').createListingOptimizeSetup({...args,listingsModeCapability:projectFeatureMode(token),product:{id:row.id,name:row.name,imageUrl:row.image_url,retailer_id:row.retailer_id,status:row.status}});}
   return createListingActionSetup({...args,listingsModeCapability:projectFeatureMode(token),product:value.product});},
  async reconstruct(args){const app=application(),optimize=args.savedProposal?.kind==='listing_optimize_setup';
   const saved=optimize?require('./secureshopRoleListingOptimizeSetup').validateListingOptimizeSetup(args.savedProposal):validateListingActionSetup(args.savedProposal);
   await args.beforeEffect?.();const token=await captureFeatureMode(app.modeAuthority,args.context.scope,'listings');await token.assertCurrent();
   if(!isDeepStrictEqual(projectFeatureMode(token),saved.listingsModeCapability))throw fail('SECURESHOP_FEATURE_MODE_STALE');
   let rebuilt;
   if(optimize){const value=await app.prepareChatSetup({context:args.context,action:'optimize',selected:args.selected,signal:args.signal,beforeEffect:args.beforeEffect});
    const row=value.product;rebuilt=require('./secureshopRoleListingOptimizeSetup').createListingOptimizeSetup({...args,listingsModeCapability:projectFeatureMode(token),product:{id:row.id,name:row.name,imageUrl:row.image_url,retailer_id:row.retailer_id,status:row.status}});}
   else rebuilt=createListingActionSetup({...args,listingsModeCapability:projectFeatureMode(token),
    retainedItem:saved.item,retainedChoiceSnapshot:saved.choiceSnapshot});
   // The saved role choice digest is checked by RoleChat against its original immutable search page.
   if(!isDeepStrictEqual(rebuilt,saved))throw fail('ROLE_LISTINGS_SETUP_MISMATCH');
   await args.beforeEffect?.();return rebuilt;}
 });
}
module.exports={createListingsChatSetup,createListingActionSetup,validateListingActionSetup,projectListingActionSetup};
