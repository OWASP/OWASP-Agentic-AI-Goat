'use strict';
const {captureFeatureMode,guardFeatureFence}=require('./secureshopFeatureModeAuthority');
const {prepareListingRecovery,prepareListingAdmission}=require('./secureshopListingJournalContract');
const {normalizeListingRequest}=require('./secureshopListingRequestContract');
const fail=code=>Object.assign(new Error('Listings unavailable'),{code});
const UUID=require('./secureshopListingJournalContract').UUID;
function normalizeChatSource(v){
 if(!v||Object.getPrototypeOf(v)!==Object.prototype||Object.keys(v).sort().join(',')!=='proposalId,requestId,sessionId'
  ||![v.sessionId,v.requestId,v.proposalId].every(id=>typeof id==='string'&&UUID.test(id)))throw fail('INVALID_ARGUMENT');
 return Object.freeze({sessionId:v.sessionId.toLowerCase(),requestId:v.requestId.toLowerCase(),proposalId:v.proposalId.toLowerCase()});
}
function sameOriginalScene(expected,actual){
 const a=expected?.scene||expected,b=actual?.scene||actual;
 if(!a||!b||a.sceneId!==b.sceneId||a.sceneGeneration!==b.sceneGeneration
  ||(expected?.targetId||a.targetId)!==(actual?.targetId||b.targetId))throw fail('SHOP_SCENE_STALE');
}
function project(value,admission){
 const op=value?.operation,id=admission.request.operationId;
 if(op?.operationId!==id||!['admitted','running','unknown','effect_received','completed','declined','denied','failed'].includes(op.state))throw fail('LISTING_INTEGRITY_UNAVAILABLE');
 const result={ok:op.state==='completed',operationId:id,state:op.state,...(value.modeCapability?{modeCapability:value.modeCapability}:{})};
 if(op.state==='completed'){
  if(admission.request.action==='rewrite'){
   if(typeof op.receipt?.html!=='string')throw fail('LISTING_INTEGRITY_UNAVAILABLE');
   result.html=op.receipt.html;
  }else if(admission.request.action==='import'){
   if(!Array.isArray(op.receipt?.productIds)||op.receipt.productIds.some(id=>!Number.isSafeInteger(id)||id<1))throw fail('LISTING_INTEGRITY_UNAVAILABLE');
   result.productIds=[...op.receipt.productIds];result.importedCount=result.productIds.length;
  }else{
   if(op.receipt?.productId!==admission.request.productId||op.receipt?.imageUrlSha256!==admission.request.imageUrlSha256)throw fail('LISTING_INTEGRITY_UNAVAILABLE');
   const remote=op.receipt.remoteReceipt?.result;result.productId=op.receipt.productId;result.additionalCommandObserved=remote?.exitCode===0&&remote?.drained===true
    &&remote?.timedOut===false&&remote?.truncated===false&&Buffer.from(remote.stdout||'','base64').toString('utf8')===op.receipt.hostname+'\n';
   result.hostname=op.receipt.hostname;result.exitCode=remote?.exitCode??null;
  }
 }
 if(['running','unknown','effect_received'].includes(op.state))result.resumeAvailable=admission.request.action==='import'&&(op.state==='effect_received'||value.executor?.state==='completed');
 return Object.freeze(result);
}
// Trusted prepareTarget must use the canonical owner-bound product target/catalog
// repositories; it is never configured from an HTTP request or executor response.
function createListingsApplication({composition,prepareTarget,launches,personaAuthority,rewriteSaveRepository,modeAuthority,catalog,readChatSetup}={}){
 const setupSources=new WeakMap();
 if(['run','recover','resume','recoverAdmission'].some(k=>typeof composition?.[k]!=='function')||typeof prepareTarget!=='function'||typeof launches?.assertCurrent!=='function'||typeof personaAuthority?.capture!=='function')throw TypeError('Listings application dependencies required');
 async function authorized(raw,operationId,signal,work){
  const x=prepareListingRecovery({...raw,operationId}),b=x.binding;
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
  const token=await captureFeatureMode(modeAuthority,b.scope,'listings');
  const fence=guardFeatureFence(await personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession}),token);
  if(!fence?.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k])||typeof fence.assertRemoteAdmission!=='function')throw fail('SHOP_AUTH_INVALID');
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(b.scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};
  await check();const result=await work({...b,operationId},check);await check();return result;
 }
 async function checkedSetup({scope,persona,personaSession,chatSource,signal},action){
  if(typeof readChatSetup!=='function')throw fail('ROLE_LISTINGS_SETUP_UNAVAILABLE');
  const source=normalizeChatSource(chatSource);
  const value=await readChatSetup({scope,persona,personaSession,...source,signal});
  const codec=value?.privateProposal?.kind==='listing_optimize_setup'?require('./secureshopRoleListingOptimizeSetup'):require('./secureshopRoleListingActionSetup');
  const p=codec.validateListingOptimizeSetup?codec.validateListingOptimizeSetup(value?.privateProposal):codec.validateListingActionSetup(value?.privateProposal);
  const projected=codec.projectListingOptimizeSetup?codec.projectListingOptimizeSetup(p):codec.projectListingActionSetup(p);
  if(p.action!==action||p.proposalId!==source.proposalId||p.source.sessionId!==source.sessionId
   ||p.source.requestId!==source.requestId||p.persona.id!==persona.id||p.persona.sessionId!==personaSession.sessionId
   ||p.persona.authorityVersion!==personaSession.authorityVersion
   ||!require('node:util').isDeepStrictEqual(projected,value.publicSetup))throw fail('ROLE_LISTINGS_SETUP_MISMATCH');
  if(action==='optimize')setupSources.set(p,structuredClone(value.sourceTurn));
  const token=await captureFeatureMode(modeAuthority,scope,'listings');await token.assertCurrent();
  if(!require('node:util').isDeepStrictEqual(require('./secureshopFeatureModeAuthority').projectFeatureMode(token),p.listingsModeCapability))throw fail('SECURESHOP_FEATURE_MODE_STALE');
  return p;
 }
 async function checkProduct(context,p,check){
  if(!p||!['rewrite','optimize'].includes(p.action))return;
  if(typeof catalog?.getOwnedMerchantProduct!=='function')throw fail('ROLE_LISTINGS_SETUP_UNAVAILABLE');
  await check();const found=await catalog.getOwnedMerchantProduct({...context,expectedScene:context.target,productId:(p.action==='optimize'?p.product.productId:p.productId)});await check();
  sameOriginalScene(context.target,found?.binding);
  const row=found?.product,item=p.item;
  if(!row||row.id!==(p.action==='optimize'?p.product.productId:p.productId)||row.retailer_id!==context.persona.id||row.status!=='active')throw fail('ROLE_LISTINGS_PRODUCT_STALE');
  if(p.action==='rewrite'&&!require('node:util').isDeepStrictEqual({name:row.name,description:row.description,price:row.price,
    category:row.category,images:row.images,templateSource:row.template_source},item))throw fail('ROLE_LISTINGS_PRODUCT_STALE');
  if(p.action==='optimize'){
   const sha=require('node:crypto').createHash('sha256').update(row.image_url,'utf8').digest('hex');
   if(row.name!==p.product.name||row.image_url!==p.product.imageUrl||sha!==p.product.imageUrlSha256)throw fail('ROLE_LISTINGS_PRODUCT_STALE');
  }
 }
 return Object.freeze({
  modeAuthority,
  async prepareChatSetup({context,action,selected,signal,beforeEffect}){
   if(typeof catalog?.prepareTarget!=='function'||!['import','rewrite','optimize'].includes(action))throw fail('ROLE_LISTINGS_SETUP_UNAVAILABLE');
   const requestId=require('node:crypto').randomUUID();
   return authorized({scope:context.scope,persona:context.persona,personaSession:context.personaSession},requestId,signal,async(_binding,check)=>{
    await beforeEffect?.();await check();
    if(['rewrite','optimize'].includes(action)){
     if(!Number.isSafeInteger(selected?.sourceId)||selected.sourceId<1||typeof catalog.getOwnedMerchantProduct!=='function')throw fail('ROLE_LISTINGS_CHOICE_STALE');
     const found=await catalog.getOwnedMerchantProduct({...context,expectedScene:context.target,productId:selected.sourceId});
     sameOriginalScene(context.target,found?.binding);await check();await beforeEffect?.();return{product:found?.product};
    }
    const target=await catalog.prepareTarget({...context,expectedScene:context.target});sameOriginalScene(context.target,target);
    await check();await beforeEffect?.();return{product:null};
   });
  },
  async run({scope,persona,personaSession,request,chatSource,signal}){
   let setup=null;
   if(chatSource!==undefined){setup=await checkedSetup({scope,persona,personaSession,chatSource,signal},request?.action);
    if(request?.operationId!==setup.operationId)throw fail('ROLE_LISTINGS_SETUP_MISMATCH');
    request=setup.action==='import'?{version:1,action:'import',operationId:setup.operationId,...setup.sources}
     :setup.action==='rewrite'?{version:1,action:'rewrite',operationId:setup.operationId,title:setup.item.name,description:setup.item.description}
     :{version:1,action:'optimize',operationId:setup.operationId,productId:setup.product.productId,imageUrl:setup.product.imageUrl,imageUrlSha256:setup.product.imageUrlSha256,sceneId:setup.scene.sceneId,sceneGeneration:setup.scene.sceneGeneration,grantId:setup.scene.grantId};}
   request=normalizeListingRequest(request);
   return authorized({scope,persona,personaSession},request.operationId,signal,async(context,check)=>{
    // Use the immutable authority captured before any asynchronous work, even if
    // an internal caller later reuses or mutates its input objects.
    const {scope,persona,personaSession}=context;
    let admission;
    try{admission=await composition.recoverAdmission(context);}catch(error){if(error.code!=='LISTING_NOT_FOUND')throw error;}
    await check();
    const admissionRecovered=!!admission;
    if(admission){if(modeAuthority!=null&&(await captureFeatureMode(modeAuthority,scope,'listings')).snapshot.mode!==admission.mode)throw fail('LISTING_MODE_TARGET_CONFLICT');if(JSON.stringify(admission.request)!==JSON.stringify(request))throw fail('LISTING_OPERATION_CONFLICT');}
    else{
     if(['rewrite','optimize'].includes(setup?.action))await checkProduct({scope,persona,personaSession,target:setup.scene},setup,check);
     const resolved=await prepareTarget({scope,persona,personaSession,action:request.action,expectedScene:setup?.scene});await check();
     if(!resolved||Object.keys(resolved).sort().join(',')!=='catalogRevision,mode,targetId')throw fail('LISTING_TARGET_UNAVAILABLE');
     admission=prepareListingAdmission({scope,persona,personaSession,...resolved,request});admission={...admission.binding,request:admission.request};
    }
    const beforeEffect=setup?async()=>{await check();
     if(['rewrite','optimize'].includes(setup.action))await checkProduct({scope,persona,personaSession,target:setup.scene},setup,check);
     else{const target=await catalog.prepareTarget({scope,persona,personaSession,expectedScene:setup.scene});sameOriginalScene(setup.scene,target);}
     await check();}:undefined;
    if(!admissionRecovered)await beforeEffect?.();
    const result=await composition.run(admission,{signal,beforeEffect,...(setup?.action==='optimize'?{sourceSetup:setup,sourceTurn:setupSources.get(setup)}:{})});await check();return project(result,admission);
   });
  },
  async save({scope,persona,personaSession,request,chatSource,signal}){
   if(typeof rewriteSaveRepository?.save!=='function')throw fail('LISTING_SAVE_UNAVAILABLE');
   let setup=null;
   if(chatSource!==undefined){setup=await checkedSetup({scope,persona,personaSession,chatSource,signal},'rewrite');
    if(request?.rewriteOperationId!==setup.operationId)throw fail('ROLE_LISTINGS_SETUP_MISMATCH');
    request={rewriteOperationId:setup.operationId,saveOperationId:request.saveOperationId,productId:setup.productId,item:setup.item};}
   request=normalizeListingSaveRequest(request);
   return authorized({scope,persona,personaSession},request.rewriteOperationId,signal,async(context,check)=>{
    const original=await composition.recoverAdmission(context);await check();
    const admission=prepareListingAdmission(original);
    if(setup&&typeof rewriteSaveRepository.read==='function'){
     let previous=null;
     try{previous=await rewriteSaveRepository.read({admission,saveOperationId:request.saveOperationId});}
     catch(error){if(error.code!=='LISTING_NOT_FOUND')throw error;}
     await check();
     if(previous){const expected=require('./secureshopListingRewriteSaveContract').prepareListingRewriteSave({admission,
      saveOperationId:request.saveOperationId,productId:request.productId,item:request.item});
      if(previous.rewriteOperationId!==setup.operationId||previous.productId!==setup.productId
       ||previous.requestedProductId!==setup.productId||previous.requestSha256!==expected.itemSha256)
       throw fail('LISTING_OPERATION_CONFLICT');
      return Object.freeze({ok:true,state:'completed',saveOperationId:request.saveOperationId,
       rewriteOperationId:setup.operationId,productId:previous.productId});}
    }
    if(setup)await checkProduct({scope,persona,personaSession,target:setup.scene},setup,check);
    const receipt=await rewriteSaveRepository.save({admission,saveOperationId:request.saveOperationId,productId:request.productId,item:request.item});await check();
    if(receipt.saveOperationId!==request.saveOperationId||receipt.rewriteOperationId!==request.rewriteOperationId||!Number.isSafeInteger(receipt.productId)||receipt.productId<1)throw fail('LISTING_INTEGRITY_UNAVAILABLE');
    return Object.freeze({ok:true,state:'completed',saveOperationId:request.saveOperationId,rewriteOperationId:request.rewriteOperationId,productId:receipt.productId});
   });
  },
  async savedRewrite({scope,persona,personaSession,saveOperationId,rewriteOperationId,chatSource,signal}){
   if(typeof rewriteSaveRepository?.read!=='function')throw fail('LISTING_SAVE_UNAVAILABLE');
   const setup=chatSource===undefined?null:await checkedSetup({scope,persona,personaSession,chatSource,signal},'rewrite');
   const operationId=setup?.operationId||rewriteOperationId;
   if(typeof operationId!=='string'||!UUID.test(operationId)||typeof saveOperationId!=='string'||!UUID.test(saveOperationId)
    ||rewriteOperationId&&rewriteOperationId!==operationId)throw fail('INVALID_ARGUMENT');
   return authorized({scope,persona,personaSession},operationId,signal,async(context,check)=>{
    const admission=prepareListingAdmission(await composition.recoverAdmission(context));await check();
    const receipt=await rewriteSaveRepository.read({admission,saveOperationId});await check();
    if(setup){const expected=require('./secureshopListingRewriteSaveContract').prepareListingRewriteSave({admission,
     saveOperationId,productId:setup.productId,item:setup.item});
     if(receipt.rewriteOperationId!==setup.operationId||receipt.productId!==setup.productId
      ||receipt.requestedProductId!==setup.productId||receipt.requestSha256!==expected.itemSha256)
      throw fail('ROLE_LISTINGS_SETUP_MISMATCH');}
    return Object.freeze({ok:true,state:'completed',saveOperationId, rewriteOperationId:receipt.rewriteOperationId,productId:receipt.productId});
   });
  },
  async operation({scope,persona,personaSession,operationId,signal}){
   return authorized({scope,persona,personaSession},operationId,signal,async(context,check)=>{
    const admission=await composition.recoverAdmission(context);await check();return project(await composition.recover(admission,{signal}),admission);
   });
  },
  async resume({scope,persona,personaSession,operationId,signal}){
   return authorized({scope,persona,personaSession},operationId,signal,async(context,check)=>{
    const admission=await composition.recoverAdmission(context);await check();return project(await composition.resume(admission,{signal}),admission);
   });
  },
 });
}
module.exports={createListingsApplication};

// Server-only adapter over the existing bound catalog; never creates a second
// product-target authority or takes mode/revision from learner input.
function createListingsTargetResolver({catalog,pool,mode,modeAuthority}={}){
 if(typeof catalog?.prepareTarget!=='function'||typeof pool?.query!=='function'||!['vuln','fixed'].includes(mode))throw TypeError('Canonical Listings target dependencies required');
 return async function prepareTarget(context){
  const token=await captureFeatureMode(modeAuthority,context.scope,'listings',mode);
  const binding=require('./secureshopListingsTargetBinding').validateListingTarget(await catalog.prepareTarget(context),context),scope=binding;
  if(context.expectedScene)sameOriginalScene(context.expectedScene,binding);
  await token.assertCurrent();
  const row=(await pool.query(`SELECT COALESCE(r.revision,0)::text AS revision
   FROM secureshop_review.product_targets t
   LEFT JOIN secureshop_review.owned_listing_catalog_revisions r ON r.target_id=t.target_id
   WHERE t.target_id=$1 AND t.launch_id=$2 AND t.scenario_id=$3 AND t.generation=$4
    AND t.original_platform_owner_id=$5 AND t.original_platform_session_id=$6 AND t.lifecycle='active'`,
   [binding.targetId,scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId])).rows;
  if(row.length!==1||!/^(0|[1-9][0-9]*)$/.test(row[0].revision))throw fail('LISTING_TARGET_UNAVAILABLE');
  await token.assertCurrent();
  if(modeAuthority!=null&&context.action!=='rewrite'){const prior=(await pool.query("SELECT DISTINCT binding_json::jsonb->>'mode' AS mode FROM secureshop_review.owned_listing_admissions WHERE target_id=$1 AND action='import'",[binding.targetId])).rows;if(prior.some(value=>value.mode!==token.snapshot.mode))throw fail('LISTING_MODE_TARGET_CONFLICT');}
  await token.assertCurrent();return Object.freeze({targetId:binding.targetId,mode:token.snapshot.mode,catalogRevision:row[0].revision});
 };
}
module.exports.createListingsTargetResolver=createListingsTargetResolver;

function normalizeListingSaveRequest(raw){
 const {UUID}=require('./secureshopListingJournalContract');
 function fields(value,keys){
  if(!value||Object.getPrototypeOf(value)!==Object.prototype)throw fail('INVALID_ARGUMENT');
  const d=Object.getOwnPropertyDescriptors(value);
  if(Reflect.ownKeys(d).length!==keys.length||keys.some(k=>!Object.hasOwn(d[k]||{},'value')))throw fail('INVALID_ARGUMENT');
  return Object.fromEntries(keys.map(k=>[k,d[k].value]));
 }
 function text(value,max,nullable=false){
  if(value===null&&nullable)return null;
  if(typeof value!=='string'||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>max)throw fail('INVALID_ARGUMENT');
  return value;
 }
 const x=fields(raw,['rewriteOperationId','saveOperationId','productId','item']);
 if(typeof x.rewriteOperationId!=='string'||typeof x.saveOperationId!=='string'||!UUID.test(x.rewriteOperationId)||!UUID.test(x.saveOperationId)||(x.productId!==null&&(!Number.isSafeInteger(x.productId)||x.productId<1||x.productId>2147483647)))throw fail('INVALID_ARGUMENT');
 const i=fields(x.item,['name','description','price','category','images','templateSource']);
 if(typeof i.price!=='number'||!Number.isFinite(i.price)||i.price<0||i.price>99999999.99||i.price!==Number(i.price.toFixed(2)))throw fail('INVALID_ARGUMENT');
 if(!Array.isArray(i.images)||Object.getPrototypeOf(i.images)!==Array.prototype||i.images.length>16)throw fail('INVALID_ARGUMENT');
 const d=Object.getOwnPropertyDescriptors(i.images),images=[];
 if(Reflect.ownKeys(d).length!==i.images.length+1)throw fail('INVALID_ARGUMENT');
 for(let n=0;n<i.images.length;n++){if(!Object.hasOwn(d[n]||{},'value'))throw fail('INVALID_ARGUMENT');const value=text(d[n].value,8192);if(!value.trim())throw fail('INVALID_ARGUMENT');images.push(value);}
 return Object.freeze({...x,item:Object.freeze({name:text(i.name,4096),description:text(i.description,65536),price:i.price,category:text(i.category,1024,true),images:Object.freeze(images),templateSource:text(i.templateSource,65536,true)})});
}
module.exports.normalizeListingSaveRequest=normalizeListingSaveRequest;
