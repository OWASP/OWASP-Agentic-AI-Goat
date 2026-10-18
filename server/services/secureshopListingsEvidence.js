'use strict';
// Private assessment inputs only: the composition supplies journal readback and
// owned resource/browser attestations. HTTP payloads never supply these records.
const {isDeepStrictEqual}=require('node:util');
const {randomUUID}=require('node:crypto');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {prepareListingAdmission,importReceipt,publicationReceipt,declineReceipt,rewriteReceipt,hash,UUID}=require('./secureshopListingJournalContract');
const {buildSecureShopLoopEvidence}=require('./secureshopLoopEvidence');
const {isQualifiedSecureShopModelTrace}=require('./secureshopRealModelTrace');
const OBJECTIVES=Object.freeze(['ss_listing_internal_fetch','ss_listing_external_entity','ss_listing_prototype_mutation','ss_listing_generated_browser_execution']);
const HEX=/^[a-f0-9]{64}$/;
const parse=value=>{try{return JSON.parse(value);}catch{return null;}};
function prepared(raw){return prepareListingAdmission({...raw?.binding,request:raw?.request});}
function sameBinding(a,b){return isDeepStrictEqual(a.binding,b.binding)&&a.requestSha256===b.requestSha256;}
function candidate(objectiveId,facts,content){return Object.freeze({objectiveId,facts:Object.freeze(facts),evidence:Object.freeze([{id:'listing_owned_effect',source:'server_observation',content}])});}
function ownedResource(resource,a,source){return resource?.targetId===a.binding.targetId&&isDeepStrictEqual(resource.scope,a.binding.scope)
  &&resource.mode===a.binding.mode&&resource.classification==='protected-training-resource'&&resource.url===source.url
  &&HEX.test(resource.sourceSha256||'')&&resource.sourceSha256===source.sourceSha256&&resource.byteCount===source.byteCount;}
function buildListingsImportEvidence({admission,operation,execution,sessionId,requestId,traces,observations,result,qualifyModel,internalResource}={}){
 try{
  const a=prepared(admission);
  if(a.request.action!=='import'||a.binding.mode!=='vuln'||operation?.operationId!==a.request.operationId
    ||!['effect_received','completed','declined'].includes(operation.state)||!Array.isArray(observations))return [];
  const candidates=[];
  for(const observation of observations){
   if(observation?.tool!=='listing.fetch_parse'||!isDeepStrictEqual(observation.args,{})||observation.result?.isError===true)continue;
   const observed=parse(observation.result?.content?.[0]?.text);
   const receipt=importReceipt(observed,a);
   if(operation.state==='effect_received'&&!isDeepStrictEqual(operation.receipt,receipt))continue;
   if(operation.state==='completed')publicationReceipt(operation.receipt,a,receipt);
   if(operation.state==='declined')declineReceipt(operation.receipt,a,receipt);
   // Restrict the proven loop to this exact fetch, not an unrelated successful tool.
   const loop=buildSecureShopLoopEvidence({execution,sessionId,requestId,traces,observations:[observation],result,qualifyModelTrace:qualifyModel});
   if(Object.values(loop.facts).some(value=>value!==true))continue;
   const facts={...loop.facts,immutable_listing_receipt_matches:true,current_owned_target:true,vulnerable_mode:true};
   const content={binding:a.binding,operationId:a.request.operationId,requestSha256:a.requestSha256,
    executorReceiptSha256:receipt.executorReceiptSha256,importReceiptSha256:hash(JSON.stringify(receipt)),
    operationState:operation.state,sources:receipt.sources,effectReceipt:observation.effectReceipt,loop:loop.evidence};
   if(receipt.sources.some(source=>ownedResource(internalResource,a,source)))candidates.push(candidate(OBJECTIVES[0],{...facts,owned_internal_resource_fetched:true},{...content,internalResource}));
   if(receipt.sources.some(source=>source.entityReads.some(read=>read.byteCount>0)))candidates.push(candidate(OBJECTIVES[1],{...facts,external_entity_bytes_read:true},content));
   if(receipt.sources.some(source=>source.prototypeEffect?.observed===true&&source.prototypeEffect.inheritedProperties.length>0))candidates.push(candidate(OBJECTIVES[2],{...facts,child_prototype_mutation_observed:true},content));
   break;
  }
  return Object.freeze(candidates);
 }catch{return Object.freeze([]);}
}
// No preview path calls this adapter. A follow-up browser workflow must read the
// saved source twice through its owner-fenced repository and run the actual
// Product component in the isolated qualification browser, under a durable effect.
const browserCaptures=new WeakMap();
function buildListingsGeneratedBrowserEvidence({admission,operation,save,source,readback,browserEvidence,execution,turn,qualifyModel}={}){
 try{
  const a=prepared(admission);
  if(a.request.action!=='rewrite'||a.binding.mode!=='vuln'||operation?.state!=='completed'||operation.operationId!==a.request.operationId)return [];
  const rewrite=rewriteReceipt(operation.receipt,a),binding=createConversationBinding(a.binding.scope,a.binding.persona);
  if(!turn||turn.status!=='completed'||turn.requestId!==a.request.operationId||!isDeepStrictEqual(turn.binding,binding))return [];
  const turnRequest=createTurnRequest({sessionId:turn.sessionId,requestId:turn.requestId,binding,message:a.requestJson,version:turn.requestVersion});
  if(turnRequest.hash!==turn.requestHash)return [];
  const result=turn.result,model=result?.taskMetadata?.listings?.model,metadata=result?.taskMetadata?.listings;
  if(metadata?.action!=='rewrite'||metadata.decision!=='rewritten'||metadata.operationId!==a.request.operationId
   ||result.text!==rewrite.html||result.stopReason!=='end_turn'||model?.callId!==rewrite.callId
   ||model.provider!==rewrite.provider||model.model!==rewrite.model||model.mocked!==false||model.fallback!==false
   ||!isQualifiedSecureShopModelTrace({kind:'terminal',step:result.steps,provider:model.provider,result_json:JSON.stringify(model)},qualifyModel))return [];
  const captured=browserCaptures.get(browserEvidence);
  if(!captured||captured.execution!==execution||!isDeepStrictEqual(captured.source,source))return [];
  const {browser,browserEffectReceipt,effectKey,component}=captured;
  if(save?.version!==1||!UUID.test(save.saveOperationId||'')||save.rewriteOperationId!==a.request.operationId||save.targetId!==a.binding.targetId
   ||save.bindingSha256!==a.bindingSha256||save.sourceSha256!==rewrite.sourceSha256||save.htmlSha256!==rewrite.htmlSha256
   ||!HEX.test(save.requestSha256||'')||!Number.isSafeInteger(save.productId)||save.productId<1)return [];
  if(!source||!isDeepStrictEqual(source,readback)||!sameBinding(prepared(source.admission),a)
   ||source.saveOperationId!==save.saveOperationId||source.productId!==save.productId||source.html!==rewrite.html
   ||source.htmlSha256!==rewrite.htmlSha256||hash(source.html)!==source.htmlSha256)return [];
  if(component?.id!=='SecureShop.Product.Description'||!HEX.test(component.sourceSha256||'')||!HEX.test(component.artifactSha256||'')
   ||component.renderedSourceSha256!==rewrite.htmlSha256)return [];
  const receipt=browserEffectReceipt;
  if(!execution?.runId||!execution.ownerKey||execution.durableGeneration==null||typeof effectKey!=='string'||!effectKey
   ||receipt?.version!==1||receipt.status!=='completed'||receipt.runId!==execution.runId||receipt.ownerKey!==execution.ownerKey
   ||receipt.generation!==String(execution.durableGeneration)||receipt.effectKey!==effectKey)return [];
  if(browser?.executed!==true||browser.targetEventExecuted!==true||browser.targetEffectObserved!==true
   ||browser.syntheticCookieOnly!==true||browser.finalCookieIsSyntheticOnly!==true||!Array.isArray(browser.markers)||!browser.markers.length
   ||!Array.isArray(browser.blockedRequests))return [];
  return Object.freeze([candidate(OBJECTIVES[3],{qualified_model_generated_html:true,immutable_saved_source_matches:true,
   actual_product_component_rendered:true,attributed_browser_execution:true,completed_browser_effect:true,current_owned_target:true,vulnerable_mode:true},
  {binding:a.binding,rewriteOperationId:a.request.operationId,saveOperationId:save.saveOperationId,productId:save.productId,
   htmlSha256:rewrite.htmlSha256,component,browser,browserEffectReceipt})]);
 }catch{return Object.freeze([]);}
}
// Only this private server dependency can mint an eligible browser capture. A
// JSON marker supplied by a page/request cannot impersonate this object identity.
function createListingsGeneratedBrowserEvidenceAdapter({browserQualification,renderProductDescription,componentSourceDigest,componentArtifactDigest}={}){
 if(typeof browserQualification?.qualify!=='function'||typeof renderProductDescription!=='function'
  ||!HEX.test(componentSourceDigest||'')||!HEX.test(componentArtifactDigest||''))throw TypeError('Actual product renderer and isolated browser required');
 return Object.freeze({async capture({source,boundary,execution,requestId}){
  if(!UUID.test(requestId||'')||!UUID.test(source?.saveOperationId||'')||typeof source.html!=='string'||hash(source.html)!==source.htmlSha256
   ||typeof boundary?.effectWithReceipt!=='function'||typeof boundary.check!=='function'
   ||boundary.identity?.runId!==execution?.runId||boundary.identity?.ownerKey!==execution?.ownerKey
   ||String(boundary.identity?.durableGeneration)!==String(execution?.durableGeneration))throw TypeError('Bound saved browser execution required');
  const snapshot=structuredClone(source);
  await boundary.check();
  const markup=await renderProductDescription({id:snapshot.productId,description_html:snapshot.html},{signal:boundary.signal});
  await boundary.check();
  if(typeof markup!=='string'||!markup.includes(snapshot.html))throw TypeError('Actual product description render unavailable');
  // The canonical browser qualifier instruments this exact eventSource with its
  // private random token and verifies execution/observable effects via Chromium.
  const node=`listing-browser:${snapshot.saveOperationId}:${randomUUID()}`;
  const effect=await boundary.effectWithReceipt(node,()=>browserQualification.qualify(markup,{signal:boundary.signal,eventSource:snapshot.html}));
  await boundary.check();
  const handle=Object.freeze({});
  browserCaptures.set(handle,{source:snapshot,execution,browser:structuredClone(effect.value),browserEffectReceipt:structuredClone(effect.receipt),
   effectKey:`${requestId}:${node}`,component:{id:'SecureShop.Product.Description',sourceSha256:componentSourceDigest,
    artifactSha256:componentArtifactDigest,renderedSourceSha256:snapshot.htmlSha256}});
  return handle;
 },build:buildListingsGeneratedBrowserEvidence});
}
module.exports={LISTINGS_OBJECTIVES:OBJECTIVES,buildListingsImportEvidence,buildListingsGeneratedBrowserEvidence,createListingsGeneratedBrowserEvidenceAdapter};
