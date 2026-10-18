'use strict';
const {verifyReceipt}=require('../database/postgres/secureshopAuditQueryRepository');
const {createLaunchScope}=require('./secureshopConversationBinding');
const witnesses=new WeakMap();
function uncertain(cause){if(cause?.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN')return cause;const error=Object.assign(Error('Owned manual audit effect outcome uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});Object.defineProperty(error,'cause',{value:cause});return error;}
function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
function createOwnedAuditManualAdapter({repository,client}){
 return Object.freeze({
 async read({binding,persona,operationId,token},fence){
  const identity=freeze(structuredClone({binding:createLaunchScope(binding),persona,operationId}));
  if(fence!==undefined){const b=fence.binding;
   if(typeof fence.assertRemoteAdmission!=='function'||!b
    ||Object.keys(identity.binding).some(key=>identity.binding[key]!==b[key])
    ||identity.persona?.role!=='admin'||b.role!=='admin'||identity.persona.id!==b.personaId)throw TypeError('Manual audit persona fence mismatch');
  }
  await fence?.assertRemoteAdmission();
  const saved=await repository.read({...identity,token});
  await fence?.assertRemoteAdmission();
  if(saved.state==='not_found')return{version:1,operationId,status:'not_found',result:null,source:null};
  const request=freeze(structuredClone(saved.request));
  let receipt=saved.receipt;
  if(saved.state==='pending'){
   // Reconcile only an already completed remote receipt. Never call search,
   // begin or target provisioning from protected recovery.
   try{receipt=await client.receipt({binding:identity.binding,operationId,username:request.username});}
   catch(error){await fence?.assertRemoteAdmission();if(error?.code!=='AUDIT_QUERY_UNCERTAIN')throw error;
    return{version:1,operationId,status:'unconfirmed',result:null,source:null};}
   await fence?.assertRemoteAdmission();verifyReceipt(receipt,request);
   receipt=await repository.complete({request,token,receipt});
  }else if(saved.state!=='completed')throw Error('Invalid audit readback state');
  await fence?.assertRemoteAdmission();verifyReceipt(receipt,request);
  await repository.assertCurrent({request,token});await fence?.assertRemoteAdmission();
  return freeze({version:1,operationId,status:'completed',result:structuredClone(receipt.result),
   source:{sourceSha256:receipt.sourceSha256,payloadSha256:receipt.payloadSha256}});
 },
 async execute({request,token,beforeEffect,signal},fence){
  if(beforeEffect!==undefined&&typeof beforeEffect!=='function')throw TypeError('Invalid audit effect guard');
  const identity=freeze(structuredClone(request));
  if(fence!==undefined){const scope=createLaunchScope(identity.binding),actual=createLaunchScope(fence?.binding),b=fence?.binding;
   if(typeof fence.assertRemoteAdmission!=='function'||Object.keys(scope).some(key=>scope[key]!==actual[key])||b.personaId!==identity.persona?.id||b.role!=='admin'||identity.persona?.role!=='admin'||typeof b.sessionId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(b.sessionId)||typeof b.authorityVersion!=='string'||!/^[1-9][0-9]*$/.test(b.authorityVersion))throw TypeError('Manual audit persona fence mismatch');
   await fence.assertRemoteAdmission();}
  let effectMayExist=false;try{const admission=await repository.begin({request:identity,token});const body={binding:identity.binding,operationId:identity.operationId,username:identity.username};
  effectMayExist=admission.state==='pending'||admission.state==='completed';
  if(fence!==undefined)await fence.assertRemoteAdmission();
  let receipt=admission.receipt;
  if(admission.state!=='completed'){if(fence!==undefined)await fence.assertRemoteAdmission();await beforeEffect?.();signal?.throwIfAborted();effectMayExist=true;receipt=await client[admission.state==='pending'?'receipt':'search'](body);if(fence!==undefined)await fence.assertRemoteAdmission();verifyReceipt(receipt,identity);if(fence!==undefined)await fence.assertRemoteAdmission();receipt=await repository.complete({request:identity,token,receipt});}
  if(fence!==undefined)await fence.assertRemoteAdmission();
  await repository.assertCurrent({request:identity,token});if(fence!==undefined)await fence.assertRemoteAdmission();const result=freeze(structuredClone(receipt.result));witnesses.set(result,freeze({version:1,decisionSource:'manual',modelProvenance:false,request:identity,receipt:structuredClone(receipt)}));return result;
  }catch(error){if(fence!==undefined&&effectMayExist)throw uncertain(error);throw error;}
 }});
}
module.exports={createOwnedAuditManualAdapter,witnessFor:result=>witnesses.get(result)||null};
