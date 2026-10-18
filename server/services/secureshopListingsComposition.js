'use strict';
// Unmounted composition; callers provide trusted server dependencies, never HTTP configuration.
const {createHash,randomUUID}=require('node:crypto');
const {prepareListingAdmission}=require('./secureshopListingJournalContract');
const {createListingJournalRepository}=require('../database/postgres/secureshopListingJournalRepository');
const {createOwnedListingsClient}=require('./secureshopOwnedListingsClient');
const {createListingImportReceiptAdapter}=require('./secureshopListingImportReceiptAdapter');
const {createListingExecutorBridge}=require('./secureshopListingExecutorBridge');
const {createBoundListings}=require('./secureshopBoundListings');
const {resolveListingTarget,withListingTarget}=require('./secureshopListingsTargetBinding');
const {createLaunchScope}=require('./secureshopConversationBinding');
const fail=code=>Object.assign(new Error('Listings composition unavailable'),{code});
function createListingsComposition({pool,personaAuthority,capabilityKey,targetManager,launches,conversationRepository,
 journal,coordinator,provider,promptPolicyRepository,toolPolicyRepository,assessmentFactory,assessmentDependencies,modeAuthority,systemDiagnosticClient,makeId,maxClients=512,resolveTarget}={}){
 if(typeof targetManager?.resolveConfiguration!=='function'||!Number.isSafeInteger(maxClients)||maxClients<1||maxClients>4096)throw TypeError('Trusted Listings target manager required');
 const clients=new Map();
 let listingJournal;
 function capture(prepared){return prepareListingAdmission({...prepared?.binding,request:prepared?.request});}
 async function privateClient(prepared,target){
  const admission=capture(prepared),b=admission.binding;
  const storage=target?createLaunchScope(target):b.scope;
  const query=Object.freeze({scope:storage,targetId:b.targetId,mode:b.mode});
  const raw=await targetManager.resolveConfiguration(query,target?.scene?{targetBinding:target,merchantId:b.persona.id}:undefined);
  const required=['scope','targetId','mode','origin','token','runtimeIdentity','runtimeDigest','executorId'];
  const descriptors=raw&&Object.getOwnPropertyDescriptors(raw);
  if(!descriptors||Object.getPrototypeOf(raw)!==Object.prototype
   ||Reflect.ownKeys(descriptors).some(k=>!required.includes(k)||!Object.hasOwn(descriptors[k],'value'))
   ||required.some(k=>!Object.hasOwn(descriptors,k)))throw fail('LISTINGS_MANAGER_CONFIGURATION');
  const config=structuredClone(raw);
  if(config.targetId!==b.targetId||config.mode!==b.mode||!config.scope
    ||Object.keys(config.scope).length!==Object.keys(storage).length
    ||Object.keys(storage).some(k=>config.scope[k]!==storage[k]))throw fail('LISTINGS_MANAGER_BINDING');
  const canonicalConfig=Object.fromEntries(required.map(k=>[k,k==='scope'?storage:config[k]]));
  const key=JSON.stringify(query),fingerprint=createHash('sha256').update(JSON.stringify(canonicalConfig)).digest('hex');
  const previous=clients.get(key);
  if(previous){if(previous.fingerprint!==fingerprint)throw fail('LISTINGS_MANAGER_DRIFT');return previous;}
  if(clients.size>=maxClients)throw fail('LISTINGS_CLIENT_CAPACITY');
  const {scope,targetId,...registration}=config;
  const client=createOwnedListingsClient(registration);
  const record={fingerprint,client,key,users:0,retired:false};clients.set(key,record);return record;
 }
 async function withPrivateClient(prepared,work){
  const admission=capture(prepared),target=await resolveListingTarget(resolveTarget,admission.binding);
  const record=await privateClient(admission,target);if(record.retired)throw fail('LISTINGS_TARGET_RETIRED');
  // Journal preparation captures the persona fence before its scene lease.
  // Hold the scene only around external HTTP effects/readback, never around
  // a callback that may reacquire a persona authority transaction.
  const client=target?.scene?Object.freeze({...record.client,...Object.fromEntries(
   ['execute','get','readVerifiedResult','health'].map(name=>[name,(...args)=>withListingTarget(target,()=>record.client[name](...args))]))}):record.client;
  record.users++;try{return await work(client);}finally{record.users--;if(record.retired&&!record.users&&clients.get(record.key)===record)clients.delete(record.key);}
 }
 listingJournal=createListingJournalRepository({pool,personaAuthority,capabilityKey,resolveTarget,
  async validateImportReceipt(receiptHandle,prepared){
   const admission=capture(prepared);
   if(receiptHandle!==admission.request.operationId)throw fail('LISTINGS_RECEIPT_HANDLE');
   return withPrivateClient(admission,async client=>{
   // After a process restart, restore registration only after canonical persisted
   // admission validation. This is GET recovery, never a second executor POST.
   await listingJournal.get({...admission.binding,request:admission.request});
   return client.withAdmission(admission,()=>createListingImportReceiptAdapter({attestations:client}).normalize(receiptHandle,admission));
   });
  }});
 const importExecutor=Object.freeze({
  async execute(input){
   const admission=capture(input.admission);
   await input.checkCurrent();
   return withPrivateClient(admission,async client=>{await input.checkCurrent();
    return createListingExecutorBridge({listingJournal,client}).execute({...input,admission});
   });
  },
 });
 if(assessmentFactory&&assessmentDependencies)throw TypeError('Choose one Listings assessment configuration');
 const selectedAssessment=assessmentDependencies
  ?require('./secureshopListingsAssessment').createListingsAssessmentCollection(assessmentDependencies).assessmentFactory:assessmentFactory;
 const optimizeClient=systemDiagnosticClient===undefined?undefined:require('./secureshopListingOptimizeExecutor').createListingOptimizeExecutor({client:systemDiagnosticClient});
 const sameOptimizeTarget=(target,admission)=>target?.targetId===admission.binding.targetId&&target.scene?.sceneId===admission.request.sceneId&&target.scene?.sceneGeneration===admission.request.sceneGeneration&&target.scene?.grantId===admission.request.grantId;
 const optimizeExecutor=optimizeClient&&Object.freeze({async execute(input){const admission=capture(input.admission),target=await resolveListingTarget(resolveTarget,admission.binding);if(!sameOptimizeTarget(target,admission))throw fail('LISTINGS_TARGET_STALE');let receipt;await withListingTarget(target,async()=>{await input.checkCurrent();receipt=await optimizeClient.execute({...input,admission});});const current=await resolveListingTarget(resolveTarget,admission.binding);if(!sameOptimizeTarget(current,admission))throw fail('LISTINGS_TARGET_STALE');await input.checkCurrent();return receipt;}});
 const graph=createBoundListings({launches,conversationRepository,journal,coordinator,provider,listingJournal,importExecutor,optimizeExecutor,
  modeAuthority,personaAuthority,promptPolicyRepository,toolPolicyRepository,assessmentFactory:selectedAssessment,...(makeId?{makeId}:{})});
 const savedEvidence=require('../database/postgres/secureshopListingsEvidenceRepository').createListingsEvidenceRepository({reviewPool:pool,personaAuthority,listingJournal,resolveTarget});
 async function withOriginalRewriteMode(value,raw){
  if(value.result?.modeCapability)return Object.freeze({...value,modeCapability:value.result.modeCapability});
  const admission=prepareListingAdmission(raw),b=admission.binding;
  if(admission.request.action!=='rewrite'||value.operation?.state!=='completed')return value;
  const fence=await personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
  const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
  if(!fence?.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k])||typeof fence.withPersonaEffect!=='function')throw fail('SHOP_AUTH_INVALID');
  const modeCapability=await fence.withPersonaEffect(client=>require('../database/postgres/secureshopTurnModeProjection').readTurnModeProjection(client,{
   scope:b.scope,persona:b.persona,requestId:admission.request.operationId,purpose:'secureshop_listing_rewrite',message:JSON.stringify(admission.request),featureId:'listings',
   verifyResult:result=>result.taskMetadata?.listings?.operationId===admission.request.operationId&&result.taskMetadata?.listings?.action==='rewrite'
    &&(b.mode==='fixed'?result.text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'):result.text)===value.operation.receipt?.html}));
  return modeCapability?Object.freeze({...value,modeCapability}):value;
 }
 const service={
  readSavedEvidence:input=>savedEvidence.readSaved(input),
  async releaseRetiredTarget(raw,{operationId}={}){
   // Only a canonical cleanup receipt re-read and authenticated remote forget
   // acknowledgement can release target identity/configuration memory.
   if(typeof targetManager.acknowledgeRetirement!=='function')throw fail('LISTINGS_CLEANUP_PROOF');
   const value=structuredClone(raw);
   const proof=await targetManager.acknowledgeRetirement(value,{operationId});
   if(proof?.forgotten!==true||proof.operationId!==operationId||proof.targetId!==value.targetId)throw fail('LISTINGS_CLEANUP_PROOF');
   const scope=require('./secureshopConversationBinding').createLaunchScope(value.scope);
   const key=JSON.stringify({scope,targetId:value.targetId,mode:value.mode}),record=clients.get(key);
   if(record){record.retired=true;if(!record.users)clients.delete(key);}
   return Object.freeze({released:true,targetId:value.targetId});
  },
  recoverAdmission:raw=>listingJournal.recoverAdmission(raw),
  run:async(raw,options)=>withOriginalRewriteMode(await graph.run(raw,options),raw),
  async resume(raw,{signal}={}){
   signal?.throwIfAborted();
   const admission=prepareListingAdmission(raw),b=admission.binding;
   if(admission.request.action!=='import')throw fail('LISTING_RESUME_UNAVAILABLE');
   // Explicit command, separate from GET recovery. Authenticate and reconcile the
   // original effect before a new model decision; never execute the import again.
   let operation=await listingJournal.get({...b,request:admission.request});
   signal?.throwIfAborted();
   if(['completed','declined'].includes(operation.state))return Object.freeze({operation,replayed:true});
   if(['running','unknown'].includes(operation.state)){
    operation=await listingJournal.transition({...b,request:admission.request},{eventId:randomUUID(),expectedSequence:operation.sequence,state:'effect_received',receipt:admission.request.operationId});
   }
   if(operation.state!=='effect_received')throw fail('LISTING_RESUME_UNAVAILABLE');
   return graph.resume({...b,request:admission.request},{signal});
  },
  async recover(raw,{signal}={}){
   const admission=prepareListingAdmission(raw),b=admission.binding;
   const expected={...b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession};
   const fence=await personaAuthority.capture({scope:b.scope,personaId:b.persona.id,role:b.persona.role,...b.personaSession});
   if(!fence?.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k])||typeof fence.assertRemoteAdmission!=='function')throw fail('SHOP_AUTH_INVALID');
   const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(b.scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};
   await check();const operation=await listingJournal.get({...b,request:admission.request});await check();
   if(admission.request.action!=='import'||!['running','unknown','effect_received'].includes(operation.state))return withOriginalRewriteMode(Object.freeze({operation}),raw);
   return withPrivateClient(admission,async client=>{
   const executor=await createListingExecutorBridge({listingJournal,client}).recover({admission,signal,checkCurrent:check});
   await check();return Object.freeze({operation,executor});
   });
  },
 };
 let active=0,disposed=false;
 const invoke=name=>async(...args)=>{
  if(disposed)throw fail('LISTINGS_COMPOSITION_DISPOSED');
  active++;try{return await service[name](...args);}finally{active--;}
 };
 return Object.freeze({readSavedEvidence:invoke('readSavedEvidence'),releaseRetiredTarget:invoke('releaseRetiredTarget'),run:invoke('run'),recover:invoke('recover'),resume:invoke('resume'),recoverAdmission:invoke('recoverAdmission'),
  dispose(){
   if(active)throw fail('LISTINGS_COMPOSITION_BUSY');
   disposed=true;clients.clear();
  },
 });
}
module.exports={createListingsComposition};
