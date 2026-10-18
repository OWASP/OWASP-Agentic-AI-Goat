'use strict';
const { createHash } = require('node:crypto');
const { canonicalDigest } = require('./mcp/protocolContext');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { createSecureShopEmbeddingReindex } = require('./secureshopEmbeddingReindex');
const { executionScope } = require('./secureshopSceneBinding');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/;
const CORPORA=new Set(['products','reviews','manuals','policies']);
const CAPABILITY='secureshop-owned-system-rebuild.v1';
const fail=(code,message='System rebuild unavailable')=>Object.assign(new Error(message),{code});
function exact(value,keys){if(!value||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(value,k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value')))throw fail('INVALID_ARGUMENT');}
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function normalizeRebuildRequest(raw){exact(raw,['version','operationId','corpus']);if(raw.version!==1||typeof raw.operationId!=='string'||!UUID.test(raw.operationId)||typeof raw.corpus!=='string')throw fail('INVALID_ARGUMENT');if(!CORPORA.has(raw.corpus))throw fail('EMBEDDING_REINDEX_UNSUPPORTED');return Object.freeze({version:1,operationId:raw.operationId.toLowerCase(),corpus:raw.corpus});}
function rebuildRequestDigest(raw){return digest(normalizeRebuildRequest(raw));}
function rebuildBindingDigest(requestSha256,binding,actor){if(!HASH.test(requestSha256))throw fail('INVALID_ARGUMENT');const storage={targetId:binding.targetId,launchId:binding.launchId,scenarioId:binding.scenarioId,generation:binding.generation,platformOwnerId:binding.platformOwnerId,platformSessionId:binding.platformSessionId};const identity={id:actor.id,role:actor.role,sessionId:actor.sessionId,authorityVersion:actor.authorityVersion};return binding.scene?digest({version:2,requestSha256,storage,execution:executionScope(binding),sceneId:binding.scene.sceneId,sceneGeneration:binding.scene.sceneGeneration,grantId:binding.scene.grantId,actor:identity}):digest({version:1,requestSha256,target:storage,actor:identity});}
function createSecureShopSystemRebuildService({resolveTarget,journal,revisionRepository,embedder,checkCurrent,policySource=null}={}){
 if(typeof resolveTarget!=='function'||typeof journal?.begin!=='function'||typeof journal?.read!=='function'||typeof journal?.complete!=='function'||typeof journal?.markFailed!=='function'||typeof journal?.abandon!=='function'||typeof revisionRepository?.publishInTransaction!=='function'||typeof embedder?.embed!=='function'||typeof embedder?.getRuntimeFingerprint!=='function'||typeof checkCurrent!=='function')throw new TypeError('System rebuild service dependencies required');
 const authorityInput=raw=>{exact(raw,['scope','persona','personaSession']);const copy=structuredClone(raw),scope=createLaunchScope(copy.scope),persona=createConversationBinding(scope,copy.persona);if(persona.role!=='admin')throw fail('ADMIN_REQUIRED');exact(copy.personaSession,['sessionId','authorityVersion']);if(typeof copy.personaSession.sessionId!=='string'||!UUID.test(copy.personaSession.sessionId)||typeof copy.personaSession.authorityVersion!=='string'||!/^[1-9]\d{0,15}$/.test(copy.personaSession.authorityVersion)||BigInt(copy.personaSession.authorityVersion)>BigInt(Number.MAX_SAFE_INTEGER))throw fail('SHOP_AUTH_INVALID');return Object.freeze({scope,persona:Object.freeze({id:persona.shopUserId,role:persona.role}),personaSession:Object.freeze({...copy.personaSession,sessionId:copy.personaSession.sessionId.toLowerCase()})});};
 const resolve=async(raw,options)=>{
 const admitted=authorityInput(raw),resolved=await resolveTarget(admitted,{signal:options?.signal});
  if(!resolved?.binding||!resolved?.actor||typeof resolved?.personaEffect?.admitRebuild!=='function'||typeof resolved.personaEffect.publish!=='function')throw fail('SHOP_AUTH_INVALID');
  try{if(!resolved.binding.scene)exact(resolved.binding,['launchId','scenarioId','generation','platformOwnerId','platformSessionId','targetId']);executionScope(resolved.binding);exact(resolved.actor,['id','role','sessionId','authorityVersion']);}catch{throw fail('SHOP_AUTH_INVALID');}
  if(typeof resolved.binding.targetId!=='string'||!UUID.test(resolved.binding.targetId))throw fail('SHOP_AUTH_INVALID');
  // The target belongs to immutable storage; a scene's current execution
  // scope contains only launch/session authority, not the birth target ID.
  const expected=admitted.scope;
  if(Object.keys(expected).some(k=>executionScope(resolved.binding)[k]!==expected[k])||resolved.actor.id!==admitted.persona.id||resolved.actor.role!=='admin'||resolved.actor.sessionId!==admitted.personaSession.sessionId||resolved.actor.authorityVersion!==admitted.personaSession.authorityVersion)throw fail('SHOP_AUTH_INVALID');
  return Object.freeze({...resolved,scope:admitted.scope});
 };
 const prepared=async(raw,options)=>{
  exact(raw,['scope','persona','personaSession','request']);const copy=structuredClone(raw),request=normalizeRebuildRequest(copy.request);const resolved=await resolve({scope:copy.scope,persona:copy.persona,personaSession:copy.personaSession},options);
  const requestSha256=rebuildRequestDigest(request),bindingSha256=rebuildBindingDigest(requestSha256,resolved.binding,resolved.actor);
  if(request.corpus==='policies'&&typeof policySource?.capture!=='function')throw fail('EMBEDDING_REINDEX_UNSUPPORTED');
  const policySnapshot=request.corpus==='policies'?await policySource.capture({scope:copy.scope,persona:copy.persona,personaSession:copy.personaSession}):null;
  return Object.freeze({...resolved,request,requestSha256,bindingSha256,journalInput:Object.freeze({binding:resolved.binding,actor:resolved.actor,request,requestSha256,bindingSha256,...(policySnapshot?{policySnapshot}:{})})});
 };
 const classify=error=>error?.name==='AbortError'?'ABORTED':error?.code==='SHOP_AUTH_INVALID'?'AUTHORITY_REVOKED':error?.code==='EMBEDDING_RUNTIME_CHANGED'?'RUNTIME_CHANGED':['EMBEDDING_REINDEX_STALE_SOURCE','STALE_SOURCE'].includes(error?.code)?'SOURCE_CHANGED':['EMBEDDING_REVISION_UNAVAILABLE','EMBEDDING_REINDEX_INVALID'].includes(error?.code)?'PUBLICATION_REJECTED':'EXECUTION_FAILED';
 return Object.freeze({
  async administration(raw,{signal}={}){
   const p=await resolve(structuredClone(raw),{signal});signal?.throwIfAborted();
   await p.personaEffect.check(p.binding);signal?.throwIfAborted();
   return Object.freeze({rebuildCapability:CAPABILITY,scopeKey:canonicalDigest({version:'secureshop-system-rebuild-administration.v1',binding:p.binding,actor:p.actor}),corpora:Object.freeze([...CORPORA].filter(c=>c!=='policies'||typeof policySource?.capture==='function'))});
  },
  async execute(raw,{signal}={}){
   const p=await prepared(raw,{signal});signal?.throwIfAborted();
   const admitted=await p.personaEffect.admitRebuild(journal,p.binding,p.journalInput);
   if(admitted?.kind==='replay')return admitted.result;
   if(admitted?.kind!=='worker'||!admitted.handle||!admitted.snapshot)throw fail('REBUILD_JOURNAL_INVALID');
   let publishing=false,settled=false;
   const facade=Object.freeze({
    async snapshot(){throw fail('REBUILD_SNAPSHOT_INVALID');},
    async snapshotSelective(binding,input){if(Object.keys(p.binding).some(k=>binding?.[k]!==p.binding[k])||JSON.stringify(input?.sourceKinds)!==JSON.stringify({products:['product','listing'],reviews:['review'],manuals:['manual'],policies:['policy']}[p.request.corpus]))throw fail('REBUILD_SNAPSHOT_INVALID');return admitted.snapshot;},
    async publish(binding,publication,options){publishing=true;const result=await journal.complete(admitted.handle,binding,publication,options);settled=true;return result;},
   });
   try{
    const worker=createSecureShopEmbeddingReindex({repository:facade,embedder,checkCurrent});
    if(admitted.snapshot.operationMode==='initialize'){
     const fullFacade=Object.freeze({snapshot:async binding=>{if(Object.keys(p.binding).some(k=>binding?.[k]!==p.binding[k]))throw fail('REBUILD_SNAPSHOT_INVALID');return admitted.snapshot;},publish:facade.publish});
     return await createSecureShopEmbeddingReindex({repository:fullFacade,embedder,checkCurrent}).reindex({scope:p.scope,binding:p.binding,operationId:p.request.operationId,signal,personaEffect:p.personaEffect});
    }
    if(admitted.snapshot.operationMode!=='selective')throw fail('REBUILD_SNAPSHOT_INVALID');
    return await worker.reindexSelective({scope:p.scope,binding:p.binding,operationId:p.request.operationId,corpus:p.request.corpus,signal,personaEffect:p.personaEffect});
   }catch(error){
    if(settled)throw error;
    if(publishing){await journal.abandon(admitted.handle).catch(()=>{});throw error;}
    try{
     const failureFacade=Object.freeze({publish:()=>journal.markFailed(admitted.handle,classify(error))});
     await p.personaEffect.publish(failureFacade,p.binding,Object.freeze({}));settled=true;
    }catch(cause){if(!settled)await journal.abandon(admitted.handle).catch(()=>{});throw cause;}
    throw error;
   }
  },
  async read(raw,{signal}={}){exact(raw,['scope','persona','personaSession','operationId']);const copy=structuredClone(raw);if(typeof copy.operationId!=='string'||!UUID.test(copy.operationId))throw fail('INVALID_ARGUMENT');const p=await resolve({scope:copy.scope,persona:copy.persona,personaSession:copy.personaSession},{signal});signal?.throwIfAborted();await p.personaEffect.check(p.binding);const result=await journal.read({binding:p.binding,actor:p.actor,operationId:copy.operationId.toLowerCase()});await p.personaEffect.check(p.binding);return result;},
 });
}
module.exports={SYSTEM_REBUILD_CAPABILITY:CAPABILITY,normalizeRebuildRequest,rebuildRequestDigest,rebuildBindingDigest,createSecureShopSystemRebuildService};
