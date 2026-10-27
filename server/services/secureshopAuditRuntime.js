'use strict';
const path=require('node:path');
const {captureFeatureMode,guardFeatureFence,featureModeForFence}=require('./secureshopFeatureModeAuthority');
const {createSecureShopAuditRunner}=require('./secureshopAuditRunner');
const {createSecureShopAuditJob}=require('./secureshopAuditJob');
const {createSecureShopAuditAssessment}=require('./secureshopAuditAssessment');
const {consumeSecureShopAuditEvidence}=require('./secureshopAuditVerifiedEvidence');
const {createSecureShopModelQualifier}=require('./secureshopModelQualification');
const {OllamaProvider}=require('./secureshop/providers/ollamaProvider');

// One retained runtime shares conversation authority and ledger with reset.
// Configuration and private spool location are server-owned, never HTTP input.
function createSecureShopAuditRuntime({agentsPool,reviewPool,ledger,turns,conversations,journal,
  receipts,progress,judge,root,baseUrl,model,personaAuthority,personaBindings,modeAuthority,scenes,toolPolicyAdmission,toolPolicyRepository,promptPolicyRepository,assessmentVariant='instruction'}={}){
  if (!['instruction','unbounded'].includes(assessmentVariant)) throw new TypeError('Invalid audit assessment configuration');
  const conversationPurpose=require('./secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES[assessmentVariant==='unbounded'?'auditUnbounded':'auditSummary'];
  const taskRequestVersion=assessmentVariant==='unbounded'?2:1;
  if (!conversationPurpose) throw new TypeError('Audit conversation purpose unavailable');
  if(typeof root!=='string'||!path.isAbsolute(root)||typeof model!=='string'||!model.trim()
    ||typeof baseUrl!=='string'||typeof ledger?.readCompletedEffect!=='function'
    ||typeof agentsPool?.query!=='function'||typeof agentsPool?.connect!=='function'
    ||typeof reviewPool?.connect!=='function'||typeof conversations?.create!=='function')throw new TypeError('Owned audit runtime configuration required');
  if(personaBindings!==undefined&&typeof personaAuthority?.capture!=='function')throw new TypeError('Audit persona authority required');
  if(personaAuthority!==undefined&&typeof personaAuthority?.capture!=='function')throw new TypeError('Invalid audit persona authority');
  if (scenes !== undefined && (typeof scenes?.readRetained !== 'function' || !personaAuthority))
    throw new TypeError('Audit retained scene authority required');
  if (assessmentVariant==='unbounded' && (!personaAuthority || !scenes)) throw new TypeError('Unbounded audit requires retained persona and scene authority');
  const witnessSelectors=new Map();
  const sceneContexts=new WeakMap();
  async function retainScene(binding) {
    const {executionScope,withSceneLease,assertSceneGrant}=require('./secureshopSceneBinding');
    const sceneBinding=await scenes.readRetained(binding);
    const keys=['launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
    const fail=()=>Object.assign(new Error('Audit selected practice is unavailable'),{code:'SHOP_SCENE_STALE',executionBoundary:true});
    if (!sceneBinding?.scene || keys.some(key=>executionScope(sceneBinding)[key]!==binding[key])) throw fail();
    const checkScene=async()=>{
      const current=await scenes.readRetained(binding);
      if (!current?.scene || current.targetId!==sceneBinding.targetId
          || ['sceneId','sceneGeneration','grantId'].some(key=>current.scene[key]!==sceneBinding.scene[key])
          || keys.some(key=>executionScope(current)[key]!==binding[key])) throw fail();
      await withSceneLease(sceneBinding,async()=>{
        const client=await reviewPool.connect();
        try { await assertSceneGrant(client,sceneBinding); } finally { client.release(); }
      });
    };
    await checkScene();
    return Object.freeze({sceneBinding,checkScene});
  }
  const capturePersonaAuthority=personaAuthority?async({binding,personaSession})=>{
    personaSession=personaSession===undefined?undefined:Object.freeze({sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
    const fence=await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,
      sessionId:personaSession?.sessionId,authorityVersion:personaSession?.authorityVersion});
    const actual=fence?.binding;
    if(!actual||typeof fence.assertRemoteAdmission!=='function'||typeof fence.withPersonaEffect!=='function'
      ||['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key=>actual[key]!==binding[key])
      ||actual.personaId!==binding.shopUserId||actual.role!==binding.role
      ||typeof personaSession?.sessionId!=='string'||actual.sessionId!==personaSession.sessionId.toLowerCase()
      ||typeof personaSession?.authorityVersion!=='string'||actual.authorityVersion!==personaSession.authorityVersion)
      throw Object.assign(new Error('Audit persona authority unavailable'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
    const guarded=guardFeatureFence(fence,await captureFeatureMode(modeAuthority,binding,'audit_summary'));
    if (scenes) {
      await guarded.assertRemoteAdmission();
      sceneContexts.set(guarded,await retainScene(binding));
      await guarded.assertRemoteAdmission();
    }
    return guarded;
  }:undefined;
  if(promptPolicyRepository!==undefined&&(typeof promptPolicyRepository?.admitRunSnapshot!=='function'||typeof personaAuthority?.capture!=='function'))throw new TypeError('Audit prompt policy authority required');
  if(toolPolicyRepository!==undefined){
    if(toolPolicyAdmission!==undefined)throw new TypeError('Specify one audit policy source');
    if(typeof personaAuthority?.capture!=='function')throw new TypeError('Audit policy persona authority required');
    toolPolicyAdmission=require('./secureshopBoundToolPolicyAdmission').createBoundToolPolicyAdmission({
      repository:toolPolicyRepository,workflow:'audit-summary',
      declaredTools:require('./secureshopAuditExecutionConfig').createSecureShopAuditExecutionConfig().manifest.getForRole('admin')});
  }
  if(toolPolicyAdmission!==undefined&&(typeof toolPolicyAdmission!=='function'||!personaAuthority))throw new TypeError('Audit policy authority required');
  const endpoint=new URL(baseUrl);
  if(!['http:','https:'].includes(endpoint.protocol)||endpoint.username||endpoint.password)
    throw new TypeError('Invalid audit model endpoint');
  const provider=new OllamaProvider({baseUrl,model});
  const timing=require('./secureshopAuditTiming').createSecureShopAuditTiming({
    profile:assessmentVariant==='unbounded'?'unbounded':'instruction',
  });
  const qualifyModel=createSecureShopModelQualifier(provider);
  const snapshot=require('../database/postgres/secureshopAuditSnapshot').createSecureShopAuditSnapshot({agentsPool,reviewPool});
  const auditJudge=judge===undefined?require('./secureshopAuditTiming').createSecureShopAuditJudge(timing):judge;
  const assessmentOptions={receipts,progress,judge:auditJudge,qualifyModel,personaBindings};
  const assessmentFactory=assessmentVariant==='unbounded'
    ?require('./secureshopAuditUnboundedAssessment').createSecureShopAuditUnboundedAssessment({...assessmentOptions,
      readWitness:async({binding,execution,evidence})=>{
        const reader=require('../database/postgres/secureshopAuditRunReader').createSecureShopAuditRunReader({pool:agentsPool,checkCurrent:execution.check,readCompletedEffect:(context,key)=>ledger.readCompletedEffect(context,key)});
        return require('./secureshopAuditUnboundedWitnessReader').createSecureShopAuditUnboundedWitnessReader({openAuditRun:input=>reader.open(input),selectWitness:witnessSelectors.get(execution.runId)})({binding,execution,evidence});
      }})
    :createSecureShopAuditAssessment(assessmentOptions);
  const sceneSource=scenes?require('../database/postgres/secureshopSceneProductAuditSource').createSecureShopSceneProductAuditSource({reviewPool}):undefined;
  const beginAssessment=async(context,fence)=>{
    const scene=sceneContexts.get(fence);
    if (!scene) return assessmentFactory(context,fence);
    const execution=Object.freeze({...context.execution,check:async()=>{
      await context.execution.check();await scene.checkScene();await context.execution.check();
    }});
    await execution.check();
    return assessmentFactory({...context,execution},fence);
  };
  const runner=createSecureShopAuditRunner({turns,conversations,journal,beginAssessment,capturePersonaAuthority,timing,conversationPurpose,
    executeJob:async(input,personaFence)=>{
      const check=input.boundary.check;
      const repository=require('../database/postgres/secureshopAuditRunRepository').createSecureShopAuditRunRepository({pool:agentsPool,checkCurrent:check});
      const reader=require('../database/postgres/secureshopAuditRunReader').createSecureShopAuditRunReader({pool:agentsPool,checkCurrent:check,
        readCompletedEffect:(context,key)=>ledger.readCompletedEffect(context,key)});
      const scene=sceneContexts.get(personaFence);
      if (scenes && !scene) throw new Error('Audit retained scene admission unavailable');
      if (assessmentVariant==='unbounded') {
        await check();await scene.checkScene();await personaFence.assertRemoteAdmission();
        const eventId=require('node:crypto').randomUUID();
        const descriptor={sourceEventId:`agents:${eventId}`,actor:'admin',action:'audit_unbounded_requested',target:input.boundary.identity.runId,
          paramsJson:JSON.stringify({requestId:input.requestId,requestedCount:input.requestedCount,nonce:require('node:crypto').randomUUID()})};
        const store=require('../database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agentsPool});
        await require('./secureshopSceneBinding').withSceneLease(scene.sceneBinding,()=>personaFence.withPersonaEffect(async(client,authority)=>{
          if (!authority || authority.personaId!==input.persona.id || authority.role!=='admin' || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(key=>authority[key]!==input.scope[key])) throw new Error('Audit witness authority unavailable');
          await store.append(client,{eventId,scope:input.scope,persona:input.persona,actor:descriptor.actor,action:descriptor.action,target:descriptor.target,paramsJson:descriptor.paramsJson,outcome:'completed',sourceKind:'audit_request',sourceId:input.requestId});
        }));
        await check();await scene.checkScene();await personaFence.assertRemoteAdmission();
        witnessSelectors.set(input.boundary.identity.runId,require('./secureshopAuditUnboundedWitnessReader').createSecureShopAuditUnboundedOwnedWitnessSelector(descriptor));
      }
      try { return await createSecureShopAuditJob({snapshot,...(scene?{sceneSource,...scene}:{}),
        taskRequestVersion,
        repository:personaFence?Object.freeze({publish:value=>repository.publish(value,personaFence)}):repository,
        reader,root,baseUrl,model,mode:featureModeForFence(personaFence)?.effectiveMode||'vuln',
        ...(promptPolicyRepository ? {capturePromptPolicy: async execution => {
          if(!personaFence)throw new Error('Audit prompt policy persona unavailable');
          await check();await personaFence.assertRemoteAdmission();
          const b=personaFence.binding;
          const admitted=await promptPolicyRepository.admitRunSnapshot({
            scope:Object.freeze(Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>[k,b[k]]))),
            persona:Object.freeze({id:b.personaId,role:b.role}),
            personaSession:Object.freeze({sessionId:b.sessionId,authorityVersion:b.authorityVersion}),runId:execution.runId});
          await personaFence.assertRemoteAdmission();await check();return admitted;
        }} : {}),
        ...(toolPolicyAdmission ? {admitTool: async invocation => {
          if(!personaFence)throw new Error('Audit policy persona unavailable');
          await check();await personaFence.assertRemoteAdmission();
          const b=personaFence.binding;
          const receipt=await toolPolicyAdmission(Object.freeze({...invocation,
            scope:Object.freeze(Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>[k,b[k]]))),
            persona:Object.freeze({id:b.personaId,role:b.role}),
            personaSession:Object.freeze({sessionId:b.sessionId,authorityVersion:b.authorityVersion})}));
          await personaFence.assertRemoteAdmission();await check();return receipt;
        }} : {}),
        consumeEvidence:(evidence,options)=>consumeSecureShopAuditEvidence(evidence,{qualifyModel,check:options.check})})(input); } finally { witnessSelectors.delete(input.boundary.identity?.runId); }
    }});
  return Object.freeze({
    async createSession({scope,persona,personaSession}={}){
      const binding=require('./secureshopConversationBinding').createConversationBinding(scope,persona);
      if(binding.role!=='admin')throw new TypeError('Administrator audit session required');
      const fence=capturePersonaAuthority?await capturePersonaAuthority({binding,personaSession}):undefined;
      await fence?.assertRemoteAdmission();
      const session=await conversations.create(binding,{id:binding.shopUserId,role:binding.role},
        conversationPurpose);
      await fence?.assertRemoteAdmission();
      await sceneContexts.get(fence)?.checkScene();
      await fence?.assertRemoteAdmission();
      return Object.freeze({sessionId:session.id});
    },
    run:input=>runner.run(input),
  });
}
module.exports={createSecureShopAuditRuntime};
