'use strict';
const {featureModeForFence}=require('./secureshopFeatureModeAuthority');
const {assertFixedAuditCount}=require('./secureshopAuditFixedProjection');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {SECURESHOP_CONVERSATION_PURPOSES}=require('./secureshopConversationPurpose');
const PURPOSE=SECURESHOP_CONVERSATION_PURPOSES.auditSummary;

// Dedicated workflow: the worker owns the actual model graph while the parent
// retains durable admission, authority and the whole-job effect boundary.
function createSecureShopAuditRunner({turns,conversations,journal,executeJob,beginAssessment,capturePersonaAuthority,
  conversationPurpose=PURPOSE,timing=require('./secureshopAuditTiming').createSecureShopAuditTiming()}={}) {
  if ([turns?.run,conversations?.assertOwned,executeJob].some(fn=>typeof fn!=='function'))
    throw new TypeError('Bound audit runner dependencies required');
  if(beginAssessment!==undefined&&typeof beginAssessment!=='function')throw new TypeError('Invalid audit assessment factory');
  if(capturePersonaAuthority!==undefined&&typeof capturePersonaAuthority!=='function')throw new TypeError('Invalid audit persona authority');
  if(!Number.isSafeInteger(timing?.runTimeoutMs)||timing.runTimeoutMs<1||timing.runTimeoutMs>290000||typeof timing.deadline!=='function')throw new TypeError('Invalid audit timing');
  if (![SECURESHOP_CONVERSATION_PURPOSES.auditSummary,SECURESHOP_CONVERSATION_PURPOSES.auditUnbounded].filter(Boolean).includes(conversationPurpose)) throw new TypeError('Invalid audit conversation purpose');
  const admission=createTurnAdmission({journal});
  return Object.freeze({
    async run({sessionId,requestId,scope,persona,personaSession,requestedCount,signal,requestContext,beforeEffect}={}) {
      if(beforeEffect!==undefined&&typeof beforeEffect!=='function')throw new TypeError('Invalid audit job guard');
      const binding=createConversationBinding(scope,persona);
      if(binding.role!=='admin'||!Number.isSafeInteger(requestedCount)||requestedCount<1)
        throw new TypeError('Administrator audit count required');
      const trustedPersona=Object.freeze({id:binding.shopUserId,role:binding.role});
      const personaFence=capturePersonaAuthority?await capturePersonaAuthority(Object.freeze({binding,
        personaSession:personaSession?Object.freeze({...personaSession}):undefined})):undefined;
      if(capturePersonaAuthority&&!personaFence)throw Object.assign(new Error('Persona authority required'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
      if(personaFence)await personaFence.assertRemoteAdmission();
      const modeCapability=featureModeForFence(personaFence);
      if(modeCapability?.effectiveMode==='fixed')assertFixedAuditCount(requestedCount);
      // Versioned canonical operation input binds count into the existing
      // journal hash: the same request ID cannot silently change its workload.
      const message=require('./secureshopRoleAuditJobProposal').requestMessage('summary',{requestedCount},requestContext);
      const request=createTurnRequest({sessionId,requestId,binding,message});
      let prepared;
      const admit=async()=>{
        if(personaFence)await personaFence.assertRemoteAdmission();
        await beforeEffect?.();signal?.throwIfAborted();
        prepared=await admission.prepare({sessionId:request.sessionId,requestId:request.requestId,binding,message});
        if(personaFence)await personaFence.assertRemoteAdmission();
        return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};
      };
      try {
        const auditDeadline=timing.deadline();
        const outcome=await turns.run(request.sessionId,binding,trustedPersona,{
          signal,idempotencyKey:request.requestId,conversationPurpose,admit,timeoutMs:timing.runTimeoutMs,
        },async boundary=>{
          const checkAuthority=async()=>{await boundary.check();await personaFence?.assertRemoteAdmission();await beforeEffect?.();await boundary.check();};
          const protectedBoundary={...boundary,check:checkAuthority};
          // No fallback admission outside the coordinator's retained lease.
          if(!prepared||prepared.status!=='claimed')throw new Error('Durable audit admission was not performed');
          return admission.execute(prepared,protectedBoundary,async()=>{
            const execution=Object.freeze({...boundary.identity,check:checkAuthority,signal:boundary.signal,auditDeadline,
              ...(boundary.trace?{trace:boundary.trace}:{})});
            const assessment=beginAssessment?(personaFence
              ?await beginAssessment({binding,execution},personaFence)
              :await beginAssessment({binding,execution})):undefined;
            if(beginAssessment&&[assessment?.consume,assessment?.outcome].some(fn=>typeof fn!=='function'))
              throw new TypeError('Audit assessment lifecycle unavailable');
            const result=await executeJob({scope:binding,persona:trustedPersona,
              requestId:request.requestId,requestedCount,boundary:protectedBoundary,assessment,includeChatEvidence:requestContext!==undefined,
              ...(conversationPurpose===SECURESHOP_CONVERSATION_PURPOSES.auditUnbounded
                ?{workerBudget:()=>timing.remainingWorkerMs(auditDeadline)}:{})},
              ...(personaFence?[personaFence]:[]));
            await checkAuthority();
            if(result?.runId!==boundary.identity?.runId||result.objectiveCredit!==false
                ||typeof result.summary!=='string'||!result.summary.trim()
                ||Buffer.byteLength(result.summary)>65536||result.requestedCount!==requestedCount
                ||!Number.isSafeInteger(result.rowCount)||result.rowCount<0||result.rowCount>requestedCount
                ||result.provider!=='ollama'||typeof result.model!=='string'||!result.model)
              throw new Error('Invalid audit job result');
            // Explicit DTO prevents functions, private paths or raw artifacts
            // from being copied into the replay journal or HTTP result.
            const grade=assessment?assessment.outcome():undefined;
            if(assessment&&(typeof grade?.completed!=='boolean'
              ||!['pass','fail','inconclusive','unavailable'].includes(grade.judgment?.verdict)))
              throw new Error('Invalid audit assessment outcome');
            // executeJob has independently read and verified the worker's
            // retained model chain before returning this identity. Record the
            // actor after assessment so a Judge trace cannot replace the run's
            // actor provider/model in Agent Runs. A failed trace also prevents
            // journal completion.
            await protectedBoundary.trace?.({node:'audit_actor_verified',type:'decision',
              data:{decisionSource:'model',provider:result.provider,model:result.model}});
            const savedResult={runId:result.runId,summary:result.summary,provider:result.provider,model:result.model,
              requestedCount,rowCount:result.rowCount,objectiveCredit:grade?.completed===true,
              ...(modeCapability?{modeCapability}:{}),
              ...(requestContext!==undefined?{evidence:result.evidence,
                _auditJob:{version:1,requestContext,modeCapability}}:{}),
              ...(grade?{assessment:{judgment:grade.judgment,completed:grade.completed===true}}:{} )};
            if(requestContext!==undefined){const{_auditJob,...publicValue}=savedResult;require('./secureshopRoleAuditJobProposal').result('summary',publicValue);}
            return savedResult;
          },...(personaFence?[personaFence]:[]));
        });
        signal?.throwIfAborted();if(personaFence)await personaFence.assertRemoteAdmission();
        await conversations.assertOwned(request.sessionId,binding,trustedPersona,conversationPurpose);
        signal?.throwIfAborted();if(personaFence)await personaFence.assertRemoteAdmission();
        return {...outcome.result,replayed:outcome.replayed};
      }catch(error){await admission.abandon(prepared);throw error;}
    },
  });
}
module.exports={createSecureShopAuditRunner};
