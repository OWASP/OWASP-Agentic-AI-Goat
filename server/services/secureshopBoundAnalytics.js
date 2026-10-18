'use strict';
const { randomUUID, createHash } = require('node:crypto');
const {guardFeatureFence,POLICIES}=require('./secureshopFeatureModeAuthority');
const {target:checkedTarget,sameScope,hash:canonicalHash}=require('../../sidecars/analytics-sql-target/contract');
const { createLaunchScope } = require('./secureshopConversationBinding');
const {SECURESHOP_CONVERSATION_PURPOSES}=require('./secureshopConversationPurpose');
const ANALYTICS_PURPOSE=SECURESHOP_CONVERSATION_PURPOSES.analytics;
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { TOOL, fail, sqlArgument, modelIdentity, createAnalyticsExecutionConfig } = require('./secureshopAnalyticsExecutionConfig');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH=/^[a-f0-9]{64}$/;
const sha=value=>createHash('sha256').update(value).digest('hex');
function operationIdentity(runId, requestId, sessionId, callId) {
  const hex=sha(JSON.stringify(['secureshop-analytics-query-v1',runId,requestId,sessionId,callId])).slice(0,32).split('');
  hex[12]='5';hex[16]='8';const id=hex.join('');
  return `${id.slice(0,8)}-${id.slice(8,12)}-${id.slice(12,16)}-${id.slice(16,20)}-${id.slice(20)}`;
}
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value)!==Object.prototype || Reflect.ownKeys(value).length!==keys.length
      || keys.some(key=>!Object.hasOwn(Object.getOwnPropertyDescriptor(value,key)||{},'value'))) throw fail('ANALYTICS_INVALID_ARGUMENT');
}
function checkedReceipt(value, expected) {
  exact(value,['version',...([2,3,4].includes(value?.version)?['protectedEvidence']:[]),...([3,4].includes(value?.version)?['mode']:[]),...(value?.version===4?['denial']:[]),'operationId','targetId','scope','runId','requestId','sessionId','callId','sqlSha256','sourceManifestSha256','resultSha256','result']);
  if(![1,2,3,4].includes(value.version)||!UUID.test(value.targetId)||!UUID.test(value.operationId)||!UUID.test(value.runId)
      ||value.targetId!==expected.target.targetId||value.sourceManifestSha256!==expected.target.sourceManifestSha256
      ||typeof value.callId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.callId)||value.operationId!==expected.operationId||value.runId!==expected.runId
      ||value.requestId!==expected.requestId||value.sessionId!==expected.sessionId||value.callId!==expected.callId
      ||value.sqlSha256!==sha(expected.sql)||!HASH.test(value.sourceManifestSha256)||!HASH.test(value.resultSha256))throw fail('ANALYTICS_RECEIPT_MISMATCH');
  exact(value.scope,Object.keys(expected.scope));
  if(Object.keys(expected.scope).some(k=>value.scope[k]!==expected.scope[k]))throw fail('ANALYTICS_RECEIPT_MISMATCH');
  const result=value.result;exact(result,['sql','columns','rows','row_count','error']);
  if(result.sql!==expected.sql||(value.version===4?result.error!=='Database permission denied (42501).':result.error!==null)||!Array.isArray(result.columns)||result.columns.length>128
      ||result.columns.some(v=>typeof v!=='string'||!v||Buffer.byteLength(v)>256)||new Set(result.columns).size!==result.columns.length
      ||!Array.isArray(result.rows)||result.rows.length>1000||result.row_count!==result.rows.length
      ||result.rows.some(row=>!row||Object.getPrototypeOf(row)!==Object.prototype||Object.keys(row).some(k=>!result.columns.includes(k)))
      ||Buffer.byteLength(JSON.stringify(result))>1024*1024||canonicalHash(result)!==value.resultSha256)throw fail('ANALYTICS_RECEIPT_MISMATCH');
  if([3,4].includes(value.version)){const mode=require('./secureshopAnalyticsModeAuthority').checkedMode(value.mode);if(!expected.mode||canonicalHash(mode)!==canonicalHash(expected.mode))throw fail('ANALYTICS_RECEIPT_MISMATCH');}
  if([2,3,4].includes(value.version))require('./secureshopAnalyticsProtectedEvidence').validateProtectedEvidence(value.protectedEvidence,result);
  if(value.version===4){exact(value.denial,['code','source','backendAbsent']);if(value.mode.mode!=='fixed'||value.denial.code!=='42501'||value.denial.source!=='postgresql'||value.denial.backendAbsent!==true||result.rows.length||result.columns.length||value.protectedEvidence.observations.length)throw fail('ANALYTICS_RECEIPT_MISMATCH');}
  return Object.freeze(structuredClone(value));
}
// Unmounted foundation. The adapter is a server-owned dependency, never supplied
// by the request. No global commerce import, legacy translator or mock fallback.
function createSecureShopBoundAnalytics({ launches, conversationRepository, journal, coordinator, provider,
  personaAuthority, ownedQuery, promptPolicyRepository, assessmentFactory, disclosureAssessmentFactory, nlSqlAssessmentFactory, requestRepository, modeAuthority, makeId=randomUUID }={}) {
  if(typeof launches?.assertCurrent!=='function'||typeof coordinator?.run!=='function'||typeof provider?.chat!=='function'
      ||typeof provider?.finalResponse!=='function'||typeof personaAuthority?.capture!=='function'
      ||typeof ownedQuery?.resolve!=='function'||typeof ownedQuery?.execute!=='function'||typeof makeId!=='function')throw TypeError('Owned analytics dependencies required');
  if(requestRepository!==undefined&&['admit','read'].some(key=>typeof requestRepository?.[key]!=='function'))throw TypeError('Analytics admission repository required');
  if(assessmentFactory!==undefined&&typeof assessmentFactory!=='function')throw TypeError('Analytics assessment factory required');
  if(disclosureAssessmentFactory!==undefined&&(typeof disclosureAssessmentFactory!=='function'||typeof assessmentFactory!=='function'))throw TypeError('Analytics disclosure and loop assessments required');
  if(nlSqlAssessmentFactory!==undefined&&(typeof nlSqlAssessmentFactory!=='function'||typeof disclosureAssessmentFactory!=='function'))throw TypeError('Analytics NL SQL and post-journal assessments required');
  const policyOptions=require('./secureshopPromptPolicyRunnerOptions').promptPolicyRunnerOptions(promptPolicyRepository,personaAuthority,{recipient:'analytics'});
  const config=createAnalyticsExecutionConfig(ownedQuery.schema);
  const resolveOwnedTarget=ownedQuery.resolve.bind(ownedQuery);
  const executeOwnedQuery=ownedQuery.execute.bind(ownedQuery);
  const conversations=createBoundConversationService({conversations:conversationRepository,launches,makeId});
  const turns=createBoundTurns({conversations,coordinator});
  function project({outcome,target,scope,personaSession,requestId,sessionId,question,mode}) {
const metadata=outcome.taskMetadata?.analytics;
    const denied=metadata?.receipt?.version===4;
    if(outcome.stopReason!==(denied?'tool_denied':'end_turn')||typeof outcome.text!=='string'||!outcome.text.trim()||metadata?.version!==1)throw fail();
    if(metadata.personaSession?.sessionId!==personaSession.sessionId||metadata.personaSession?.authorityVersion!==personaSession.authorityVersion)throw fail('SHOP_AUTH_INVALID');
    const stored=metadata.receipt;const receipt=checkedReceipt(stored,{target,scope,requestId,mode,sessionId:sessionId,
      runId:stored?.runId,operationId:stored?.operationId,callId:stored?.callId,sql:stored?.result?.sql});
    const effect=metadata.effectReceipt;let effectCoordinates;try{effectCoordinates=JSON.parse(effect?.effectKey?.slice(requestId.length+1));}catch{}
    if(effect?.version!==1||effect.status!=='completed'||effect.runId!==receipt.runId||typeof effect.ownerKey!=='string'||!effect.ownerKey||typeof effect.generation!=='string'||!/^[0-9]+$/.test(effect.generation)||typeof effect.effectKey!=='string'||!effect.effectKey.startsWith(requestId+':')||!Array.isArray(effectCoordinates)||effectCoordinates.length!==3||!Number.isSafeInteger(effectCoordinates[0])||effectCoordinates[0]<0||effectCoordinates[1]!==receipt.callId||effectCoordinates[2]!==TOOL)throw fail('ANALYTICS_EFFECT_MISMATCH');
    if(denied){if(metadata.provider!==null||metadata.model!==null||outcome.text!==receipt.result.error)throw fail('ANALYTICS_RECEIPT_MISMATCH');}else modelIdentity({provider:metadata.provider,model:metadata.model,mocked:false,fallback:false});
    return Object.freeze({ok:!denied,...(denied?{status:'denied',responseSource:'server'}:{}),...receipt.result,answer:denied?null:outcome.text,provider:metadata.provider,model:metadata.model,
      requestId,question,sessionId:sessionId,runId:receipt.runId,receipt,effectReceipt:metadata.effectReceipt,
      ...(outcome.modeCapability?{modeCapability:outcome.modeCapability}:{})});
  }
  async function recover(input) {
    if(!requestRepository)throw fail('ANALYTICS_RECOVERY_UNAVAILABLE');
    exact(input,['scope','persona','personaSession','requestId','signal']);
    exact(input.scope,['launchId','scenarioId','generation','platformOwnerId','platformSessionId']);exact(input.persona,['id','role']);exact(input.personaSession,['sessionId','authorityVersion']);
    const scope=createLaunchScope(input.scope),persona=Object.freeze({...input.persona}),personaSession=Object.freeze({...input.personaSession}),{requestId,signal}=input;
    if(!UUID.test(requestId)||!['merchant','admin'].includes(persona.role))throw fail('ANALYTICS_INVALID_ARGUMENT');
    const fence=await personaAuthority.capture({scope,personaId:persona.id,role:persona.role,...personaSession});
    const expected={...scope,personaId:persona.id,role:persona.role,...personaSession};
    if(typeof fence?.assertRemoteAdmission!=='function'||Object.keys(expected).some(k=>fence.binding?.[k]!==expected[k]))throw fail('SHOP_AUTH_INVALID');
    const current=async()=>{signal?.throwIfAborted();await launches.assertCurrent(scope);await fence.assertRemoteAdmission();signal?.throwIfAborted();};
    await current();const packet=await requestRepository.read({scope,persona,personaSession,requestId});await current();
    if(!packet)return null;
    if(packet.status!=='completed')return Object.freeze({requestId,question:packet.question,sessionId:packet.sessionId,status:packet.status==='started'?'pending':'uncertain'});
    const target=checkedTarget(await resolveOwnedTarget({scope,persona,personaSession,signal,checkCurrent:current}));
    if(!sameScope(target.scope,scope))throw fail('ANALYTICS_RECEIPT_MISMATCH');
    const result=project({outcome:packet.result,target,scope,personaSession,requestId,sessionId:packet.sessionId,question:packet.question,mode:packet.modeSnapshot});await current();
    return Object.freeze({status:'completed',...result});
  }
  return Object.freeze({purpose:ANALYTICS_PURPOSE,recover,async query(input) {
    exact(input,['scope','persona','personaSession','question','requestId','signal']);
    exact(input.scope,['launchId','scenarioId','generation','platformOwnerId','platformSessionId']);
    const scope=createLaunchScope(input.scope);exact(input.persona,['id','role']);exact(input.personaSession,['sessionId','authorityVersion']);
    if(!Number.isSafeInteger(input.persona.id)||input.persona.id<1||!['merchant','admin'].includes(input.persona.role)
        ||!UUID.test(input.personaSession.sessionId)||typeof input.personaSession.authorityVersion!=='string'||!/^[1-9][0-9]{0,18}$/.test(input.personaSession.authorityVersion)||BigInt(input.personaSession.authorityVersion)>9223372036854775807n
        ||!UUID.test(input.requestId)||typeof input.question!=='string'||!input.question.trim()||Buffer.byteLength(input.question)>8192)throw fail('ANALYTICS_INVALID_ARGUMENT');
    const persona=Object.freeze({...input.persona}),personaSession=Object.freeze({...input.personaSession});
    const question=input.question,requestId=input.requestId,signal=input.signal;
    const fence=await personaAuthority.capture({scope,personaId:persona.id,role:persona.role,...personaSession});
    if(typeof fence?.assertRemoteAdmission!=='function'||!fence.binding
        ||Object.keys(scope).some(k=>fence.binding[k]!==scope[k])||fence.binding.personaId!==persona.id||fence.binding.role!==persona.role
        ||fence.binding.sessionId!==personaSession.sessionId||fence.binding.authorityVersion!==personaSession.authorityVersion)throw fail('SHOP_AUTH_INVALID');
    let modeToken=null;
    const current=async()=>{signal?.throwIfAborted();await launches.assertCurrent(scope);await fence.assertRemoteAdmission();if(modeToken)await modeToken.assertCurrent();signal?.throwIfAborted();};
    await current();const session=await conversations.create(scope,persona,ANALYTICS_PURPOSE);await current();
    if(modeAuthority)modeToken=modeAuthority.assertToken(await modeAuthority.capture(scope));
    if(requestRepository){const admission=await requestRepository.admit({scope,persona,personaSession,requestId,sessionId:session.id,question,...(modeToken?{modeSnapshot:modeToken.mode}:{})});
      if(admission.created!==true){modeToken=null;return recover({scope,persona,personaSession,requestId,signal});}await current();
      if(typeof ownedQuery.prepare==='function'){await ownedQuery.prepare({scope,persona,personaSession,signal,checkCurrent:current,...(modeToken?{mode:modeToken.mode}:{})});await current();}}
    const target=checkedTarget(await resolveOwnedTarget({scope,persona,personaSession,signal,checkCurrent:current}));
    if(!sameScope(target.scope,scope))throw fail('ANALYTICS_RECEIPT_MISMATCH');await current();
    let accepted=null,acceptedEffect=null,finalModel=null,selected=null,dispatched=false,executionIdentity;
    const checkedProvider={...(provider.config?{config:provider.config}:{}),async chat(args){
      const value=await provider.chat({...args,maxToolCalls:1});modelIdentity(value);
      if(value.stop_reason!=='tool_use'||!Array.isArray(value.tool_uses)||value.tool_uses.length!==1)throw fail();
      const call=value.tool_uses[0];if(call.name!==TOOL||typeof call.id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(call.id))throw fail();
      const sql=sqlArgument(call.args);selected=Object.freeze({callId:call.id,sql});return value;
    },async finalResponse(args){const value=await provider.finalResponse(args);finalModel=modelIdentity(value);
      if(value.stop_reason!=='end_turn'||value.responseMode!=='structured_final'||typeof value.text!=='string'||!value.text.trim()
          ||Buffer.byteLength(value.text)>65536||(value.tool_uses&&value.tool_uses.length)||(value.tool_calls&&value.tool_calls.length))throw fail();return value;}};
    const postJournal=disclosureAssessmentFactory?require('./secureshopAnalyticsPostJournalAssessment').createAnalyticsPostJournalAssessment({loopFactory:assessmentFactory,disclosureFactory:disclosureAssessmentFactory,additionalFactories:nlSqlAssessmentFactory?[nlSqlAssessmentFactory]:[],privateEvidence:Object.freeze({question,read:()=>({receipt:accepted,effectReceipt:acceptedEffect})}),async readCommittedProjection(result){
      if(!requestRepository)throw fail('ANALYTICS_RECOVERY_UNAVAILABLE');await current();const packet=await requestRepository.read({scope,persona,personaSession,requestId});await current();
      if(packet?.status!=='completed'||packet.sessionId!==session.id||canonicalHash(packet.result)!==canonicalHash(result))throw fail('ANALYTICS_RECEIPT_MISMATCH');
      return project({outcome:packet.result,target,scope,personaSession,requestId,sessionId:session.id,question:packet.question,mode:packet.modeSnapshot});
    }}):null;
    function acceptObservation(observation){
        const receipt=observation.effectReceipt;
        if(!accepted||observation.tool!==TOOL||observation.callId!==accepted.callId||sqlArgument(observation.args)!==accepted.result.sql
            ||observation.result?.isError||observation.result?.content?.[0]?.text!==JSON.stringify(accepted.result)
            ||receipt?.version!==1||receipt.status!=='completed'||receipt.runId!==executionIdentity.runId||receipt.ownerKey!==executionIdentity.ownerKey
            ||receipt.generation!==String(executionIdentity.durableGeneration)||receipt.effectKey!==`${requestId}:${JSON.stringify([observation.step,observation.callId,TOOL])}`)throw fail('ANALYTICS_EFFECT_MISMATCH');
        acceptedEffect=Object.freeze(structuredClone(receipt));return true;

    }
    const runner=createBoundAgentRunner({turns,conversations,repository:conversationRepository,journal,provider:checkedProvider,...config,...policyOptions,...(assessmentFactory?{assessmentFactory:postJournal?postJournal.factory:assessmentFactory}:{}),...(postJournal?{afterJournalCommit:postJournal.afterCommit}:{}),
      pool:{async callTool(){throw fail('SCOPED_TOOL_UNAVAILABLE');}},conversationPurpose:ANALYTICS_PURPOSE,executionScope:'turn',limits:{maxSteps:2,maxParallelTools:1},
      capturePersonaAuthority:()=>modeToken?guardFeatureFence(fence,Object.freeze({snapshot:Object.freeze({featureId:'analytics',policyVersion:POLICIES.analytics,mode:modeToken.mode.mode}),assertCurrent:modeToken.assertCurrent,...(modeToken.assertCurrentAtEffect?{assertCurrentAtEffect:modeToken.assertCurrentAtEffect}:{})})):fence,personaLocalToolModes:{[TOOL]:'remote_admission'},
      async createLocalTools(_binding,context,_authority,execution){
        executionIdentity=execution;
        if(!UUID.test(execution.runId)||!execution.ownerKey||execution.durableGeneration==null)throw fail('ANALYTICS_RUN_UNAVAILABLE');
        return new Map([[TOOL,async(args,invocation)=>{
          const sql=sqlArgument(args);if(dispatched||!selected||selected.sql!==sql||selected.callId!==invocation.callId||invocation.tool!==TOOL)throw fail();
          dispatched=true;await current();await execution.check();
          const operationId=operationIdentity(execution.runId,requestId,session.id,invocation.callId);
          const expected={target,scope,runId:execution.runId,requestId,sessionId:session.id,callId:invocation.callId,operationId,sql,...(modeToken?{mode:modeToken.mode}:{})};
          const receipt=checkedReceipt(await executeOwnedQuery(Object.freeze({...expected,persona,personaSession,signal:execution.signal,checkCurrent:current})),expected);
          await current();await execution.check();accepted=receipt;
          return {content:[{type:'text',text:JSON.stringify(receipt.result)}]};
        }]]);
      },
      async terminalAfterLocalTool({observation}){if(accepted?.version!==4)return null;acceptObservation(observation);return {source:'server',stopReason:'tool_denied',text:accepted.result.error};},
      async enterFinalResponseAfterLocalTool({observation}){return acceptObservation(observation);      },async resultMetadata({result}){
        await current();const denied=accepted?.version===4;if(!accepted||!acceptedEffect||(!denied&&!finalModel)||result.stopReason!==(denied?'tool_denied':'end_turn'))throw fail();
        return {analytics:{version:1,personaSession,receipt:accepted,effectReceipt:acceptedEffect,provider:denied?null:finalModel.provider,model:denied?null:finalModel.model}};
      },
    });
    const outcome=await runner.run({sessionId:session.id,requestId,scope,persona,personaSession,message:question,signal});
    await current();return project({outcome,target,scope,personaSession,requestId,sessionId:session.id,question,mode:modeToken?.mode});
  }});
}
module.exports={createSecureShopBoundAnalytics};
