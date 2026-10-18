'use strict';
const {captureFeatureMode,guardFeatureFence}=require('./secureshopFeatureModeAuthority');
const {createLaunchScope,createConversationBinding}=require('./secureshopConversationBinding');
const {privateRequestFor,receiptFor}=require('./secureshopOwnedAuditSearchSnapshot');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const TIMING_AGENT=Symbol('owned-audit-timing-agent');
function uncertain(cause){if(cause?.code==='PERSONA_EFFECT_OUTCOME_UNCERTAIN')return cause;const error=Object.assign(Error('Owned audit target outcome uncertain'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});Object.defineProperty(error,'cause',{value:cause});return error;}
function createOwnedAuditSearchApplication({launches,personaAuth,snapshots,client,manualAdapter,graphAdapter,turns,journal,decisionGraph,beginAssessment,beginTimingAssessment,conversations,targetAdmissions,personaAuthority,toolPolicyAdmission,promptPolicyAdmission,modeAuthority}){
 if(promptPolicyAdmission!==undefined&&(typeof promptPolicyAdmission!=='function'||!personaAuthority))throw TypeError('Prompt admission requires captured persona authority');
 if(toolPolicyAdmission!==undefined&&(typeof toolPolicyAdmission!=='function'||!personaAuthority))throw TypeError('Policy admission requires captured persona authority');
 if(personaAuthority!==undefined&&typeof personaAuthority?.capture!=='function')throw TypeError('Persona authority required');
 async function capture(binding,session){if(personaAuthority===undefined)return undefined;if(typeof session?.sessionId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(session.sessionId)||typeof session.authorityVersion!=='string'||!/^[1-9][0-9]*$/.test(session.authorityVersion))throw TypeError('Persona credential session required');const credential=Object.freeze({sessionId:session.sessionId.toLowerCase(),authorityVersion:session.authorityVersion});const fence=await personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:credential.sessionId,authorityVersion:credential.authorityVersion});if(!fence||typeof fence.assertRemoteAdmission!=='function'||typeof fence.withPersonaEffect!=='function')throw TypeError('Persona fence required');const scope=createLaunchScope(binding),actual=createLaunchScope(fence.binding);if(Object.keys(scope).some(key=>scope[key]!==actual[key])||fence.binding.personaId!==binding.shopUserId||fence.binding.role!==binding.role||fence.binding.sessionId!==credential.sessionId||fence.binding.authorityVersion!==credential.authorityVersion)throw TypeError('Persona fence mismatch');await fence.assertRemoteAdmission();return modeAuthority==null?fence:guardFeatureFence(fence,await captureFeatureMode(modeAuthority,binding,'audit'));}
 const admission=createTurnAdmission({journal});
 async function admittedSnapshot(scope){
  if(typeof targetAdmissions?.admit!=='function')throw Error('Audit target admission unavailable');
  const existing=typeof targetAdmissions.readSnapshot==='function'?await targetAdmissions.readSnapshot({binding:scope}):null;
  if(existing)return existing;
  const snapshot=await snapshots.capture(scope),source=receiptFor(snapshot);
  try{await targetAdmissions.admit({binding:scope,sourceSha256:source.sourcesSha256,payloadSha256:source.payloadSha256,snapshot});}
  catch(error){if(error.code!=='AUDIT_TARGET_ADMISSION_CONFLICT'||typeof targetAdmissions.readSnapshot!=='function')throw error;const original=await targetAdmissions.readSnapshot({binding:scope});if(!original)throw error;return original;}
  return snapshot;
 }
 async function legacyTarget(scope){await launches.assertCurrent(scope);let selected=await client.target({binding:scope});if(selected.missing){const snapshot=await admittedSnapshot(scope);await launches.assertCurrent(scope);await client.provision(privateRequestFor(snapshot));selected=await client.target({binding:scope});}await launches.assertCurrent(scope);return selected;}
 async function target(scope,fence,executionCheck){
  if(fence===undefined)return legacyTarget(scope);
  const check=async()=>{if(executionCheck)await executionCheck();await launches.assertCurrent(scope);await fence.assertRemoteAdmission();if(executionCheck)await executionCheck();};
  let provisionDispatched=false;
  try{
   await check();let selected=await client.target({binding:scope});await check();
   if(selected.missing){
    const snapshot=await admittedSnapshot(scope);await check();
    // Reconcile a concurrent or previously acknowledged target before dispatch.
    selected=await client.target({binding:scope});await check();
    if(selected.missing){provisionDispatched=true;await client.provision(privateRequestFor(snapshot));await check();selected=await client.target({binding:scope});await check();}
   }
   if(selected.missing)throw Error('Owned audit target unavailable after provisioning');
   return selected;
  }catch(error){if(provisionDispatched)throw uncertain(error);throw error;}
 }
 const methods={
  async readSearch({scope:input,persona,expectedPersonaSession,token,operationId,signal}){
   signal?.throwIfAborted();const scope=createLaunchScope(input);
   const auth=await personaAuth.authenticateBoundToken({scope,token});
   if(auth.user?.role!=='admin'||auth.user.id!==persona?.id||persona.role!=='admin')throw Error('Current admin persona required');
   if(expectedPersonaSession&&(expectedPersonaSession.sessionId?.toLowerCase()!==auth.sessionId?.toLowerCase()||expectedPersonaSession.authorityVersion!==auth.authorityVersion))throw Object.assign(Error('Current admin session required'),{code:'SHOP_AUTH_INVALID'});
   const binding=createConversationBinding(scope,persona),fence=await capture(binding,{sessionId:auth.sessionId,authorityVersion:auth.authorityVersion});
   const modeToken=await captureFeatureMode(modeAuthority,scope,'audit');await modeToken.assertCurrent();
   const modeCapability=require('./secureshopFeatureModeAuthority').projectFeatureMode(modeToken);
   if(modeToken.snapshot.mode==='fixed')return{version:1,operationId,status:'blocked',result:null,source:null,
    reason:'Raw audit SQL teaching tool is disabled in fixed mode',modeCapability};
   await launches.assertCurrent(scope);signal?.throwIfAborted();
   const result=await manualAdapter.read({binding:scope,persona:{id:persona.id,role:persona.role},operationId,token},fence);
   signal?.throwIfAborted();await fence?.assertRemoteAdmission();await launches.assertCurrent(scope);await modeToken.assertCurrent();
   return{...result,modeCapability};
  },
  async createAgentSession({scope,persona,personaSession},variant){
   if(!decisionGraph||typeof conversations?.create!=='function')throw Error('Audit agent unavailable');const binding=createConversationBinding(scope,persona);if(binding.role!=='admin')throw Error('Admin persona required');const fence=await capture(binding,personaSession);const purpose=variant===TIMING_AGENT?'secureshop_audit_sql_timing':'secureshop_audit_sql';const session=await conversations.create(binding,persona,purpose);await fence?.assertRemoteAdmission();return{ok:true,sessionId:session.id};
  },
  async search({scope:input,persona,expectedPersonaSession,token,operationId,username,signal,beforeEffect}){
   if(beforeEffect!==undefined&&typeof beforeEffect!=='function')throw TypeError('Invalid audit effect guard');
   signal?.throwIfAborted();const scope=createLaunchScope(input);const auth=await personaAuth.authenticateBoundToken({scope,token});if(auth.user?.role!=='admin'||auth.user.id!==persona?.id||persona.role!=='admin')throw Error('Current admin persona required');
   if(expectedPersonaSession&&(expectedPersonaSession.sessionId?.toLowerCase()!==auth.sessionId?.toLowerCase()||expectedPersonaSession.authorityVersion!==auth.authorityVersion))throw Object.assign(Error('Current admin session required'),{code:'SHOP_AUTH_INVALID'});
   const binding=createConversationBinding(scope,persona),fence=await capture(binding,{sessionId:auth.sessionId,authorityVersion:auth.authorityVersion});
   const modeToken=await captureFeatureMode(modeAuthority,scope,'audit');await modeToken.assertCurrent();
   if(modeToken.snapshot.mode==='fixed')return {ok:false,blocked:true,reason:'Raw audit SQL teaching tool is disabled in fixed mode',modeCapability:require('./secureshopFeatureModeAuthority').projectFeatureMode(modeToken)};
   const selected=await target(scope,fence,async()=>{signal?.throwIfAborted();await beforeEffect?.();signal?.throwIfAborted();});signal?.throwIfAborted();
   const result=await manualAdapter.execute({request:{binding:scope,persona:{id:persona.id,role:persona.role},operationId,username,...selected},token,signal,
    beforeEffect:async()=>{await fence?.assertRemoteAdmission();await modeToken.assertCurrent();await beforeEffect?.();await modeToken.assertCurrent();signal?.throwIfAborted();}},...(fence?[fence]:[]));signal?.throwIfAborted();await fence?.assertRemoteAdmission();await modeToken.assertCurrent();return result;
  },
  async runAgent({sessionId,requestId,scope,persona,personaSession,message,signal,requestContext,beforeEffect},variant){
   if(beforeEffect!==undefined&&typeof beforeEffect!=='function')throw TypeError('Invalid audit job guard');
   const admittedMessage=require('./secureshopRoleAuditJobProposal').requestMessage('agent',{message},requestContext);
   const timing=variant===TIMING_AGENT,assessmentFactory=timing?beginTimingAssessment:beginAssessment;
   if(typeof decisionGraph?.run!=='function'||typeof assessmentFactory!=='function')throw Error('Audit decision and assessment runtime unavailable');
   const binding=createConversationBinding(scope,persona);if(binding.role!=='admin')throw Error('Current admin persona required');const fence=await capture(binding,personaSession);let prepared;if(requestContext!==undefined&&!fence)throw Error('Audit chat persona authority required');
   const originalCheck=async()=>{signal?.throwIfAborted();await fence?.assertRemoteAdmission();await beforeEffect?.();signal?.throwIfAborted();};await originalCheck();
   try{const outcome=await turns.run(sessionId,binding,persona,{signal,conversationPurpose:timing?'secureshop_audit_sql_timing':'secureshop_audit_sql',idempotencyKey:requestId,admit:async()=>{await originalCheck();prepared=await admission.prepare({sessionId,requestId,binding,message:admittedMessage});await originalCheck();return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};}},originalBoundary=>{const boundary=fence?Object.freeze({...originalBoundary,async check(){await originalBoundary.check();await originalCheck();await originalBoundary.check();}}):originalBoundary;return admission.execute(prepared,boundary,async()=>{
    const execution={...boundary.identity,check:boundary.check};const assessment=await assessmentFactory({binding,execution},...(fence?[fence]:[]));
    const result=await decisionGraph.run({message,boundary,signal,ownerId:binding.platformOwnerId,mode:assessment.mode,...(promptPolicyAdmission?{promptPolicyAdmission:async()=>{
      await boundary.check();const credential=fence.binding;
      const snapshot=await promptPolicyAdmission(Object.freeze({scope:createLaunchScope(binding),
        persona:Object.freeze({id:credential.personaId,role:credential.role}),
        personaSession:Object.freeze({sessionId:credential.sessionId,authorityVersion:credential.authorityVersion}),runId:execution.runId}));
      await boundary.check();return snapshot;
    }}:{}),...(toolPolicyAdmission?{toolPolicyAdmission:async invocation=>{
      await boundary.check();const credential=fence.binding;
      const receipt=await toolPolicyAdmission(Object.freeze({scope:createLaunchScope(binding),
        persona:Object.freeze({id:credential.personaId,role:credential.role}),
        personaSession:Object.freeze({sessionId:credential.sessionId,authorityVersion:credential.authorityVersion}),
        runId:execution.runId,invocationId:`${invocation.step}:${invocation.callId}`,
        agent:'audit',tool:'search_by_user',args:invocation.args}));
      await boundary.check();return receipt;
    }}:{}),query:async username=>{await boundary.check();const launch=createLaunchScope(binding),selected=await target(launch,fence,boundary.check);await boundary.check();return boundary.effect('owned-audit-query:'+requestId,()=>graphAdapter.execute({request:{binding:launch,operationId:requestId,runId:execution.runId,username,...selected},execution},...(fence?[fence]:[])));}});
    await boundary.check();let verdict;try{verdict=await assessment.consume(result);}catch(error){if(error.code!==(timing?'AUDIT_SQL_TIMING_EVIDENCE_UNAVAILABLE':'AUDIT_SQL_EVIDENCE_UNAVAILABLE'))throw error;verdict={passed:false,reason:timing?'Authentic model-selected timing was not established':'Authentic model-selected extraction was not established'};}
    await boundary.check();
    const publicResult={text:result.text,query:result.query,provider:result.provider,model:result.model,assessment:verdict};
    if(requestContext!==undefined){
     const witness=require('./secureshopOwnedAuditDecisionGraph').witnessFor(result),modeCapability=require('./secureshopFeatureModeAuthority').featureModeForFence(fence);
     const digest=require('./mcp/protocolContext').canonicalDigest;
     const evidence=witness?.modelProvenance===true?{version:1,modelProvenance:true,
      sourceSha256:witness.effect.receipt.sourceSha256,payloadSha256:witness.effect.receipt.payloadSha256,
      resultSha256:digest(result.query),decisionSha256:digest(witness.decision),responseSha256:digest(witness.response),
      tool:{name:'audit.search_by_user',args:{username:witness.effect.request.username}},
      trace:[{step:1,phase:'decision',provider:witness.decision.provider,model:witness.decision.model,tool:'audit.search_by_user'},
       {step:2,phase:'final',provider:witness.response.provider,model:witness.response.model,tool:null}]}:null;
     for(const phase of evidence?.trace||[])await boundary.trace?.({node:`audit_chat_${phase.phase}`,type:'decision',
      data:{decisionSource:'model',provider:phase.provider,model:phase.model,...(phase.tool?{tool:phase.tool}:{})}});
     Object.assign(publicResult,{runId:execution.runId,modeCapability,evidence,
      _auditJob:{version:1,requestContext,modeCapability}});
    }
    if(requestContext!==undefined){const{_auditJob,...publicValue}=publicResult;require('./secureshopRoleAuditJobProposal').result('agent',publicValue);}
    return publicResult;
   },...(fence?[fence]:[]));});await fence?.assertRemoteAdmission();return outcome;}catch(error){await admission.abandon(prepared);throw error;}
  },
  async runGraph({sessionId,requestId,scope,persona,personaSession,username,signal}){
   const binding=createConversationBinding(scope,persona);if(binding.role!=='admin')throw Error('Current admin persona required');const fence=await capture(binding,personaSession);
   const modeToken=await captureFeatureMode(modeAuthority,scope,'audit');await modeToken.assertCurrent();
   if(modeToken.snapshot.mode==='fixed')return {ok:false,blocked:true,reason:'Raw audit SQL teaching tool is disabled in fixed mode',modeCapability:require('./secureshopFeatureModeAuthority').projectFeatureMode(modeToken)};
   const message=JSON.stringify(['owned-audit-sql',1,username]);let prepared;
   try{const outcome=await turns.run(sessionId,binding,persona,{signal,idempotencyKey:requestId,admit:async()=>{await fence?.assertRemoteAdmission();prepared=await admission.prepare({sessionId,requestId,binding,message});await fence?.assertRemoteAdmission();return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};}},originalBoundary=>{const boundary=fence?Object.freeze({...originalBoundary,async check(){await originalBoundary.check();await fence.assertRemoteAdmission();await originalBoundary.check();}}):originalBoundary;return admission.execute(prepared,boundary,async()=>{
    const launch=createLaunchScope(binding);const selected=await target(launch,fence,boundary.check);const execution={...boundary.identity,check:boundary.check};
    return boundary.effect('owned-audit-query:'+requestId,()=>graphAdapter.execute({request:{binding:launch,operationId:requestId,runId:execution.runId,username,...selected},execution},...(fence?[fence]:[])));
   },...(fence?[fence]:[]));});await fence?.assertRemoteAdmission();return outcome;}catch(error){await admission.abandon(prepared);throw error;}
  }
 };
 let active=0;
 async function admitted(method,input,variant){if(active>=2)throw Object.assign(Error('Audit capacity busy; retry the same operation'),{code:'AUDIT_RUNTIME_BUSY',statusCode:503});active++;try{input?.signal?.throwIfAborted();return await methods[method](input,variant);}finally{active--;}}
 return Object.freeze({...methods,search:input=>admitted('search',input),readSearch:input=>admitted('readSearch',input),runAgent:input=>admitted('runAgent',input),
  createTimingSession:input=>methods.createAgentSession(input,TIMING_AGENT),
  runTimingAgent:input=>admitted('runAgent',input,TIMING_AGENT)});
}
module.exports={createOwnedAuditSearchApplication};
