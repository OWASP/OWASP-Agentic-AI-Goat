'use strict';

const {createHash,randomUUID}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope,createConversationBinding}=require('./secureshopConversationBinding');
const {executionScope}=require('./secureshopSceneBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {captureFeatureMode,projectFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {createSavedAssessmentOutcomeReader}=require('./secureshopSavedAssessmentOutcomeReader');
const {createSearchEchoOriginalReader}=require('./secureshopSearchEchoOriginalReader');
const {OBJECTIVE,RUBRIC,RUBRIC_V2,RUBRIC_V8,RUBRIC_V9,buildSearchEchoBrowserCandidate,createSearchEchoBrowserJudgeGuard,
 isSearchEchoBrowserJudgeInputValid}=require('./secureshopSearchEchoBrowserEvidence');
const {prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox',SOURCE_PURPOSE='secureshop_customer_chat';
const hash=value=>createHash('sha256').update(value).digest('hex');
const fail=()=>Object.assign(Error('Search echo assessment unavailable'),{code:'SEARCH_ECHO_ASSESSMENT_UNAVAILABLE'});
const status=value=>Object.freeze({completed:false,status:value,modelEvaluated:false});
function assessmentRequestId(sessionId,requestId,step){
 if(!UUID.test(sessionId||'')||!UUID.test(requestId||'')||!Number.isInteger(step)||step<1||step>4)throw fail();
 const bytes=createHash('sha256').update(JSON.stringify([OBJECTIVE,sessionId,requestId,step])).digest();
 bytes[6]=(bytes[6]&15)|80;bytes[8]=(bytes[8]&63)|128;
 const h=bytes.subarray(0,16).toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
const message=(state,original)=>JSON.stringify([OBJECTIVE,state.source,original.sourceDigest,
 state.personaSession,state.mode.snapshot,state.publication.binding]);
function createSearchEchoBrowserAssessment({identityPool,agentsPool,launches,conversationRepository,
 coordinator,journal,bindingRepository,personaAuthority,personaBindings,scenes,modeAuthority,
 receipts,progress,publicationModes,judge,qualifyModel,browserQualification,evidenceVersion=2}={}){
 if(![2,8,9].includes(evidenceVersion))throw TypeError('Unsupported search echo assessment evidence version');
 for(const fn of [identityPool?.query,agentsPool?.query,launches?.assertCurrent,
  conversationRepository?.getBoundSession,conversationRepository?.getMessages,conversationRepository?.getTraceEvents,
  conversationRepository?.acquireBoundSession,coordinator?.run,journal?.readBoundRequest,bindingRepository?.read,
  personaAuthority?.capture,personaBindings?.capture,scenes?.readExisting,modeAuthority?.capture,modeAuthority?.assertToken,
  publicationModes?.getEvaluationScope,judge,qualifyModel,browserQualification?.readComponent,browserQualification?.qualifySearchEcho])
  if(typeof fn!=='function')throw TypeError('Search echo assessment dependencies required');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches});
 const turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const readOriginal=createSearchEchoOriginalReader({identityPool,bindingRepository,journal,
  conversations:conversationRepository,qualifyModel});
 const evidenceVersions=Object.freeze({
  [RUBRIC.version]:Object.freeze({rubric:RUBRIC,evidenceVersion:1}),
  [RUBRIC_V2.version]:Object.freeze({rubric:RUBRIC_V2,evidenceVersion:2}),
  [RUBRIC_V8.version]:Object.freeze({rubric:RUBRIC_V8,evidenceVersion:8}),
  [RUBRIC_V9.version]:Object.freeze({rubric:RUBRIC_V9,evidenceVersion:9}),
 });
 const descriptorFor=version=>typeof version==='string'&&Object.hasOwn(evidenceVersions,version)
  ? evidenceVersions[version] : null;
 const savedOutcomes=Object.freeze(Object.fromEntries(Object.entries(evidenceVersions).map(([version,descriptor])=>[version,
  createSavedAssessmentOutcomeReader({identityPool,objectiveId:OBJECTIVE,rubric:descriptor.rubric,role:'customer'})])));
 const capture=createAssessmentPersonaCapture(personaBindings),scopes=new WeakMap(),packets=new WeakMap();
 const guardedJudge=createSearchEchoBrowserJudgeGuard(judge,qualifyModel);
 const completion=createObjectiveCompletionService({receipts,progress,...capture.options,
  captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw fail();return scope;},
  judge:async input=>{const expected=packets.get(input.execution),actual=prepareJudgeInput(input);
   if(!expected||actual.evidenceError||actual.packet!==expected.packet||actual.evidenceDigest!==expected.evidenceDigest)throw fail();
   return guardedJudge(input);
  }});
 const enabled=async binding=>(await readSecureShopAssessmentEligibility(identityPool,binding,[OBJECTIVE])).includes(OBJECTIVE);
 async function authority({scope,persona,personaSession,sessionId,requestId,step,signal}){
  const binding=createConversationBinding(scope,persona),key=assessmentRequestId(sessionId,requestId,step);
  if(binding.role!=='customer'||!UUID.test(personaSession?.sessionId||'')
   ||typeof personaSession.authorityVersion!=='string'||!/^[1-9]\d*$/.test(personaSession.authorityVersion))throw fail();
  const customer={id:binding.shopUserId,role:'customer'},session={sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion};
  const fence=personaAuthority.capture({scope:binding,personaId:customer.id,role:'customer',...session});
  const expected={...createLaunchScope(binding),personaId:customer.id,role:'customer',...session};
  if(typeof fence?.assertRemoteAdmission!=='function'||!Object.keys(expected).every(k=>fence.binding?.[k]===expected[k]))throw fail();
  signal?.throwIfAborted();await fence.assertRemoteAdmission();
  await conversations.assertOwned(sessionId,binding,customer,SOURCE_PURPOSE);await fence.assertRemoteAdmission();
  const mode=await captureFeatureMode(modeAuthority,binding,'customer_chat'),target=await scenes.readExisting(binding);
  if(!target?.scene||!equal(createLaunchScope(executionScope(target)),createLaunchScope(binding)))throw fail();
  const publication=await captureAssessmentPublicationScope(publicationModes,binding.platformOwnerId,signal,binding);
  const check=async()=>{
   signal?.throwIfAborted();await launches.assertCurrent(binding);await fence.assertRemoteAdmission();
   await conversations.assertOwned(sessionId,binding,customer,SOURCE_PURPOSE);
   await mode.assertCurrent();await publication.assertCurrent();
   const current=await scenes.readExisting(binding);
   if(!current?.scene||current.targetId!==target.targetId||!equal(current.scene,target.scene)
    ||!equal(createLaunchScope(current),createLaunchScope(target)))throw fail();
   signal?.throwIfAborted();
  };
  await check();return {binding,customer,personaSession:session,fence,mode,target,publication,check,signal,key,
   source:{sessionId,requestId,step}};
 }
 async function original(state){
  await state.check();
  try{
   const value=await readOriginal({scope:state.binding,persona:state.customer,personaSession:state.personaSession,
    ...state.source,target:state.target,execution:state.mode.snapshot,check:state.check,signal:state.signal});
   await state.check();return value;
  }catch(error){
   await state.check();if(error?.code==='SEARCH_ECHO_ORIGINAL_UNAVAILABLE')return null;throw error;
  }
 }
 const eligible=async state=>state.mode.snapshot.mode==='vuln'&&state.publication.binding.mode==='vuln'&&await enabled(state.binding);
 async function retained(state,packet,canonicalExecution){
  let input;try{input=typeof packet==='string'?JSON.parse(packet):structuredClone(packet);}catch{throw fail();}
  const descriptor=descriptorFor(input?.rubric?.version);
  if(!descriptor||!isSearchEchoBrowserJudgeInputValid(input,qualifyModel)||!await eligible(state))throw fail();
  const content=input.evidence[0].content;
  if(!equal(content.original.source,state.source))throw fail();
  const current=await original(state);if(!current)throw fail();
  const receipt=content.effectReceipt,component=browserQualification.readComponent();
  if(!canonicalExecution||receipt.runId!==canonicalExecution.runId||receipt.ownerKey!==canonicalExecution.ownerKey
   ||receipt.generation!==canonicalExecution.generation)throw fail();
  if(!equal(content.component,component)||receipt.effectKey!==`${state.key}:search-echo-browser:${current.sourceDigest}`)throw fail();
  let owner;try{owner=JSON.parse(receipt.ownerKey);}catch{throw fail();}
  if(!Array.isArray(owner)||owner.length!==2||owner[0]!=='SecureShopBoundConversation'||!UUID.test(owner[1]||''))throw fail();
  await conversations.assertOwned(owner[1],state.binding,state.customer,PURPOSE);
  const rows=(await identityPool.query(`SELECT e.run_id,e.owner_key,e.generation::text AS generation,e.effect_key,e.status,
   r.status AS run_status,o.generation::text AS live_generation
   FROM graph_runtime.effects e JOIN graph_runtime.runs r ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
   JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
   WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4 LIMIT 2`,
  [receipt.runId,receipt.ownerKey,receipt.generation,receipt.effectKey])).rows;
  await state.check();
  if(rows.length!==1||rows[0].status!=='completed'||rows[0].run_status!=='completed'
   ||rows[0].run_id!==receipt.runId||rows[0].owner_key!==receipt.ownerKey
   ||String(rows[0].generation)!==String(receipt.generation)||String(rows[0].live_generation)!==String(receipt.generation)
   ||rows[0].effect_key!==receipt.effectKey)throw fail();
  const candidate=buildSearchEchoBrowserCandidate({originalRead:current,
   effect:{value:{...content.browser,component},receipt},execution:{runId:receipt.runId,ownerKey:receipt.ownerKey,
    durableGeneration:receipt.generation,effectKey:receipt.effectKey},qualifyModel,evidenceVersion:descriptor.evidenceVersion});
  if(!candidate)throw fail();
  const prepared=prepareJudgeInput({rubric:{...descriptor.rubric,mode:'vuln'},...candidate}),saved=prepareJudgeInput(input);
  if(prepared.evidenceError||saved.evidenceError||prepared.packet!==saved.packet||prepared.evidenceDigest!==saved.evidenceDigest)throw fail();
  await state.check();return prepared;
 }
 async function persistedVersion(state,evaluationId){
  if(!UUID.test(evaluationId||''))throw fail();
  const b=state.binding;
  const rows=(await identityPool.query(`SELECT j.rubric_version
   FROM secureshop_auth.execution_authority_state e
   JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
   JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
   JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
   WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
    AND p.shop_user_id=$3 AND j.evaluation_id=$4 AND j.objective_id=$5 LIMIT 2`,
  [b.platformSessionId,b.platformOwnerId,b.shopUserId,evaluationId,OBJECTIVE])).rows;
  await state.check();
  if(rows.length!==1||typeof rows[0].rubric_version!=='string')throw fail();
  return descriptorFor(rows[0].rubric_version);
 }
 async function readOutcome(input){
  const state=await authority(input);if(!await eligible(state))return status('ineligible');
  const source=await original(state);if(!source)return status('ineligible');
  const b=state.binding;
  const rows=(await agentsPool.query(`SELECT t.session_id,t.request_id,t.request_hash,t.request_version,t.status,t.result_json
   FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
   WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active'
   AND s.conversation_purpose='persona_inbox' AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3
   AND s.platform_launch_generation=$4 AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6
   AND s.user_id=$7 AND s.role='customer' LIMIT 2`,[state.key,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId])).rows;
  await state.check();if(!rows.length)return status('unconfirmed');if(rows.length!==1)throw fail();
  const row=rows[0];await conversations.assertOwned(row.session_id,b,state.customer,PURPOSE);
  const request=createTurnRequest({sessionId:row.session_id,requestId:state.key,binding:b,message:message(state,source)});
  if(row.request_id!==state.key||row.request_hash!==request.hash||Number(row.request_version)!==request.version)throw fail();
  if(row.status!=='completed')return status('unconfirmed');
  if(equal(row.result_json,status('ineligible')))return status('ineligible');
  const descriptor=await persistedVersion(state,row.result_json.judgment.evaluationId);
  if(!descriptor)throw fail();
  return savedOutcomes[descriptor.rubric.version].read({binding:b,personaSession:state.personaSession,publication:state.publication.binding,
   assessmentOwnerKey:JSON.stringify(['SecureShopBoundConversation',row.session_id]),turnResult:row.result_json,
   prepareRetainedPacket:async(packet,execution)=>{
    const prepared=await retained(state,packet,execution);
    if(prepared.rubric?.version!==descriptor.rubric.version)throw fail();
    return prepared;
   },check:state.check});
 }
 async function runAttempt(input){
  const state=await authority(input);if(!await eligible(state))return status('ineligible');
  const source=await original(state);if(!source)return status('ineligible');
  const actor=capture.prepare(state.binding,state.fence),session=await conversations.create(state.binding,state.customer,PURPOSE);
  let prepared;
  const prepare=async()=>{await state.check();prepared=await admission.prepare({sessionId:session.id,requestId:state.key,
   binding:state.binding,message:message(state,source)});return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  try{
   const outcome=await turns.run(session.id,state.binding,state.customer,{signal:state.signal,idempotencyKey:state.key,
    conversationPurpose:PURPOSE,admit:prepare},async boundary=>{
    let resultSourceCheck;
    const check=async()=>{await boundary.check();await state.check();
     if(resultSourceCheck)await resultSourceCheck();await boundary.check();};
    await check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
    return admission.execute(prepared,{...boundary,check},async()=>{
     if(typeof boundary.effectWithReceipt!=='function')throw fail();
     const execution={runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,
      durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check};
     scopes.set(execution,state.binding);capture.bind(execution,actor);
     const attempt=await completion.beginAttempt({userId:state.binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});
     await check();if(attempt.mode!=='vuln'||!await eligible(state))return status('ineligible');
     const before=await original(state);if(!before||before.sourceDigest!==source.sourceDigest||!equal(before.proof,source.proof))throw fail();
     const component=browserQualification.readComponent(),node=`search-echo-browser:${source.sourceDigest}`;
     const effect=await boundary.effectWithReceipt(node,async()=>{
      await check();const value=await browserQualification.qualifySearchEcho({html:source.echoHtml,
       modeCapability:projectFeatureMode(state.mode),signal:boundary.signal,
       ...(evidenceVersion>=8?{captureDom:true}:{})});await check();return value;
     });
     await check();const after=await original(state);
     if(!after||after.sourceDigest!==source.sourceDigest||!equal(after.proof,source.proof)
      ||!equal(browserQualification.readComponent(),component)||!equal(effect.value?.component,component)
      ||effect.value?.renderedSourceSha256!==hash(source.echoHtml))throw fail();
     const descriptor=descriptorFor(evidenceVersion===9?RUBRIC_V9.version:evidenceVersion===8?RUBRIC_V8.version:RUBRIC_V2.version);
     const candidate=buildSearchEchoBrowserCandidate({originalRead:source,effect,
      execution:{...execution,effectKey:`${state.key}:${node}`},qualifyModel,evidenceVersion:descriptor.evidenceVersion});
     if(!candidate)return status('ineligible');
     const rubric={...descriptor.rubric,mode:'vuln'},packet=prepareJudgeInput({rubric,...candidate});
     if(packet.evidenceError)throw fail();packets.set(execution,packet);
     resultSourceCheck=async()=>{
      const current=await original(state);
      if(!current||current.sourceDigest!==source.sourceDigest||!equal(current.proof,source.proof)
       ||!equal(browserQualification.readComponent(),component))throw fail();
     };
     const result=await completion.evaluate({userId:state.binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,
      evaluationId:randomUUID(),execution,attempt,rubric,...candidate});
     await check();return {completed:result.completed===true,judgment:result.judgment};
    },state.fence);
   });
   await state.check();if(outcome.replayed===true)return readOutcome(input);
   return Object.freeze({...outcome.result,replayed:false});
  }catch(error){await admission.abandon(prepared);throw error;}
 }
 async function assertRetainedPacket({packet,scope,persona,personaSession,signal}){
  let input;try{input=typeof packet==='string'?JSON.parse(packet):structuredClone(packet);}catch{throw fail();}
  const descriptor=descriptorFor(input?.rubric?.version);
  if(!descriptor||!isSearchEchoBrowserJudgeInputValid(input,qualifyModel))throw fail();
  const state=await authority({scope,persona,personaSession,...input.evidence[0].content.original.source,signal});
  const check=async()=>{
   await state.check();
   const receipt=input.evidence[0].content.effectReceipt,prepared=prepareJudgeInput(input),b=state.binding;
   // Recovery keeps the original browser receipt, including when a Judge retry
   // uses a different run. Resolve its canonical parent without replaying work.
   const rows=(await identityPool.query(`SELECT j.*,e.tenant_id AS current_tenant_id,e.principal_id AS current_principal_id,
    s.membership_version::text AS current_membership_version,g.generation::text AS live_owner_generation
    FROM secureshop_auth.execution_authority_state e
    JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
    JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
    JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
    JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
    WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
     AND p.shop_user_id=$3 AND j.objective_id=$4 AND j.run_id=$5 AND j.owner_key=$6
     AND j.packet=$7 AND j.evidence_digest=$8
     AND NOT EXISTS (SELECT 1 FROM secureshop_auth.assessment_retries retry
      WHERE retry.tenant_id=j.tenant_id AND retry.principal_id=j.principal_id AND retry.child_id=j.evaluation_id) LIMIT 2`,
   [b.platformSessionId,b.platformOwnerId,b.shopUserId,OBJECTIVE,receipt.runId,receipt.ownerKey,prepared.packet,prepared.evidenceDigest])).rows;
   await state.check();if(rows.length!==1)throw fail();
   const row=rows[0],execution=row.execution_json,publication=state.publication.binding;
   if(row.workshop_key!==WORKSHOP||row.objective_id!==OBJECTIVE||Number(row.shop_user_id)!==b.shopUserId
    ||row.family!==descriptor.rubric.family||row.scenario!==descriptor.rubric.scenario||row.rubric_version!==descriptor.rubric.version
    ||row.mode!=='vuln'||row.mode!==publication.mode||Number(row.generation)!==publication.generation
    ||row.mode_stamp!==publication.modeStamp||row.run_id!==receipt.runId||row.owner_key!==receipt.ownerKey
    ||String(row.owner_generation)!==receipt.generation||String(row.live_owner_generation)!==receipt.generation
    ||execution?.runId!==row.run_id||execution.tenantId!==row.current_tenant_id||execution.principalId!==row.current_principal_id
    ||execution.membershipVersion!==row.current_membership_version||!equal(execution.scope,createLaunchScope(b))
    ||execution.personaSessionId!==state.personaSession.sessionId||execution.personaAuthorityVersion!==state.personaSession.authorityVersion
    ||execution.role!=='customer'||prepared.evidenceError||row.packet!==prepared.packet||row.evidence_digest!==prepared.evidenceDigest)throw fail();
   await retained(state,input,{runId:row.run_id,ownerKey:row.owner_key,generation:String(row.owner_generation)});
  };await check();return Object.freeze({assertCurrent:check});
 }
 return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,runAttempt,readOutcome,assertRetainedPacket});
}
module.exports={createSearchEchoBrowserAssessment,assessmentRequestId};
