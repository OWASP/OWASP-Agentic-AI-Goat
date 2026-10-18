'use strict';
const {randomUUID,createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createConversationBinding,createLaunchScope}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {captureFeatureMode,projectFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {captureAssessmentPublicationScope}=require('./secureshopAssessmentPublicationScope');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {createSavedAssessmentOutcomeReader}=require('./secureshopSavedAssessmentOutcomeReader');
const {prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
const {OBJECTIVE,RUBRIC,buildPolicyFinalHtmlCandidate,createPolicyFinalHtmlJudgeGuard}=require('./secureshopPolicyFinalHtmlEvidence');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox';
const fail=()=>Object.assign(Error('Policy final response assessment unavailable'),{code:'POLICY_FINAL_HTML_UNAVAILABLE'});
const need=v=>{if(!v)throw fail();};
const status=value=>Object.freeze({completed:false,status:value,modelEvaluated:false});
function assessmentId(sessionId,requestId){need(UUID.test(sessionId||'')&&UUID.test(requestId||''));
 const bytes=createHash('sha256').update(JSON.stringify([OBJECTIVE,sessionId,requestId])).digest();bytes[6]=(bytes[6]&15)|80;bytes[8]=(bytes[8]&63)|128;
 const h=bytes.subarray(0,16).toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;}
const message=(state,original)=>JSON.stringify([OBJECTIVE,state.sessionId,state.requestId,original.sourceDigest,state.mode.snapshot,state.publication.binding]);
function createPolicyFinalHtmlAssessment({identityPool,agentsPool,launches,conversationRepository,coordinator,journal,
 personaAuthority,personaBindings,modeAuthority,publicationModes,availability,receipts,progress,judge,qualifyModel,originalReader,browserQualification}){
 for(const fn of [identityPool?.query,agentsPool?.query,launches?.assertCurrent,conversationRepository?.getBoundSession,
  coordinator?.run,journal?.readBoundRequest,personaAuthority?.capture,personaBindings?.capture,modeAuthority?.capture,
  publicationModes?.getEvaluationScope,availability?.assertObjective,judge,qualifyModel,originalReader,
  browserQualification?.qualifyPolicyOutput,browserQualification?.readComponent])need(typeof fn==='function');
 const conversations=createBoundConversationService({conversations:conversationRepository,launches}),turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal});
 const capture=createAssessmentPersonaCapture(personaBindings),scopes=new WeakMap(),packets=new WeakMap();
 const completion=createObjectiveCompletionService({receipts,progress,...capture.options,judge:createPolicyFinalHtmlJudgeGuard(judge,execution=>packets.get(execution)),
  captureInstanceScope:execution=>{const value=scopes.get(execution);need(value);return value;}});
 async function authority({scope,persona,personaSession,sessionId,requestId,signal}){
  const binding=createConversationBinding(scope,persona);need(UUID.test(requestId||''));
  need(UUID.test(personaSession?.sessionId||'')&&typeof personaSession.authorityVersion==='string'&&/^[1-9]\d*$/.test(personaSession.authorityVersion));
  const fence=personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion});
  capture.prepare(binding,fence);
  const mode=await captureFeatureMode(modeAuthority,binding,'controlled_ssrf');
  const publication=await captureAssessmentPublicationScope(publicationModes,binding.platformOwnerId,signal,binding);
  const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(binding);await fence.assertRemoteAdmission();
   await mode.assertCurrent();await publication.assertCurrent();await availability.assertObjective(OBJECTIVE);signal?.throwIfAborted();};
  await check();
  const state={binding,persona:{id:binding.shopUserId,role:binding.role},personaSession,fence,mode,publication,check,signal,sessionId,requestId};
  return state;
 }
 const read=async state=>{await state.check();const original=await originalReader({binding:state.binding,sessionId:state.sessionId,
  requestId:state.requestId,mode:state.mode.snapshot,check:state.check,signal:state.signal});await state.check();return original;};
 async function readRun(input){const state=await authority(input),original=await read(state),r=original.proof.turn.result_json;
  return Object.freeze({sessionId:original.source.sessionId,requestId:original.source.requestId,response:original.html,
   stopReason:'end_turn',replayed:true,modeCapability:r.modeCapability});}
 const eligible=state=>state.mode.snapshot.mode==='vuln'&&state.publication.binding.mode==='vuln';
 async function retained(state,packet,execution){
  const input=typeof packet==='string'?JSON.parse(packet):structuredClone(packet),content=input.evidence?.find(e=>e.id==='policy_final_proof')?.content;
  const receipt=content?.effectReceipt;need(eligible(state)&&receipt&&execution&&receipt.runId===execution.runId
   &&receipt.ownerKey===execution.ownerKey&&String(receipt.generation)===String(execution.generation));
  const original=await read(state),key=assessmentId(original.source.sessionId,state.requestId);
  need(receipt.effectKey===`${key}:policy-final-html:${original.sourceDigest}`);
  const rows=(await identityPool.query(`SELECT e.status,r.status AS run_status,o.generation::text AS live_generation
   FROM graph_runtime.effects e JOIN graph_runtime.runs r USING(run_id,owner_key,generation)
   JOIN graph_runtime.owners o ON o.owner_key=e.owner_key
   WHERE e.run_id=$1 AND e.owner_key=$2 AND e.generation=$3 AND e.effect_key=$4`,
  [receipt.runId,receipt.ownerKey,receipt.generation,receipt.effectKey])).rows;
  await state.check();need(rows.length===1&&rows[0].status==='completed'&&rows[0].run_status==='completed'
   &&String(rows[0].live_generation)===String(receipt.generation)&&equal(await browserQualification.readComponent(),content.component));
  const candidate=buildPolicyFinalHtmlCandidate({original,effect:{receipt,value:content.browser},
   execution:{runId:receipt.runId,ownerKey:receipt.ownerKey,durableGeneration:receipt.generation,effectKey:receipt.effectKey},qualifyModel});
  need(candidate);const actual=prepareJudgeInput(input),expected=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...candidate});
  need(!actual.evidenceError&&!expected.evidenceError&&actual.packet===expected.packet&&actual.evidenceDigest===expected.evidenceDigest);return expected;
 }
 async function readOutcome(input){
  const state=await authority(input);if(!eligible(state))return status('ineligible');
  need(UUID.test(state.sessionId||''));const original=await read(state),key=assessmentId(state.sessionId,state.requestId),b=state.binding;
  const rows=(await agentsPool.query(`SELECT t.session_id,t.request_hash,t.request_version,t.status,t.result_json
   FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
   WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active' AND s.conversation_purpose=$2
   AND s.platform_launch_id=$3 AND s.platform_scenario_id=$4 AND s.platform_launch_generation=$5
   AND s.original_platform_owner_id=$6 AND s.original_platform_session_id=$7 AND s.user_id=$8 AND s.role=$9 LIMIT 2`,
  [key,PURPOSE,b.launchId,b.scenarioId,b.generation,b.platformOwnerId,b.platformSessionId,b.shopUserId,b.role])).rows;
  await state.check();if(!rows.length)return status('unconfirmed');need(rows.length===1);const row=rows[0];
  await conversations.assertOwned(row.session_id,b,state.persona,PURPOSE);
  const request=createTurnRequest({sessionId:row.session_id,requestId:key,binding:b,message:message(state,original)});
  need(row.request_hash===request.hash&&Number(row.request_version)===request.version);
  if(row.status!=='completed')return status('unconfirmed');if(equal(row.result_json,status('ineligible')))return status('ineligible');
  return createSavedAssessmentOutcomeReader({identityPool,objectiveId:OBJECTIVE,rubric:RUBRIC,role:b.role}).read({binding:b,
   personaSession:state.personaSession,publication:state.publication.binding,assessmentOwnerKey:JSON.stringify(['SecureShopBoundConversation',row.session_id]),
   turnResult:row.result_json,prepareRetainedPacket:(packet,execution)=>retained(state,packet,execution),check:state.check});
 }
 async function runAttempt(input){
  const state=await authority(input);if(!eligible(state))return status('ineligible');need(UUID.test(state.sessionId||''));
  const original=await read(state);
  const sourceBudget=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},facts:{},evidence:[{id:'policy_final_source',source:'server_observation',content:{policyBody:original.proof.request.policyHtml,finalResponse:original.html}},{id:'policy_final_browser',source:'server_observation',content:'Preflight only; no browser observation exists yet.'}]},16000);
  need(!sourceBudget.evidenceError);
  const key=assessmentId(state.sessionId,state.requestId),actor=capture.prepare(state.binding,state.fence);
  const session=await conversations.create(state.binding,state.persona,PURPOSE);let prepared;
  const prepare=async()=>{await state.check();prepared=await admission.prepare({sessionId:session.id,requestId:key,binding:state.binding,message:message(state,original)});
   return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
  try{const outcome=await turns.run(session.id,state.binding,state.persona,{signal:state.signal,idempotencyKey:key,conversationPurpose:PURPOSE,admit:prepare},async boundary=>{
   const check=async()=>{await boundary.check();await state.check();};await check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
   return admission.execute(prepared,{...boundary,check},async()=>{
    const execution={runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check};
    scopes.set(execution,state.binding);capture.bind(execution,actor);
    const attempt=await completion.beginAttempt({userId:state.binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution});
    await check();if(attempt.mode!=='vuln'||!eligible(state))return status('ineligible');
    const node=`policy-final-html:${original.sourceDigest}`,component=await browserQualification.readComponent();
    const effect=await boundary.effectWithReceipt(node,async()=>{await check();const value=await browserQualification.qualifyPolicyOutput({html:original.html,
     modeCapability:projectFeatureMode(state.mode),signal:boundary.signal});await check();return value;});
    need(equal(await read(state),original)&&equal(await browserQualification.readComponent(),component)&&equal(effect.value.component,component));
    const candidate=buildPolicyFinalHtmlCandidate({original,effect,execution:{...execution,effectKey:`${key}:${node}`},qualifyModel});
    if(!candidate)return status('ineligible');
    const preparedPacket=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...candidate});need(!preparedPacket.evidenceError);packets.set(execution,preparedPacket);
    const result=await completion.evaluate({userId:state.binding.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,evaluationId:randomUUID(),
     execution,attempt,rubric:{...RUBRIC,mode:'vuln'},...candidate});
    await check();need(equal(await read(state),original));return {completed:result.completed===true,judgment:result.judgment};
   },state.fence);
  });await state.check();if(outcome.replayed===true)return readOutcome(input);return Object.freeze({...outcome.result,replayed:false});
  }catch(error){await admission.abandon(prepared);throw error;}
 }
 return Object.freeze({objectiveId:OBJECTIVE,readRun,readOutcome,runAttempt,completionService:completion});
}
module.exports={createPolicyFinalHtmlAssessment,assessmentId};
