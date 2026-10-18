'use strict';

const {createHash,randomUUID}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {createBoundConversationService}=require('./secureshopBoundConversation');
const {createBoundTurns}=require('./secureshopBoundTurns');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {captureFeatureMode}=require('./secureshopFeatureModeAuthority');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {OBJECTIVE,RUBRIC,validateMcpImpersonationEvidence,projectMcpImpersonationCandidate,
  createMcpImpersonationJudgeGuard}=require('./secureshopMcpImpersonationEvidence');

const WORKSHOP='secureshop_agent_security',PURPOSE='persona_inbox';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail=()=>Object.assign(Error('MCP impersonation assessment unavailable'),{code:'MCP_IMPERSONATION_EVIDENCE_UNAVAILABLE'});
const unconfirmed=()=>Object.freeze({completed:false,status:'unconfirmed',modelEvaluated:false});
const ineligible=()=>Object.freeze({completed:false,status:'ineligible',modelEvaluated:false});
function assessmentRequestId(sessionId,requestId){
  if(!UUID.test(sessionId||'')||!UUID.test(requestId||''))throw fail();
  const bytes=createHash('sha256').update(JSON.stringify(['mcp-impersonation-assessment-v1',sessionId,requestId])).digest();
  bytes[6]=(bytes[6]&15)|80;bytes[8]=(bytes[8]&63)|128;
  const hex=bytes.subarray(0,16).toString('hex');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
const message=(sessionId,requestId,personaSession)=>JSON.stringify([OBJECTIVE,sessionId,requestId,
  personaSession.sessionId,personaSession.authorityVersion]);
function invocationIds(traces){
  const ids=new Set();
  for(const row of traces){
    if(row.kind!=='mcp_result')continue;
    let value;try{value=JSON.parse(row.result_json);}catch{return [];}
    const id=value?._meta?.ownedRegistryInvocation?.request?.operationId;
    if(typeof id==='string'&&UUID.test(id))ids.add(id);
  }
  return [...ids];
}
function createMcpImpersonationAssessment({identityPool,agentsPool,launches,conversationRepository,
  coordinator,turnJournal,registryRepository,invocationJournal,personaAuthority,personaBindings,
  receipts,progress,judge,qualifyModel,modeAuthority}={}){
  for(const value of [identityPool?.query,agentsPool?.query,launches?.assertCurrent,
    conversationRepository?.getTraceEvents,coordinator?.run,turnJournal?.readRegisteredAdminRequest,
    registryRepository?.readAssessmentRevisions,invocationJournal?.readCompleted,
    personaAuthority?.capture,personaBindings?.capture,modeAuthority?.capture,
    modeAuthority?.assertToken,judge,qualifyModel])
    if(typeof value!=='function')throw fail();
  const conversations=createBoundConversationService({conversations:conversationRepository,launches});
  const turns=createBoundTurns({conversations,coordinator}),admission=createTurnAdmission({journal:turnJournal});
  const scopes=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
  const completion=createObjectiveCompletionService({receipts,progress,judge:createMcpImpersonationJudgeGuard(judge),
    ...capture.options,captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw fail();return scope;}});
  const enabled=async scope=>(await readSecureShopAssessmentEligibility(identityPool,scope,[OBJECTIVE])).includes(OBJECTIVE);
  async function authority({scope,persona,personaSession,sessionId,requestId,signal}){
    const binding=createConversationBinding(scope,persona);
    if(binding.role!=='admin'||!UUID.test(sessionId||'')||!UUID.test(requestId||'')
      ||!UUID.test(personaSession?.sessionId||'')||typeof personaSession.authorityVersion!=='string')throw fail();
    const fence=personaAuthority.capture({scope:binding,personaId:binding.shopUserId,role:'admin',
      sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion});
    const mode=await captureFeatureMode(modeAuthority,binding,'registered_mcp');
    if(!Number.isSafeInteger(mode.snapshot.generation)||mode.snapshot.generation<0
      ||typeof mode.snapshot.modeStamp!=='string'||!/^[a-f0-9]{64}$/.test(mode.snapshot.modeStamp))throw fail();
    const check=async()=>{signal?.throwIfAborted();await launches.assertCurrent(binding);
      await mode.assertCurrent();await fence.assertRemoteAdmission();signal?.throwIfAborted();};
    await check();return {binding,fence,mode,check,personaSession,sessionId,requestId};
  }
  async function original(state,verifyOriginal){
    const {binding,sessionId,requestId,personaSession,mode,check}=state;
    if(typeof verifyOriginal!=='function')throw fail();
    const protectedRead=await verifyOriginal();await check();
    if(protectedRead?.status!=='completed')return null;
    await conversations.assertOwned(sessionId,binding,{id:binding.shopUserId,role:'admin'},'general');
    const turn=await turnJournal.readRegisteredAdminRequest({sessionId,requestId,binding});
    const meta=turn?.result_json?.taskMetadata?.registeredAdmin;
    if(turn?.status!=='completed'||turn.session_id!==sessionId||turn.request_id!==requestId
      ||meta?.version!==3||!Array.isArray(meta.traceEventIds)||meta.traceEventIds.length<3
      ||meta.traceEventIds.length>4096||mode.snapshot.mode!=='vuln')return null;
    const traces=await conversationRepository.getTraceEvents(sessionId,binding,meta.traceEventIds,'general');
    await conversations.assertOwned(sessionId,binding,{id:binding.shopUserId,role:'admin'},'general');await check();
    const ids=invocationIds(traces);if(ids.length!==1)return null;
    const stored=await invocationJournal.readCompleted({scope:binding,invocationId:ids[0]});
    const request=stored?.envelope?.request;
    if(request?.requestId!==requestId||request?.binding?.shopUserId!==binding.shopUserId)return null;
    const revisions=await registryRepository.readAssessmentRevisions({scope:binding,
      persona:{id:binding.shopUserId,role:'admin'},personaSession,
      entryId:request.entryId,registryVersion:request.registryVersion});
    const run=(await identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,status
      FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2`,
    [request.runId,JSON.stringify(['SecureShopBoundConversation',sessionId])])).rows;
    const effects=(await identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
      FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND effect_key=$3`,
    [request.runId,JSON.stringify(['SecureShopBoundConversation',sessionId]),stored.envelope.effectKey])).rows;
    await check();if(run.length!==1||effects.length!==1)return null;
    try{return validateMcpImpersonationEvidence({binding,...revisions,stored,turn,traces,run:run[0],effects,
      modeExecution:mode.snapshot,qualifyModel});}catch(error){
      if(error?.code==='MCP_IMPERSONATION_EVIDENCE_INVALID')return null;throw error;
    }
  }
  async function readOutcome(input){
    const state=await authority(input);const {binding,personaSession,sessionId,requestId,mode,check}=state;
    if(typeof input.verifyOriginal!=='function')throw fail();
    const source=await input.verifyOriginal();await check();if(source?.status!=='completed')return unconfirmed();
    await conversations.assertOwned(sessionId,binding,{id:binding.shopUserId,role:'admin'},'general');
    const originalTurn=await turnJournal.readRegisteredAdminRequest({sessionId,requestId,binding});
    const registered=originalTurn?.result_json?.taskMetadata?.registeredAdmin;
    await check();
    if(originalTurn?.status!=='completed'||registered?.version!==3
      ||mode.snapshot.mode!=='vuln'||!isDeepStrictEqual(registered.execution,mode.snapshot))return ineligible();
    const key=assessmentRequestId(sessionId,requestId);
    const values=[key,binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,
      binding.platformSessionId,binding.shopUserId,binding.role];
    const rows=(await agentsPool.query(`SELECT t.session_id,t.request_id,t.status,t.request_hash,t.request_version,t.result_json
      FROM secureshop_agents.turn_requests t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE t.request_id=$1 AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.conversation_purpose='persona_inbox' AND s.platform_launch_id=$2
        AND s.platform_scenario_id=$3 AND s.platform_launch_generation=$4
        AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6
        AND s.user_id=$7 AND s.role=$8 LIMIT 2`,values)).rows;
    await check();if(rows.length===0)return unconfirmed();if(rows.length!==1)throw fail();
    const row=rows[0],expected=createTurnRequest({sessionId:row.session_id,requestId:key,binding,
      message:message(sessionId,requestId,personaSession)});
    if(row.request_id!==key||row.request_hash!==expected.hash||row.request_version!==expected.version)throw fail();
    if(row.status!=='completed')return unconfirmed();
    const result=row.result_json;
    if(result?.completed===false&&result.status==='ineligible'
      &&result.modelEvaluated===false&&isDeepStrictEqual(Object.keys(result).sort(),
        ['completed','modelEvaluated','status']))return ineligible();
    if(!result||typeof result!=='object'||Array.isArray(result)
      ||!isDeepStrictEqual(Object.keys(result).sort(),['completed','judgment'])
      ||typeof result.completed!=='boolean'||!result.judgment
      ||typeof result.judgment!=='object'||Array.isArray(result.judgment))throw fail();
    return Object.freeze({...structuredClone(result),replayed:true});
  }
  async function runAttempt(input){
    const state=await authority(input),{binding,fence,check,personaSession,sessionId,requestId,mode}=state;
    if(mode.snapshot.mode!=='vuln'||!await enabled(binding))return ineligible();
    const proof=await original(state,input.verifyOriginal);if(!proof)return ineligible();
    const actor=capture.prepare(binding,fence),persona={id:binding.shopUserId,role:'admin'};
    const session=await conversations.create(binding,persona,PURPOSE),key=assessmentRequestId(sessionId,requestId);
    let prepared;
    const prepare=async()=>{await check();prepared=await admission.prepare({sessionId:session.id,requestId:key,
      binding,message:message(sessionId,requestId,personaSession)});
      return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};};
    try{
      const outcome=await turns.run(session.id,binding,persona,{signal:input.signal,idempotencyKey:key,
        conversationPurpose:PURPOSE,admit:prepare},async originalBoundary=>{
        const boundary={...originalBoundary,async check(){await originalBoundary.check();await check();}};
        await boundary.check();if(!prepared){await prepare();if(prepared.status==='completed')return prepared.outcome;}
        return admission.execute(prepared,boundary,async()=>{
          const execution=Object.freeze({runId:boundary.identity.runId,ownerKey:boundary.identity.ownerKey,
            durableGeneration:boundary.identity.durableGeneration,signal:boundary.signal,check:boundary.check});
          scopes.set(execution,binding);capture.bind(execution,actor);
          const attempt=await completion.beginAttempt({userId:binding.platformOwnerId,workshopKey:WORKSHOP,
            objectiveId:OBJECTIVE,execution});await boundary.check();
          if(attempt.mode!=='vuln'||!await enabled(binding))return {completed:false,status:'ineligible',modelEvaluated:false};
          const confirmed=await original(state,input.verifyOriginal);await boundary.check();
          if(!confirmed||JSON.stringify(confirmed)!==JSON.stringify(proof))
            return {completed:false,status:'ineligible',modelEvaluated:false};
          const packet=projectMcpImpersonationCandidate(proof);
          const result=await completion.evaluate({userId:binding.platformOwnerId,workshopKey:WORKSHOP,
            objectiveId:OBJECTIVE,evaluationId:randomUUID(),execution,attempt,rubric:{...RUBRIC,mode:attempt.mode},
            facts:packet.facts,evidence:packet.evidence});
          await boundary.check();return {completed:result.completed===true,judgment:result.judgment};
        },fence);
      });
      await check();if(outcome.result?.status==='ineligible')return ineligible();
      return Object.freeze({...outcome.result,replayed:outcome.replayed===true});
    }catch(error){await admission.abandon(prepared);throw error;}
  }
  return Object.freeze({objectiveId:OBJECTIVE,completionService:completion,runAttempt,readOutcome});
}
module.exports={createMcpImpersonationAssessment,assessmentRequestId};
