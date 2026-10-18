"use strict";
const {createHash}=require('node:crypto');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {createObjectiveJudge,prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const {createLaunchScope,createConversationBinding,conversationBindingMatches}=require('./secureshopConversationBinding');
const {OBJECTIVE,RUBRIC,buildAnalyticsNlSqlCandidate,createAnalyticsNlSqlJudgeGuard}=require('./secureshopAnalyticsNlSqlEvidence');
const WORKSHOP='secureshop_agent_security';
function evaluationId(runId){
 const chars=createHash('sha256').update(JSON.stringify(['analytics-nl-sql-v1',runId,OBJECTIVE])).digest('hex').slice(0,32).split('');
 chars[12]='5';chars[16]='8';const v=chars.join('');return `${v.slice(0,8)}-${v.slice(8,12)}-${v.slice(12,16)}-${v.slice(16,20)}-${v.slice(20)}`;
}
function createAnalyticsNlSqlAssessment({receipts,progress,personaBindings,qualifyModel,isAvailable,judge}={}){
 if(typeof qualifyModel!=='function'||typeof isAvailable!=='function')throw TypeError('Analytics NL SQL qualification and availability required');
 const scopes=new WeakMap(),states=new WeakMap(),capture=createAssessmentPersonaCapture(personaBindings);
 const guarded=createAnalyticsNlSqlJudgeGuard(judge||createObjectiveJudge(),qualifyModel);
 const completion=createObjectiveCompletionService({receipts,progress,...capture.options,
  captureInstanceScope:execution=>{const scope=scopes.get(execution);if(!scope)throw Object.assign(Error('Analytics NL SQL scope unavailable'),{executionBoundary:true});return scope;},
  judge:async input=>{
   const status=states.get(input.execution);
   if(status){return {family:RUBRIC.family,scenario:RUBRIC.scenario,objectiveId:OBJECTIVE,rubricVersion:RUBRIC.version,
    mode:input.rubric.mode,runId:input.execution.runId,evidenceDigest:prepareJudgeInput(input).evidenceDigest,
    verdict:status==='unavailable'?'unavailable':'fail',assessmentStatus:status,modelEvaluated:false,
    errorCode:status==='unavailable'?'JUDGE_UNAVAILABLE':'REQUIRED_FACTS_NOT_SATISFIED',criteria:[],provider:null,model:null,usage:null,
    explanation:status==='unavailable'?'Committed response assessment is unavailable; no Judge model was called and no completion was awarded.':'Not evaluated by a Judge model: original natural-language SQL evidence is incomplete or ineligible.'};}
   return guarded(input);
  }});
 return async function factory(context,fence,privateEvidence){
  const binding=createConversationBinding(context.binding,{id:context.binding.shopUserId,role:context.binding.role}),scope=createLaunchScope(binding);
  if(!await isAvailable(scope))return null;
  if(typeof privateEvidence?.read!=='function'||typeof privateEvidence.question!=='string'||typeof privateEvidence.projectResult!=='function')throw TypeError('Private Analytics NL SQL capture required');
  const persona=capture.prepare(binding,fence),observations=[];let execution,attempt,outcome;
  function verify(run,packet){if(run!==execution||packet.attempt!==attempt||packet.sessionId!==context.sessionId||packet.requestId!==context.requestId||!conversationBindingMatches(packet.binding,binding))throw Object.assign(Error('Analytics NL SQL assessment binding mismatch'),{executionBoundary:true});}
  return {
   async begin(run){if(execution)throw Object.assign(Error('Analytics NL SQL assessment already started'),{executionBoundary:true});execution=run;scopes.set(run,scope);capture.bind(run,persona);attempt=await completion.beginAttempt({userId:scope.platformOwnerId,workshopKey:WORKSHOP,objectiveId:OBJECTIVE,execution:run});return attempt;},
   async observe(run,packet){verify(run,packet);if(observations.length>=256)throw Error('Analytics NL SQL evidence limit');observations.push(packet.observation);},
   async finalize(run,packet){
    verify(run,packet);if(outcome)return outcome;await run.check();
    let candidate,status;
    if(packet.postJournalError)status='unavailable';
    else if(attempt.mode!=='vuln')status='ineligible';
    else {
     // The wrapper supplies only the immutable completed journal projection.
     // Execution callbacks stay outside the retained lossless JSON proof.
     const triple={runId:run.runId,ownerKey:run.ownerKey,durableGeneration:run.durableGeneration};
     try {const source={context:{binding,sessionId:context.sessionId,requestId:context.requestId},execution:triple,
      traces:packet.traces,observations,result:packet.result,receipt:privateEvidence.read().receipt,
      question:privateEvidence.question,projection:await privateEvidence.projectResult(packet.result)};
     await run.check();candidate=buildAnalyticsNlSqlCandidate({source,assessmentExecution:triple,qualifyModel});
     if(!candidate)status='ineligible';
     }catch(error){await run.check();if(error?.name==='AbortError')throw error;status='unavailable';}
    }
    await run.check();if(status)states.set(run,status);
    const input=candidate||{facts:{},evidence:[{id:'analytics_nl_sql_reference',source:'server_observation',content:'Original reference unavailable'},
     {id:'analytics_nl_sql_observation',source:'server_observation',content:'Original response unavailable'}]};
    outcome=await completion.evaluate({userId:scope.platformOwnerId,workshopKey:WORKSHOP,evaluationId:evaluationId(run.runId),execution:run,attempt,
     ...input,rubric:{...RUBRIC,mode:attempt.mode}});return outcome;
   }
  };
 };
}
module.exports={OBJECTIVE,evaluationId,createAnalyticsNlSqlAssessment};
