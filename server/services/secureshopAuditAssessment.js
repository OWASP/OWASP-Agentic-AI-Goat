'use strict';
const {randomUUID}=require('node:crypto');
const {createObjectiveCompletionService}=require('./secureshopObjectiveCompletionService');
const {createConversationBinding,createLaunchScope}=require('./secureshopConversationBinding');
const {AUDIT_INSTRUCTION_OBJECTIVE,prepareSecureShopAuditJudgePacket}=require('./secureshopAuditJudgePacket');
const {createAssessmentPersonaCapture}=require('./secureshopAssessmentPersonaCapture');
const WORKSHOP='secureshop_agent_security';

function createSecureShopAuditAssessment({receipts,progress,judge,qualifyModel,personaBindings}={}){
  if(typeof qualifyModel!=='function')throw new TypeError('Trusted audit model qualifier required');
  const scopes=new WeakMap();
  const personaCapture=createAssessmentPersonaCapture(personaBindings);
  const completion=createObjectiveCompletionService({receipts,progress,...(judge?{judge}:{}),
    ...personaCapture.options,
    captureInstanceScope:execution=>{
      const scope=scopes.get(execution);if(!scope)throw new Error('Audit assessment scope unavailable');return scope;
    }});
  return async function begin({binding:input,execution}={},personaFence){
    const binding=createConversationBinding(input,{id:input?.shopUserId,role:input?.role});
    if(binding.role!=='admin'||typeof execution?.check!=='function'||!execution.runId||scopes.has(execution))
      throw new TypeError('Protected audit assessment required');
    const scope=createLaunchScope(binding),capture=personaCapture.prepare(binding,personaFence);
    scopes.set(execution,scope);personaCapture.bind(execution,capture);
    const attempt=await completion.beginAttempt({userId:scope.platformOwnerId,workshopKey:WORKSHOP,
      objectiveId:AUDIT_INSTRUCTION_OBJECTIVE,execution});
    if(!['vuln','fixed'].includes(attempt.mode)||!Number.isSafeInteger(attempt.generation)||attempt.generation<0)
      throw new Error('Audit grading mode or generation is unavailable');
    let started=false,settled=false,result;
    return Object.freeze({
      async consume(evidence){
        await execution.check();
        if(started||evidence?.runId!==execution.runId)throw new Error('Audit assessment evidence mismatch or replay');
        started=true;
        if(capture)await capture.fence.assertRemoteAdmission();
        const packet=await prepareSecureShopAuditJudgePacket(evidence,{qualifyModel,check:execution.check,mode:attempt.mode});
        if(capture){await capture.fence.assertRemoteAdmission();await execution.check();}
        result=await completion.evaluate({userId:scope.platformOwnerId,workshopKey:WORKSHOP,
          evaluationId:randomUUID(),execution,attempt,...packet});
        await execution.check();settled=true;
      },
      outcome(){
        if(!settled)throw new Error('Audit assessment did not complete');
        return result;
      },
    });
  };
}
module.exports={createSecureShopAuditAssessment};
