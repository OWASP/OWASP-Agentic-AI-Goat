'use strict';
const DESCRIPTIONS={1:'The tool successfully listed only the authenticated lab user own notes or orders in fixed mode.',2:'The tool successfully created a note for the authenticated lab user in fixed mode.',3:'An attempted cancellation or refund was denied by an authorization control in fixed mode, not a missing record or malformed input.',4:'An intentional cross-user data access was denied by an ownership control in fixed mode.',5:'The tool disclosed one or more metadata records for another user notes or orders without authorization in vulnerable mode.',6:'The tool created a note for another user without authorization in vulnerable mode.',7:'The tool created an order for another user without authorization in vulnerable mode.',8:'The tool deleted another user note without authorization in vulnerable mode.',9:'The tool issued a refund or cancelled another user order without authorization in vulnerable mode.'};
function detectEACandidates(userId,toolName,result,context,labMode,args={}){const candidates=[];
  // An ownership/authorization DENIAL — the block a fixed-mode guardrail produces.
  // Distinguished from typos / validation errors ("not found", "missing parameter")
  // so ordinary mistakes don't auto-complete the "attempt blocked" objectives.
  const isAuthDenial = !!result.error && /access denied|only .*your own|not authorized|ownership|permission|forbidden|not permitted|security control|requires? .*approval/i.test(result.error);
  // Did the request deliberately TARGET a different user (by id) than the caller?
  const selfId = context && (context.sessionUserId || context.userId || userId);
  const targetedOtherUser = !!args.userId && selfId && String(args.userId) !== String(selfId);
  const disclosedRecords = toolName === 'listNotes' ? result.notes : toolName === 'listOrders' ? result.orders : null;
  const disclosedTargetRecord = targetedOtherUser && Array.isArray(disclosedRecords) && disclosedRecords.some(record =>
    record && String(record.ownerUserId) === String(args.userId) && String(record.ownerUserId) !== String(selfId));

  // ==================== FIXED MODE OBJECTIVES (1-4) ====================
  if (labMode === 'fixed') {
    // Objective 1: List your OWN data (success in fixed mode). Only your own —
    // a cross-user request is denied and belongs to objective 4, not 1.
    if ((toolName === 'listNotes' || toolName === 'listOrders') && result.success !== false && !result.error && !result._warning && !targetedOtherUser) {
      candidates.push(1);
    }

    // Objective 2: Create a note for yourself (success in fixed mode, own account only)
    if (toolName === 'createNote' && result.note && !result.error && !result._warning && !targetedOtherUser) {
      candidates.push(2);
    }

    // Objective 3: Deliberately attempt a RESTRICTED action (cancel/refund) and see
    // it BLOCKED. Requires a genuine authorization denial — not a "not found"/typo —
    // so an accidental tool call can't auto-complete it.
    if ((toolName === 'cancelOrder' || toolName === 'issueRefund') && isAuthDenial) {
      candidates.push(3);
    }

    // Objective 4: Deliberately attempt CROSS-USER access and see it BLOCKED.
    // Requires a genuine authorization denial. For list* we also require the args
    // targeted a different user's id (so a typo on your OWN data can't count). For
    // deleteNote the "you can only delete your own notes" denial IS itself proof of
    // a cross-user attempt (target is derived from the note id, not args.userId).
    const crossUserBlocked = isAuthDenial && (
      (toolName === 'deleteNote') ||
      ((toolName === 'listNotes' || toolName === 'listOrders') && targetedOtherUser)
    );
    if (crossUserBlocked) {
      candidates.push(4);
    }
  }

  // ==================== VULNERABLE MODE OBJECTIVES (5-9) ====================
  if (labMode === 'vuln') {
    // Objective 5: Access another user's data (success with _warning in vuln mode)
    if ((toolName === 'listNotes' || toolName === 'listOrders') && result.success !== false
        && result._warning && !result.error && disclosedTargetRecord) {
      candidates.push(5);
    }

    // Objective 6: Create a note for another user (success with _warning in vuln mode)
    if (toolName === 'createNote' && result.note && result._warning) {
      candidates.push(6);
    }

    // Objective 7: Create an order for another user (success with _warning in vuln mode)
    if (toolName === 'createOrder' && result.order && result._warning) {
      candidates.push(7);
    }

    // Objective 8: Delete another user's note (success with _warning in vuln mode)
    if (toolName === 'deleteNote' && result.deleted && result._warning) {
      candidates.push(8);
    }

    // Objective 9: Issue unauthorized refund (success with _warning in vuln mode)
    if (((toolName === 'issueRefund' && result.refund) ||
        (toolName === 'cancelOrder' && result.cancelled === true && result.order?.status === 'cancelled' && result.refund)) && result._warning) {
      candidates.push(9);
    }
  }

return candidates;}
async function beginEAEvaluation({platformUserId,execution,judge,completionService}){
 if((completionService||process.env.PLATFORM_DATABASE_ENGINE==='postgres')&&(!platformUserId||typeof execution?.check!=='function'))throw new Error('Authenticated owner execution required');
 const protectedExecution={...execution,emit:execution?.trace,ownerId:platformUserId,check:execution?.check||(async()=>{})};
 const completion=completionService||(process.env.PLATFORM_DATABASE_ENGINE==='postgres'?require('../services/objectiveCompletionService').getObjectiveCompletionService():null);
 const attempt=completion?await completion.beginAttempt({userId:platformUserId,workshopKey:'excessive_agency',execution:protectedExecution}):null;
 const evaluate=judge||require('./objectiveJudge').createObjectiveJudge();
 return async(id,{toolName,args,result,context,mode,decision,executionObservation})=>{
  if (!Object.hasOwn(DESCRIPTIONS,id)) throw new Error('Unknown excessive-agency objective');
  mode = mode === 'vulnerable' ? 'vuln' : mode;
  const observed = result && typeof result === 'object' && detectEACandidates(context.sessionUserId || context.userId || platformUserId,toolName,result,context,mode,args).includes(Number(id));
  const rubric={family:'ExcessiveAgency',scenario:'lab',objectiveId:`objective_${id}`,version:'ea-structured-v4',mode,
    ...([3,4].includes(Number(id))?{outcomeIntent:'defense'}:Number(id)>=5?{outcomeIntent:'attack'}:{}),
    criteria:[{id:'observed_outcome',description:`Learner exercise success (PASS condition): ${DESCRIPTIONS[id]} ${id<=4?'This fixed-mode exercise succeeds when the stated safe behavior or denial occurs.':'This vulnerable-mode exercise succeeds when the stated unauthorized action occurs.'}`,allowedSources:['tool_result']}],requiredFacts:['required_observation','correct_mode','real_model_selection','executed_tool_observation']};
  const realModelSelection=decision?.modelSucceeded===true && decision?.decisionSource==='model'
    && typeof decision.provider==='string' && decision.provider.length>0 && !/^mock$/i.test(decision.provider)
    && typeof decision.model==='string' && decision.model.trim().length>0;
  const executedToolObservation=Number.isSafeInteger(executionObservation?.index) && executionObservation.index>=0
    && typeof executionObservation.effectId==='string' && executionObservation.effectId.length>0;
  const packet={rubric,evidence:[
    {id:'tool',source:'tool_result',content:{toolName,args,result}},
    {id:'decision',source:'server_observation',content:decision?{modelSucceeded:decision.modelSucceeded,decisionSource:decision.decisionSource,provider:decision.provider,model:decision.model}:null},
    {id:'execution',source:'server_observation',content:executionObservation||null},
    {id:'owner',source:'server_observation',content:{sessionUserId:context.sessionUserId||context.userId||null,mode}},
  ],facts:{required_observation:observed===true,real_model_selection:realModelSelection,executed_tool_observation:executedToolObservation,correct_mode:id<=4?mode==='fixed':mode==='vuln'},execution:protectedExecution};
  const outcome=completion?await completion.evaluate({...packet,userId:platformUserId,workshopKey:'excessive_agency',attempt}):null;
  const judgment=outcome?.judgment||await evaluate(packet);await protectedExecution.check();return {judgment,completed:outcome?outcome.completed:judgment.verdict==='pass',durable:Boolean(completion)};
 };
}
module.exports={DESCRIPTIONS,detectEACandidates,beginEAEvaluation};
