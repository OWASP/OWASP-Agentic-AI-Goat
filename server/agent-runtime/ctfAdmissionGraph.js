'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
async function runCtfAdmissionGraph({payload,stage,participant,stageId,sessionToken,ownerId=participant.user_id,lessonReceipt},{classifyTechnique,hashPayload,isNearDuplicate,TECHNIQUE_TAGS,CTFHelpers,atomicIncrementAttempts,runDefenseLayers,execution,languageModel}) {
 let techniqueTag,techniqueConfidence,payloadHash,normalizedSnippet,adaptiveMode,showFeedback,attemptNumber,blockedResponse;
 const done=value=>{blockedResponse=value;return {next:END};};
 const bindLesson=value=>{
   lessonReceipt?.bindAttempt(value);
   const lessonState=lessonReceipt?.project({ownerId,participantId:participant.id,
     stageId,attemptNumber:value});
   return lessonState ? {lessonState} : {};
 };
 const graph=new StateGraph(Annotation.Root({next:Annotation()}))
.addNode('classify_hash',async()=>{
    // 7. Classify technique
    ({ tag: techniqueTag, confidence: techniqueConfidence } = classifyTechnique(payload));

    // 8. Compute payload hash
    ({ hash: payloadHash, normalized: normalizedSnippet } = hashPayload(payload));

    // 9. Adaptive blocklist checks
    adaptiveMode = stage.adaptive_mode || 'none';
    showFeedback = (await CTFHelpers.getConfig('ctf_show_technique_feedback')) === 'true';


return {next:'technique_shield'};
})
.addNode('technique_shield',async()=>{
    // Technique blocklist (per-user, per-stage)
    if (adaptiveMode === 'technique' || adaptiveMode === 'hybrid') {
      if (techniqueTag !== TECHNIQUE_TAGS.OTHER) {
        const isBlocked = await CTFHelpers.istechniqueBlocked(participant.id, stageId, techniqueTag);
        if (isBlocked) {
          const attemptNumber = await atomicIncrementAttempts(participant.id, stageId);
          const blockReason = showFeedback
            ? `Technique "${techniqueTag}" has already been used on this level. Try a different approach.`
            : 'This approach has been blocked. Try something different.';
          await CTFHelpers.logAttempt(participant.id, stageId, attemptNumber, payload, null, false, 0, sessionToken, techniqueTag, techniqueConfidence, true, blockReason, payloadHash);
          lessonReceipt?.observeCategoryReuseBlock();
          return done({ success: false, blocked: true, reason: blockReason, techniqueTag, attemptNumber,
            ...bindLesson(attemptNumber) });
        }
      }
    }


return {next:'payload_shield'};
})
.addNode('payload_shield',async()=>{
    // Payload blocklist (global, per-stage)
    if (adaptiveMode === 'payload' || adaptiveMode === 'hybrid') {
      const blocklistRows = await CTFHelpers.getPayloadBlocklist(stageId);
      const duplicateCheck = isNearDuplicate(payloadHash, normalizedSnippet, blocklistRows);
      if (duplicateCheck.blocked) {
        const attemptNumber = await atomicIncrementAttempts(participant.id, stageId);
        await CTFHelpers.incrementPayloadHitCount(stageId, duplicateCheck.matchedHash);
        const blockReason = showFeedback
          ? `This payload (or a very similar one) has already been used successfully by another participant.`
          : 'This approach has been blocked by the community shield.';
        await CTFHelpers.logAttempt(participant.id, stageId, attemptNumber, payload, null, false, 0, sessionToken, techniqueTag, techniqueConfidence, true, blockReason, payloadHash);
        lessonReceipt?.observeSharedSimilarityBlock();
        return done({ success: false, blocked: true, reason: blockReason, attemptNumber,
          ...bindLesson(attemptNumber) });
      }
    }


return {next:'input_defenses'};
})
.addNode('input_defenses',async()=>{
    // 10. Defense layers (input filters)
    const defenseResult = await runDefenseLayers(stage, payload, { execution, languageModel });
    if (defenseResult.blocked) {
      const attemptNumber = await atomicIncrementAttempts(participant.id, stageId, true);
      const blockReason = stage.feedback_mode === 'silent' ? 'Your input was blocked by the defense system.' : defenseResult.reason;
      await CTFHelpers.logAttempt(participant.id, stageId, attemptNumber, payload, null, false, 0, sessionToken, techniqueTag, techniqueConfidence, true, blockReason, payloadHash);
      lessonReceipt?.observeInputGuard();
      return done({ success: false, blocked: true, reason: blockReason, attemptNumber,
        ...(stage.feedback_mode !== 'silent' && defenseResult.languageDecision
          ? { languageStatus: defenseResult.languageDecision.status } : {}),
        ...bindLesson(attemptNumber) });
    }


return {next:'allocate_attempt'};
})
.addNode('allocate_attempt',async()=>{
    // 11. Call LLM — atomic increment to prevent race conditions
    attemptNumber = await atomicIncrementAttempts(participant.id, stageId);
    lessonReceipt?.bindAttempt(attemptNumber);


return {next:END};
})
.addEdge(START,'classify_hash')
.addConditionalEdges('classify_hash',s=>s.next,['technique_shield',END])
.addConditionalEdges('technique_shield',s=>s.next,['payload_shield',END])
.addConditionalEdges('payload_shield',s=>s.next,['input_defenses',END])
.addConditionalEdges('input_defenses',s=>s.next,['allocate_attempt',END])
.addEdge('allocate_attempt',END).compile();
 await graph.invoke({});return {techniqueTag,techniqueConfidence,payloadHash,normalizedSnippet,adaptiveMode,showFeedback,attemptNumber,blockedResponse};
}
module.exports={runCtfAdmissionGraph};
