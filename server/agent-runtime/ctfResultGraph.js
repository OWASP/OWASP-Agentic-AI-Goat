'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
async function runCtfResultGraph({wasSuccessful,progress,participant,stageId,payload,techniqueTag,adaptiveMode,payloadHash,normalizedSnippet,stage,attemptNumber,studentResponse,responseTime,sessionToken,techniqueConfidence,showFeedback,ownerId=participant.user_id,lessonReceipt},{CTFHelpers,ctfDb,leaderboardRefresh,TECHNIQUE_TAGS,commit,judgment}) {
 let output,categoryConsumed=false;
 const graph=new StateGraph(Annotation.Root({}))
 .addNode('commit_attempt',async()=>{const result=await commit();wasSuccessful=result.accepted;categoryConsumed=result.categoryConsumed===true;if(result.stale){const error=new Error('CTF stage or progress changed during grading');error.name='AbortError';throw error;}return {};})
.addNode('feedback',async()=>{
    // 16. Return hint availability state (hints now require explicit purchase)
    const hintGating = parseInt(await CTFHelpers.getConfig('ctf_hint_gating_attempts') || '3');
    const hintsAvailable = attemptNumber >= hintGating;

    // Re-read progress to get current hints_used / hint_penalty_total
    const updatedProgress = await CTFHelpers.getProgress(participant.id,stageId);;

    // 17. Get used techniques for feedback
    let usedTechniques = [];
    if ((adaptiveMode === 'technique' || adaptiveMode === 'hybrid') && categoryConsumed) {
      lessonReceipt?.observeCategoryConsumed();
    }
    if (showFeedback && (adaptiveMode === 'technique' || adaptiveMode === 'hybrid')) {
      usedTechniques = await CTFHelpers.getUserTechniques(participant.id, stageId);
    }

    const hintPenalty = updatedProgress?.hint_penalty_total || 0;
    const effectiveScore = Math.max(0, (stage.level_score ?? 100) - hintPenalty);
    const lessonState = lessonReceipt?.project({ownerId,participantId:participant.id,stageId,attemptNumber});

    output = {
      success: wasSuccessful,
      judgment: judgment ? {verdict:judgment.verdict,rubricVersion:judgment.rubricVersion,judgeVersion:judgment.judgeVersion} : undefined,
      aiResponse: studentResponse,
      attemptNumber,
      responseTime,
      techniqueTag: showFeedback ? techniqueTag : undefined,
      blocked: false,
      hintsAvailable,
      hintsUsed: updatedProgress?.hints_used || 0,
      hintPenaltyTotal: hintPenalty,
      usedTechniques: usedTechniques.length > 0 ? usedTechniques.map(t => t.technique_tag) : undefined,
      ...(lessonState ? {lessonState} : {}),
      message: wasSuccessful
        ? `Congratulations! You've completed ${stage.stage_name}! Score: +${effectiveScore}${hintPenalty > 0 ? ` (${hintPenalty} pts deducted for hints)` : ''}`
        : judgment?.verdict === 'unavailable'
          ? 'Grading is temporarily unavailable. Your response was saved, but no completion credit was awarded. Please try again.'
          : judgment?.verdict === 'inconclusive'
            ? 'The Judge could not verify completion from this response. No completion credit was awarded. Please try again.'
            : 'The AI didn\'t reveal the secret. Try a different approach.'
    };

return {};})

 .addEdge(START,'commit_attempt').addEdge('commit_attempt','feedback').addEdge('feedback',END).compile();
 await graph.invoke({});return output;
}
module.exports={runCtfResultGraph};
