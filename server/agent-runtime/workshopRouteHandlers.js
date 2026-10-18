'use strict';

/** Handlers shared by the actual SQL/NoSQL routers; dependencies injectable in tests. */
function createWorkshopRouteHandlers({ agent, store, workshopKey, challengeKey,
  modeService, syncObjectiveComplete, resetWorkshopProgress, detectCompletedObjectives,
  objectiveLabels, clearState, resetMessage, grading, validateSession, legacyFixture=false, logger = console }) {
  grading ||= require('../services/workshopObjectiveGrader').createWorkshopObjectiveGrader({
    workshopKey, syncObjectiveComplete, objectiveLabels, challengeKey,
  });
  const sessionFor=req=>legacyFixture?{check:async()=>{},wrap:execution=>execution}:require('./admittedPlatformSession').createAdmittedPlatformSessionFence(req,{
    validateSession:validateSession||(process.env.PLATFORM_DATABASE_ENGINE==='postgres'?token=>require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token):undefined),
  });
  return {
    async chat(req, res) {
      const { userMessage } = req.body || {};
      const userId = String(req.user.id);
      if (typeof userMessage !== 'string' || !userMessage.trim()) {
        return res.status(400).json({ success: false, message: 'userMessage is required.' });
      }
      const controller = new AbortController();
      const disconnected = () => { if (!res.writableEnded) controller.abort(); };
      req.once('aborted', disconnected);
      res.once('close', disconnected);
      try {
        const fence=sessionFor(req);
        await fence.check();
        const checkPublication=fence.check;
        const mode = await modeService.getMode({ userId: req.user.id, workshopKey });
        let completedObjectives = [], judgments = [], attempt, gradingExecution;
        const result = await agent.invoke(userId, userMessage, mode, {
          signal: controller.signal,
          ...(legacyFixture?{}:{wrapExecution:fence.wrap}),
          includeRunMetadata: true,
          idempotencyKey: req.get?.('Idempotency-Key') || undefined,
          onStart: async execution => {
            gradingExecution = { ...execution, ownerId: userId, emit: execution.trace };
            attempt = await grading.begin(req.user.id, gradingExecution);
          },
          onResult: async (dto, check, _execution, toolInvocation) => {
            const observations=(dto.toolObservations?.length?dto.toolObservations:[dto.toolUsed?{index:0,toolUsed:dto.toolUsed,toolResult:dto.toolResult,invocation:toolInvocation}:null]).filter(Boolean);
            for(const observation of observations){
              await grading.observe?.({userId:req.user.id,result:{...dto,toolUsed:observation.toolUsed,toolResult:observation.toolResult,toolInvocation:observation.invocation},execution:gradingExecution,attempt,observationIndex:observation.index});
            }
            const candidates=[];
            const gradingTargets=observations.length?observations:[{index:0,toolUsed:dto.toolUsed,toolResult:dto.toolResult,invocation:toolInvocation}];
            for(const observation of gradingTargets){
              const params=observation.invocation?.params||{};
              const observedRequest=typeof params.searchTerm==='string'?params.searchTerm:typeof params.query==='string'?params.query:userMessage;
              for(const objectiveId of new Set(detectCompletedObjectives(observedRequest,observation.toolUsed,observation.toolResult,mode)))candidates.push({objectiveId,observation});
            }
            const judgmentIndexes = new Map();
            for (const {objectiveId,observation} of candidates) {
              if (completedObjectives.includes(objectiveId)) continue;
              await check();
              const grade = await grading.evaluate({ userId: req.user.id, objectiveId, message: userMessage,
                result: {...dto,toolUsed:observation.toolUsed,toolResult:observation.toolResult,toolInvocation:observation.invocation}, observationIndex: observation.index, mode, execution: gradingExecution, attempt });
              // Preserve each evaluation in durable history, but return one
              // current summary per objective to existing learner clients.
              if (judgmentIndexes.has(objectiveId)) judgments[judgmentIndexes.get(objectiveId)] = grade.judgment;
              else { judgmentIndexes.set(objectiveId, judgments.length); judgments.push(grade.judgment); }
              if (grade.completed) completedObjectives.push(objectiveId);
              await check();
            }
          },
        });
        await checkPublication();
        res.json({ success: true, ...result, completedObjectives, judgments, mode });
      } catch (error) {
        if (controller.signal.aborted || res.destroyed) return;
        if(error?.code==='GRAPH_RUN_CAPACITY_EXCEEDED')return res.status(503).json({success:false,code:'GRAPH_RUN_CAPACITY_EXCEEDED',message:'Agent capacity is unavailable.'});
        if(error?.code==='SESSION_REVOKED')return res.status(401).json({success:false,message:'Session is no longer current',code:'SESSION_REVOKED'});
        logger.error(`[${workshopKey}] Chat error:`, error);
        const oversized=['WORKSHOP_REQUEST_TOO_LARGE','WORKSHOP_CONTEXT_TOO_LARGE'].includes(error.code);
        const body={success:false,message:error.name === 'AbortError' ? 'Request cancelled or reset. Please try again.'
          : oversized ? 'The request is too large for this workshop model context.' : 'An error occurred while processing your request.'};
        if(oversized)body.code=error.code;
        res.status(error.name === 'AbortError' ? 409 : oversized ? 413 : 500).json(body);
      } finally {
        req.removeListener('aborted', disconnected);
        res.removeListener('close', disconnected);
      }
    },
    async reset(req, res) {
      const userId = String(req.user.id);
      try {
        const fence=sessionFor(req);await fence.check();
        await agent.reset(userId, async execution => {
          const guarded=legacyFixture?{check:async()=>{await execution?.check?.();}}:fence.wrap(execution);
          await guarded.check();await store.clearHistory(userId);await guarded.check();
          await store[clearState](userId);await guarded.check();
          await resetWorkshopProgress(userId, workshopKey);await guarded.check();
        });
        await fence.check();
        res.json({ success: true, message: resetMessage });
      } catch (error) {
        if(error?.code==='GRAPH_RUN_CAPACITY_EXCEEDED')return res.status(503).json({success:false,code:'GRAPH_RUN_CAPACITY_EXCEEDED',message:'Agent capacity is unavailable.'});
        if(error?.code==='SESSION_REVOKED')return res.status(401).json({success:false,message:'Session is no longer current',code:'SESSION_REVOKED'});
        if(error?.name==='AbortError')return res.status(409).json({success:false,message:'Reset was superseded or cancelled.'});
        logger.error(`[${workshopKey}] Reset error:`, error);
        res.status(500).json({ success: false, message: 'Failed to reset.' });
      }
    },
  };
}
module.exports = { createWorkshopRouteHandlers };
