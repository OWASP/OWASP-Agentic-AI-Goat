'use strict';

const express = require('express');
const router  = express.Router();
const store = require('../database/sensitiveInfoWorkshopDb');
const { SensitiveInfoWorkshopAgent, OBJECTIVES,
  createSensitiveInfoWorkshopStateStore, getConfiguredSsrfExamples } = require('../services/sensitiveInfoWorkshopAgent');
const { authenticateToken } = require('../middleware/adminAuth');
const workshopModeService = require('../services/workshopModeService');
const { createWorkshopModeHandlers } = require('../services/workshopModeHandlers');
const { projectCanonicalSensitiveProgress } = require('../services/sensitiveInfoProgressProjection');
const { readSensitiveInfoPresentation } = require('../services/sensitiveInfoPresentation');
const { assertFinflowRequest } = require('../agent-runtime/finflowDecisions');

const logger = require('../utils/contextLogger');
const { syncObjectiveComplete, syncWorkshopStarted, checkAndMarkWorkshopComplete, resetWorkshopProgress } = require('../utils/progressSync');

const { createConfiguredFinflowTraversalManager } = require('../services/sensitiveInfoResetComposition');
const createRouteTraversalManager = getComposition => createConfiguredFinflowTraversalManager(
  getComposition ? { getComposition } : undefined);
const configuredTraversalManager = createRouteTraversalManager();
const configuredDurableResources = require('../services/finflowAgentResourceComposition')
  .configuredFinflowAgentResources();
const sensitiveStateStore = createSensitiveInfoWorkshopStateStore({
  traversalManager: configuredTraversalManager,
  durableResources: configuredDurableResources,
});
const agent = new SensitiveInfoWorkshopAgent({ stateStore: sensitiveStateStore });
const WORKSHOP_KEY = 'sensitive_info_disclosure';
const modeHandlers = createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY });
const admitObjective = async objectiveId => {
  try {
    return await require('../services/finflowObjectiveAdmission').createWorkshopObjectiveAdmission({
      pool: require('../services/postgresPlatformStores').getPostgresPlatformStores().pool,
    }).admit(objectiveId);
  } catch (error) {
    if (['BAD_REQUEST','NOT_FOUND','EXERCISE_UNAVAILABLE','OBJECTIVE_DISABLED','EXERCISE_AVAILABILITY_UNAVAILABLE'].includes(error.code)) throw error;
    throw Object.assign(new Error('Exercise availability is temporarily unavailable'),
      { code: 'EXERCISE_AVAILABILITY_UNAVAILABLE', statusCode: 503 });
  }
};

function invalidChatRequest(message) {
  const error = new Error(message);
  error.code = 'BAD_REQUEST';
  error.statusCode = 400;
  return error;
}

// Keep the learner's prompt byte-for-byte intact. This boundary only rejects
// shapes that would otherwise reach the graph and fail as a 500 (or be read
// ambiguously by a model); it does not trim or sanitize teaching payloads.
function validateSensitiveInfoChatBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw invalidChatRequest('Request body must be an object');
  }
  const { userMessage, conversationHistory = [] } = body;
  if (typeof userMessage !== 'string' || userMessage.length === 0 || !/\S/u.test(userMessage)) {
    throw invalidChatRequest('userMessage must be a non-blank string');
  }
  try {
    assertFinflowRequest(userMessage);
  } catch (error) {
    error.code = 'BAD_REQUEST';
    error.statusCode = 400;
    throw error;
  }
  if (!Array.isArray(conversationHistory)) {
    throw invalidChatRequest('conversationHistory must be an array');
  }
  for (const item of conversationHistory) {
    if (!item || typeof item !== 'object' || Array.isArray(item)
      || !['user', 'assistant'].includes(item.role) || typeof item.content !== 'string') {
      throw invalidChatRequest('conversationHistory entries must contain a user or assistant role and string content');
    }
  }
  return { userMessage, conversationHistory };
}

function sendAvailabilityError(res, error) {
  const statuses = { NOT_FOUND: 404, EXERCISE_UNAVAILABLE: 403,
    EXERCISE_AVAILABILITY_UNAVAILABLE: 503 };
  const status = statuses[error?.code];
  if (!status) return false;
  res.status(status).json({ error: 'Exercise unavailable', code: error.code });
  return true;
}

router.get('/mode', authenticateToken, modeHandlers.get);
router.post('/mode', authenticateToken, modeHandlers.set);


// ============================================================
// LLM Status
// ============================================================
router.get('/llm-status', async (_req, res) => {
  const { getFinflowProviderStatus } = require('../services/finflowProviderStatus');
  const aiService = require('../services/multiProviderAIService');
  res.json(await getFinflowProviderStatus(aiService));
});

// ============================================================
// Init — initialize user state and return enabled objectives
// ============================================================
router.post('/init', authenticateToken, async (req, res) => {
  try {
    const userId = String(req.user.id);
    await admitObjective();

    await configuredDurableResources.assertReady();
    await store.ensureObjectives(userId);

    await syncWorkshopStarted(req.user.id, WORKSHOP_KEY);
    let objectives = OBJECTIVES;
    let ssrfExamples = Object.create(null);
    if (store.engine === 'postgres') {
      const presentation = await readSensitiveInfoPresentation({
        platformStores: require('../services/postgresPlatformStores').getPostgresPlatformStores(),
        userId: req.user.id, workshopKey: WORKSHOP_KEY, objectives: OBJECTIVES,
        getSsrfExamples: getConfiguredSsrfExamples,
      });
      objectives = presentation.progress
        .map(({ completed, completed_at, ...objective }) => objective);
      ssrfExamples = presentation.ssrfExamples;
    }
    await admitObjective();
    res.json({ success: true, objectives, ssrfExamples });
  } catch (err) {
    if (sendAvailabilityError(res, err)) return;
    console.error('[SensitiveInfo] Init error:', err);
    res.status(500).json({ error: 'Init failed' });
  }
});

// ============================================================
// Chat — main endpoint
// ============================================================
router.post('/chat', authenticateToken, async (req, res) => {
  try {
    const { userMessage, conversationHistory } = validateSensitiveInfoChatBody(req.body);
    const { objectiveId } = req.body;
    const userId = String(req.user.id);
    const sessionFence=require('../agent-runtime/admittedPlatformSession').createAdmittedPlatformSessionFence(req,{validateSession:token=>require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token)});
    await sessionFence.check();
    if (!userMessage) return res.status(400).json({ error: 'userMessage required' });

    const admission = await admitObjective(objectiveId);
    const selectedObjectiveId = admission.generalChat ? undefined : admission.objectiveId;
    const payload = await agent.runUserExclusive(userId, async (requestState,execution) => {
      execution=sessionFence.wrap(execution);
      await execution.check();
      await admitObjective(selectedObjectiveId);
      const mode = await workshopModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
      await execution.check();
      const result = await agent.processMessage(
        userMessage, conversationHistory, mode, selectedObjectiveId, userId, requestState,{execution});

      // Persist completed objectives — upsert pattern.
      // Hard guard: objectives can ONLY be earned in vulnerable mode. Fixed mode is
      // the hardened variant where every attack is blocked, so nothing must complete
      // there even if a detector upstream misfires on a refusal's wording.
      const earnedIds = mode === 'vulnerable' ? (result.completedObjectiveIds || []) : [];
      const newlyCompleted = [];
      for (const objId of earnedIds) {
        await execution.check();
        const updated = await store.completeObjective(userId,objId);
        if (updated && updated.changes > 0) {
          newlyCompleted.push(objId);
          logger.info('objective_completed', { workshop: 'sensitive_info', userId, objectiveId: objId, mode });
          const obj = OBJECTIVES.find(o => o.id === objId);
          if (!result.durableGrading) await syncObjectiveComplete(req.user.id, WORKSHOP_KEY, objId, obj?.label || objId, obj?.category || '');
        }
      }
      await execution.check();
      await checkAndMarkWorkshopComplete(req.user.id, WORKSHOP_KEY, OBJECTIVES.length);
      await execution.check();

      // Log tool calls
      for (const tc of (result.toolCalls || [])) {
        await execution.check();
        await store.logToolCall(userId,{...tc,mode});
      }

      logger.info('chat_request', { workshop: 'sensitive_info', userId, mode, promptLength: userMessage.length, toolsCalled: (result.toolCalls || []).map(tc => tc.name), objectivesCompleted: newlyCompleted });
      return {
        success: result.success,
        response: result.response,
        toolCalls: result.toolCalls,
        newlyCompletedObjectives: newlyCompleted,
        judgments: result.judgments || [],
        run:result.run,
        mode
      };
    });
    await sessionFence.check();
    res.json(payload);
  } catch (err) {
    if(err.code==='GRAPH_RUN_CAPACITY_EXCEEDED')return res.status(503).json({error:'Agent capacity is unavailable.',code:'GRAPH_RUN_CAPACITY_EXCEEDED'});
    if(err.code==='SESSION_REVOKED')return res.status(401).json({error:'Session is no longer current',code:'SESSION_REVOKED'});
    logger.error('route_error', { route: 'POST /api/workshop/sensitive-info/chat', message: err.message });
    console.error('[SensitiveInfo] Chat error:', err);
    const admissionStatus = ['BAD_REQUEST','NOT_FOUND','EXERCISE_UNAVAILABLE','OBJECTIVE_DISABLED','EXERCISE_AVAILABILITY_UNAVAILABLE'].includes(err.code) ? err.statusCode : null;
    res.status(admissionStatus || (err.name === 'AbortError' ? 409 : 500)).json({ error: 'Chat failed', message: err.message, ...(admissionStatus ? { code: err.code } : {}) });
  }
});

// ============================================================
// Progress — get user progress
// ============================================================
router.get('/progress/:userId', authenticateToken, async (req, res) => {
  try {
    await admitObjective();
    const userId = String(req.user.id);
    if (store.engine === 'postgres') {
      const presentation = await readSensitiveInfoPresentation({
        platformStores: require('../services/postgresPlatformStores').getPostgresPlatformStores(),
        userId: req.user.id, workshopKey: WORKSHOP_KEY, objectives: OBJECTIVES,
        getSsrfExamples: getConfiguredSsrfExamples,
      });
      await admitObjective();
      return res.json(presentation);
    }
    const rows = await store.getProgress(userId);

    // Map to objectives list with completed flag
    const progressMap = {};
    for (const row of rows) progressMap[row.objective_id] = { completed: !!row.completed, completed_at: row.completed_at };

    const progress = OBJECTIVES.map(obj => ({
      ...obj,
      completed: !!(progressMap[obj.id] && progressMap[obj.id].completed),
      completed_at: progressMap[obj.id] ? progressMap[obj.id].completed_at : null
    }));

    const completedCount = progress.filter(p => p.completed).length;

    res.json({ success: true, progress, completedCount, total: OBJECTIVES.length });
  } catch (err) {
    if (sendAvailabilityError(res, err)) return;
    console.error('[SensitiveInfo] Progress error:', err);
    res.status(500).json({ error: 'Progress fetch failed' });
  }
});

// ============================================================
// Reset — wipe progress for user
// ============================================================
router.post('/progress/reset', authenticateToken, async (req, res) => {
  try {
    const userId = String(req.user.id);
    const aggregate = await require('../services/sensitiveInfoResetComposition').getSensitiveInfoResetComposition();
    let resetResult;
    if (aggregate) resetResult=await aggregate.reset.reset(req.user.id,
      {operationId:req.get('x-reset-operation-id')||undefined});
    else if (store.engine === 'postgres') {
      const unavailable = new Error('Canonical Sensitive Information reset is disabled for maintenance');
      unavailable.code = 'RESET_STORAGE_NOT_READY';
      throw unavailable;
    } else await agent.resetUserExclusive(userId, async () => {
      await store.resetUser(userId);
      await resetWorkshopProgress(req.user.id, WORKSHOP_KEY);
      await store.ensureObjectives(userId);

      // This lock covers durable reset work and state invalidation as one
      // same-user ordering unit. A failed durable reset keeps simulator state.
      sensitiveStateStore.resetUser(userId);
    });

    res.json({ success: true, message: 'Progress reset', ...(resetResult ? {reset:{
      operationId:resetResult.operationId,fromGeneration:resetResult.fromGeneration,
      toGeneration:resetResult.toGeneration,status:resetResult.status}} : {}) });
  } catch (err) {
    if(err.code==='GRAPH_RUN_CAPACITY_EXCEEDED')return res.status(503).json({error:'Agent capacity is unavailable.',code:'GRAPH_RUN_CAPACITY_EXCEEDED'});
    console.error('[SensitiveInfo] Reset error:', err);
    const unavailable=err?.code==='RESET_STORAGE_NOT_READY';
    const invalid=err instanceof TypeError;
    const conflict=err?.name==='AbortError'||['SENSITIVE_INFO_RESET_BUSY','SENSITIVE_INFO_RESET_SCOPE_MISMATCH'].includes(err?.code);
    res.status(unavailable?503:invalid?400:conflict?409:500).json({ error: unavailable
      ?'Canonical Sensitive Information reset is not ready':'Reset failed',
      ...(unavailable?{unavailable:true}:{}) });
  }
});

router.resetOwner=(owner,work)=>agent.resetUserExclusive(String(owner),async()=>{
  await work();
  sensitiveStateStore.resetUser(String(owner));
});
if (process.env.EXPORT_INTERNALS === '1') {
  router.configuredTraversalManager = configuredTraversalManager;
  router.createRouteTraversalManager = createRouteTraversalManager;
}
router.validateSensitiveInfoChatBody = validateSensitiveInfoChatBody;
module.exports = router;
