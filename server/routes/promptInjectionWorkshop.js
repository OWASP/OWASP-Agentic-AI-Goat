/**
 * Prompt Injection Workshop API
 * Live Llama AWS Assistant with database-configured objectives.
 */

const express = require('express');
const defaultWorkshopService = require('../services/promptInjectionWorkshop');
const defaultAiService = require('../services/multiProviderAIService');
const defaultLogger = require('../utils/contextLogger');
const { WORKSHOP_OBJECTIVES } = require('../config/workshopCatalog');
const { createDefaultPromptInjectionProgressService } = require('../services/promptInjectionProgressService');
const { getPromptInjectionProviderStatus } = require('../services/promptInjectionStatusService');
const defaultDpiRuns = require('../agent-runtime/runCoordinator').createRunCoordinator({ family: 'DPI', defaultTimeoutMs: 300000 });

const OBJECTIVE_LABELS = Object.fromEntries(
  WORKSHOP_OBJECTIVES.direct_prompt_injection.map(({ id, text }) => [id, text])
);

function getAuthenticatedUserId(req) {
  const rawUserId = req.user?.id;
  const userId = Number(rawUserId);
  return Number.isInteger(userId) && userId > 0 ? userId : null;
}

function sendProgressError(res, error, fallbackMessage) {
  const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 500;
  return res.status(statusCode).json({
    success: false,
    error: statusCode < 500 ? error.message : fallbackMessage,
    ...(error.field ? { field: error.field } : {}),
    ...(error.code ? { code: error.code } : {}),
  });
}

async function awaitProgressInitialization(progressReady) {
  const state = await progressReady;
  if (state?.error) throw state.error;
}

function createPromptInjectionWorkshopRouter({
  workshopService = defaultWorkshopService,
  aiService = defaultAiService,
  logger = defaultLogger,
  progressService,
  progressReady,
  completionService,
  modeService = require('../services/workshopModeService'),
  validateSession,
  legacyFixture = false,
  runCoordinator = require('../agent-runtime/runCoordinator').createRunCoordinator({ family: 'DPI', defaultTimeoutMs: 300000 }),
} = {}) {
  if (!progressService) progressService = createDefaultPromptInjectionProgressService();
  if (!progressReady) progressReady = Promise.resolve({ error: null });
  const router = express.Router();
  const dpiRuns = runCoordinator;
  const modeConfig=require('../services/workshopModeService').WORKSHOP_MODE_CATALOG.direct_prompt_injection;
  const modeReply=mode=>({
    ...require('../services/workshopModeCapability').projectWorkshopModeCapability('direct_prompt_injection',mode),
    fixedObjectiveIds:modeConfig.fixedObjectiveIds,
    fixedQualification:require('../agent-runtime/dpiFixedQualification'),
  });
  router.get('/mode',async(req,res)=>{const userId=getAuthenticatedUserId(req);if(!userId)return res.status(401).json({error:'Authentication required'});if(Object.keys(req.query).length)return res.status(400).json({error:'Mode accepts no owner filters'});try{res.set('Cache-Control','no-store');res.json(modeReply(await modeService.getMode({userId,workshopKey:'direct_prompt_injection'})));}catch(error){sendProgressError(res,error,'Mode unavailable');}});
  router.post('/mode',async(req,res)=>{const userId=getAuthenticatedUserId(req);if(!userId)return res.status(401).json({error:'Authentication required'});if(Object.keys(req.query).length||!req.body||Array.isArray(req.body)||Object.keys(req.body).join(',')!=='mode'||!modeConfig.allowedModes.includes(req.body.mode))return res.status(400).json({error:'A supported mode is required'});try{res.json(modeReply(await modeService.setMode({userId,workshopKey:'direct_prompt_injection',mode:req.body.mode})));}catch(error){sendProgressError(res,error,'Mode unavailable');}});


// Debug: log every request that reaches this router (path is relative to mount /api/workshop/prompt-injection)
router.use((req, res, next) => {
  console.log('[PromptInjection API]', req.method, req.originalUrl, '| path:', req.path);
  next();
});

/**
 * GET /api/workshop/prompt-injection/health
 * Verify API reachability and configured provider health.
 */
router.get('/health', async (req, res) => {
  try {
    const providerStatus = await getPromptInjectionProviderStatus(aiService);
    return res.json({
      ok: true,
      api: 'prompt-injection',
      message: 'Prompt Injection Workshop API is running',
      providerStatus,
    });
  } catch (e) {
    const info = aiService.getActiveProviderInfo?.() || {};
    return res.json({
      ok: true,
      api: 'prompt-injection',
      message: 'Prompt Injection Workshop API is running',
      providerStatus: {
        available: false,
        provider: info.provider || 'unknown',
        providerName: info.providerName || 'AI provider',
        model: info.model || null,
        message: e.message || 'Provider health check failed',
        error: e.message || null,
      },
    });
  }
});

/**
 * GET /api/workshop/prompt-injection/llm-status
 * Check if the configured AI provider is available for the workshop.
 */
router.get('/llm-status', async (req, res) => {
  try {
    return res.json(await getPromptInjectionProviderStatus(aiService));
  } catch (err) {
    const info = aiService.getActiveProviderInfo?.() || {};
    res.json({
      available: false,
      provider: info.provider || 'unknown',
      providerName: info.providerName || 'AI provider',
      model: info.model || null,
      message: err.message || 'AI service unavailable'
    });
  }
});

/**
 * POST /api/workshop/prompt-injection/chat
 * Send user message to Llama with conversation history; get response and optional completed objective.
 * Body: { userMessage: string, conversationHistory: [{ type: 'user'|'ai', content: string }], completedObjectives: { [objectiveId]: true } }
 */
router.post('/chat', async (req, res) => {
  console.log('[PromptInjection API] POST /chat hit');
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: 'An authenticated user is required',
        field: 'userId',
        code: 'AUTH_REQUIRED',
      });
    }
    const validator=validateSession||(token=>require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token));
    const sessionFence=legacyFixture===true?{check:async()=>{},wrap:e=>e}:require('../agent-runtime/admittedPlatformSession').createAdmittedPlatformSessionFence(req,{validateSession:validator});
    const sessionCheck=sessionFence.check;
    await sessionCheck();
    const { userMessage, conversationHistory = [], completedObjectives = {}, activeObjectiveId = 'interact' } = req.body;

    if (!userMessage || typeof userMessage !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'userMessage is required and must be a string'
      });
    }

    const payload = await dpiRuns.run(userId, {}, async execution => {
    await awaitProgressInitialization(progressReady);
    await progressService.assertObjectiveEnabled(activeObjectiveId);
    const gradingExecution = {...sessionFence.wrap(execution),ownerId:userId,emit:execution.trace};
    const durableCompletion = completionService || require('../services/objectiveCompletionService').getObjectiveCompletionService();
    const attempt = durableCompletion ? await durableCompletion.beginAttempt({
      userId, workshopKey: 'direct_prompt_injection', objectiveId: activeObjectiveId,
      execution: gradingExecution,
    }) : null;
    const result = await workshopService.chat(
      userMessage.trim(),
      Array.isArray(conversationHistory) ? conversationHistory : [],
      typeof completedObjectives === 'object' ? completedObjectives : {},
      activeObjectiveId,
      {execution:gradingExecution,completionService:durableCompletion,attempt,userId}
    );

    await gradingExecution.check();
    const userKey = String(userId);
    let progress;
    if (result.durableGrading) {
      // The accepted receipt already updated the canonical objective or the
      // first practice-interaction counter in the same generation-fenced
      // transaction. Local progress is only read back here.
      progress = await progressService.getProgress({ userId, userKey });
    } else if (result.validInteraction && activeObjectiveId === 'interact') {
      progress = await progressService.recordValidInteraction({ userId, userKey });
    } else if (result.completedObjectiveId) {
      progress = await progressService.completeObjective({
        userId,
        userKey,
        objectiveId: result.completedObjectiveId,
        label: OBJECTIVE_LABELS[result.completedObjectiveId],
      });
    } else {
      progress = await progressService.getProgress({ userId, userKey });
    }

    return {
      success: true,
      response: result.response,
      ...(result.selectedLesson ? {selectedLesson: require('../agent-runtime/dpiPolicyContract').admitSelectedLesson(result.selectedLesson, activeObjectiveId, attempt?.mode)} : {}),
      ...(result.publication ? {publication:result.publication} : {}),
      model: result.model,
      provider: result.provider,
      judgment: result.judgment,
      completedObjectiveId: result.completedObjectiveId || null,
      validInteraction: result.validInteraction || false,
      progress,
    };
    });
    await sessionCheck();
    res.json(payload);
  } catch (err) {
    if (err.code === 'GRAPH_RUN_CAPACITY_EXCEEDED') return res.status(503).json({success:false,code:'GRAPH_RUN_CAPACITY_EXCEEDED',error:'Agent capacity is unavailable.',response:null,completedObjectiveId:null});
    if (err.name === 'AbortError' || err.code === 'AGENT_RUN_CANCELLED') {
      return res.status(409).json({ success: false, code: 'AGENT_RUN_CANCELLED', error: 'Agent run was cancelled.', response: null, completedObjectiveId: null });
    }
    if (err.statusCode) return sendProgressError(res, err, 'Failed to save progress');
    const info = aiService.getActiveProviderInfo?.() || {};
    const provider = String(info.provider || process.env.AI_PROVIDER || 'unknown').toLowerCase();
    logger.error('prompt_injection_llm_error', { provider, error: err.message });
    const isProviderTimeout = err.name === 'TimeoutError' || err.code === 'ETIMEDOUT'
      || /\btimeout\b|\btimed out\b/i.test(err.message || '');
    if (isProviderTimeout) {
      return res.status(504).json({
        success: false,
        code: 'AI_PROVIDER_TIMEOUT',
        error: 'The model did not finish within the request deadline. Check inference speed and server logs before retrying.',
        provider: info.provider || provider,
        providerName: info.providerName || 'AI provider',
        response: null,
        completedObjectiveId: null
      });
    }
    const isOllamaUnavailable = provider === 'ollama' && err.message && (
      err.message.includes('Ollama') ||
      err.message.includes('ECONNREFUSED') ||
      err.message.includes('ENOTFOUND')
    );
    const ollamaUrl = provider === 'ollama'
      ? (aiService.getOllamaBaseURL ? aiService.getOllamaBaseURL() : (process.env.OLLAMA_BASE_URL || 'http://localhost:11434'))
      : undefined;
    const hint = isOllamaUnavailable
      ? ` Ensure Ollama is running (ollama serve) and reachable at ${ollamaUrl}. Set OLLAMA_BASE_URL in .env if Ollama runs elsewhere.`
      : '';
    res.status(isOllamaUnavailable ? 503 : 500).json({
      success: false,
      error: (err.message || 'Chat failed') + hint,
      provider: info.provider || provider,
      providerName: info.providerName || 'AI provider',
      ...(ollamaUrl ? { ollamaBaseURL: ollamaUrl } : {}),
      response: null,
      completedObjectiveId: null
    });
  }
});

/**
 * GET /api/workshop/prompt-injection/progress
 * Load persisted progress for the currently enabled catalog objectives.
 * Progress is stored under the authenticated user's numeric key.
 */
router.get('/progress', async (req, res) => {
  const userId = getAuthenticatedUserId(req);
  if (!userId) {
    return res.status(401).json({
      success: false,
      error: 'An authenticated user is required',
      field: 'userId',
      code: 'AUTH_REQUIRED',
    });
  }
  try {
    await awaitProgressInitialization(progressReady);
    const progress = await progressService.getProgress({ userId, userKey: String(userId) });
    return res.json({ success: true, ...progress });
  } catch (error) {
    return sendProgressError(res, error, 'Failed to load progress');
  }
});

/**
 * POST /api/workshop/prompt-injection/progress/complete
 * Mark an objective as completed. Stored by user_key for per-user isolation.
 */
router.post('/progress/complete', (_req, res) => {
  res.status(410).json({
    success: false,
    error: 'Objective completion is recorded by the authenticated chat endpoint.',
    code: 'CLIENT_PROGRESS_MUTATION_RETIRED',
  });
});

/**
 * POST /api/workshop/prompt-injection/progress/interaction
 * Increment interaction count for practice objective (interact). If count >= 2, mark completed.
 */
router.post('/progress/interaction', (_req, res) => {
  res.status(410).json({
    success: false,
    error: 'Practice interactions are recorded by the authenticated chat endpoint.',
    code: 'CLIENT_PROGRESS_MUTATION_RETIRED',
  });
});

/**
 * POST /api/workshop/prompt-injection/progress/reset
 * Delete progress for the current user only. Only the owning user or an admin may reset.
 */
router.post('/progress/reset', async (req, res) => {
  const userId = getAuthenticatedUserId(req);
  if (!userId) {
    return res.status(401).json({
      success: false,
      error: 'An authenticated user is required',
      field: 'userId',
      code: 'AUTH_REQUIRED',
    });
  }
  try {
    const validator=validateSession||(token=>require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token));
    const sessionFence=legacyFixture===true?{check:async()=>{}}:require('../agent-runtime/admittedPlatformSession').createAdmittedPlatformSessionFence(req,{validateSession:validator});
    await sessionFence.check();
    await awaitProgressInitialization(progressReady);
    let progress;
    await dpiRuns.reset(userId, async () => {
      await sessionFence.check();
      progress = await progressService.resetProgress({ userId, userKey: String(userId) });
    });
    return res.json({ success: true, progress });
  } catch (error) {
    logger.error('prompt_injection_progress_reset_error', { error: error.message });
    return sendProgressError(res, error, 'Failed to reset progress');
  }
});

/**
 * POST /api/workshop/prompt-injection/reset
 * No server-side session; client resets locally. This endpoint exists for parity.
 */
router.post('/reset', (req, res) => {
  res.json({ success: true, message: 'Reset is handled on the client. Send a new conversationHistory to start fresh.' });
});

// If no route matched (e.g. wrong method or path), return 404 with debug info so we can tell route vs Ollama
router.all(/.*/, (req, res) => {
  console.warn('[PromptInjection API] No route matched:', req.method, req.path);
  res.status(404).json({
    error: 'Prompt injection workshop route not found',
    method: req.method,
    path: req.path,
    hint: 'Expected POST /chat. Check that the request URL is exactly /api/workshop/prompt-injection/chat and the server was restarted after code changes.'
  });
});

  return router;
}

const router = createPromptInjectionWorkshopRouter({ runCoordinator: defaultDpiRuns });
module.exports = router;
module.exports.createPromptInjectionWorkshopRouter = createPromptInjectionWorkshopRouter;
module.exports.resetOwner = (owner, work) => defaultDpiRuns.reset(owner, work);
