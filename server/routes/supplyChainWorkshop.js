/**
 * Supply Chain RCE Lab — API routes
 * Mounts at: /api/workshop/supply-chain
 */

const express = require('express');
const router = express.Router();
const codeBotRuns = require('../agent-runtime/runCoordinator').createRunCoordinator({ family: 'CodeBot' });
const aiService = require('../services/multiProviderAIService');
const supplyStore = require('../database/supplyChainWorkshopDb');
const { runAsync, getAsync, allAsync } = supplyStore;
const logger = require('../utils/contextLogger');
const {
  OBJECTIVES,
  VULNERABLE_SYSTEM_PROMPT,
  FIXED_SYSTEM_PROMPT,
  CODEBOT_TOOL_SCHEMAS,
  executeCodeBotTool,
  detectObjectives,
} = require('../services/supplyChainWorkshopAgent');

const { syncObjectiveComplete, syncWorkshopStarted, checkAndMarkWorkshopComplete, resetWorkshopProgress } = require('../utils/progressSync');
const { authenticateToken } = require('../middleware/adminAuth');
const workshopModeService = require('../services/workshopModeService');
const codeBotSandboxRuntime = require('../services/supplyChain/codeBotSandboxRuntime');
const { createWorkshopModeHandlers } = require('../services/workshopModeHandlers');
const { ownerWorkflowRoute, getOwnerExecution } = require('../agent-runtime/ownerWorkflowRoutes');
const { OwnerWorkflowHttpError } = require('../agent-runtime/ownerWorkflowHttpError');
const codeBotExecutionBoundary = require('../services/supplyChain/codeBotExecutionBoundary').getConfiguredCodeBotExecutionBoundary();
const { getConfiguredCodeBotRequestJournal, requestFingerprint } = require('../agent-runtime/codeBotRequestJournal');
const codeBotRequestJournal = getConfiguredCodeBotRequestJournal();
const codeBotProduction = require('../services/supplyChain/codeBotProduction').getCodeBotProductionActivation();

const SC_OBJECTIVE_IDS = OBJECTIVES.map(o => o.id);
const WORKSHOP_KEY = 'supply_chain_rce';
const modeHandlers = createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY });

function idempotencyKey(request, platformSessionId) {
  const supplied = request.get?.('Idempotency-Key') || request.headers?.['idempotency-key'];
  return require('../services/supplyChain/codeBotProduction').requestKey(supplied, platformSessionId,
    { postgres: process.env.PLATFORM_DATABASE_ENGINE === 'postgres' });
}

function normalizeCodeBotInput(body) {
  if (!body || typeof body.userMessage !== 'string' || !body.userMessage.trim() || Buffer.byteLength(body.userMessage) > 65536) {
    const error = new Error('userMessage must be a non-empty string no larger than 65536 bytes');error.status = 400;throw error;
  }
  const history = body.conversationHistory == null ? [] : body.conversationHistory;
  if (!Array.isArray(history) || history.length > 64 || history.some(item => !item || typeof item.role !== 'string'
      || typeof item.content !== 'string' || Buffer.byteLength(item.role) > 64 || Buffer.byteLength(item.content) > 65536)) {
    const error = new Error('conversationHistory must contain bounded text messages');error.status = 400;throw error;
  }
  return Object.freeze({ userMessage: body.userMessage,
    conversationHistory: Object.freeze(history.slice(-8).map(item => Object.freeze({ role: item.role, content: item.content }))) });
}

async function bindCodeBotSession(req, res, next) {
  try {
    const authority = await codeBotExecutionBoundary.resolveRequest(req);
    req.codeBotRouteScope = Object.freeze({ ownerId: String(authority.platformOwnerId), authority });
    next();
  } catch (error) {
    const status = error.status || (/SESSION|OWNER/.test(error.code || '')
      || ['JsonWebTokenError', 'TokenExpiredError', 'NotBeforeError'].includes(error.name) ? 401 : 503);
    res.status(status).json({ error: status === 400 ? error.message : 'A current CodeBot platform session is required' });
  }
}

function bindCodeBotChat(req, res, next) {
  try {
    const input = normalizeCodeBotInput(req.body);
    const authority = req.codeBotRouteScope.authority;
    const key = idempotencyKey(req, authority.platformSessionId);
    req.codeBotRouteScope = Object.freeze({ ...req.codeBotRouteScope, idempotencyKey: key,
      requestFingerprint: key ? requestFingerprint(input) : null });
    req.codeBotInput = input;next();
  } catch (error) { res.status(error.status || 400).json({ error: error.message }); }
}

const codeBotHttpCoordinator = Object.freeze({
  run(scope, options, execute) { return codeBotRuns.run(scope.ownerId, { ...options, idempotencyKey: scope.idempotencyKey }, execute); },
  reset(scope, execute) { return codeBotRuns.reset(scope.ownerId, execute); },
});
const routeOwner = req => req.codeBotRouteScope;

router.get('/mode', authenticateToken, modeHandlers.get);
router.post('/mode', authenticateToken, modeHandlers.set);

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Some LLMs (Llama 3.1:8b) return tool calls as raw JSON text rather than
 * structured tool_calls. Detect that pattern and return the parsed call.
 * Falls back to regex when JSON is malformed (e.g. unescaped braces in manifest).
 * @param {string} text - LLM response text
 * @param {string} userMessage - Original user message (used to recover params when JSON is malformed)
 */
function tryParseTextToolCall(text, userMessage) {
  if (!text) return null;
  const stripped = text.replace(/^```(?:json)?\s*/m, '').replace(/\s*```$/m, '').trim();

  // Only inspect if this looks like a tool call at all
  const knownTools = ['check_dependencies', 'review_code', 'explain_error'];
  const nameMatch = stripped.match(/"name"\s*:\s*"(check_dependencies|review_code|explain_error)"/);
  if (!nameMatch) return null;

  const toolName = nameMatch[1];

  // Try clean JSON parse first
  try {
    const parsed = JSON.parse(stripped);
    if (typeof parsed.name === 'string' && knownTools.includes(parsed.name) && (parsed.parameters || parsed.arguments)) {
      return { name: parsed.name, params: parsed.parameters || parsed.arguments };
    }
  } catch (e) {
    // Malformed JSON (e.g. LLM put unescaped JSON inside string value)
    // Recover params from the user message for check_dependencies
    if (toolName === 'check_dependencies') {
      const parsedManifest = extractJsonFromMessage(userMessage);
      if (parsedManifest) {
        return { name: toolName, params: { manifest: JSON.stringify(parsedManifest) } };
      }
    }
    // For other tools, return with empty params
    return { name: toolName, params: {} };
  }
  return null;
}



async function ensureObjectives(userId) {
  if(supplyStore.engine==='postgres')return supplyStore.ensureObjectives(userId);
  for (const id of SC_OBJECTIVE_IDS) {
    await runAsync(
      `INSERT OR IGNORE INTO sc_progress (user_id, objective_id, status) VALUES (?, ?, 'pending')`,
      [userId, id]
    );
  }
}

async function getProgress(userId) {
  if(supplyStore.engine==='postgres'){
    const rows=await require('../services/postgresPlatformStores').getPostgresPlatformStores().progress.getUserWorkshopProgress(userId);
    const completed=new Map(rows.filter(row=>row.workshop_key===WORKSHOP_KEY).map(row=>[row.objective_id,row.completed_at]));
    return SC_OBJECTIVE_IDS.map(id=>({objective_id:id,status:completed.has(id)?'completed':'pending',completed_at:completed.get(id)||null}));
  }
  return allAsync(
    `SELECT objective_id, status, completed_at FROM sc_progress WHERE user_id = ?`,
    [userId]
  );
}

async function completeObjective(userId, objectiveId) {
  if(supplyStore.engine==='postgres')return supplyStore.completeObjective(userId,objectiveId);
  const existing = await getAsync(
    `SELECT status FROM sc_progress WHERE user_id = ? AND objective_id = ?`,
    [userId, objectiveId]
  );
  if (!existing) return {changed:false,completed:false};
  if(existing.status==='completed')return {changed:false,completed:true};
  await runAsync(
    `INSERT OR REPLACE INTO sc_progress (user_id, objective_id, status, completed_at) VALUES (?, ?, 'completed', datetime('now'))`,
    [userId, objectiveId]
  );
  return {changed:true,completed:true};
}

function extractJsonFromMessage(message) {
  const jsonMatch = message.match(/(\{[\s\S]*\})/);
  if (!jsonMatch) return null;
  try {
    return JSON.parse(jsonMatch[1]);
  } catch (e) {
    return null;
  }
}

// ── Endpoints ──────────────────────────────────────────────────────────────

// POST /api/workshop/supply-chain/init
router.post('/init', authenticateToken, async (req, res) => {
  const userId = String(req.user.id);
  try {
    await ensureObjectives(userId);
    await syncWorkshopStarted(req.user.id, WORKSHOP_KEY);
    const progress = await getProgress(userId);
    res.json({ success: true, progress });
  } catch (err) {
    logger.error('route_error', { route: 'POST /api/workshop/supply-chain/init', message: err.message });
    console.error('[SC Workshop] Init error:', err);
    res.status(500).json({ error: 'Failed to initialize objectives' });
  }
});

// GET /api/workshop/supply-chain/progress/:userId
router.get('/progress/:userId', authenticateToken, async (req, res) => {
  const userId = String(req.user.id);
  try {
    await ensureObjectives(userId);
    const progress = await getProgress(userId);
    res.json({ success: true, progress });
  } catch (err) {
    logger.error('route_error', { route: 'GET /api/workshop/supply-chain/progress/:userId', message: err.message });
    console.error('[SC Workshop] Progress error:', err);
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// POST /api/workshop/supply-chain/progress/reset
router.post('/progress/reset', authenticateToken, codeBotProduction.requireReady, bindCodeBotSession, ownerWorkflowRoute(codeBotHttpCoordinator, routeOwner, async (req, res) => {
  const userId = String(req.user.id);
  try {
      await req.codeBotRouteScope.authority.assertCurrent();
      await codeBotSandboxRuntime.resetOwnerBeforeProgress(userId, async () => {
        await req.codeBotRouteScope.authority.assertCurrent();
        if(supplyStore.engine==='postgres')await supplyStore.resetUser(userId);
        else await runAsync(`DELETE FROM sc_progress WHERE user_id = ?`, [userId]);
        await req.codeBotRouteScope.authority.assertCurrent();
        await resetWorkshopProgress(req.user.id, WORKSHOP_KEY);
        await req.codeBotRouteScope.authority.assertCurrent();
        await ensureObjectives(userId);
      });
      await req.codeBotRouteScope.authority.assertCurrent();
    const progress = await getProgress(userId);
    res.json({ success: true, progress });
  } catch (err) {
    logger.error('route_error', { route: 'POST /api/workshop/supply-chain/progress/reset', message: err.message });
    console.error('[SC Workshop] Reset error:', err);
    if (/^CODEBOT_PLATFORM_/.test(err.code || '')) throw new OwnerWorkflowHttpError(409, 'The CodeBot platform session is no longer current');
    res.status(err.code === 'CODEBOT_RESET_UNAVAILABLE' ? 503 : 500).json({
      error: err.code === 'CODEBOT_RESET_UNAVAILABLE'
        ? 'The isolated CodeBot lab could not be reset; progress was not changed.'
        : 'Failed to reset progress'
    });
  }
}, { reset: true }));

// GET /api/workshop/supply-chain/llm-status
router.get('/llm-status', async (req, res) => {
  try {
    const aiService = require('../services/multiProviderAIService');
    const info = aiService.getActiveProviderInfo();
    const provider = (info.provider || 'ollama').toLowerCase();

    if (provider === 'bedrock') {
      const verification = await aiService.verifyProviderConnection('bedrock');
      return res.json({
        available: verification.available,
        provider: info.provider,
        providerName: info.providerName,
        model: info.model,
        region: aiService.bedrockRegion,
        message: verification.message
      });
    }

    if (provider !== 'ollama') {
      return res.json({
        available: true,
        provider: info.provider,
        providerName: info.providerName,
        model: info.model,
        message: `${info.providerName || provider} ready (model: ${info.model}).`
      });
    }

    const available = await aiService.checkOllamaAvailable();
    const ollamaUrl = aiService.getOllamaBaseURL
      ? aiService.getOllamaBaseURL()
      : (process.env.OLLAMA_BASE_URL || 'http://localhost:11434');
    let ollamaVersion = null;
    let availableModels = [];
    if (available) {
      try {
        const axios = require('axios');
        const vRes = await axios.get(`${ollamaUrl}/api/version`, { timeout: 3000 });
        ollamaVersion = vRes.data?.version || null;
      } catch (_) {}
      try {
        const axios = require('axios');
        const mRes = await axios.get(`${ollamaUrl}/api/tags`, { timeout: 3000 });
        availableModels = (mRes.data?.models || []).map(m => m.name);
      } catch (_) {}
    }
    return res.json({
      available,
      provider: 'ollama',
      model: info.model,
      ollamaBaseURL: ollamaUrl,
      ollamaVersion,
      availableModels,
      message: available
        ? `Ollama ready at ${ollamaUrl} · v${ollamaVersion || '?'} · model: ${info.model}`
        : `Ollama not reachable at ${ollamaUrl}. Start Ollama and reload.`
    });
  } catch (err) {
    res.json({ available: false, provider: 'unknown', model: null, message: err.message || 'AI service unavailable' });
  }
});

// POST /api/workshop/supply-chain/chat
router.post('/chat', authenticateToken, codeBotProduction.requireConfigured, bindCodeBotSession, bindCodeBotChat, ownerWorkflowRoute(codeBotHttpCoordinator, routeOwner, async (req, res) => {
  const { userMessage, conversationHistory } = req.codeBotInput;
  const userId = String(req.user.id);

  let journalClaim;
  let journalValue;
  try {
    const execution = codeBotExecutionBoundary.bind(req.codeBotRouteScope.authority, getOwnerExecution());
    if (req.codeBotRouteScope.idempotencyKey) {
      journalValue = { ownerKey: execution.ownerKey, requestKey: req.codeBotRouteScope.idempotencyKey,
        fingerprint: req.codeBotRouteScope.requestFingerprint, userId: req.codeBotRouteScope.authority.platformOwnerId,
        platformSessionId: req.codeBotRouteScope.authority.platformSessionId,
        generation: execution.durableGeneration, runId: execution.runId };
      journalClaim = await require('../services/supplyChain/codeBotProduction').admitCodeBotRequest({
        journal: codeBotRequestJournal, value: journalValue, execution, activation: codeBotProduction,
      });
      if (journalClaim.replayed) return res.json(journalClaim.response);
    }
    const payload = await (async () => {
    await execution.check();
    await ensureObjectives(userId);
    await execution.check();
    const mode = await workshopModeService.getMode({ userId: req.user.id, workshopKey: WORKSHOP_KEY });
    const evaluate=await require('../agent-runtime/codeBotJudge').beginCodeBotEvaluation({userId,execution});
    const newlyCompleted = [],judgments=[],projectionPending=[];
    let finalResponse = '';
    let toolResult = null;
    let calledToolName = null;
    let calledParams = null,rawModelResponse='',toolInvocations=[],modelIsReal=false;

    ({ finalResponse, toolResult, calledToolName, calledParams,rawModelResponse,toolInvocations,modelIsReal } = await require('../agent-runtime/codeBotGraph').runCodeBotGraph(
      { userMessage, conversationHistory, mode, userId },
      { aiService, executeCodeBotTool, CODEBOT_TOOL_SCHEMAS, FIXED_SYSTEM_PROMPT, VULNERABLE_SYSTEM_PROMPT,
        tryParseTextToolCall, extractJsonFromMessage, logger, execution }
    ));

    await execution.check();
    // ── Detect and complete objectives ────────────────────────────────────────
    const triggered=new Set(detectObjectives(null,null,null,rawModelResponse,userMessage));
    for(const call of toolInvocations)for(const id of detectObjectives(call.name,call.params,call.result,rawModelResponse,userMessage))triggered.add(id);
    for (const id of triggered) {
      const outcome=await evaluate(id,{userMessage,rawModelResponse,toolInvocations,mode,observed:true,modelIsReal});judgments.push(outcome.judgment);
      await execution.check();if(!outcome.completed)continue;
      const obj=OBJECTIVES.find(o=>o.id===id);
      if(!outcome.durable)await syncObjectiveComplete(req.user.id,WORKSHOP_KEY,id,obj?.label||id);
      // Canonical acceptance is authoritative; a failed projection must not ask the learner to replay a mutating tool.
      try{const completed=await completeObjective(userId,id);if(completed.completed)newlyCompleted.push(id);}
      catch(error){projectionPending.push(id);newlyCompleted.push(id);logger.error('progress_projection_pending',{workshop:'supply_chain',userId,objectiveId:id,message:error.message});}
    }
    await checkAndMarkWorkshopComplete(req.user.id, WORKSHOP_KEY, OBJECTIVES.length);

    logger.info('chat_request', { workshop: 'supply_chain', userId, mode, promptLength: userMessage.length, toolsCalled: calledToolName ? [calledToolName] : [], objectivesCompleted: newlyCompleted });
    return { success: true, response: finalResponse, toolCalls: [], newlyCompletedObjectives: newlyCompleted, judgments,projectionPending,run:{runId:execution.runId},mode };

    })();
    if (journalClaim && !journalClaim.replayed) {
      await execution.check();await codeBotRequestJournal.complete(journalValue, payload);await execution.check();
    }
    return res.json(payload);
  } catch (err) {
    if (journalClaim && !journalClaim.replayed && journalValue) {
      try { await codeBotRequestJournal.markUncertain(journalValue); } catch (journalError) { err.journalError = journalError; }
    }
    const bindingError=require('../agent-runtime/codeBotManifestBinding').bindingErrorResponse(err);
    if(bindingError)throw new OwnerWorkflowHttpError(bindingError.status,bindingError.body.error);
    if(/^CODEBOT_REQUEST_(?:FINGERPRINT|SESSION|GENERATION|INCOMPLETE)/.test(err.code||''))throw new OwnerWorkflowHttpError(409,err.message);
    if(/^CODEBOT_REQUEST_(?:JOURNAL_UNAVAILABLE|ADMISSION_REJECTED|COMPLETION_REJECTED)/.test(err.code||''))throw new OwnerWorkflowHttpError(503,'CodeBot request replay storage is unavailable');
    if(err.code==='CODEBOT_RUNNER_UNAVAILABLE')throw new OwnerWorkflowHttpError(503,'The isolated CodeBot workshop is unavailable. No model or tool was run.');
    if(err.code==='GRAPH_EFFECT_REPLAY_BLOCKED')throw new OwnerWorkflowHttpError(409,'This CodeBot effect was already attempted; submit a new request identifier to retry explicitly');
    logger.error('route_error', { route: 'POST /api/workshop/supply-chain/chat', message: err.message });
    console.error('[SC Workshop] Chat error:', err);
    if(err.name==='AbortError')throw err;
    throw new OwnerWorkflowHttpError(500,'Internal server error');
  }
}));

router.resetOwner=(owner,work)=>codeBotRuns.reset(owner,work);
module.exports = router;
