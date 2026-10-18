'use strict';
const express = require('express');
const router = express.Router();
const novaAgent = require('../services/novaAgentService');
const db = require('../database/nosqlWorkshopDb');
const { authenticateToken } = require('../middleware/adminAuth');
const workshopModeService = require('../services/workshopModeService');
const { createWorkshopModeHandlers } = require('../services/workshopModeHandlers');
const { createWorkshopConfigService } = require('../services/workshopConfigService');
const { syncObjectiveComplete, resetWorkshopProgress } = require('../utils/progressSync');

const OBJECTIVE_LABELS = {
  nosqli_1:  'Trigger NoSQL Error',
  nosqli_2:  'Boolean Operator Bypass ($gt)',
  nosqli_3:  'Regex Wildcard Injection ($regex)',
  nosqli_4:  'Database Version Extraction',
  nosqli_5:  'Collection Schema Extraction',
  nosqli_6:  'Not-Equal Operator Bypass ($ne)',
  nosqli_7:  'Where Clause Injection ($where)',
  nosqli_8:  'Array Query Injection ($in)',
  nosqli_9:  'Extract Author Contact Data',
  nosqli_10: 'Extract Restricted Research Data',
};

// ── Helpers ───────────────────────────────────────────────────────────────────

const WORKSHOP_KEY = 'nosql_injection_workshop';
const modeHandlers = createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY });
const workshopConfig = createWorkshopConfigService();

function getUserKey(req) { return String(req.user.id); }

// ── Objective detection ────────────────────────────────────────────────────────

function detectCompletedObjectives(userMessage, toolUsed, toolResult, mode = 'fixed') {
  if (mode !== 'vuln') return [];
  if (toolUsed !== 'search_papers') return [];

  const msg = userMessage;
  const isErr = toolResult && toolResult.error;
  const isArr = Array.isArray(toolResult);
  const completed = [];

  // nosqli_1: NoSQL error triggered by malformed operator
  if (isErr) completed.push('nosqli_1');

  // nosqli_2: $gt operator bypass returned results
  if (/\$gt/i.test(msg) && isArr) completed.push('nosqli_2');

  // nosqli_3: $regex wildcard injection returned results
  if (/\$regex/i.test(msg) && isArr) completed.push('nosqli_3');

  // nosqli_4: Database version extraction via $where db.version()
  if (/db\.version|buildInfo|serverStatus/i.test(msg) && isArr) completed.push('nosqli_4');

  // nosqli_5: Schema/field extraction via $where Object.keys(this)
  if (/Object\.keys|keys\(this\)|schema.*extract/i.test(msg) && isArr) completed.push('nosqli_5');

  // nosqli_6: $ne operator bypass
  if (/\$ne/i.test(msg) && isArr) completed.push('nosqli_6');

  // nosqli_7: $where JavaScript injection (but not db.version or Object.keys — those are nosqli_4/5)
  if (/\$where/i.test(msg) && !/db\.version|Object\.keys/i.test(msg) && isArr) completed.push('nosqli_7');

  // nosqli_8: $in array query injection
  if (/\$in/i.test(msg) && isArr) completed.push('nosqli_8');

  // nosqli_9: author contact/profile extraction via email regex
  if (/email.*\$regex|\$regex.*email|author.*\$exists|\$exists.*author/i.test(msg) && isArr) completed.push('nosqli_9');

  // nosqli_10: restricted data extraction via access_level $ne
  if (/access_level.*\$ne|\$ne.*access_level|access_level.*restricted/i.test(msg) && isArr) completed.push('nosqli_10');

  return completed;
}

// ── GET /api/workshop/nosql/mode ───────────────────────────────────────────────

router.get('/mode', authenticateToken, modeHandlers.get);

// ── POST /api/workshop/nosql/mode ─────────────────────────────────────────────

router.post('/mode', authenticateToken, modeHandlers.set);

// ── GET /api/workshop/nosql/llm-status ────────────────────────────────────────

router.get('/llm-status', async (req, res) => {
  try {
    const aiService = require('../services/multiProviderAIService');
    const providerInfo = aiService.getActiveProviderInfo();
    const health = await aiService.healthCheck().catch(() => ({ status: 'unhealthy' }));
    const available = health.status === 'healthy' || health.healthy === true;
    res.json({
      available,
      model: providerInfo.model || process.env.OLLAMA_MODEL || 'llama3.1:8b',
      provider: providerInfo.provider || 'ollama',
      providerName: providerInfo.providerName || 'Ollama',
    });
  } catch (err) {
    res.json({ available: false, model: 'unknown', provider: 'ollama', providerName: 'Ollama' });
  }
});

// ── POST /api/workshop/nosql/chat ─────────────────────────────────────────────

const routeHandlers = require('../agent-runtime/workshopRouteHandlers').createWorkshopRouteHandlers({
  agent: novaAgent, store: db, workshopKey: WORKSHOP_KEY, challengeKey: 'nosql_injection',
  modeService: workshopModeService, syncObjectiveComplete, resetWorkshopProgress,
  detectCompletedObjectives, objectiveLabels: OBJECTIVE_LABELS,
  clearState: 'clearReadingList', resetMessage: 'Chat history, reading list, and progress cleared.',
});
router.post('/chat', authenticateToken, routeHandlers.chat);

// ── GET /api/workshop/nosql/progress ──────────────────────────────────────────

router.get('/progress', authenticateToken, async (req, res) => {
  try {
    const progress = await require('../services/postgresPlatformStores').getPostgresPlatformStores().progress.getWorkshopProgress(req.user.id, WORKSHOP_KEY);
    return res.json({ success: true, objectives: Object.fromEntries((progress?.objectives || []).map(objective => [objective.id, { completed: objective.completed, completedAt: objective.completedAt || null }])) });
  } catch { return res.status(500).json({ success: false, error: 'Unable to load workshop progress' }); }
});

// ── POST /api/workshop/nosql/progress/complete ────────────────────────────────

router.post('/progress/complete', authenticateToken, (_req, res) => {
  res.status(409).json({ success: false, code: 'JUDGED_ATTEMPT_REQUIRED',
    message: 'Objectives are evaluated from agent execution evidence during chat. Direct completion is unavailable.' });
});

// ── POST /api/workshop/nosql/reset ────────────────────────────────────────────

router.post('/reset', authenticateToken, routeHandlers.reset);

// ── GET /api/workshop/nosql/history/:userId ───────────────────────────────────

router.get('/history/:userId', authenticateToken, async (req, res) => {
  const userId = String(req.user.id);
  try {
    const history = await db.getHistory(userId, 50);
    res.json({ success: true, history });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to load history.' });
  }
});

// ── GET /api/workshop/nosql/solutions/status ──────────────────────────────────

router.get('/solutions/status', async (_req, res) => {
  try { return res.json({ success: true, objectives: await workshopConfig.getSolutionVisibilityMap(WORKSHOP_KEY) }); }
  catch { return res.status(500).json({ success: false, error: 'Unable to load workshop content' }); }
});

// ── GET /api/workshop/nosql/solutions/:objectiveId ────────────────────────────

router.get('/solutions/:objectiveId', async (req, res) => {
  const { objectiveId } = req.params;
  if (!OBJECTIVE_LABELS[objectiveId]) {
    return res.status(400).json({ success: false, error: 'Unknown objectiveId' });
  }
  try { return res.json({ success: true, solution: await workshopConfig.getStudentContent(WORKSHOP_KEY, objectiveId, 'solution') }); }
  catch (error) {
    if (error.code === 'FORBIDDEN') return res.status(403).json({ success: false, error: 'Solution not available for this objective' });
    if (error.code === 'NOT_FOUND') return res.status(404).json({ success: false, error: 'Solution content not found' });
    return res.status(500).json({ success: false, error: 'Unable to load workshop content' });
  }
});

module.exports = router;

// Export internals for testing (only when EXPORT_INTERNALS=1)
if (process.env.EXPORT_INTERNALS === '1') {
  module.exports.detectCompletedObjectives = detectCompletedObjectives;
}
