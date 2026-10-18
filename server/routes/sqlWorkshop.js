'use strict';
const express = require('express');
const router = express.Router();
const ariaAgent = require('../services/ariaAgentService');
const db = require('../database/sqlWorkshopDb');
const { authenticateToken } = require('../middleware/adminAuth');
const workshopModeService = require('../services/workshopModeService');
const { createWorkshopModeHandlers } = require('../services/workshopModeHandlers');
const { createWorkshopConfigService } = require('../services/workshopConfigService');
const { syncObjectiveComplete, resetWorkshopProgress } = require('../utils/progressSync');

const OBJECTIVE_LABELS = {
  sqli_1:  'Trigger SQL Syntax Error',
  sqli_2:  'Boolean-Based Bypass',
  sqli_3:  'Determine Column Count (ORDER BY)',
  sqli_4:  'UNION NULL Probe — Wrong Count',
  sqli_5:  'Match Column Count with UNION SELECT',
  sqli_6:  'Identify String-Compatible Columns',
  sqli_7:  'Extract Database Version',
  sqli_8:  'Enumerate Database Tables',
  sqli_9:  'Dump Column Schema',
  sqli_10: 'Extract Sensitive Order Data',
};

// ── Helpers ───────────────────────────────────────────────────────────────────

const WORKSHOP_KEY = 'sql_injection_workshop';
const modeHandlers = createWorkshopModeHandlers({ workshopKey: WORKSHOP_KEY });
const workshopConfig = createWorkshopConfigService();

function getUserKey(req) { return String(req.user.id); }

// ── Objective detection ────────────────────────────────────────────────────────

function detectCompletedObjectives(userMessage, toolUsed, toolResult, mode = 'fixed') {
  if (mode !== 'vuln') return [];
  if (toolUsed !== 'search_products') return [];

  const msg = userMessage;
  const isErr = toolResult && toolResult.error;
  const isArr = Array.isArray(toolResult);
  const completed = [];

  // sqli_1: SQL syntax error triggered
  if (isErr) completed.push('sqli_1');

  // sqli_2: Boolean-based OR bypass returned results
  if (/%'\s*or\s*'1'\s*=\s*'1/i.test(msg) && isArr) completed.push('sqli_2');

  // sqli_3: ORDER BY enumeration attempted
  if (/%'\s*order\s*by\s*\d+/i.test(msg)) completed.push('sqli_3');

  // sqli_4: UNION with wrong column count caused error
  if (/union\s+select\s+null\s*--/i.test(msg) && !/union\s+select\s+(null,\s*){2,}/i.test(msg) && isErr) {
    completed.push('sqli_4');
  }

  // sqli_5: UNION with 8 NULLs succeeded
  if (/union\s+select\s+null(\s*,\s*null){7}\s*--/i.test(msg) && isArr) completed.push('sqli_5');

  // sqli_6: String literal injected in a column position
  if (/union\s+select\s+.*'[A-Za-z_]+'.*--/i.test(msg) && isArr) completed.push('sqli_6');

  if (/\bversion\s*\(\s*\)|current_setting\s*\(\s*'server_version'\s*\)/i.test(msg) && isArr && toolResult.length) completed.push('sqli_7');
  if (/pg_catalog\.pg_tables|information_schema\.tables/i.test(msg) && isArr && toolResult.length) completed.push('sqli_8');
  if (/information_schema\.columns/i.test(msg) && /table_name\s*=\s*'orders'/i.test(msg) && isArr && toolResult.length) completed.push('sqli_9');

  // sqli_10: data exfiltrated from the isolated workshop orders table.
  if (/from\s+(?:aria\.)?orders\b/i.test(msg) && isArr && toolResult.length > 0) completed.push('sqli_10');

  return completed;
}

// ── GET /api/workshop/sql/mode ─────────────────────────────────────────────────

router.get('/mode', authenticateToken, modeHandlers.get);

// ── POST /api/workshop/sql/mode ────────────────────────────────────────────────

router.post('/mode', authenticateToken, modeHandlers.set);

// ── GET /api/workshop/sql/llm-status ──────────────────────────────────────────

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

// ── POST /api/workshop/sql/chat ────────────────────────────────────────────────

const routeHandlers = require('../agent-runtime/workshopRouteHandlers').createWorkshopRouteHandlers({
  agent: ariaAgent, store: db, workshopKey: WORKSHOP_KEY, challengeKey: 'sql_injection',
  modeService: workshopModeService, syncObjectiveComplete, resetWorkshopProgress,
  detectCompletedObjectives, objectiveLabels: OBJECTIVE_LABELS,
  clearState: 'clearCart', resetMessage: 'Chat history, cart, and progress cleared.',
});
router.post('/chat', authenticateToken, routeHandlers.chat);

// ── GET /api/workshop/sql/progress ────────────────────────────────────────────

router.get('/progress', authenticateToken, async (req, res) => {
  try {
    const progress = await require('../services/postgresPlatformStores').getPostgresPlatformStores().progress.getWorkshopProgress(req.user.id, WORKSHOP_KEY);
    return res.json({ success: true, objectives: Object.fromEntries((progress?.objectives || []).map(objective => [objective.id, { completed: objective.completed, completedAt: objective.completedAt || null }])) });
  } catch { return res.status(500).json({ success: false, error: 'Unable to load workshop progress' }); }
});

// ── POST /api/workshop/sql/progress/complete ──────────────────────────────────

router.post('/progress/complete', authenticateToken, (_req, res) => {
  res.status(409).json({ success: false, code: 'JUDGED_ATTEMPT_REQUIRED',
    message: 'Objectives are evaluated from agent execution evidence during chat. Direct completion is unavailable.' });
});

// ── POST /api/workshop/sql/reset ──────────────────────────────────────────────

router.post('/reset', authenticateToken, routeHandlers.reset);

// ── GET /api/workshop/sql/history/:userId ─────────────────────────────────────

router.get('/history/:userId', authenticateToken, async (req, res) => {
  const userId = String(req.user.id);
  try {
    const history = await db.getHistory(userId, 50);
    res.json({ success: true, history });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to load history.' });
  }
});

// ── GET /api/workshop/sql/solutions/status ────────────────────────────────────

router.get('/solutions/status', async (_req, res) => {
  try { return res.json({ success: true, objectives: await workshopConfig.getSolutionVisibilityMap(WORKSHOP_KEY) }); }
  catch { return res.status(500).json({ success: false, error: 'Unable to load workshop content' }); }
});

// ── GET /api/workshop/sql/solutions/:objectiveId ──────────────────────────────

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
