'use strict';

const fs   = require('fs');
const path = require('path');

const logsDir = process.env.LOGS_DIR || path.join(__dirname, '../logs');
const llmLog  = path.join(logsDir, 'llm_requests.log');

// Lazy-require to avoid circular dependency at startup
let _logger = null;
const getLogger = () => {
  if (!_logger) _logger = require('../utils/logger');
  return _logger;
};

let _getRequestContext = null;
const getCtx = () => {
  if (!_getRequestContext) {
    try { _getRequestContext = require('../utils/requestContext').getRequestContext; }
    catch (_) { _getRequestContext = () => ({}); }
  }
  return _getRequestContext();
};

/**
 * Log a single LLM provider call.
 *
 * userId, username, ip, and requestId are auto-filled from the
 * AsyncLocalStorage request context when not explicitly passed.
 */
function logLLMCall({
  provider = 'ollama',
  model = '-',
  promptLength = 0,
  responseLength = 0,
  latencyMs = 0,
  success = true,
  error,
  requestId,
  userId,
  username,
  ip,
  mode,
  toolsCalled,
  messageSummary,
  responseSnippet
} = {}) {
  const ts  = new Date().toISOString();
  const ctx = getCtx();

  const _requestId = requestId ?? ctx.requestId ?? null;
  const _userId    = userId    ?? ctx.userId    ?? null;
  const _username  = username  ?? ctx.username  ?? null;
  const _ip        = ip        ?? ctx.ip        ?? null;

  // Structured JSON -> Winston -> stdout/CloudWatch
  const entry = {
    type: 'llm_call',
    ts,
    provider,
    model,
    promptLength,
    responseLength,
    latencyMs,
    success,
    requestId: _requestId,
    userId:    _userId,
    username:  _username,
    ip:        _ip,
    mode
  };
  if (error)           entry.error          = error;
  if (toolsCalled)     entry.toolsCalled    = toolsCalled;
  if (messageSummary)  entry.messageSummary = messageSummary.substring(0, 120);
  if (responseSnippet) entry.responseSnippet = responseSnippet.substring(0, 150);

  if (success) {
    getLogger().info('llm_call', entry);
  } else {
    getLogger().error('llm_call_error', entry);
  }

  // Flat format -> llm_requests.log  (FinFlow workshop reads this file for objectives)
  try {
    if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });
    const msgSafe  = (messageSummary  || '').substring(0, 120).replace(/"/g, "'");
    const respSafe = (responseSnippet || '').substring(0, 150).replace(/\n/g, ' ').replace(/"/g, "'");
    const line =
      `[${ts}] user=${_userId || 'system'} username=${_username || 'system'} ip=${_ip || '-'} model=${model} mode=${mode || 'n/a'} ` +
      `message="${msgSafe}" ` +
      `tools_called=${toolsCalled || 'none'} ` +
      `response="${respSafe}"\n`;
    fs.appendFileSync(llmLog, line);
  } catch (_) { /* never crash the main request */ }
}

module.exports = { logLLMCall };
