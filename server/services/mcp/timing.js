'use strict';

function milliseconds(value, fallback, maximum, name) {
  if (value === undefined) return fallback;
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    throw new RangeError(`Invalid ${name}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 100 || parsed > maximum) {
    throw new RangeError(`Invalid ${name}`);
  }
  return parsed;
}

// Model calls share the coordinator's existing owner deadline. These values
// never start a fresh run deadline or increase the decision/tool call limits.
function createMcpTiming({ env = process.env } = {}) {
  const decisionTimeoutMs = milliseconds(env.MCP_DECISION_TIMEOUT_MS, 30000, 90000, 'MCP_DECISION_TIMEOUT_MS');
  const responseTimeoutMs = milliseconds(env.MCP_RESPONSE_TIMEOUT_MS, 30000, 90000, 'MCP_RESPONSE_TIMEOUT_MS');
  const runTimeoutMs = milliseconds(env.MCP_RUN_TIMEOUT_MS, 120000, 290000, 'MCP_RUN_TIMEOUT_MS');
  if (decisionTimeoutMs > runTimeoutMs || responseTimeoutMs > runTimeoutMs) {
    throw new RangeError('MCP model timeout exceeds the owner run timeout');
  }
  return Object.freeze({ decisionTimeoutMs, responseTimeoutMs, runTimeoutMs });
}

function isMcpReconScope({ workshopKey, family, scenario, objectiveId } = {}) {
  return workshopKey === 'mcp_workshop' && family === 'MCP'
    && scenario === 'assistant_tools' && objectiveId === 'mcp_recon';
}

// Recon grading uses the same enclosing owner signal. This setting is read
// only for its server-owned scope, and never replaces a retained rubric.
function createMcpReconTiming({ env = process.env } = {}) {
  const timing = createMcpTiming({ env });
  const judgeTimeoutMs = milliseconds(env.MCP_RECON_JUDGE_TIMEOUT_MS, 90000, 120000, 'MCP_RECON_JUDGE_TIMEOUT_MS');
  if (judgeTimeoutMs > timing.runTimeoutMs) throw new RangeError('MCP recon Judge timeout exceeds the owner run timeout');
  return Object.freeze({ ...timing, judgeTimeoutMs });
}

module.exports = { createMcpTiming, createMcpReconTiming, isMcpReconScope };
