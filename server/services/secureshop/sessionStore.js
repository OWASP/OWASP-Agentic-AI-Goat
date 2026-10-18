'use strict';

const crypto = require('node:crypto');

const BUDGET = Number(process.env.SS_AGENT_SESSION_TOKEN_BUDGET || 100000);
const sessionExecutions = new Map();
const pg = () => require('../../database/postgres/secureshopAgentsDb').getSecureShopAgentsDb();

async function createSession({ userId, role }) {
  return pg().createSession(crypto.randomUUID(), userId, role);
}

async function getSession(sessionId) {
  return pg().getSession(sessionId);
}

/** Keep two turns for the same session from interleaving in this process. */
async function runSessionExclusive(sessionId, operation) {
  const key = String(sessionId);
  const previous = sessionExecutions.get(key) || Promise.resolve();
  const current = previous.catch(() => {}).then(operation);
  sessionExecutions.set(key, current);
  try {
    return await current;
  } finally {
    if (sessionExecutions.get(key) === current) sessionExecutions.delete(key);
  }
}

async function appendUserMessage(sessionId, content) {
  return pg().appendMessage(sessionId, { role: 'user', content });
}

async function appendAssistantMessage(sessionId, content) {
  return pg().appendMessage(sessionId, { role: 'assistant', content });
}

async function appendToolResult(sessionId, toolCallId, content) {
  return pg().appendMessage(sessionId, { role: 'tool', tool_call_id: toolCallId, content });
}

async function getMessages(sessionId) {
  return pg().getMessages(sessionId);
}

async function remainingBudget(sessionId) {
  return BUDGET - await pg().getTokens(sessionId);
}

async function addUsedTokens(sessionId, n) {
  return pg().addTokens(sessionId, n);
}

async function appendAssistantToolCalls(sessionId, calls) {
  return pg().appendMessage(sessionId, {
    role: 'assistant',
    content: '',
    tool_calls: calls.map((call) => ({
      id: call.id,
      type: 'function',
      function: { name: call.name, arguments: JSON.stringify(call.args || {}) },
    })),
  });
}

module.exports = {
  createSession,
  getSession,
  runSessionExclusive,
  appendUserMessage,
  appendAssistantMessage,
  appendAssistantToolCalls,
  appendToolResult,
  getMessages,
  remainingBudget,
  addUsedTokens,
};
