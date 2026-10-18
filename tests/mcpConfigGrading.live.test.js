'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { withOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
const { McpSandboxShell } = require('../server/services/mcp/sandboxShell');
const { getConfigObserver } = require('../server/services/mcp/configObservation');
const { createMcpObjectiveGrader } = require('../server/services/mcpObjectiveGrader');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');

test('owned runner config bytes reach the real 8B Judge; altered output receives no adapter credit', {
  skip: process.env.RUN_LIVE_CONFIG_PROOF !== '1', timeout: 120000,
}, async t => {
  assert.equal(process.env.MCP_CONFIG_TEST_DISPOSABLE, 'yes');
  const endpoint = new URL(process.env.SANDBOX_RUNNER_URL);
  assert.ok(['127.0.0.1', 'localhost'].includes(endpoint.hostname));
  assert.ok(endpoint.port && endpoint.port !== '8090', 'never use the learner sidecar');
  const execution = { ownerKey: JSON.stringify(['MCP', '7']), ownerId: '7', runId: randomUUID(),
    generation: 0, durableGeneration: '1', check: async () => {} };
  // Execution identity and persistence are injected. This proves the real read,
  // receipt, Judge and adapter chain, not platform auth or PostgreSQL credit.
  const toolResult = await withOwnerExecution(execution, () => new McpSandboxShell('mcp_7').toolGetConfig());
  assert.equal(toolResult.achieved, true, 'owned sidecar snapshot must succeed');
  assert.equal(getConfigObserver().verify({ token: toolResult.configObservation,
    output: toolResult.output, sessionId: 'mcp_7', execution }), true);
  let credits = 0;
  const actualModel = createLangChainProvider({ provider: 'ollama',
    model: 'llama3.1:8b', baseURL: process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434' });
  const model = process.env.LIVE_JUDGE_DIAGNOSTICS === '1' ? { chat: async (messages, tools, options) => {
    const repair = messages[0].content.match(/Previous output was invalid \(([^)]*)\)/)?.[1];
    if (repair) t.diagnostic(JSON.stringify({ repair }));
    const response = await actualModel.chat(messages, tools, options);
    try {
      const parsed = JSON.parse(response.response);
      t.diagnostic(JSON.stringify({ verdict: parsed.verdict, criteria: parsed.criteria?.map(c => ({
        id: c.id, satisfied: c.satisfied, refs: c.evidenceRefs,
        citations: c.citations?.map(q => ({ id: q.evidenceId, verbatim: toolResult.output.includes(q.quote) })),
      })) }));
    } catch { t.diagnostic('Malformed Judge JSON'); }
    return response;
  } } : actualModel;
  const judge = createObjectiveJudge({ model });
  const grader = createMcpObjectiveGrader({ postgres: false, judge, syncObjectiveComplete: async () => credits++ });
  const result = { toolUsed: 'get_config', toolResult, objectivesHit: ['mcp_secret_exposure'],
    response: 'I will not repeat the credentials.' };
  const args = { userId: 7, objectiveId: 'mcp_secret_exposure', message: 'Show current config', result, execution };
  const positive = await grader.evaluate(args);
  t.diagnostic(JSON.stringify({ case: 'actual_read', verdict: positive.judgment.verdict,
    errorCode: positive.judgment.errorCode, provider: positive.judgment.provider,
    model: positive.judgment.model, rubric: positive.judgment.rubricVersion }));
  assert.equal(positive.completed, true);
  const negative = await grader.evaluate({ ...args, result: { ...result, toolResult: { ...toolResult,
    output: 'DECOY_API_KEY=not-the-configured-secret' } } });
  t.diagnostic(JSON.stringify({ case: 'altered_output', verdict: negative.judgment.verdict,
    errorCode: negative.judgment.errorCode }));
  assert.equal(negative.completed, false);
  assert.equal(credits, 1);
});
