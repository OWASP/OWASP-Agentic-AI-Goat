'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { cases } = require('./fixtures/xssEmailJudgeCases');
const { LEVELS } = require('../server/services/xssEmailObjectiveGrader');
const { judgeDiagnostic } = require('./fixtures/judgeDiagnostic');

test('legacy email Judge fixtures cover all four published levels with positive and negative evidence', () => {
  assert.equal(cases.length, 8);
  assert.deepEqual([...new Set(cases.map(item => item.level))].sort(), Object.keys(LEVELS).map(Number));
  for (const item of cases) {
    const required = item.packet.rubric.requiredFacts;
    assert.equal(required.every(key => item.packet.facts[key] === true), item.label === 'positive');
    assert.equal(item.packet.evidence.some(evidence => evidence.source === 'server_observation'), true);
    assert.equal(item.packet.execution.runId, `xss-email-${item.level}-${item.label}`);
  }
});

test('local Ollama 8B qualifies all legacy email positive and negative receipts', {
  skip: process.env.RUN_LIVE_JUDGE !== '1', timeout: 600000,
}, async t => {
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
  const judge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama',
    model: 'llama3.1:8b', baseURL: process.env.OLLAMA_BASE_URL || 'http://localhost:11434' }) });
  const failures = [];
  for (const item of cases) {
    const judgment = await judge(item.packet);
    const completed = judgment.verdict === 'pass'
      && item.packet.rubric.requiredFacts.every(key => item.packet.facts[key] === true);
    const diagnostic = { ...judgeDiagnostic({ family: 'LegacyEmail', id: `level_${item.level}`,
      expected: item.expected, judgment, label: item.label }), level: item.level, completed };
    t.diagnostic(JSON.stringify(diagnostic));
    if ((item.label === 'positive' ? !completed : judgment.verdict === 'pass' || completed)
      || judgment.provider !== 'ollama' || judgment.model !== 'llama3.1:8b') failures.push(diagnostic);
  }
  assert.deepEqual(failures, []);
});
