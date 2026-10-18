'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createWorkshopObjectiveGrader } = require('../server/services/workshopObjectiveGrader');
const { createObjectiveCompletionService } = require('../server/services/objectiveCompletionService');
const { getObjectiveRubric } = require('../server/config/objectiveRubrics');

function canonicalFixture(workshopKey) {
  const records = new Map();
  let awards = 0;
  const service = createObjectiveCompletionService({
    progress: { getGeneration: async () => 0 },
    receipts: {
      async beginEvaluation(record) { records.set(record.evaluationId, record); return { ...record, generation: 0, verdict: null }; },
      async recordVerdict({ evaluationId, result }) {
        if (result.verdict === 'pass') awards++;
        return { ...records.get(evaluationId), result, verdict: result.verdict,
          disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass' };
      },
    },
    // Deliberately overgenerous Judge: the canonical service must still refuse
    // an award when a server-derived prerequisite is false.
    judge: async () => ({ verdict: 'pass', criteria: [], explanation: 'controlled pass' }),
  });
  return { grader: createWorkshopObjectiveGrader({ workshopKey, postgres: true, completionService: service }), awards: () => awards };
}

for (const [workshopKey, objectiveId, tool, error] of [
  ['sql_injection_workshop', 'sqli_1', 'search_products', 'SQL syntax error'],
  ['nosql_injection_workshop', 'nosqli_1', 'search_papers', 'MongoServerError: malformed operator'],
]) {
  test(`${workshopKey} refuses nonmodel decisions even when tool output and Judge pass`, async () => {
    for (const decisionSource of ['scripted', 'mock', undefined, 'model']) {
      const f = canonicalFixture(workshopKey);
      const execution = { runId: randomUUID(), check: async () => {} };
      const attempt = await f.grader.begin(7, execution);
      const result = await f.grader.evaluate({ userId: 7, objectiveId, message: 'I claim a genuine model ran', mode: 'vuln', execution, attempt,
        result: { toolUsed: tool, toolResult: { error }, response: 'deterministic formatting is not actor proof',
          toolInvocation: { tool, params: {}, decisionSource } } });
      assert.equal(result.completed, decisionSource === 'model', String(decisionSource));
      assert.equal(f.awards(), decisionSource === 'model' ? 1 : 0);
    }
  });
}

test('all twenty rubrics require model decisions without changing MCP gates', () => {
  for (const [key, prefix, version] of [['sql_injection_workshop','sqli','aria_sql.v3'], ['nosql_injection_workshop','nosqli','nova_operator_sim.v3']]) {
    for (let index = 1; index <= 10; index++) {
      const rubric = getObjectiveRubric(key, `${prefix}_${index}`, 'vuln');
      assert.ok(rubric.requiredFacts.includes('model_decision_observed'));
      assert.equal(rubric.version, version);
    }
  }
  assert.equal(getObjectiveRubric('mcp_workshop', 'mcp_recon', 'vuln').requiredFacts.includes('model_decision_observed'), false);
});

test('scripted historical probes cannot combine with a current model probe to establish column boundary', async () => {
  let packet;
  const histories = [
    { evidence: { tool: 'search_products', invocation: { decisionSource: 'scripted', params: { searchTerm: "%' ORDER BY 8 --" } }, result: [{ name: 'fixture' }] } },
    { evidence: { tool: 'search_products', invocation: { decisionSource: 'model', params: { searchTerm: "%' ORDER BY 9 --" } }, result: { error: 'ORDER BY position 9 is not in select list' } } },
  ];
  const grader = createWorkshopObjectiveGrader({ workshopKey: 'sql_injection_workshop', postgres: true,
    evidenceRepository: { list: async () => histories }, completionService: { evaluate: async args => { packet = args; return { completed: false }; } } });
  await grader.evaluate({ userId: 7, objectiveId: 'sqli_3', message: 'boundary', mode: 'vuln', execution: { check: async () => {} }, attempt: { generation: 0 },
    result: { toolUsed: 'search_products', toolInvocation: { tool: 'search_products', decisionSource: 'model', params: { searchTerm: 'ORDER BY 9' } }, toolResult: histories[1].evidence.result } });
  assert.equal(packet.facts.model_decision_observed, true);
  assert.equal(packet.facts.objective_signal_detected, false);
  assert.equal(packet.evidence.find(row => row.id === 'order_probes').content.length, 1);
  assert.equal(histories.length, 2, 'historical records are retained unchanged');
});

test('retained legacy fixture adapter cannot convert a scripted Judge pass into credit', async () => {
  let credits = 0;
  const grader = createWorkshopObjectiveGrader({ workshopKey: 'sql_injection_workshop', postgres: false,
    objectiveLabels: { sqli_1: 'Syntax' }, syncObjectiveComplete: async () => credits++,
    judge: async () => ({ verdict: 'pass' }) });
  const result = await grader.evaluate({ userId: 7, objectiveId: 'sqli_1', message: 'claim', mode: 'vuln', execution: { check: async () => {} },
    result: { toolUsed: 'search_products', toolResult: { error: 'SQL syntax error' },
      toolInvocation: { tool: 'search_products', decisionSource: 'scripted', params: {} } } });
  assert.equal(result.completed, false);
  assert.equal(result.judgment.verdict, 'fail');
  assert.equal(credits, 0);
});
