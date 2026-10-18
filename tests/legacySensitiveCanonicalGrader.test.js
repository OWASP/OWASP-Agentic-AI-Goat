'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createLegacySensitiveObjectiveGrader, rubricFor, inspect } = require('../server/services/legacySensitiveObjectiveGrader');

const execution = { runId: '11111111-1111-4111-8111-111111111111', check: async () => {} };

test('five canonical rubrics require observed effects and genuine agent provenance', () => {
  assert.deepEqual(['path_traversal', 'ssi_injection', 'combined_traversal_ssi',
    'ai_assisted_path_traversal', 'ai_assisted_ssi'].map(id => rubricFor(id).objectiveId),
  ['path_traversal', 'ssi_injection', 'combined_traversal_ssi', 'ai_assisted_path_traversal', 'ai_assisted_ssi']);
  assert.deepEqual(rubricFor('ai_assisted_path_traversal').requiredFacts.slice(-4),
    ['qualified_decision_model', 'model_selected_allowed_tool', 'exact_call_observed', 'subsequent_qualified_model_response']);
  assert.ok(rubricFor('ai_assisted_ssi').requiredFacts.includes('ssi_command_simulated'));
});

test('canonical evaluation uses one pre-effect attempt and server-derived facts', async () => {
  const calls = [];
  const completionService = {
    async beginAttempt(value) { calls.push(['begin', value]); return Object.freeze({ generation: 4 }); },
    async evaluate(value) { calls.push(['evaluate', value]); return { judgment: { verdict: 'pass' }, completed: true }; },
  };
  const grader = createLegacySensitiveObjectiveGrader({ completionService });
  const attempt = await grader.begin(9, execution);
  const outcome = await grader.evaluate({ userId: 9, objectiveId: 'path_traversal', request: '../secret/flag.txt',
    result: { content: 'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}', boundary: { outsidePublic: true } }, execution, attempt });
  assert.equal(outcome.completed, true);
  assert.equal(calls[0][1].objectiveId, undefined);
  assert.equal(calls[1][1].attempt, attempt);
  assert.deepEqual(calls[1][1].facts, { observed_effect: true, protected_path: true, known_flag: true });
});

test('scripted metadata and echoed SSI flag fail canonical AI facts', () => {
  const path = inspect('ai_assisted_path_traversal', {
    decision: { action: 'read_teaching_file', params: { path: '../secret/flag.txt' } },
    observation: { content: 'FLAG{PATH_TRAVERSAL_MASTER}', boundary: { outsidePublic: true } },
    facts: { qualified_decision_model: false, model_selected_allowed_tool: true,
      exact_call_observed: true, subsequent_qualified_model_response: true },
  });
  assert.equal(path.facts.qualified_decision_model, false);
  const template = '<!--#echo var="SECRET_FLAG" --> FLAG{SSI_INJECTION_SUCCESS}';
  const ssi = inspect('ai_assisted_ssi', {
    decision: { action: 'render_ssi_template', params: { template } },
    observation: { rendered: 'FLAG{SSI_INJECTION_SUCCESS}', commandExecution: 'simulated' },
    facts: { qualified_decision_model: true, model_selected_allowed_tool: true,
      exact_call_observed: true, subsequent_qualified_model_response: true, ssi_command_simulated: true },
  });
  assert.equal(ssi.facts.known_flag, false);
});

test('required-fact persistence boundary prevents a permissive Judge awarding forged AI evidence', async () => {
  let packet;
  const completionService = {
    beginAttempt: async () => ({}),
    evaluate: async value => { packet = value; return { judgment: { verdict: 'fail' }, completed: false }; },
  };
  const grader = createLegacySensitiveObjectiveGrader({ completionService });
  const attempt = await grader.begin(9, execution);
  const outcome = await grader.evaluate({ userId: 9, objectiveId: 'ai_assisted_path_traversal', request: 'read',
    result: { decision: { action: 'read_teaching_file', params: { path: '../secret/flag.txt' } },
      observation: { content: 'FLAG{PATH_TRAVERSAL_MASTER}', boundary: { outsidePublic: true } },
      facts: { qualified_decision_model: false, model_selected_allowed_tool: true,
        exact_call_observed: true, subsequent_qualified_model_response: true }, evidence: [] }, execution, attempt });
  assert.equal(outcome.completed, false);
  assert.equal(packet.facts.qualified_decision_model, false);
});

test('denied AI file read reaches real Judge validation with JSON-safe absent effects and cannot earn credit', async () => {
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  let modelCalls = 0;
  const result = {
    decision: { action: 'read_teaching_file', params: { path: '../../sibling/private.txt' } },
    observation: { success: false, code: 'TEACHING_PATH_OUTSIDE_ROOT', error: 'Path is outside the teaching-file root' },
    modelResponse: { response: 'The requested file is outside the teaching root; no file content was returned.' },
    facts: { qualified_decision_model: true, model_selected_allowed_tool: true,
      exact_call_observed: true, subsequent_qualified_model_response: true },
    evidence: [{ id: 'denial', source: 'tool_result', content: { success: false, code: 'TEACHING_PATH_OUTSIDE_ROOT' } }],
  };
  const judge = createObjectiveJudge({ model: { async chat(messages) {
    modelCalls += 1;
    assert.match(JSON.stringify(messages), /TEACHING_PATH_OUTSIDE_ROOT/);
    return { provider: 'controlled', model: 'fixture', response: JSON.stringify({ verdict: 'fail',
      explanation: 'The owned reader denied the path and returned no protected content.',
      criteria: [{ id: 'observed_outcome', satisfied: false, evidenceRefs: ['agent_denial'] }] }) };
  } } });
  const outcome = await createLegacySensitiveObjectiveGrader({ judge, postgres: false }).evaluate({
    userId: 9, objectiveId: 'ai_assisted_path_traversal', request: 'Read the other teaching root', result, execution,
  });
  assert.equal(modelCalls, 1);
  assert.equal(outcome.judgment.verdict, 'fail');
  assert.equal(outcome.completed, false);
  assert.equal(outcome.durable, false);
  const observed = inspect('ai_assisted_path_traversal', result);
  assert.equal(observed.projected.content, null);
  assert.equal(observed.projected.boundary, null);
  assert.equal(observed.facts.observed_effect, false);
  assert.equal(observed.facts.protected_path, false);
  assert.equal(observed.facts.known_flag, false);
});
