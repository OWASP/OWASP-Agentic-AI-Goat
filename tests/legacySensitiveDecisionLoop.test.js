'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  runLegacySensitiveDecisionLoop,
  DEFAULT_MAX_TOOL_CALLS,
} = require('../server/agent-runtime/legacySensitiveDecisionLoop');

function execution({ check = async () => {}, receipt = value => value } = {}) {
  const events = [];
  const effects = [];
  const current = {
    runId: '11111111-1111-4111-8111-111111111111',
    ownerKey: '["LegacySensitiveInfo","41"]',
    durableGeneration: '7',
    signal: new AbortController().signal,
    check,
    trace: async event => events.push(event),
    async effectWithReceipt(effectKey, callback) {
      const value = await callback();
      const completed = {
        value,
        receipt: {
          version: 1,
          status: 'completed',
          runId: current.runId,
          ownerKey: current.ownerKey,
          generation: current.durableGeneration,
          effectKey: `${current.runId}:${effectKey}`,
        },
      };
      effects.push(completed);
      return receipt(completed);
    },
  };
  return Object.assign(current, { events, effects });
}

function parseCandidate(candidate) {
  const value = JSON.parse(candidate.response);
  if (!value || typeof value.action !== 'string' || !value.params || Array.isArray(value.params)) {
    throw Object.assign(new Error('invalid'), { code: 'MODEL_DECISION_INVALID' });
  }
  const allowed = value.action === 'finish'
    ? Object.keys(value.params).length === 0
    : ['read_teaching_file', 'render_ssi_template'].includes(value.action)
      && Object.keys(value.params).length === 1
      && typeof value.params[value.action === 'read_teaching_file' ? 'path' : 'template'] === 'string';
  if (!allowed) throw Object.assign(new Error('invalid'), { code: 'MODEL_DECISION_INVALID' });
  return value;
}

function candidate(action, params = {}, extra = {}) {
  return { response: JSON.stringify({ action, params }), provider: 'fixture', model: 'fixture', ...extra };
}

function fixture({ selections, observations = {}, execution: owner = execution(), respond, maxBytes, maxToolCalls } = {}) {
  const decisionInputs = [];
  const responseInputs = [];
  const executed = [];
  let index = 0;
  return {
    owner,
    decisionInputs,
    responseInputs,
    executed,
    run: () => runLegacySensitiveDecisionLoop({
      request: 'Use the isolated teaching lab',
      execution: owner,
      maxBytes,
      maxToolCalls,
      decide: async input => {
        decisionInputs.push(input);
        return selections[index++];
      },
      validateDecision: parseCandidate,
      executeDecision: async selected => {
        executed.push(selected);
        return observations[selected.ordinal] || { success: true, selected: selected.params };
      },
      respond: async input => {
        responseInputs.push(input);
        return respond ? respond(input) : { response: 'Grounded terminal response', provider: 'fixture', model: 'fixture' };
      },
      qualifyModel: ({ result }) => result.provider === 'fixture' && result.model === 'fixture',
    }),
  };
}

test('a later decision consumes the ordered observation and finish produces last-hop compatibility', async () => {
  const run = fixture({
    selections: [
      candidate('read_teaching_file', { path: '../secret/template.txt' }),
      candidate('render_ssi_template', { template: '<!--#echo var="API_KEY" -->' }),
      candidate('finish'),
    ],
    observations: {
      1: { content: 'Key: <!--#echo var="API_KEY" -->', boundary: { outsidePublic: true } },
      2: { rendered: 'Key: fixture', commandExecution: 'none' },
    },
  });
  const result = await run.run();
  assert.equal(result.status, 'completed');
  assert.equal(result.qualified, true);
  assert.equal(run.decisionInputs.length, 3);
  assert.deepEqual(run.decisionInputs[1].trajectory[0].observation,
    { content: 'Key: <!--#echo var="API_KEY" -->', boundary: { outsidePublic: true } });
  assert.equal(run.responseInputs[0].trajectory.length, 2);
  assert.equal(result.decision.action, 'render_ssi_template');
  assert.equal(result.observation.rendered, 'Key: fixture');
  assert.equal(result.modelDecision, result.trajectory[1].modelDecision);
  assert.equal(result.finishDecision.action, 'finish');
  assert.equal(result.decisions.length, 3);
  assert.equal(result.decisionQualified, true);
  assert.equal(result.trajectory.every(hop => hop.decisionQualified === true), true);
  assert.equal(result.hopDigest, result.trajectory[1].hopDigest);
  assert.match(result.terminalDigest, /^[a-f0-9]{64}$/);
  assert.notEqual(result.terminalDigest, result.hopDigest);
  assert.deepEqual(run.owner.events.filter(row => row.type === 'node_start').map(row => row.node), [
    'decide', 'validate', 'execute', 'record_observation',
    'decide', 'validate', 'execute', 'record_observation',
    'decide', 'validate', 'respond', 'finish',
  ]);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.trajectory), true);
  assert.equal(Object.isFrozen(result.trajectory[0].observation), true);
});

test('qualified finish before any tool is an ordinary no-operation response', async () => {
  const run = fixture({ selections: [candidate('finish')] });
  const result = await run.run();
  assert.equal(result.status, 'no_operation');
  assert.equal(result.qualified, true);
  assert.equal(result.decisionQualified, true);
  assert.equal(result.responseQualified, true);
  assert.equal(result.decision, null);
  assert.equal(result.observation, null);
  assert.equal(result.effectReceipt, null);
  assert.equal(result.hopDigest, null);
  assert.match(result.terminalDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(result.trajectory, []);
  assert.equal(run.executed.length, 0);
  assert.equal(run.responseInputs[0].decision, null);
});

test('one tool preserves exact selected argument bytes and then finishes', async () => {
  const exact = '../secret/a b/<!--#echo var="API_KEY" -->.txt';
  const run = fixture({ selections: [candidate('read_teaching_file', { path: exact }), candidate('finish')] });
  const result = await run.run();
  assert.equal(result.status, 'completed');
  assert.equal(run.executed[0].params.path, exact);
  assert.equal(result.decision.params.path, exact);
  assert.equal(result.trajectory[0].decision.params.path, exact);
});

test('equal calls at different steps receive distinct chained effect identities', async () => {
  const same = candidate('read_teaching_file', { path: '../secret/repeat.txt' });
  const run = fixture({ selections: [same, same, candidate('finish')] });
  const result = await run.run();
  assert.equal(result.trajectory.length, 2);
  assert.notEqual(result.trajectory[0].callId, result.trajectory[1].callId);
  assert.notEqual(result.trajectory[0].effectReceipt.effectKey, result.trajectory[1].effectReceipt.effectKey);
  assert.equal(result.trajectory[0].previousHopDigest, null);
  assert.equal(result.trajectory[1].previousHopDigest, result.trajectory[0].hopDigest);
  assert.deepEqual(run.executed.map(row => row.ordinal), [1, 2]);
});

test('a requested fourth tool ends as an honest noncredit step-limit outcome', async () => {
  const selections = Array.from({ length: DEFAULT_MAX_TOOL_CALLS + 1 }, (_, index) =>
    candidate('read_teaching_file', { path: `file-${index}.txt` }));
  const run = fixture({ selections });
  const result = await run.run();
  assert.equal(result.status, 'step_limit');
  assert.equal(result.qualified, false);
  assert.equal(result.responseQualified, false);
  assert.equal(result.decisionQualified, true);
  assert.equal(result.trajectory.length, 3);
  assert.equal(result.decisions.length, 4);
  assert.equal(result.decisions[3].decision.params.path, 'file-3.txt');
  assert.equal(result.decision.params.path, 'file-2.txt');
  assert.equal(result.hopDigest, result.trajectory[2].hopDigest);
  assert.equal(result.terminalDigest, null);
  assert.equal(run.executed.length, 3);
  assert.equal(run.responseInputs.length, 0);
});

test('invalid receipts and invalid decisions stop before a later inference or effect', async t => {
  for (const [label, alter] of [
    ['owner', row => ({ ...row, ownerKey: '["LegacySensitiveInfo","sibling"]' })],
    ['run', row => ({ ...row, runId: '22222222-2222-4222-8222-222222222222' })],
    ['generation', row => ({ ...row, generation: '8' })],
    ['effect', row => ({ ...row, effectKey: 'wrong-effect' })],
  ]) await t.test(`${label} receipt binding`, async () => {
    const owner = execution({ receipt: completed => ({ ...completed, receipt: alter(completed.receipt) }) });
    const run = fixture({ execution: owner, selections: [candidate('read_teaching_file', { path: 'x' })] });
    await assert.rejects(run.run(), { code: 'EFFECT_RECEIPT_INVALID' });
    assert.equal(run.decisionInputs.length, 1);
    assert.equal(run.responseInputs.length, 0);
  });
  await t.test('malformed finish', async () => {
    const run = fixture({ selections: [candidate('finish', { extra: 'x' })] });
    await assert.rejects(run.run(), { code: 'MODEL_DECISION_INVALID' });
    assert.equal(run.executed.length, 0);
    assert.equal(run.responseInputs.length, 0);
  });
});

test('fallback decisions and responses cannot qualify', async () => {
  const decisionRun = fixture({ selections: [candidate('finish', {}, { fallback: true })] });
  const unqualifiedDecision = await decisionRun.run();
  assert.equal(unqualifiedDecision.status, 'unqualified_model');
  assert.equal(decisionRun.responseInputs.length, 0);

  const responseRun = fixture({ selections: [candidate('finish')],
    respond: () => ({ response: 'fixture fallback', provider: 'fixture', model: 'fixture', fallback: true }) });
  const unqualifiedResponse = await responseRun.run();
  assert.equal(unqualifiedResponse.status, 'unqualified_response');
  assert.equal(unqualifiedResponse.qualified, false);
});

test('cancellation after a durable observation prevents another decision and terminal response', async () => {
  let cancel = false;
  const owner = execution({ check: async () => {
    if (cancel) throw Object.assign(new Error('reset'), { name: 'AbortError' });
  } });
  const original = owner.effectWithReceipt;
  owner.effectWithReceipt = async (...args) => {
    const completed = await original(...args);
    cancel = true;
    return completed;
  };
  const run = fixture({ execution: owner, selections: [candidate('read_teaching_file', { path: '../secret/flag.txt' })] });
  await assert.rejects(run.run(), { name: 'AbortError' });
  assert.equal(owner.effects.length, 1);
  assert.equal(owner.effects[0].receipt.status, 'completed');
  assert.equal(run.decisionInputs.length, 1);
  assert.equal(run.responseInputs.length, 0);
});

test('request, observations, accumulated trajectory, and terminal evidence stay bounded', async t => {
  await t.test('request', async () => {
    const owner = execution();
    await assert.rejects(runLegacySensitiveDecisionLoop({
      request: 'x'.repeat(1100), execution: owner, maxBytes: 1024,
      decide: async () => candidate('finish'), validateDecision: parseCandidate,
      executeDecision: async () => ({}), respond: async () => ({ response: 'done' }), qualifyModel: () => true,
    }), { code: 'DECISION_REQUEST_TOO_LARGE' });
  });
  await t.test('trajectory', async () => {
    const run = fixture({ maxBytes: 1024,
      selections: [candidate('read_teaching_file', { path: 'x' }), candidate('finish')],
      observations: { 1: { content: 'y'.repeat(900) } },
    });
    await assert.rejects(run.run(), { code: 'DECISION_EVIDENCE_TOO_LARGE' });
    assert.equal(run.decisionInputs.length, 1);
  });
  await t.test('finish selection cannot trigger response inference after exhausting aggregate budget', async () => {
    let responded = false;
    const run = fixture({ maxBytes: 1600,
      selections: [candidate('read_teaching_file', { path: 'x' }),
        candidate('finish', {}, { boundedMetadata: 'm'.repeat(650) })],
      observations: { 1: { content: 'y'.repeat(250) } },
      respond: () => { responded = true; return { response: 'must not run', provider: 'fixture', model: 'fixture' }; },
    });
    await assert.rejects(run.run(), { code: 'DECISION_EVIDENCE_TOO_LARGE' });
    assert.equal(run.decisionInputs.length, 2);
    assert.equal(responded, false);
  });
});

test('loop observability survives the shared trace metadata projection without tool content', async () => {
  const { traceData } = require('../server/agent-runtime/runTraceStore');
  const run = fixture({ selections: [candidate('read_teaching_file', { path: 'guide.txt' }), candidate('finish')],
    observations: { 1: { content: 'PRIVATE_TOOL_OBSERVATION' } } });
  await run.run();
  const events = run.owner.events.map(event => ({ ...event, data: traceData(event.data) }));
  const allowedTypes = new Set(['node_start', 'node_end', 'decision', 'provisional', 'tool', 'error']);
  assert.ok(events.every(event => allowedTypes.has(event.type)), 'events must satisfy PostgreSQL events_event_type_check');
  const decisions = events.filter(event => event.type === 'decision' && event.node === 'decide');
  assert.deepEqual(decisions.map(event => event.data.attempt), [1, 2]);
  assert.equal(decisions.every(event => event.data.provider === 'fixture' && event.data.model === 'fixture'), true);
  assert.equal(events.some(event => event.type === 'node_start' && event.node === 'decide' && event.data.toolSteps === 1), true);
  assert.equal(events.find(event => event.type === 'decision' && event.node === 'finish').data.terminationReason, 'model_finished');
  assert.equal(JSON.stringify(events).includes('PRIVATE_TOOL_OBSERVATION'), false);
});
