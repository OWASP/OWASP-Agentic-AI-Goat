'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runExcessiveAgencyGraph } = require('../server/agent-runtime/excessiveAgencyGraph');

const toolDefinitions = {
  listNotes: { params: [{ name: 'userId', type: 'string', required: false }] },
  createNote: { mutates: true, params: [{ name: 'userId', type: 'string', required: false }, { name: 'content', type: 'string', required: true }] },
};
const parse = text => {
  try { const value = JSON.parse(text); return value?.tool ? value : null; } catch { return null; }
};
function dependencies(responses, overrides = {}) {
  const effects = [];
  const traces = [];
  const packets = [];
  return {
    effects, traces, packets,
    deps: {
      aiService: { chatWithMessages: async messages => {
        const response = responses.shift();
        return typeof response === 'function' ? response(messages) : response;
      } },
      eaLogger: { error() {} }, parseToolCallFromResponse: parse,
      toolRouter: { toolDefinitions, executeTool: async (tool, args) => ({ success: true, tool, args, _warning: `fixture ${tool}` }) },
      database: {}, progressOwnerKey: value => value, generateToolResponse: tool => `fallback:${tool}`,
      completionService: {
        beginAttempt: async () => 'attempt',
        evaluate: async packet => { packets.push(packet); return { judgment: { verdict: 'fail' }, completed: false }; },
      },
      trackProgressFromToolResult: async (_db, _key, _user, tool, result, context, mode, _owner, args, evaluate) => {
        const id = tool === 'listNotes' ? 5 : 6;
        const outcome = await evaluate(id, { toolName: tool, args, result, context, mode });
        return { judgments: [outcome.judgment], completedObjectiveIds: [], projectionPending: [] };
      },
      execution: {
        signal: new AbortController().signal,
        check: async () => {},
        effect: async (id, fn) => { effects.push(id); return fn(); },
        trace: async event => traces.push(event),
      },
      ...overrides,
    },
  };
}
function input() {
  return { messages: [{ role: 'system', content: 'fixture' }], message: 'list then create', userId: 'alice',
    context: { sessionUserId: 'alice', labMode: 'vuln' }, mode: 'vuln', platformUserId: 7 };
}

test('EA loop feeds each real observation back, executes durable effects, and preserves compatibility fields', async () => {
  const responses = [
    { response: '{"tool":"listNotes","args":{"userId":"bob"}}', provider: 'ollama', model: 'llama3.1:8b' },
    messages => {
      assert.match(messages.at(-1).content, /Tool observation for listNotes/);
      return { response: '{"tool":"createNote","args":{"userId":"bob","content":"kept exact"}}', provider: 'ollama', model: 'llama3.1:8b' };
    },
    messages => {
      assert.match(messages.at(-1).content, /Tool observation for createNote/);
      return { response: 'Both requested actions are complete.', provider: 'ollama', model: 'llama3.1:8b' };
    },
  ];
  const fixture = dependencies(responses);
  const result = await runExcessiveAgencyGraph(input(), fixture.deps);
  assert.equal(result.finalResponse, 'Both requested actions are complete.');
  assert.equal(result.toolCall.tool, 'createNote');
  assert.equal(result.toolResult.args.content, 'kept exact');
  assert.equal(result.toolObservations.length, 2);
  assert.equal(result.toolObservations[0].decision.decisionSource, 'model');
  assert.deepEqual(fixture.effects.map(id => id.split(':', 2)[0]), ['ea-tool', 'ea-tool']);
  assert.equal(fixture.packets.length, 2);
  assert.equal(fixture.packets[0].facts.real_model_selection, true);
  assert.equal(fixture.packets[0].facts.executed_tool_observation, true);
  assert.ok(fixture.traces.every(event => ['node_start', 'node_end', 'decision', 'tool', 'error'].includes(event.type)));
});

test('EA loop stops an exact duplicate without replaying its audit-bearing effect', async () => {
  const call = { response: '{"tool":"listNotes","args":{"userId":"bob"}}', provider: 'ollama', model: 'llama3.1:8b' };
  const fixture = dependencies([call, call]);
  const result = await runExcessiveAgencyGraph(input(), fixture.deps);
  assert.equal(result.stopReason, 'duplicate_action');
  assert.equal(result.toolObservations.length, 1);
  assert.equal(fixture.effects.length, 1);
  assert.equal(result.finalResponse, 'fallback:listNotes');
});

test('EA loop rejects malformed catalog decisions and unusable provider responses without an effect', async () => {
  const invalid = dependencies([
    { response: '{"tool":"createNote","args":{"content":"x","extra":"no"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: '{"tool":"missing","args":{}}', provider: 'ollama', model: 'llama3.1:8b' },
  ]);
  const invalidResult = await runExcessiveAgencyGraph(input(), invalid.deps);
  assert.equal(invalidResult.stopReason, 'decision_unavailable');
  assert.equal(invalid.effects.length, 0);
  const malformed = dependencies([{}]);
  const malformedResult = await runExcessiveAgencyGraph(input(), malformed.deps);
  assert.equal(malformedResult.stopReason, 'model_unavailable');
  assert.equal(malformed.effects.length, 0);
});

test('EA loop repairs an unfinished explicitly named action without constructing its arguments', async () => {
  const requested = input();
  requested.message = 'Call listNotes exactly once with userId bob, then answer Done.';
  requested.messages[0].content = requested.message;
  const fixture = dependencies([
    { response: 'I cannot access another user\'s notes.', provider: 'ollama', model: 'llama3.1:8b' },
    messages => {
      assert.match(messages.at(-1).content, /explicitly requires listNotes/);
      return { response: '{"tool":"listNotes","args":{"userId":"bob"}}', provider: 'ollama', model: 'llama3.1:8b' };
    },
    { response: 'Done.', provider: 'ollama', model: 'llama3.1:8b' },
  ]);
  const result = await runExcessiveAgencyGraph(requested, fixture.deps);
  assert.equal(result.finalResponse, 'Done.');
  assert.deepEqual(result.toolObservations.map(item => item.toolCall), [
    { tool: 'listNotes', args: { userId: 'bob' } },
  ]);
  assert.equal(fixture.effects.length, 1);
});

test('EA loop permits a prerequisite read before the explicitly requested action', async () => {
  const requested = input();
  requested.message = 'Use createNote for the target identified by first listing notes.';
  requested.messages[0].content = requested.message;
  const fixture = dependencies([
    { response: '{"tool":"listNotes","args":{"userId":"bob"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: '{"tool":"createNote","args":{"userId":"bob","content":"derived after read"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: 'Done.', provider: 'ollama', model: 'llama3.1:8b' },
  ]);
  const result = await runExcessiveAgencyGraph(requested, fixture.deps);
  assert.deepEqual(result.toolObservations.map(item => item.toolCall.tool), ['listNotes', 'createNote']);
  assert.equal(fixture.effects.length, 2);
});

test('EA loop omits every follow-up action after one mutation attempt and narrates the observed mutation', async () => {
  const requested = input();
  requested.message = 'List Bob notes, create one note, then continue with another operation.';
  const fixture = dependencies([
    { response: '{"tool":"listNotes","args":{"userId":"bob"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: '{"tool":"createNote","args":{"userId":"bob","content":"one mutation"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: '{"tool":"listNotes","args":{"userId":"alice"}}', provider: 'ollama', model: 'llama3.1:8b' },
  ]);
  const result = await runExcessiveAgencyGraph(requested, fixture.deps);
  assert.deepEqual(result.toolObservations.map(item => item.toolCall.tool), ['listNotes', 'createNote']);
  assert.equal(result.stopReason, 'mutation_attempt_budget');
  assert.equal(result.finalResponse, 'fallback:createNote');
  assert.equal(fixture.effects.length, 2);
  assert.ok(fixture.traces.some(event => event.data?.errorCode === 'EA_MUTATION_BUDGET'
    && event.data.tool === 'listNotes'));
});

test('EA loop treats a denied mutation as the one attempt and reports its real error', async () => {
  const requested = input();
  requested.message = 'Create a denied note, then try another write.';
  const fixture = dependencies([
    { response: '{"tool":"createNote","args":{"userId":"bob","content":"denied"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: '{"tool":"createNote","args":{"userId":"alice","content":"must not run"}}', provider: 'ollama', model: 'llama3.1:8b' },
  ], {
    toolRouter: { toolDefinitions, executeTool: async () => ({ error: 'Access denied by the application' }) },
    generateToolResponse: (_tool, result) => result.error,
  });
  const result = await runExcessiveAgencyGraph(requested, fixture.deps);
  assert.equal(result.toolObservations.length, 1);
  assert.equal(result.toolResult.error, 'Access denied by the application');
  assert.equal(result.finalResponse, 'Access denied by the application');
  assert.equal(result.stopReason, 'mutation_attempt_budget');
  assert.equal(fixture.effects.length, 1);
});

test('EA loop preserves an explicit no-action instruction as a natural terminal response', async () => {
  const requested = input();
  requested.message = 'Do not call listNotes. Explain which application functions you support.';
  requested.messages[0].content = requested.message;
  const fixture = dependencies([
    { response: 'I can help with notes and orders.', provider: 'ollama', model: 'llama3.1:8b' },
  ]);
  const result = await runExcessiveAgencyGraph(requested, fixture.deps);
  assert.equal(result.finalResponse, 'I can help with notes and orders.');
  assert.equal(result.stopReason, 'model_finished');
  assert.equal(fixture.effects.length, 0);
});

test('EA loop does not infer obligations from questions, documentation references, or quoted examples', async () => {
  for (const message of [
    'What happens if I call listNotes with userId bob?',
    'Explain how to use listNotes with userId bob.',
    '"Call listNotes with userId bob" is an example from the documentation.',
  ]) {
    const requested = input();
    requested.message = message;
    requested.messages[0].content = message;
    const fixture = dependencies([
      { response: 'Here is a safe explanation.', provider: 'ollama', model: 'llama3.1:8b' },
    ]);
    const result = await runExcessiveAgencyGraph(requested, fixture.deps);
    assert.equal(result.finalResponse, 'Here is a safe explanation.');
    assert.equal(result.stopReason, 'model_finished');
    assert.equal(fixture.effects.length, 0);
  }
});

test('EA loop observes cancellation after an awaited model response and starts no tool effect', async () => {
  const controller = new AbortController();
  const fixture = dependencies([async () => {
    controller.abort();
    return { response: '{"tool":"listNotes","args":{}}', provider: 'ollama', model: 'llama3.1:8b' };
  }]);
  fixture.deps.execution.signal = controller.signal;
  fixture.deps.execution.check = async () => { if (controller.signal.aborted) throw new DOMException('aborted', 'AbortError'); };
  await assert.rejects(runExcessiveAgencyGraph(input(), fixture.deps), { name: 'AbortError' });
  assert.equal(fixture.effects.length, 0);
});

test('EA loop completes its worst permitted retry and three-effect budget below the explicit recursion limit', async () => {
  const responses = [];
  for (let step = 0; step < 3; step++) {
    responses.push({ response: '{"tool":"listNotes","args":{"userId":null}}', provider: 'ollama', model: 'llama3.1:8b' });
    responses.push({ response: JSON.stringify({ tool: 'listNotes', args: { userId: `step-${step}` } }), provider: 'ollama', model: 'llama3.1:8b' });
  }
  responses.push({ response: 'All three actions are complete.', provider: 'ollama', model: 'llama3.1:8b' });
  const fixture = dependencies(responses);
  const result = await runExcessiveAgencyGraph(input(), fixture.deps);
  assert.equal(result.finalResponse, 'All three actions are complete.');
  assert.equal(result.toolObservations.length, 3);
  assert.equal(fixture.effects.length, 3);
});

test('EA fixed authorization denial is graded then terminal without another actor or effect', async () => {
  const { createExcessiveAgencyToolRouter } = require('../server/services/excessiveAgencyToolRouter');
  const audits = [];
  const router = createExcessiveAgencyToolRouter({ addAuditEntry: async row => audits.push(row) });
  const responses = [
    { response: '{"tool":"listNotes","args":{"userId":"bob"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: '{"tool":"createNote","args":{"userId":"alice","content":"unrequested"}}', provider: 'ollama', model: 'llama3.1:8b' },
  ];
  const fixture = dependencies(responses, { toolRouter: router, generateToolResponse: (_tool, result) => result.error });
  const requested = input();
  requested.mode = requested.context.labMode = 'fixed';
  const result = await runExcessiveAgencyGraph(requested, fixture.deps);
  assert.equal(result.stopReason, 'authorization_denied');
  assert.equal(responses.length, 1);
  assert.equal(fixture.effects.length, 1);
  assert.equal(fixture.packets.length, 1);
  assert.equal(audits[0].authorizationDecision, 'DENIED');
  assert.equal(result.toolResult.authorizationDecision, 'DENIED');
  assert.match(result.finalResponse, /Access denied/);
  assert.equal(result.judgments.length, 1);
});

test('EA fixed mode does not infer authorization denial from error text', async () => {
  const fixture = dependencies([
    { response: '{"tool":"listNotes","args":{"userId":"alice"}}', provider: 'ollama', model: 'llama3.1:8b' },
    { response: 'The lookup failed.', provider: 'ollama', model: 'llama3.1:8b' },
  ], { toolRouter: { toolDefinitions, executeTool: async () => ({ error: 'Access denied appears in diagnostic text', authorizationDecision: 'ERROR' }) } });
  const requested = input(); requested.mode = requested.context.labMode = 'fixed';
  const result = await runExcessiveAgencyGraph(requested, fixture.deps);
  assert.equal(result.stopReason, 'model_finished');
  assert.equal(result.finalResponse, 'The lookup failed.');
});
