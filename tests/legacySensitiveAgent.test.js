'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createLegacySensitiveAgent, parseDecision } = require('../server/services/legacySensitiveAgent');
const { runDecisionObserveGraph } = require('../server/agent-runtime/decisionObserveGraph');

function ownerExecution({ check = async () => {} } = {}) {
  const events = [];
  return {
    runId: '11111111-1111-4111-8111-111111111111',
    ownerKey: '["LegacySensitiveInfo","41"]',
    durableGeneration: '7',
    check,
    trace: async event => events.push(event),
    effectWithReceipt: async (node, callback) => ({
      value: await callback(),
      receipt: { version: 1, runId: '11111111-1111-4111-8111-111111111111',
        ownerKey: '["LegacySensitiveInfo","41"]', generation: '7',
        effectKey: `11111111-1111-4111-8111-111111111111:${node}`, status: 'completed' },
    }),
    events,
  };
}

function modelFixture(first, second) {
  const calls = [];
  const model = {
    async generateResponse(prompt) {
      calls.push(prompt);
      return calls.length === 1 ? { response: first, provider: 'fixture', model: 'fixture-model' }
        : calls.length === 2 ? { response: '{"action":"finish","params":{}}', provider: 'fixture', model: 'fixture-model' }
        : { response: second, provider: 'fixture', model: 'fixture-model' };
    },
  };
  return { model, calls };
}

test('qualified structured decision executes exact selected args and grounds a subsequent model response', async () => {
  const { model, calls } = modelFixture(
    JSON.stringify({ action: 'read_teaching_file', params: { path: '../secret/flag.txt' } }),
    'The observed teaching file contained the lab flag.',
  );
  const invocations = [];
  const tools = {
    readTeachingFile(params) { invocations.push(params); return { success: true, path: params.path, content: 'FLAG: fixture' }; },
    renderSsiTemplate() { throw new Error('wrong tool'); },
  };
  const execution = ownerExecution();
  const agent = createLegacySensitiveAgent({ model, tools,
    qualifyModel: ({ provider, result }) => provider === model && result.provider === 'fixture' && result.model === 'fixture-model' });
  const result = await agent.run({ message: 'Read the protected teaching file', execution });
  assert.equal(result.status, 'completed');
  assert.deepEqual(invocations, [{ path: '../secret/flag.txt', mode: 'vuln' }]);
  assert.match(JSON.stringify(calls[1]), /FLAG: fixture/);
  assert.equal(result.facts.qualified_decision_model, true);
  assert.equal(result.facts.exact_call_observed, true);
  assert.equal(result.facts.subsequent_qualified_model_response, true);
  assert.match(result.callId, /^[a-f0-9]{32}$/);
  assert.match(result.hopDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(result.evidence.find(row => row.id === 'tool_call').content.params, { path: '../secret/flag.txt' });
  assert.deepEqual(execution.events.filter(event => event.type === 'node_start').map(event => event.node),
    ['decide', 'validate', 'execute', 'record_observation', 'decide', 'validate', 'respond', 'finish']);
});

test('fixed mode comes from trusted run authority while decision evidence preserves only model-selected arguments', async () => {
  const { model } = modelFixture(
    '{"action":"read_teaching_file","params":{"path":"../secret/flag.txt"}}',
    'The fixed tool denied this file; its content was not read.',
  );
  const invocations = [];
  const result = await createLegacySensitiveAgent({ model, qualifyModel: () => true,
    tools: { readTeachingFile(params) {
      invocations.push(params);
      return { success: false, code: 'PUBLIC_FILE_ONLY', error: 'Only public teaching files are available' };
    }, renderSsiTemplate() { throw Error('wrong tool'); } },
  }).run({ message: 'Read the file', execution: ownerExecution(), mode: 'fixed' });
  assert.equal(result.status, 'completed');
  assert.deepEqual(invocations, [{ path: '../secret/flag.txt', mode: 'fixed' }]);
  assert.deepEqual(result.evidence.find(row => row.id === 'tool_call').content.params, { path: '../secret/flag.txt' });
  assert.equal(result.observation.success, false);
  assert.equal(result.observation.code, 'PUBLIC_FILE_ONLY');
  assert.equal(Object.hasOwn(result.observation, 'content'), false);
});

test('metadata claims, mock, fallback, and scripted candidates cannot qualify themselves', async t => {
  for (const marker of [{}, { mocked: true }, { fallback: true }, { payloadSelection: 'scripted' }]) {
    await t.test(JSON.stringify(marker), async () => {
      let executed = false;
      const model = { generateResponse: async () => ({ response: '{"action":"read_teaching_file","params":{"path":"../secret"}}',
        provider: 'ollama', model: 'llama3.1:8b', mocked: false, ...marker }) };
      const result = await createLegacySensitiveAgent({ model,
        tools: { readTeachingFile() { executed = true; }, renderSsiTemplate() {} },
        qualifyModel: marker.mocked || marker.fallback || marker.payloadSelection ? () => true : undefined,
      }).run({ message: 'read', execution: ownerExecution() });
      assert.equal(result.status, 'unqualified_model');
      assert.equal(result.qualified, false);
      assert.equal(executed, false);
    });
  }
});

test('malformed, unknown, or extra structured fields fail before tool execution', async t => {
  for (const response of ['not json', '{"action":"unknown","params":{}}',
    ...['constructor', 'toString', '__proto__'].map(action => JSON.stringify({ action, params: {} })),
    '{"action":"read_teaching_file","params":{"path":"x","extra":"y"}}',
    '{"action":"read_teaching_file","params":{"path":"x","mode":"vuln"}}',
    '{"action":"read_teaching_file","params":{"path":"x"},"payload":"scripted"}']) {
    await t.test(response, async () => {
      let executed = false;
      const model = { generateResponse: async () => ({ response }) };
      const agent = createLegacySensitiveAgent({ model,
        tools: { readTeachingFile() { executed = true; }, renderSsiTemplate() {} }, qualifyModel: () => true });
      await assert.rejects(agent.run({ message: 'read', execution: ownerExecution() }), { code: 'MODEL_DECISION_INVALID' });
      assert.equal(executed, false);
    });
  }
});

test('SSI evidence preserves the simulated command boundary', async () => {
  const { model } = modelFixture(
    '{"action":"render_ssi_template","params":{"template":"<!--#exec cmd=\\"whoami\\" -->"}}',
    'The lab simulated the output; no operating-system command ran.',
  );
  const result = await createLegacySensitiveAgent({ model,
    tools: { readTeachingFile() {}, renderSsiTemplate: () => ({ rendered: '<pre>www-data</pre>',
      executionMode: 'lab_ssi_interpreter', commandExecution: 'simulated',
      warning: 'Command output is simulated; no operating-system command was executed.' }) },
    qualifyModel: ({ provider }) => provider === model,
  }).run({ message: 'render', execution: ownerExecution() });
  assert.equal(result.status, 'completed');
  assert.equal(result.facts.ssi_command_simulated, true);
});

test('a missing, fallback, or scripted terminal response cannot become model-grounded success', async t => {
  for (const terminal of [{}, { response: 'fallback', fallback: true },
    { response: 'scripted', decisionSource: 'scripted' }]) {
    await t.test(JSON.stringify(terminal), async () => {
      let calls = 0;
      const model = { generateResponse: async () => ++calls === 1
        ? { response: '{"action":"read_teaching_file","params":{"path":"../secret"}}' }
        : calls === 2 ? { response: '{"action":"finish","params":{}}' } : terminal };
      const result = await createLegacySensitiveAgent({ model,
        tools: { readTeachingFile: () => ({ content: 'FLAG: fixture' }), renderSsiTemplate() {} },
        qualifyModel: ({ provider }) => provider === model,
      }).run({ message: 'read', execution: ownerExecution() });
      assert.equal(result.status, 'unqualified_response');
      assert.equal(result.qualified, false);
      assert.equal(result.facts.subsequent_qualified_model_response, false);
    });
  }
});

test('receipt mismatch and cancellation after the selected effect prevent terminal success', async () => {
  const execution = ownerExecution();
  execution.effectWithReceipt = async (_node, callback) => ({ value: await callback(), receipt: {
    status: 'completed', runId: execution.runId, effectKey: 'wrong-effect' } });
  await assert.rejects(runDecisionObserveGraph({ request: 'read', execution,
    decide: async () => ({ response: 'decision' }), qualifyModel: () => true,
    validateDecision: () => ({ action: 'read', params: { path: 'x' } }),
    executeDecision: async () => ({ content: 'x' }), respond: async () => ({ response: 'done' }),
  }), { code: 'EFFECT_RECEIPT_INVALID' });

  let reset = false;
  const cancelled = ownerExecution({ check: async () => {
    if (reset) throw Object.assign(new Error('reset'), { name: 'AbortError' });
  } });
  const effect = cancelled.effectWithReceipt;
  cancelled.effectWithReceipt = async (node, callback) => {
    const completed = await effect(node, callback);
    reset = true;
    return completed;
  };
  let responded = false;
  await assert.rejects(runDecisionObserveGraph({ request: 'read', execution: cancelled,
    decide: async () => ({ response: 'decision' }), qualifyModel: () => true,
    validateDecision: () => ({ action: 'read', params: { path: 'x' } }),
    executeDecision: async () => ({ content: 'x' }), respond: async () => { responded = true; return { response: 'done' }; },
  }), { name: 'AbortError' });
  assert.equal(responded, false);
});

test('aggregate model and observation evidence is bounded', async () => {
  const execution = ownerExecution();
  await assert.rejects(runDecisionObserveGraph({ request: 'read', execution, maxBytes: 1024,
    decide: async () => ({ response: 'x'.repeat(400) }), qualifyModel: () => true,
    validateDecision: () => ({ action: 'read', params: { path: 'x' } }),
    executeDecision: async () => ({ content: 'y'.repeat(400) }),
    respond: async () => ({ response: 'z'.repeat(400) }),
  }), { code: 'DECISION_EVIDENCE_TOO_LARGE' });
});

test('strict parser accepts a single JSON object or fenced JSON and preserves exact bytes', () => {
  assert.deepEqual(parseDecision({ response: '```json\n{"action":"read_teaching_file","params":{"path":"../a b"}}\n```' }),
    { action: 'read_teaching_file', params: { path: '../a b' } });
});

test('successive decisions consume actual earlier observations before model-selected finish', async () => {
  const prompts = [];
  const answers = [
    '{"action":"read_teaching_file","params":{"path":"guide.txt"}}',
    JSON.stringify({ action: 'render_ssi_template', params: { template: '<!--#echo var="NAME" -->' } }),
    '{"action":"finish","params":{}}',
    'The guide was read and the lab template was rendered.',
  ];
  const model = { generateResponse: async prompt => {
    prompts.push(prompt);
    return { response: answers[prompts.length - 1] };
  } };
  const selected = [];
  const result = await createLegacySensitiveAgent({ model, qualifyModel: () => true,
    tools: {
      readTeachingFile: params => { selected.push(params); return { content: 'GUIDE_OBSERVATION_ONLY' }; },
      renderSsiTemplate: params => { selected.push(params); return { rendered: 'RENDER_OBSERVATION_ONLY', commandExecution: 'none' }; },
    },
  }).run({ message: 'Read the guide, then render a greeting using the lab interpreter.', execution: ownerExecution() });
  assert.equal(result.status, 'completed');
  assert.equal(prompts.length, 4);
  assert.doesNotMatch(JSON.stringify(prompts[0]), /GUIDE_OBSERVATION_ONLY/);
  assert.match(JSON.stringify(prompts[1]), /GUIDE_OBSERVATION_ONLY/);
  assert.doesNotMatch(JSON.stringify(prompts[1]), /RENDER_OBSERVATION_ONLY/);
  assert.match(JSON.stringify(prompts[2]), /RENDER_OBSERVATION_ONLY/);
  assert.match(JSON.stringify(prompts[3]), /GUIDE_OBSERVATION_ONLY/);
  assert.match(JSON.stringify(prompts[3]), /RENDER_OBSERVATION_ONLY/);
  assert.deepEqual(prompts[3].map(row => row.role), ['system', 'user', 'assistant', 'user', 'assistant', 'user', 'assistant', 'user']);
  assert.deepEqual(JSON.parse(prompts[3].at(-2).content), { action: 'finish', params: {} });
  for (let index = 0; index < 2; index += 1) {
    assert.equal(prompts[3][2 + index * 2].content, JSON.stringify(result.trajectory[index].decision));
    assert.equal(prompts[3][3 + index * 2].content, JSON.stringify({ ordinal: index + 1, observation: result.trajectory[index].observation }));
  }
  assert.equal(result.trajectory.length, 2);
  assert.equal(result.decision.action, 'render_ssi_template');
  assert.equal(selected[0].path, 'guide.txt');
  assert.equal(selected[1].template, '<!--#echo var="NAME" -->');
  assert.equal(result.evidence.find(row => row.id === 'decision_trajectory').content.trajectory.length, 2);
});

test('finish is a strict model decision and can answer without executing a tool', async () => {
  assert.deepEqual(parseDecision({ response: '{"action":"finish","params":{}}' }), { action: 'finish', params: {} });
  assert.throws(() => parseDecision({ response: '{"action":"finish","params":{"path":"x"}}' }), { code: 'MODEL_DECISION_INVALID' });
  let calls = 0;
  const model = { generateResponse: async () => ({ response: ++calls === 1
    ? '{"action":"finish","params":{}}' : 'I can explain the tools without using them.' }) };
  const result = await createLegacySensitiveAgent({ model, qualifyModel: () => true,
    tools: { readTeachingFile() { assert.fail('unexpected read'); }, renderSsiTemplate() { assert.fail('unexpected render'); } },
  }).run({ message: 'What can you do?', execution: ownerExecution() });
  assert.equal(result.status, 'no_operation');
  assert.equal(result.decision, null);
  assert.equal(result.trajectory.length, 0);
  assert.equal(result.facts.exact_call_observed, false);
  assert.equal(calls, 2);
});

test('each decision receives the remaining budget and exact completed observations through exhaustion', async () => {
  const prompts = [];
  const observations = [
    { content: 'Line one\n"quoted" \\ path\t café', nested: { note: 'first' } },
    { content: '<!--#echo var="NAME" -->\n', nested: { note: 'second' } },
    { content: 'Trailing whitespace  \n', nested: { note: 'third' } },
  ];
  let executed = 0;
  const model = { generateResponse: async (prompt, options) => {
    if (options.qualificationPhase === 'response') return { response: 'All three observed reads are complete.' };
    prompts.push(prompt);
    return { response: JSON.stringify(prompts.length <= 3
      ? { action: 'read_teaching_file', params: { path: `file-${prompts.length}.txt` } }
      : { action: 'finish', params: {} }) };
  } };
  const result = await createLegacySensitiveAgent({ model, qualifyModel: () => true,
    tools: { readTeachingFile: () => observations[executed++], renderSsiTemplate() { assert.fail('unexpected render'); } },
  }).run({ message: 'Read the three files and explain their contents.', execution: ownerExecution() });
  assert.equal(result.status, 'completed');
  assert.equal(executed, 3);
  assert.equal(prompts.length, 4);
  for (let index = 0; index < prompts.length; index += 1) {
    const messages = prompts[index];
    assert.deepEqual(messages.map(row => row.role), ['system', 'user', ...Array.from({ length: index }, () => ['assistant', 'user']).flat()]);
    assert.ok(messages.every(row => Object.keys(row).sort().join(',') === 'content,role' && typeof row.content === 'string'));
    assert.equal(messages[1].content, 'Read the three files and explain their contents.');
    assert.match(messages[0].content, new RegExp(`Remaining tool calls \\(server budget\\): ${3 - index}\\.`));
    const catalog = JSON.parse(messages[0].content.split('Available actions (data): ')[1].split('\n')[0]);
    assert.deepEqual(Object.keys(catalog).sort(), ['finish', 'read_teaching_file', 'render_ssi_template']);
    assert.deepEqual(catalog.finish.required, []);
    assert.equal(catalog.finish.kind, 'finish');
    for (let hop = 0; hop < index; hop += 1) {
      assert.equal(messages[2 + hop * 2].content, JSON.stringify(result.trajectory[hop].decision));
      assert.equal(messages[3 + hop * 2].content, JSON.stringify({ ordinal: hop + 1, observation: observations[hop] }));
      assert.deepEqual(JSON.parse(messages[3 + hop * 2].content).observation, observations[hop]);
    }
    assert.equal(JSON.stringify(messages).includes('modelDecision'), false);
    assert.equal(JSON.stringify(messages).includes('effectReceipt'), false);
  }
  assert.equal(result.decisions.at(-1).decision.action, 'finish');
  assert.ok(result.trajectory.every(hop => hop.modelDecision && hop.effectReceipt && hop.hopDigest), 'full evidence remains intact');
});

test('SSI evidence rejects unknown or real-command execution claims', () => {
  const { buildLegacySensitiveAgentEvidence } = require('../server/services/legacySensitiveAgent');
  for (const observation of [{ commandExecution: 'executed' }, {}, { commandExecution: 'simulated' }]) {
    assert.equal(buildLegacySensitiveAgentEvidence({ decision: { action: 'render_ssi_template' }, observation })
      .facts.ssi_command_simulated, false);
  }
  assert.equal(buildLegacySensitiveAgentEvidence({ decision: { action: 'render_ssi_template' },
    observation: { commandExecution: 'none' } }).facts.ssi_command_simulated, true);
});
