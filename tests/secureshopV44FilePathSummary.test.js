'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { prepareJudgeInput, createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createBoundFilePathSummaryGraph, SUMMARY_TOOL, PURPOSE }
  = require('../server/services/secureshopBoundFilePathSummaryGraph');
const { createFilePathSummaryExecutionConfig }
  = require('../server/services/secureshopV44FilePathSummaryExecutionConfig');
const { createV44FilePathSummarySourceReader }
  = require('../server/services/secureshopV44FilePathSummarySourceReader');
const { projectFilePathSummaryTurn }
  = require('../server/services/secureshopV44FilePathSummarySavedTurn');
const { createBoundFilePathSummaryRouter }
  = require('../server/routes/secureshop/boundFilePathSummary');
const { createFilePathSummaryApplication }
  = require('../server/services/secureshopV44FilePathSummaryApplication');
const { FILE_PATH_OBJECTIVE, FILE_PATH_PURPOSE, FILE_PATH_RUBRIC,
  buildFilePathTraversalCandidate, createFilePathTraversalJudgeGuard }
  = require('../server/services/secureshopV44FilePathTraversalEvidence');
const sha = value => createHash('sha256').update(value).digest('hex');

function graphFixture(mode = 'vuln', fileOverride = {}) {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 2,
    platformOwnerId: 17, platformSessionId: 23 };
  const persona = { id: 31, role: 'customer' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const input = { scope, persona, personaSession, sessionId: randomUUID(), requestId: randomUUID(),
    message: 'Read and summarize the requested synthetic file.', path: '../etc/passwd' };
  let leased = false;
  const events = [];
  const target = createSceneBinding({ ...scope, targetId: randomUUID() }, { sceneId: randomUUID(),
    sceneGeneration: 1, grantId: randomUUID(), execution: scope, async withLease(work) {
      assert.equal(leased, false); leased = true; events.push('lease');
      try { return await work(); } finally { leased = false; events.push('release'); }
    } });
  const snapshot = { version: 1, featureId: 'file_path_summary',
    policyVersion: 'owned-synthetic-file-path-summary-v1', mode, generation: 1,
    modeStamp: 'a'.repeat(64), scope };
  const body = Buffer.from('root:x:0:0:synthetic-root:/root:/bin/false\n');
  const fileTargetId = randomUUID();
  let reads = 0, invoke, config, previous, readArguments;
  const check = async () => {};
  const execution = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', input.sessionId]),
    durableGeneration: '7', check, checkAtEffect: check };
  const dependencies = {
    launches: { assertCurrent: check, async reserveFilesTarget() {
      assert.equal(leased, false); events.push('reserve'); return { kind: 'files',
      targetId: fileTargetId, launchId: scope.launchId, scenarioId: scope.scenarioId,
      generation: scope.generation }; } }, conversationRepository: {}, journal: {}, coordinator: { run() {} },
    provider: { async chat() { return { provider: 'controlled-provider', model: 'controlled-model', mocked: false }; },
      async finalResponse() { return { provider: 'controlled-provider', model: 'controlled-model', mocked: false }; } },
    files: { async provisionReservedTarget(binding) {
      assert.equal(leased, false); events.push('provision'); return { ...binding, capability: 'private-capability' }; },
      async readFile(capability, path, options) { reads++; readArguments = { capability, path, options };
        assert.equal(leased, true); events.push('read');
        return { generation: scope.generation, virtualPath: '/etc/passwd', bytes: body.length,
          sha256: sha(body), data: Buffer.from(body), ...fileOverride }; } },
    scenes: { async readExisting() { return target; } },
    modeAuthority: { async capture() { return { snapshot, assertCurrent: check, assertCurrentAtEffect: check }; },
      assertToken: value => value },
    personaAuthority: { async capture() { return { binding: { ...scope, personaId: persona.id,
      role: persona.role, ...personaSession }, assertRemoteAdmission: check,
      withPersonaEffect: work => work({}) }; } },
    toolPolicyRepository: { admitTool() {} },
    toolPolicyAdmissionFactory({ workflow, declaredTools }) {
      assert.equal(workflow, 'file-path-summary'); assert.equal(declaredTools[0].tool, 'summarize_file');
      return async () => ({ allowed: true, action: 'dispatch', enforcement: true, policyViolation: null });
    },
    runnerFactory(options) {
      config = options;
      return { async run(args) {
        if (previous) return previous;
        await options.provider.chat({});
        const tools = await options.createLocalTools(null, null, args.localToolAuthority, execution);
        invoke = tools.get(SUMMARY_TOOL);
        const result = await invoke({ path: input.path });
        const observation = { tool: SUMMARY_TOOL, step: 1, callId: 'read-owned', args: { path: input.path }, result,
          effectReceipt: { runId: execution.runId, ownerKey: execution.ownerKey, generation: '7', status: 'completed',
            effectKey: `${input.requestId}:${JSON.stringify([1, 'read-owned', SUMMARY_TOOL])}` } };
        await options.observeLocalTool({ observation, run: execution });
        const traces = Array.from({ length: 6 }, () => ({ event_id: randomUUID() }));
        const taskMetadata = await options.resultMetadata({ result: { stopReason: 'end_turn' }, execution, traces });
        previous = { text: body.toString('utf8'), stopReason: 'end_turn', steps: 2,
          hops: [{ step: 1, tool: SUMMARY_TOOL, params: { path: input.path }, result,
            latencyMs: 1, error: null, policyViolation: null }], taskMetadata };
        return previous;
      } };
    },
  };
  return { input, dependencies, events, execution, get reads() { return reads; }, get readArguments() { return readArguments; }, get invoke() { return invoke; },
    get config() { return config; }, graph: createBoundFilePathSummaryGraph(dependencies) };
}

test('V44 config exposes only exact path args and graph persists the physical owned read receipt', async () => {
  const config = createFilePathSummaryExecutionConfig({ mode: 'vuln' });
  assert.deepEqual(config.manifest.getForRole('merchant'), []);
  assert.deepEqual(config.manifest.getForRole('customer')[0].inputSchema.required, ['path']);
  assert.equal(config.manifest.getForRole('customer')[0].inputSchema.additionalProperties, false);
  const f = graphFixture();
  const result = await f.graph.run(f.input);
  const meta = result.taskMetadata.boundFilePathSummary;
  assert.equal(f.config.conversationPurpose, PURPOSE);
  assert.equal(meta.outcome, 'read');
  assert.equal(meta.readReceipt.requestedPath, '../etc/passwd');
  assert.equal(meta.readReceipt.resolvedPath, '/etc/passwd');
  assert.equal(meta.readReceipt.bodySha256, sha(Buffer.from(result.text)));
  assert.equal(meta.readReceipt.receiptSha256, canonicalDigest((({ receiptSha256, ...rest }) => rest)(meta.readReceipt)));
  assert.equal(JSON.stringify(projectFilePathSummaryTurn({ sessionId: f.input.sessionId,
    requestId: f.input.requestId, result })).includes(meta.readReceipt.targetId), false);
  assert.equal(f.reads, 1);
  assert.deepEqual(f.events, ['reserve', 'provision', 'lease', 'read', 'release']);
  await assert.rejects(f.invoke({}), { code: 'FILE_PATH_SUMMARY_INVALID_ARGUMENT' });
  await assert.rejects(f.invoke({ path: f.input.path }), { code: 'FILE_PATH_SUMMARY_EFFECT_REPLAY_FORBIDDEN' });
});

test('V44 rejects stale physical generations, changed paths, non-Buffer data and inconsistent bytes before retaining a receipt', async () => {
  for (const override of [{ generation: 1 }, { virtualPath: '/uploads/passwd' },
    { data: 'root:x:0:0:synthetic-root:/root:/bin/false\n' }, { bytes: 1 },
    { sha256: 'b'.repeat(64) }, { data: Buffer.from('changed content') }]) {
    const f = graphFixture('vuln', override);
    await assert.rejects(f.graph.run(f.input), { code: 'FILE_PATH_SUMMARY_EFFECT_MISMATCH' });
    assert.equal(f.reads, 1);
  }
});

test('fixed mode denies traversal before the reserved reader and no receipt can be manufactured', async () => {
  const f = graphFixture('fixed');
  const result = await f.graph.run(f.input);
  assert.equal(result.taskMetadata.boundFilePathSummary.outcome, 'no_tool');
  assert.equal(result.taskMetadata.boundFilePathSummary.readReceipt, undefined);
  assert.equal(JSON.stringify(result.hops[0].result).includes('outside owned uploads'), true);
  assert.equal(f.reads, 0);
});

test('V44 final-response transition requires the exact verified local observation', async () => {
  for (const mode of ['vuln', 'fixed']) {
    const f = graphFixture(mode), result = await f.graph.run(f.input);
    const hop = result.hops[0];
    const observation = { tool: SUMMARY_TOOL, callId: 'read-owned', step: 1,
      args: hop.params, result: hop.result };
    const execution = f.execution;
    assert.equal(f.config.enterFinalResponseAfterLocalTool({ observation, execution }), true);
    for (const changed of [{ ...observation, tool: 'other.tool' },
      { ...observation, callId: 'foreign-call' }, { ...observation, step: 2 },
      { ...observation, args: { path: 'other.txt' } },
      { ...observation, result: { content: [] } }]) {
      assert.throws(() => f.config.enterFinalResponseAfterLocalTool({ observation: changed, execution }),
        { code: 'FILE_PATH_SUMMARY_EFFECT_MISMATCH' });
    }
  }
});

test('production BoundAgentRunner finishes vulnerable reads and fixed denials with a genuine answer-only response', async () => {
  const { createBoundAgentRunner } = require('../server/services/secureshopBoundAgentRunner');
  for (const { mode, invalidFinal } of ['vuln', 'fixed'].flatMap(mode =>
    [{ mode, invalidFinal: false }, { mode, invalidFinal: true }])) {
    const f = graphFixture(mode), messages = [], traces = [], requests = new Map(), modelInputs = [];
    const identity = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation',
      f.input.sessionId]), generation: 7, durableGeneration: '7' };
    const binding = { ...f.input.scope, shopUserId: f.input.persona.id, role: 'customer' };
    const finalText = mode === 'fixed' ? 'The path is outside the owned uploads directory.'
      : 'The synthetic account record is root:x:0:0:synthetic-root:/root:/bin/false';
    const dependencies = { ...f.dependencies,
      runnerFactory: createBoundAgentRunner,
      provider: { async chat(args) {
        assert.equal(modelInputs.length, 0, 'Only the first decision may offer a tool');
        modelInputs.push({ method: 'chat', ...structuredClone(args) });
        return { provider: 'controlled-provider', model: 'controlled-model', mocked: false, fallback: false,
          stop_reason: 'tool_use', tool_uses: [{ id: 'selected-path', name: SUMMARY_TOOL,
            args: { path: f.input.path } }] };
      }, async finalResponse(args) {
        assert.equal(modelInputs.length, 1);
        assert.equal(args.tools, undefined);
        assert.match(args.system, /do not request another tool/);
        const observation = JSON.parse(args.messages.at(-1).content);
        if (mode === 'fixed') {
          assert.deepEqual(observation, { path: f.input.path, error: 'path outside owned uploads directory' });
          assert.equal(f.reads, 0);
        } else {
          assert.match(observation.body, /root:x:0:0:synthetic-root/);
          assert.equal(f.reads, 1);
        }
        modelInputs.push({ method: 'finalResponse', ...structuredClone(args) });
        return { provider: 'controlled-provider', model: 'controlled-model', mocked: false, fallback: false,
          responseMode: 'structured_final', stop_reason: invalidFinal ? 'tool_use' : 'end_turn',
          text: finalText, ...(invalidFinal ? { tool_uses: [{ id: 'repeat-path', name: SUMMARY_TOOL,
            args: { path: f.input.path } }] } : {}) };
      } },
      coordinator: { async run(_id, _options, work) {
        return work(Object.freeze({ ...identity, async check() {},
          async effectWithReceipt(key, callback) { return { value: await callback(),
            receipt: { ...identity, generation: '7', effectKey: `${f.input.requestId}:${key}`,
              status: 'completed' } }; } }));
      } },
      conversationRepository: {
        async getBoundSession(id) { return { id, state: 'active', purpose: PURPOSE, binding }; },
        async getMessages() { return structuredClone(messages); },
        async appendMessage(_id, _binding, message) { messages.push(structuredClone(message)); },
        async getTokens() { return 0; }, async addTokens() {},
        async appendTraces(_id, _binding, rows) { traces.push(...rows); },
      },
      journal: {
        async claim({ requestId }) {
          if (requests.has(requestId)) return structuredClone(requests.get(requestId));
          requests.set(requestId, { status: 'started', claimId: requestId });
          return { status: 'claimed', claimId: requestId };
        },
        async complete({ requestId, result }) {
          requests.set(requestId, { status: 'completed', claimId: requestId,
            result: structuredClone(result) });
        },
        async markUncertain({ requestId }) { requests.get(requestId).status = 'uncertain'; },
      },
      toolPolicyAdmissionFactory: () => async policy => ({ admissionId: randomUUID(),
        runId: policy.runId, invocationId: policy.invocationId, toolKey: SUMMARY_TOOL,
        policyVersion: '1', registrySha256: 'a'.repeat(64), enforcement: true, allowed: true,
        action: 'dispatch', policyViolation: null }),
    };
    const graph = createBoundFilePathSummaryGraph(dependencies);
    if (invalidFinal) {
      await assert.rejects(graph.run(f.input), { code: 'FILE_PATH_SUMMARY_EFFECT_MISMATCH' });
      assert.deepEqual(modelInputs.map(row => row.method), ['chat', 'finalResponse']);
      assert.equal(f.reads, mode === 'fixed' ? 0 : 1);
      assert.equal(traces.filter(row => row.kind === 'local_tool_call').length, 1);
      assert.equal(requests.get(f.input.requestId).status, 'uncertain');
      continue;
    }
    const result = await graph.run(f.input);
    assert.equal(result.text, finalText);
    assert.equal(result.taskMetadata.boundFilePathSummary.outcome, mode === 'fixed' ? 'no_tool' : 'read');
    assert.equal(modelInputs.length, 2);
    assert.deepEqual(modelInputs.map(row => row.method), ['chat', 'finalResponse']);
    assert.equal(f.reads, mode === 'fixed' ? 0 : 1);
    assert.equal(traces.filter(row => row.kind === 'model_decision').length, 2);
    assert.equal(requests.get(f.input.requestId).status, 'completed');
    assert.deepEqual(await graph.run(f.input), { ...result, replayed: true });
    assert.equal(modelInputs.length, 2);
    assert.equal(f.reads, mode === 'fixed' ? 0 : 1);
    assert.deepEqual(f.events, mode === 'fixed' ? [] : ['reserve', 'provision', 'lease', 'read', 'release']);
  }
});

test('retained source reader reopens exact existing target without reserve or provision', async () => {
  const f = graphFixture(); const result = await f.graph.run(f.input);
  const receipt = result.taskMetadata.boundFilePathSummary.readReceipt;
  let reserve = 0, provision = 0, lookup = 0, open = 0, read = 0;
  const reader = createV44FilePathSummarySourceReader({
    launches: { async readExistingFilesTarget() { lookup++; return { kind: 'files', targetId: receipt.targetId,
      launchId: receipt.launchId, scenarioId: receipt.scenarioId, generation: receipt.generation }; },
      async reserveFilesTarget() { reserve++; } },
    files: { async openExistingReservedTarget(binding) { open++; return { ...binding, capability: 'private-capability' }; },
      async provisionReservedTarget() { provision++; }, async readFile(capability, path, options) { read++;
        assert.equal(capability, 'private-capability'); assert.equal(path, receipt.requestedPath);
        assert.equal(options.base, '/uploads'); const data = Buffer.from(result.text);
        return { data, bytes: data.length, sha256: sha(data), virtualPath: receipt.resolvedPath,
          generation: receipt.generation }; } },
  });
  const target = await f.dependencies.scenes.readExisting();
  const stale = Object.assign(Error('Launch generation retired'), { code: 'STALE_LAUNCH' });
  const assertStaleLaunch = async () => { throw stale; };
  await assert.rejects(reader.read({ scope: f.input.scope, receipt, target,
    mode: receipt.authority.mode, check: assertStaleLaunch, checkAtEffect: assertStaleLaunch }),
  error => error === stale && error.code === 'STALE_LAUNCH');
  assert.deepEqual({ reserve, provision, lookup, open, read },
    { reserve: 0, provision: 0, lookup: 0, open: 0, read: 0 });
  const retained = await reader.read({ scope: f.input.scope, receipt, target,
    mode: receipt.authority.mode, check: async () => {}, checkAtEffect: async () => {} });
  assert.equal(retained.data.toString(), result.text);
  assert.deepEqual({ reserve, provision, lookup, open, read },
    { reserve: 0, provision: 0, lookup: 1, open: 1, read: 1 });
});

function evidenceFixture(requestedPath = '../etc/passwd') {
  const f = graphFixture(); const { input } = f;
  const scope = input.scope; const binding = { ...scope, shopUserId: input.persona.id, role: 'customer' };
  const body = Buffer.from('root:x:0:0:synthetic-root:/root:/bin/false\n');
  const operationId = randomUUID();
  const authority = { scope, persona: input.persona, personaSession: input.personaSession,
    sessionId: input.sessionId, requestId: input.requestId,
    scene: { sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID(), execution: scope },
    sceneTargetId: randomUUID(), mode: { version: 1, featureId: 'file_path_summary',
      policyVersion: 'owned-synthetic-file-path-summary-v1', mode: 'vuln', generation: 1,
      modeStamp: 'a'.repeat(64), scope } };
  const receiptBody = { version: 1, operationId, requestedPath, resolvedPath: '/etc/passwd',
    targetId: randomUUID(), launchId: scope.launchId, scenarioId: scope.scenarioId, generation: scope.generation,
    byteCount: body.length, bodySha256: sha(body), authority };
  const receipt = { ...receiptBody, receiptSha256: canonicalDigest(receiptBody) };
  const originalEnvelope = JSON.stringify({ version: 1, message: input.message, path: requestedPath,
    operationId, authoritySha256: canonicalDigest(authority) });
  const result = { content: [{ type: 'text', text: JSON.stringify({ path: requestedPath,
    cleaned_path: requestedPath.replace(/\.\.\//g, ''), extension: '', body: body.toString(),
    summary: `File ${requestedPath} contents:\n\n${body}` }) }] };
  const ownerKey = JSON.stringify(['SecureShopBoundConversation', input.sessionId]);
  const runId = randomUUID(), callId = 'read-owned';
  const effectKey = `${input.requestId}:${JSON.stringify([1, callId, SUMMARY_TOOL])}`;
  const ids = Array.from({ length: 6 }, randomUUID);
  const model = { model: 'real-model', mocked: false };
  const trace = (i, value) => ({ event_id: ids[i], session_id: input.sessionId, ...value });
  const response = `The synthetic account record is ${body.toString().trim()}`;
  const traces = [
    trace(0, { kind: 'model_decision', actor: 'supervisor', step: 1, provider: 'real-provider',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: callId, name: SUMMARY_TOOL,
        args: { path: requestedPath } }] }), result_json: JSON.stringify(model) }),
    trace(1, { kind: 'local_tool_call', actor: 'supervisor→task', step: 1, agent_ns: 'summarizer',
      tool_name: 'summarize_file', params_json: JSON.stringify({ path: requestedPath }) }),
    trace(2, { kind: 'local_tool_result', actor: 'task→supervisor', step: 1, agent_ns: 'summarizer',
      tool_name: 'summarize_file', result_json: JSON.stringify(result) }),
    trace(3, { kind: 'model_decision', actor: 'supervisor', step: 2, provider: 'real-provider',
      result_json: JSON.stringify({ ...model, decision: 'final', text: response }) }),
    trace(4, { kind: 'final', actor: 'supervisor', step: 2 }),
    trace(5, { kind: 'terminal', actor: 'supervisor', step: 2, provider: 'real-provider',
      result_json: JSON.stringify({ ...model, stopReason: 'end_turn', steps: 2, hops: 1 }) }),
  ];
  const turn = { stopReason: 'end_turn', steps: 2, text: response,
    hops: [{ step: 1, tool: SUMMARY_TOOL, params: { path: requestedPath }, result,
      latencyMs: 1, error: null, policyViolation: null }],
    taskMetadata: { boundFilePathSummary: { version: 1, originalEnvelope, operationId, outcome: 'read',
      traceEventIds: ids, readReceipt: structuredClone(receipt), toolResultSha256: canonicalDigest(result),
      graphEffect: { runId, ownerKey, generation: '0', effectKey, status: 'completed', step: 1, callId } } } };
  const row = { session_id: input.sessionId, request_id: input.requestId, status: 'completed', request_version: 1,
    request_hash: createTurnRequest({ sessionId: input.sessionId, requestId: input.requestId,
      binding, message: originalEnvelope }).hash, result_json: turn };
  return { binding, personaSession: input.personaSession, row, traces,
    graphEffect: { run_id: runId, owner_key: ownerKey, generation: '0', effect_key: effectKey,
      status: 'completed', run_status: 'completed', live_generation: '0' },
    retained: { receipt, data: body }, qualifyModel: () => true };
}

test('V44 candidate proves exact owned traversal and leaves disclosure semantics to the canonical Judge', async () => {
  const f = evidenceFixture(); const candidate = buildFilePathTraversalCandidate(f);
  assert.equal(candidate.objectiveId, FILE_PATH_OBJECTIVE);
  assert.equal(FILE_PATH_PURPOSE, 'secureshop_file_path_summary');
  assert.equal(FILE_PATH_RUBRIC.version, 'secureshop-file-path-traversal-read-v1');
  assert.equal(candidate.evidence[0].content.requestedPath, '../etc/passwd');
  assert.ok(buildFilePathTraversalCandidate(evidenceFixture('../../etc/passwd')));
  assert.equal(candidate.evidence[1].content.body, f.retained.data.toString());
  const final = f.traces.find(row => row.kind === 'model_decision' && row.step === 2);
  final.result_json = JSON.stringify({ ...JSON.parse(final.result_json), stopReason: 'end_turn',
    providerAttempts: 1 });
  assert.deepEqual(buildFilePathTraversalCandidate(f), candidate,
    'Existing answer-only final trace preserves historical candidate bytes and rubric');
  let calls = 0;
  const guard = createFilePathTraversalJudgeGuard(async input => { calls++; assert.equal(input, input); return { verdict: 'pass' }; });
  const normalized = JSON.parse(prepareJudgeInput({ rubric: FILE_PATH_RUBRIC, ...candidate }).packet);
  assert.equal((await guard(normalized)).verdict, 'pass');
  assert.equal(calls, 1);
  assert.equal((await guard({ rubric: FILE_PATH_RUBRIC, ...candidate })).verdict, 'fail');
  assert.equal(calls, 1);
  f.row.result_json.text = 'Only a path name, without content.';
  assert.equal(buildFilePathTraversalCandidate(f), null);
});

test('V44 canonical Judge cannot satisfy disclosure with a source-only citation', async () => {
  const candidate = buildFilePathTraversalCandidate(evidenceFixture());
  const normalized = JSON.parse(prepareJudgeInput({ rubric: FILE_PATH_RUBRIC, ...candidate }).packet);
  let calls = 0;
  const judge = createObjectiveJudge({ model: { async generate() { calls++;
    return { response: JSON.stringify({ satisfied: true, citations: [{ evidenceId: 'file_path_source',
      quote: 'root:x:0:0:synthetic-root' }] }), provider: 'controlled', model: 'controlled-source-only',
      mocked: false, fallback: false }; } } });
  const result = await createFilePathTraversalJudgeGuard(judge)({ ...normalized,
    execution: { runId: randomUUID() } });
  assert.notEqual(result.verdict, 'pass');
  assert.ok(calls >= 1 && calls <= 4);
});

test('V44 JSON route forwards only the exact learner path and saved route projects no private target', async () => {
  const f = graphFixture(); const result = await f.graph.run(f.input);
  const projected = projectFilePathSummaryTurn({ sessionId: f.input.sessionId,
    requestId: f.input.requestId, result, replayed: true });
  let runInput, savedInput;
  const router = createBoundFilePathSummaryRouter({
    launches: { resolveCapability() {} }, authenticatePersona() {}, modeAuthority: { capture() {}, assertToken() {} },
    graph: { createSession() {}, async run(input) { runInput = input; return result; } },
    saved: { async read(input) { savedInput = input; return projected; } },
    assessment: { runAttempt() {}, readOutcome() {} },
  });
  const handler = (method, route) => router.stack.find(layer => layer.route?.methods[method]
    && layer.route.path === route).route.stack.at(-1).handle;
  const request = body => Object.assign(new EventEmitter(), { ssLaunch: f.input.scope,
    ssUser: f.input.persona, ssPersonaSession: f.input.personaSession, body, query: {}, params: {},
    is: value => value === 'application/json', aborted: false });
  const response = () => Object.assign(new EventEmitter(), { destroyed: false, writableEnded: false, writes: [],
    status(code) { this.code = code; return this; }, json(value) { this.writes.push(value); return this; } });
  const runReq = request({ sessionId: f.input.sessionId, requestId: f.input.requestId,
    message: f.input.message, path: '../../etc/passwd' });
  const runRes = response();
  await handler('post', '/agents/customer/file-path-summary/run')(runReq, runRes);
  assert.equal(runRes.code, 200); assert.equal(runInput.path, '../../etc/passwd');
  assert.deepEqual(Object.keys(runInput).sort(), ['message', 'path', 'persona', 'personaSession',
    'requestId', 'scope', 'sessionId', 'signal'].sort());
  assert.equal(JSON.stringify(runRes.writes[0]).includes(result.taskMetadata.boundFilePathSummary.readReceipt.targetId), false);
  const getReq = request({}); getReq.params = { sessionId: f.input.sessionId, requestId: f.input.requestId };
  const getRes = response();
  await handler('get', '/agents/customer/file-path-summary/requests/:sessionId/:requestId')(getReq, getRes);
  assert.equal(getRes.code, 200); assert.equal(savedInput.sessionId, f.input.sessionId);
  assert.deepEqual(getRes.writes, [projected]);
  const badReq = request({ sessionId: f.input.sessionId, requestId: f.input.requestId,
    message: f.input.message, path: '../../etc/passwd', capability: 'forbidden' });
  const badRes = response();
  await handler('post', '/agents/customer/file-path-summary/run')(badReq, badRes);
  assert.equal(badRes.code, 400);
});

test('V44 production application factory constructs the complete graph, saved reader, assessment and router', () => {
  const query = async () => ({ rows: [] }); const noop = async () => {};
  const application = createFilePathSummaryApplication({
    identityPool: { query }, agentsPool: { query, async connect() { return { query, release() {} }; } },
    launches: { assertCurrent: noop, reserveFilesTarget: noop, readExistingFilesTarget: noop,
      resolveCapability: noop },
    files: { provisionReservedTarget: noop, openExistingReservedTarget: noop, readFile: noop },
    conversationRepository: { getBoundSession: noop, acquireBoundSession: noop, getTraceEvents: noop },
    coordinator: { run: noop }, journal: { claim: noop, complete: noop, markUncertain: noop },
    personaAuthority: { capture: noop }, personaBindings: { capture: noop },
    scenes: { readExisting: noop, readRetained: noop },
    modeAuthority: { capture: noop, assertToken: noop },
    receipts: { beginEvaluation: noop, recordVerdict: noop },
    progress: { getGeneration: noop }, publicationModes: { getEvaluationScope: noop },
    provider: { chat: noop, finalResponse: noop }, toolPolicyRepository: { admitTool: noop },
    judge: noop, qualifyModel: () => true, authenticatePersona() {},
  });
  assert.equal(application.ready, true);
  assert.equal(typeof application.graph.run, 'function');
  assert.equal(typeof application.saved.read, 'function');
  assert.equal(typeof application.assessment.runAttempt, 'function');
  assert.equal(typeof application.router, 'function');
});
