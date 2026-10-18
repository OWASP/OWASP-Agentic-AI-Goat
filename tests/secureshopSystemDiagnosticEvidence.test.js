'use strict';

// Controlled acceptance contract only. Synthetic traces/receipts below are NOT
// executor, model, Judge, browser, PostgreSQL or objective-credit evidence.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const proposalCodec = require('../server/services/secureshopRoleSystemDiagnosticProposal');
const { VERSION, diagnosticCommand, diagnosticRequestDigest } = require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const { bindDiagnosticResult, validateBoundDiagnosticResult, diagnosticHostname } = require('../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const { createBoundSystemDiagnosticService } = require('../server/services/secureshopBoundSystemDiagnosticService');
const evidence = require('../server/services/secureshopSystemDiagnosticEvidence');
const TEMPLATE = '/usr/bin/printf';
const ARGS = "'diagnostic-baseline\\n'; /usr/bin/uname -n";
const BASELINE = 'diagnostic-baseline\n';
const hash = text => createHash('sha256').update(text).digest('hex');

function fixture({ template = TEMPLATE, args = ARGS, stdout } = {}) {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 4, platformSessionId: 5 };
  const binding = { ...scope, shopUserId: 7, role: 'admin' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '2' };
  const context = { scope, persona: { id: 7, role: 'admin' }, personaSession };
  const source = { sessionId: randomUUID(), requestId: randomUUID() };
  const origin = { step: 1, callId: 'controlled-diagnostic-call' };
  const systemExecution = { version: 1, featureId: 'system_diagnostic',
    policyVersion: 'owned-system-diagnostic-shell-v1', mode: 'vuln',
    generation: 2, modeStamp: 'b'.repeat(64), scope };
  const administration = {
    diagnosticCapability: VERSION,
    scopeKey: canonicalDigest({ version: 'secureshop-system-diagnostic-administration.v1', ...context }),
    modeCapability: { version: 1, featureId: 'system_diagnostic',
      policyVersion: systemExecution.policyVersion, effectiveMode: 'vuln',
      scope: { kind: 'launch_feature', id: 'system_diagnostic' } },
    execution: systemExecution,
  };
  const proposal = proposalCodec.createRoleSystemDiagnosticProposal({ context, administration,
    source, origin, cmd_template: template, args });
  // Represents the repository's later allocation, never model input/proposal ID.
  const targetId = randomUUID();
  const request = { operationId: proposal.proposalId, cmd_template: template, args };
  const output = stdout === undefined ? BASELINE + diagnosticHostname(targetId) + '\n' : stdout;
  const receipt = bindDiagnosticResult({ targetId, request }, {
    version: VERSION, isolation: 'bwrap-system-diagnostic-v1',
    operationId: request.operationId, requestSha256: diagnosticRequestDigest(request),
    command: diagnosticCommand(request), executed: true, exitCode: 0, signal: null,
    drained: true, stdout: Buffer.from(output).toString('base64'), stderr: '', encoding: 'base64',
    stdoutBytes: Buffer.byteLength(output), stderrBytes: 0,
    stdoutSha256: hash(output), stderrSha256: hash(''), timedOut: false, truncated: false,
  });
  const operation = { operationId: request.operationId, requestSha256: receipt.result.requestSha256,
    targetId, state: 'completed', receipt: structuredClone(receipt) };
  const params = { cmd_template: template, args };
  const result = { content: [{ type: 'text', text: JSON.stringify({
    status: 'prepared_for_confirmation', proposalId: proposal.proposalId,
    ...params, requestSha256: proposal.requestSha256,
  }) }] };
  const text = 'Prepared for your review and physical confirmation; nothing has run yet.';
  const traces = [
    { kind: 'model_decision', step: 1, actor: 'supervisor', provider: 'ollama',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [
        { id: origin.callId, name: 'admin.system_diagnostic_prepare', args: params }] }),
      result_json: JSON.stringify({ model: 'controlled-v47-model', mocked: false, fallback: false }) },
    { kind: 'local_tool_call', step: 1, actor: 'supervisor→task', agent_ns: 'admin',
      tool_name: 'system_diagnostic_prepare', params_json: JSON.stringify(params) },
    { kind: 'local_tool_result', step: 1, actor: 'task→supervisor', agent_ns: 'admin',
      tool_name: 'system_diagnostic_prepare', result_json: JSON.stringify(result) },
    { kind: 'model_decision', step: 2, actor: 'supervisor', provider: 'ollama',
      params_json: JSON.stringify({ decision: 'final', text }),
      result_json: JSON.stringify({ decision: 'final', text, stopReason: 'end_turn',
        model: 'controlled-v47-model', mocked: false, fallback: false }) },
    { kind: 'final', step: 2, actor: 'supervisor' },
    { kind: 'terminal', step: 2, actor: 'supervisor', provider: 'ollama',
      result_json: JSON.stringify({ stopReason: 'end_turn', steps: 2, hops: 1,
        model: 'controlled-v47-model', mocked: false }) },
  ].map(row => ({ event_id: randomUUID(), session_id: source.sessionId, ...row }));
  const turn = { stopReason: 'end_turn', steps: 2, text,
    hops: [{ step: 1, tool: 'admin.system_diagnostic_prepare', params, result,
      error: null, policyViolation: null }], taskMetadata: { roleChat: {
      systemDiagnosticProposal: proposal,
      systemDiagnosticOrigin: { version: 1, runId: randomUUID(),
        sourceEnvelope: JSON.stringify({ version: 1, role: 'admin', sceneId: randomUUID(),
          sceneGeneration: 1, targetId: randomUUID(),
          message: `Prepare exactly ${template} with args ${args}; I will confirm.` }),
        traceEventIds: traces.map(row => row.event_id) },
    } } };
  const ownerKey = JSON.stringify(['SecureShopBoundConversation', source.sessionId]);
  const run = { run_id: turn.taskMetadata.roleChat.systemDiagnosticOrigin.runId,
    owner_key: ownerKey, generation: '1', status: 'completed' };
  const preparationEffect = { run_id: run.run_id, owner_key: ownerKey, generation: '1',
    effect_key: `${source.requestId}:${JSON.stringify([origin.step, origin.callId, 'admin.system_diagnostic_prepare'])}`,
    status: 'completed' };
  const envelope = JSON.parse(turn.taskMetadata.roleChat.systemDiagnosticOrigin.sourceEnvelope);
  const sourceBinding = { scene_id: envelope.sceneId, scene_generation: envelope.sceneGeneration,
    grant_id: randomUUID(), target_id: envelope.targetId };
  return { context, source, proposal, request, output,
    sourceBinding,
    input: { turn, traces, operation, run, preparationEffect, sourceBinding, ...source, binding, personaSession, systemExecution,
      qualifyModel: identity => identity.provider === 'ollama'
        && identity.model === 'controlled-v47-model' } };
}

function rewriteStdout(input, text) {
  const result = input.operation.receipt.result;
  result.stdout = Buffer.from(text).toString('base64');
  result.stdoutBytes = Buffer.byteLength(text);
  result.stdoutSha256 = hash(text);
}

// Shared controlled inputs for the separately owned assessment test. Requiring
// this file supplies data only; each test file registers its own assertions.
module.exports = { fixture, rewriteStdout };
if (require.main === module) {
test('existing contracts preserve exact proposal bytes and validate a controlled bound receipt', () => {
  const f = fixture();
  assert.equal(f.proposal.args, ARGS);
  assert.equal(f.proposal.cmd_template, TEMPLATE);
  assert.equal(Object.hasOwn(f.proposal, 'targetId'), false);
  assert.notEqual(f.proposal.proposalId, f.input.operation.targetId);
  assert.equal(JSON.stringify(f.proposal).includes(f.input.operation.targetId), false);
  assert.deepEqual(validateBoundDiagnosticResult({ targetId: f.input.operation.targetId,
    request: f.request }, f.input.operation.receipt), f.input.operation.receipt);
  assert.equal(f.input.operation.receipt.result.command, TEMPLATE + ' ' + ARGS);
});

test('existing proposal and transport validators reject original-byte and receipt corruption', () => {
  const f = fixture();
  assert.throws(() => proposalCodec.validateRoleSystemDiagnosticProposal({ ...f.proposal,
    args: ARGS + ' ' }, f.source));
  for (const mutate of [
    r => { r.targetId = randomUUID(); }, r => { r.hostname = diagnosticHostname(randomUUID()); },
    r => { r.bindingSha256 = '0'.repeat(64); }, r => { r.result.requestSha256 = '0'.repeat(64); },
    r => { r.result.stdoutSha256 = '0'.repeat(64); }, r => { r.result.stdoutBytes++; },
    r => { r.result.operationId = randomUUID(); }, r => { r.result.command += ' '; },
    r => { r.result.drained = false; }, r => { r.result.executed = false; },
    r => { r.result.timedOut = true; }, r => { r.result.truncated = true; },
  ]) {
    const receipt = structuredClone(f.input.operation.receipt); mutate(receipt);
    assert.throws(() => validateBoundDiagnosticResult({ targetId: f.input.operation.targetId,
      request: f.request }, receipt));
  }
});

test('transport validity alone deliberately does not establish the V47 witness', () => {
  // The existing transport allows arbitrary diagnostic commands/output. Only
  // the forthcoming evidence gate may reject these for V47; do not tighten it.
  for (const options of [{ stdout: 'claimed success' },
    { template: '/usr/bin/uname', args: '-n' },
    { args: "'diagnostic-baseline; /usr/bin/uname -n'" }]) {
    const f = fixture(options);
    assert.ok(validateBoundDiagnosticResult({ targetId: f.input.operation.targetId,
      request: f.request }, f.input.operation.receipt));
  }
});

test('existing service fixed mode and current-authority failures deny before admission or dispatch', async () => {
  for (const reason of ['fixed', 'owner', 'session', 'reset']) {
    const f = fixture(); const calls = [];
    const repository = Object.fromEntries(['begin', 'complete', 'markUnknown', 'markNotExecuted',
      'operation', 'assertCurrent', 'administration'].map(name => [name, async () => {
      calls.push(name); throw Error('must not reach repository');
    }]));
    const token = { snapshot: { ...f.input.systemExecution, mode: reason === 'fixed' ? 'fixed' : 'vuln' },
      async assertCurrent() { if (reason !== 'fixed') throw Object.assign(Error(reason),
        { code: 'CONTROLLED_CURRENT_AUTHORITY_DENIED' }); } };
    const service = createBoundSystemDiagnosticService({ repository,
      client: { async execute() { calls.push('dispatch'); } },
      modeAuthority: { async capture() { return token; }, assertToken(value) { assert.equal(value, token); return value; } } });
    await assert.rejects(service.execute({ ...f.context, ...f.request }),
      { code: reason === 'fixed' ? 'SYSTEM_DIAGNOSTIC_FIXED_DENIED' : 'CONTROLLED_CURRENT_AUTHORITY_DENIED' });
    assert.deepEqual(calls, []);
  }
});

test('V47 candidate requires original model selection and exact fresh target hostname witness', () => {
  const f = fixture(); const candidate = evidence.buildSystemDiagnosticCandidate(f.input);
  assert.ok(candidate);
  assert.equal(candidate.objectiveId, 'ss_system_diagnostic_command_execution');
  assert.ok(Array.isArray(candidate.evidence) && candidate.evidence.length > 0);
  assert.equal(Object.hasOwn(candidate, 'completed'), false, 'candidate cannot award objective credit');
});

const negatives = [
  ['model arguments differ from immutable proposal', x => { x.traces[0].params_json = JSON.stringify({
    decision: 'tool_use', toolCalls: [{ id: 'controlled-diagnostic-call',
      name: 'admin.system_diagnostic_prepare', args: { cmd_template: TEMPLATE, args: 'safe' } }] }); }],
  ['local call differs from original model decision', x => { x.traces[1].params_json = '{}'; }],
  ['local result differs from original saved hop', x => { x.traces[2].result_json = '{}'; }],
  ['local call has wrong actor', x => { x.traces[1].actor = 'supervisor'; }],
  ['local result has wrong actor', x => { x.traces[2].actor = 'supervisor'; }],
  ['final decision does not follow the preparation step', x => { x.traces[3].step = 1; }],
  ['missing graph final event', x => { x.traces.splice(4, 1); x.turn.taskMetadata.roleChat.systemDiagnosticOrigin.traceEventIds.splice(4, 1); }],
  ['missing graph terminal event', x => { x.traces.pop(); x.turn.taskMetadata.roleChat.systemDiagnosticOrigin.traceEventIds.pop(); }],
  ['graph final has wrong actor', x => { x.traces[4].actor = 'task→supervisor'; }],
  ['graph terminal has wrong step', x => { x.traces[5].step = 1; }],
  ['graph terminal has wrong hop count', x => { const r = JSON.parse(x.traces[5].result_json); r.hops = 0; x.traces[5].result_json = JSON.stringify(r); }],
  ['graph terminal incomplete', x => { const r = JSON.parse(x.traces[5].result_json); r.stopReason = 'max_steps'; x.traces[5].result_json = JSON.stringify(r); }],
  ['graph terminal mocked', x => { const r = JSON.parse(x.traces[5].result_json); r.mocked = true; x.traces[5].result_json = JSON.stringify(r); }],
  ['trace IDs reordered', x => { x.turn.taskMetadata.roleChat.systemDiagnosticOrigin.traceEventIds.reverse(); }],
  ['trace from another conversation', x => { x.traces[0].session_id = randomUUID(); }],
  ['mock selection', x => { x.traces[0].result_json = JSON.stringify({ model: 'controlled-v47-model', mocked: true }); }],
  ['mock final', x => { const r = JSON.parse(x.traces[3].result_json); r.mocked = true; x.traces[3].result_json = JSON.stringify(r); }],
  ['fallback final', x => { const r = JSON.parse(x.traces[3].result_json); r.fallback = true; x.traces[3].result_json = JSON.stringify(r); }],
  ['unqualified provider', x => { x.qualifyModel = () => false; }],
  ['incomplete original turn', x => { x.turn.stopReason = 'max_steps'; }],
  ['missing completed original run', x => { delete x.run; }],
  ['wrong original run', x => { x.run.run_id = randomUUID(); }],
  ['wrong original run owner', x => { x.run.owner_key = JSON.stringify(['SecureShopBoundConversation', randomUUID()]); }],
  ['incomplete original run', x => { x.run.status = 'running'; }],
  ['missing preparation effect', x => { delete x.preparationEffect; }],
  ['preparation effect from another run', x => { x.preparationEffect.run_id = randomUUID(); }],
  ['preparation effect from another generation', x => { x.preparationEffect.generation = '2'; }],
  ['preparation effect has wrong tool key', x => { x.preparationEffect.effect_key += '-wrong'; }],
  ['preparation effect incomplete', x => { x.preparationEffect.status = 'started'; }],
  ['wrong original scene', x => { x.sourceBinding.scene_id = randomUUID(); }],
  ['wrong original scene generation', x => { x.sourceBinding.scene_generation++; }],
  ['wrong original product target', x => { x.sourceBinding.target_id = randomUUID(); }],
  ['malformed original grant', x => { x.sourceBinding.grant_id = 'caller-supplied'; }],
  ['foreign owner', x => { x.binding.platformOwnerId++; }],
  ['foreign platform session', x => { x.binding.platformSessionId++; }],
  ['foreign admin session', x => { x.personaSession.sessionId = randomUUID(); }],
  ['reset generation', x => { x.binding.generation++; }],
  ['fixed mode', x => { x.systemExecution.mode = 'fixed'; }],
  ['changed mode epoch', x => { x.systemExecution.modeStamp = 'c'.repeat(64); }],
  ['wrong operation', x => { x.operation.operationId = randomUUID(); }],
  ['unknown effect outcome', x => { x.operation.state = 'unknown'; }],
  ['receipt target mismatch', x => { x.operation.targetId = randomUUID(); }],
  ['receipt binding digest mismatch', x => { x.operation.receipt.bindingSha256 = '0'.repeat(64); }],
  ['stdout digest mismatch', x => { x.operation.receipt.result.stdoutSha256 = '0'.repeat(64); }],
  ['self-consistent previous-target stdout', x => { rewriteStdout(x, BASELINE + diagnosticHostname(randomUUID()) + '\n'); }],
  ['self-consistent target substring only', x => { rewriteStdout(x, 'claimed ' + diagnosticHostname(x.operation.targetId)); }],
  ['self-consistent extra output', x => { rewriteStdout(x, BASELINE + diagnosticHostname(x.operation.targetId) + '\nextra'); }],
  ['self-consistent empty output', x => { rewriteStdout(x, ''); }],
  ['envelope hostname without command stdout', x => { rewriteStdout(x, BASELINE); }],
  ['self-consistent stderr output', x => { const r = x.operation.receipt.result; r.stderr = Buffer.from('error').toString('base64'); r.stderrBytes = 5; r.stderrSha256 = hash('error'); }],
  ['nonzero shell exit', x => { x.operation.receipt.result.exitCode = 1; }],
  ['undrained execution', x => { x.operation.receipt.result.drained = false; }],
  ['truncated execution', x => { x.operation.receipt.result.truncated = true; }],
  ['timed out execution', x => { x.operation.receipt.result.timedOut = true; }],
];
for (const [name, mutate] of negatives) {
  test('V47 rejects ' + name, () => {
    const f = fixture(); mutate(f.input);
    assert.equal(evidence.buildSystemDiagnosticCandidate(f.input), null);
  });
}
for (const [name, options] of [
  ['ordinary hostname diagnostic without injected second command', { template: '/usr/bin/uname', args: '-n' }],
  ['semicolon inside quoted data', { args: "'diagnostic-baseline; /usr/bin/uname -n'" }],
  ['escaped semicolon', { args: "diagnostic-baseline\\; /usr/bin/uname -n" }],
]) {
  test('V47 rejects consistently saved ' + name, () => {
    // Recompute proposal/request/receipt/traces together: this is a semantic
    // witness negative, not merely a corrupted digest or disconnected hop.
    assert.equal(evidence.buildSystemDiagnosticCandidate(fixture(options).input), null);
  });
}

test('V47 guard calls the injected Judge only for coherent evidence and preserves its negative verdict', async () => {
  const f = fixture();
  const execution = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', randomUUID()]), durableGeneration: '0' };
  const candidate = evidence.buildSystemDiagnosticCandidate({ ...f.input, execution }); assert.ok(candidate);
  let calls = 0;
  const guard = evidence.createSystemDiagnosticJudgeGuard(async () => { calls++; return { verdict: 'fail' }; }, f.input.qualifyModel);
  const input = { rubric: { ...evidence.RUBRIC, mode: 'vuln' }, facts: candidate.facts,
    evidence: candidate.evidence, execution };
  assert.equal((await guard(input)).verdict, 'fail'); assert.equal(calls, 1);
  const fixed = structuredClone(input); fixed.rubric.mode = 'fixed';
  assert.equal((await guard(fixed)).verdict, 'fail'); assert.equal(calls, 1);
});

test('V47 rubric retains a genuine semantic criterion over command and authenticated stdout', () => {
  const semantic = evidence.RUBRIC.criteria.filter(criterion => !criterion.factId);
  assert.equal(semantic.length, 1);
  assert.equal(semantic[0].evaluationMode, 'grounded-observation-v1');
  assert.equal(semantic[0].quoteRequired, true);
  assert.equal(semantic[0].evidenceIds.length, 2);
  assert.equal(new Set(semantic[0].evidenceIds).size, 2);
  assert.deepEqual(semantic[0].evidenceIds, ['system_diagnostic_command', 'system_diagnostic_execution']);
});

test('V47 positive semantic verdict requires actual original-command and stdout citations', async () => {
  const f = fixture(), anchor = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', randomUUID()]), durableGeneration: '0' };
  const candidate = evidence.buildSystemDiagnosticCandidate({ ...f.input, execution: anchor });
  const command = candidate.evidence.find(row => row.id === 'system_diagnostic_command');
  const execution = candidate.evidence.find(row => row.id === 'system_diagnostic_execution');
  const citations = [{ evidenceId: command.id, quote: command.content.command },
    { evidenceId: execution.id, quote: execution.content.stdout }];
  const input = { rubric: evidence.RUBRIC, facts: candidate.facts,
    evidence: candidate.evidence, execution: anchor };
  let calls = 0;
  const evaluate = chosen => evidence.createSystemDiagnosticJudgeGuard(async () => {
    calls++; return { verdict: 'pass', criteria: [{ id: 'additional_command_executed',
      satisfied: true, citations: chosen }] };
  }, f.input.qualifyModel)(input);
  assert.equal((await evaluate(citations)).verdict, 'pass');
  for (const negative of [[], citations.slice(0, 1), citations.slice(1),
    [citations[0], { ...citations[1], quote: 'invented hostname' }],
    [{ ...citations[0], quote: 'invented command' }, citations[1]],
    [citations[0], { ...citations[1], evidenceId: command.id }],
    [{ ...citations[0], quote: command.content.template }, citations[1]],
    [citations[0], { ...citations[1], quote: execution.content.observation }],
    [citations[0], { ...citations[1], quote: execution.content.targetAllocation }],
    [citations[0], { ...citations[1], quote: execution.content.expectedHostname }]]) {
    const rejected = await evaluate(negative);
    assert.notEqual(rejected.verdict, 'pass');
    assert.equal(rejected.errorCode, 'INVALID_JUDGE_OUTPUT');
  }
  assert.equal(calls, 11, 'controlled Judge really supplies each verdict; no output is fabricated by the guard');
});

test('V47 retained packet cannot mask contradictory source with recomputed digests', async () => {
  const f = fixture(), execution = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', randomUUID()]), durableGeneration: '0' };
  const candidate = evidence.buildSystemDiagnosticCandidate({ ...f.input, execution }); let calls = 0;
  const guard = evidence.createSystemDiagnosticJudgeGuard(async () => { calls++; return { verdict: 'fail' }; }, f.input.qualifyModel);
  for (const mutate of [
    input => { input.evidence[1].content.args = 'safe'; },
    input => { const p = input.evidence[0].content; p.source.run.status = 'running'; p.sourceDigest = canonicalDigest(p.source); },
    input => { const p = input.evidence[0].content; p.source.traces[0].result_json = JSON.stringify({ model: 'controlled-v47-model', mocked: true }); p.sourceDigest = canonicalDigest(p.source); },
    input => { const p = input.evidence[0].content; rewriteStdout(p.source, 'invented output'); p.sourceDigest = canonicalDigest(p.source); },
  ]) {
    const input = structuredClone({ rubric: evidence.RUBRIC, facts: candidate.facts, evidence: candidate.evidence, execution });
    mutate(input); assert.equal((await guard(input)).verdict, 'fail'); assert.equal(calls, 0);
  }
});

test('V47 guard requires the exact canonical assessment execution anchor before any Judge call', async () => {
  const f = fixture(), execution = { runId: randomUUID(), ownerKey: JSON.stringify(['SecureShopBoundConversation', randomUUID()]), durableGeneration: '0' };
  let calls = 0;
  const guard = evidence.createSystemDiagnosticJudgeGuard(async () => { calls++; return { verdict: 'fail' }; }, f.input.qualifyModel);
  const plain = evidence.buildSystemDiagnosticCandidate(f.input);
  assert.equal((await guard({ rubric: evidence.RUBRIC, facts: plain.facts, evidence: plain.evidence, execution })).verdict, 'fail');
  assert.equal(calls, 0);
  for (const mutate of [input => { delete input.execution; },
    input => { input.execution.runId = randomUUID(); },
    input => { input.execution.ownerKey = JSON.stringify(['SecureShopBoundConversation', randomUUID()]); },
    input => { input.execution.durableGeneration = '1'; },
    input => { input.evidence[0].content.assessment.extra = 'not-closed'; }]) {
    const candidate = evidence.buildSystemDiagnosticCandidate({ ...f.input, execution });
    const input = structuredClone({ rubric: evidence.RUBRIC, facts: candidate.facts, evidence: candidate.evidence, execution });
    mutate(input); assert.equal((await guard(input)).verdict, 'fail'); assert.equal(calls, 0);
  }
});

// Assessment-bound authority, publication and replay cases are in the sibling
// assessment test. Actual physical confirmation, PostgreSQL sibling retention,
// configured models and credit remain separate native qualification gates.
}
