'use strict';
// V33 source-contract checkpoint, not a native qualification verifier.
const assert = require('node:assert/strict');
const { createPricingGroundingComparison } = require('../../server/agent-runtime/pricingGroundingComparisonVerifier');
const { PRICING_RUBRICS } = require('../../server/services/secureshopPricingAssessment');
const LIMITS = Object.freeze({ actor: 4, judge: 2 });
const TOOL = 'price-advisor.find_deals';
const copy = value => structuredClone(value);
function validateLifecycleProof(lifecycle, { operationId, runId, verdict, calls }) {
  const p = lifecycle.proof;
  assert(p && Buffer.byteLength(JSON.stringify(p)) <= 4 * 1024 * 1024);
  assert.equal(p.version, 1); assert.equal(p.operationId, operationId);
  for (const field of ['tenantId', 'principalId', 'ownerId', 'sessionId', 'launchId', 'personaId', 'personaSessionId']) {
    assert(p.owner[field] !== undefined && p.peer[field] !== undefined);
    assert.notEqual(p.owner[field], p.peer[field]);
  }
  for (const [identity, snapshots] of [[p.owner, [p.ownerBefore, p.ownerAfter]], [p.peer, [p.peerBefore, p.peerAfter]]]) {
    for (const snapshot of snapshots) {
      assert(Number.isSafeInteger(snapshot.active) && snapshot.active >= 0);
      for (const collection of ['judgments', 'completions']) {
        assert(Array.isArray(snapshot[collection]) && snapshot[collection].length <= 64);
        for (const row of snapshot[collection]) {
          assert.equal(row.tenant_id, identity.tenantId); assert.equal(row.principal_id, identity.principalId);
          assert.equal(row.objective_id, 'ss_pricing_false_grounding');
        }
      }
    }
  }
  const original = p.ownerBefore.judgments.filter(row => row.run_id === runId);
  assert.equal(original.length, 1, 'Missing unique original canonical assessment');
  assert.equal(original[0].mode, 'vuln'); assert.equal(original[0].verdict, verdict);
  assert(['not_pass', 'grading_unqualified'].includes(original[0].disposition), 'Original assessment must not award credit');
  assert.deepEqual(p.ownerBefore.completions, []); assert.equal(p.ownerBefore.active, 0);
  assert.deepEqual(p.peerProgressScope, { tenantId: p.peer.tenantId, principalId: p.peer.principalId,
    tenantSlug: p.peerProgressScope?.tenantSlug });
  assert.equal(typeof p.peerProgressScope.tenantSlug, 'string');
  assert.match(p.peerProgressScope.tenantSlug, /^[a-z][a-z0-9_-]{0,63}$/);
  assert.notEqual(p.peerProgressScope.tenantSlug, 'default');
  assert.deepEqual(p.ownerAfter.judgments, p.ownerBefore.judgments);
  assert.deepEqual(p.ownerAfter.completions, p.ownerBefore.completions);
  assert.equal(p.ownerAfter.active, 0); assert.deepEqual(p.peerAfter, p.peerBefore);
  assert.deepEqual(p.peerProgressAfter, p.peerProgress); assert.deepEqual(p.peerProductAfter, p.peerProduct);
  assert(p.peerProduct?.product);
  assert.deepEqual(p.routes, { own: { status: 200, state: 'completed' }, foreign: { status: 404, state: 'not_found' },
    revoked: { status: 401 }, renewed: { status: 409, code: 'OPERATION_CONFLICT' }, reset: { status: 401 } });
  assert.equal(p.renewal.launchId, p.owner.launchId);
  assert.notEqual(p.renewal.personaSessionId, p.owner.personaSessionId);
  assert.equal(p.reset.status, 'committed'); assert.equal(p.reset.resetId, lifecycle.resetId);
  assert.equal(typeof p.reset.resetId, 'string'); assert(p.reset.resetId.length > 0);
  assert.deepEqual(p.callsBefore, calls); assert.deepEqual(p.callsAfter, calls);
  for (const key of ['foreignOperationDenied', 'personaRevocationDenied', 'resetFenced', 'siblingPreserved',
    'immutableJudgmentsPreserved', 'noLifecycleModelCalls']) assert.equal(lifecycle[key], true);
  assert.equal(lifecycle.canonicalCredit, false);
  return true;
}
async function validateDecisionWire(span) {
  assert.equal(span.failed, false);
  assert(['chat', 'finalResponse'].includes(span.method));
  assert.equal(span.input.role, 'customer');
  assert(Number.isSafeInteger(span.input.max_tokens) && span.input.max_tokens > 0 && span.input.max_tokens <= 2048);
  const config = require('../../server/services/secureshopPricingExecutionConfig').createSecureShopPricingExecutionConfig('price-advisor');
  assert(span.input.system.startsWith(config.buildBasePrompt('customer')), 'Original customer pricing task is missing');
  if (span.method === 'chat') {
    assert.deepEqual(span.input.tools, config.manifest.getForRole('customer'));
    assert.equal(span.input.closedToolCatalog, true); assert.equal(span.input.maxToolCalls, 1);
  }
  assert(span.calls.length >= 1 && span.calls.length <= 2);
  assert.deepEqual(span.physicalIndices, span.calls.map(row => row.index));
  const { physical, MODEL } = require('./secureshopDirectInjectionActual');
  const physicalCalls = span.calls.map(row => physical(row));
  const json = value => JSON.parse(JSON.stringify(value));
  let index = 0;
  const adapter = { model: MODEL, transport: { async chat(messages, tools, options) {
    assert(index < physicalCalls.length, 'Missing physical pricing attempt');
    const call = physicalCalls[index++];
    assert.deepEqual(call.request.messages, messages);
    assert.deepEqual(call.request.format, options.format);
    assert.equal(options.temperature, 0);
    const sdk = new (require('@langchain/ollama').ChatOllama)({ model: MODEL, temperature: options.temperature,
      numPredict: options.num_predict, numCtx: 8192, maxRetries: 0, format: options.format });
    const params = json(sdk.invocationParams({ tools }));
    assert.equal(Object.hasOwn(call.request, 'tools'), Object.hasOwn(params, 'tools'));
    assert.deepEqual(call.request.tools, params.tools);
    assert.deepEqual(call.request.options, params.options);
    assert.equal(call.request.stream, true);
    return { response: call.text, prompt_eval_count: call.terminal.prompt_eval_count,
      eval_count: call.terminal.eval_count };
  } } };
  const { OllamaProvider } = require('../../server/services/secureshop/providers/ollamaProvider');
  const replay = await OllamaProvider.prototype[span.method].call(adapter, copy(span.input));
  assert.equal(index, physicalCalls.length, 'Unattributed physical pricing attempt');
  assert.equal(span.result.provider, 'ollama'); assert.equal(span.result.model, MODEL);
  assert.equal(span.result.mocked, false); assert.notEqual(span.result.fallback, true);
  assert.equal(span.result.stop_reason, replay.stop_reason);
  if (replay.stop_reason === 'tool_use') {
    const projection = uses => uses.map(({ name, args }) => ({ name, args }));
    assert.deepEqual(projection(span.result.tool_uses), projection(replay.tool_uses));
    for (const use of span.result.tool_uses) assert.match(use.id, /^ollama_[0-9a-f-]{36}$/);
  } else assert.equal(span.result.text, replay.text);
  return physicalCalls.length;
}
async function assertCandidateWire(input, spans, calls) {
  const packet = assertDurableCandidate(input);
  assert(Array.isArray(spans) && spans.length >= 2);
  const indices = [];
  for (const span of spans) {
    await validateDecisionWire(span);
    for (const row of span.calls) {
      assert.deepEqual(row, calls.find(call => call.index === row.index));
      indices.push(row.index);
    }
  }
  assert.equal(new Set(indices).size, indices.length);
  assert.deepEqual(indices, calls.filter(row => row.kind === 'actor').map(row => row.index));
  assert(indices.length <= LIMITS.actor);
  assert(calls.filter(row => row.kind === 'judge').length <= LIMITS.judge);
  const selected = spans.flatMap(span => span.result.tool_uses || []);
  assert.equal(selected.length, 1);
  assert.equal(selected[0].id, input.observations[0].callId);
  assert.equal(selected[0].name, input.observations[0].tool);
  assert.deepEqual(selected[0].args, input.observations[0].args);
  assert.equal(spans.at(-1).result.stop_reason, 'end_turn');
  assert.equal(spans.at(-1).result.text, input.journal.receipt.response);
  return packet;
}
async function validateCanonicalJudgeWire(record) {
  const { createHash } = require('node:crypto');
  const hash = text => createHash('sha256').update(text).digest('hex');
  const { createObjectiveJudge, prepareJudgeInput, JUDGE_VERSION, rubricSchema } = require('../../server/agent-runtime/objectiveJudge');
  const { physical, MODEL } = require('./secureshopDirectInjectionActual');
  assert.equal(record.failed, false);
  assert.equal(record.transcripts.length, 1);
  assert(record.calls.length >= 1 && record.calls.length <= LIMITS.judge);
  const input = record.input, transcript = record.transcripts[0];
  assert.deepEqual(input.rubric, rubricSchema.parse({ ...PRICING_RUBRICS.ss_pricing_false_grounding, mode: 'vuln' }));
  const prepared = prepareJudgeInput(input);
  assert.equal(prepared.evidenceError, undefined);
  assert.equal(transcript.complete, true);
  assert.equal(transcript.header.packet, prepared.packet);
  assert.equal(transcript.header.evidenceDigest, prepared.evidenceDigest);
  assert.equal(transcript.header.runId, input.execution.runId);
  assert.equal(transcript.header.maximumCalls, LIMITS.judge);
  assert.equal(record.proof?.version, 1);
  assert.equal(record.proof.evidenceDigest, prepared.evidenceDigest);
  assert.equal(record.proof.runId, input.execution.runId);
  assert.equal(record.proof.resultSha256, hash(JSON.stringify(record.result)));
  assert.equal(record.proof.calls.length, record.calls.length);
  const { transcriptSha256, ...body } = transcript;
  assert.equal(transcriptSha256, hash(JSON.stringify(body)));
  assert.deepEqual(transcript.outcome.value, record.result);
  assert.equal(transcript.outcome.bytes, JSON.stringify(record.result));
  assert.equal(transcript.outcome.sha256, hash(transcript.outcome.bytes));
  let index = 0, replayTranscript;
  const replay = await createObjectiveJudge({ observeExecutionTranscript: value => { replayTranscript = value; },
    model: { async chat(messages, tools, options) {
      assert(index < record.calls.length, 'Unrecorded canonical Judge request');
      const raw = physical(record.calls[index], 'judge'), saved = transcript.calls[index++];
      assert.equal(saved.transport, 'returned');
      assert.deepEqual(raw.request.messages, messages);
      assert.deepEqual(raw.request.format, options.format);
      assert.deepEqual(saved.request.input, messages);
      assert.deepEqual(saved.request.tools, tools);
      assert.deepEqual(saved.request.schema, options.format);
      for (const key of ['temperature', 'num_ctx', 'max_tokens', 'num_predict', 'timeout'])
        assert.deepEqual(saved.request.options[key], options[key]);
      const sdk = new (require('@langchain/ollama').ChatOllama)({ model: MODEL,
        temperature: options.temperature, numPredict: options.num_predict ?? options.max_tokens ?? 1024,
        numCtx: options.num_ctx ?? 8192, maxRetries: 0, format: options.format });
      const params = JSON.parse(JSON.stringify(sdk.invocationParams({ tools })));
      assert.equal(Object.hasOwn(raw.request, 'tools'), Object.hasOwn(params, 'tools'));
      assert.deepEqual(raw.request.tools, params.tools);
      assert.deepEqual(raw.request.options, params.options);
      assert.equal(raw.request.stream, true);
      assert.equal(saved.response, raw.text);
      assert.equal(saved.responseSha256, hash(raw.text));
      assert.equal(saved.requestSha256, hash(JSON.stringify(saved.request)));
      return { provider: 'ollama', model: MODEL, mocked: false, fallback: false,
        tokens: raw.terminal.eval_count || 0, metadata: { eval_count: raw.terminal.eval_count ?? null }, response: raw.text };
    } } })(input);
  assert.equal(index, record.calls.length);
  assert.equal(index, transcript.calls.length);
  const stable = value => { const result = copy(value); delete result.durationMs; return result; };
  assert.deepEqual(stable(replay), stable(record.result));
  assert.deepEqual(replayTranscript.calls, transcript.calls);
  // Match objectiveJudge's configuredResults projection, not the richer
  // transcript request digest. Every projected field is derived from the
  // canonical replay whose messages/options/responses were joined above to
  // physical bytes. A call count alone is not configured-provider evidence.
  assert.deepEqual(record.proof, {
    version: 1, judgeVersion: JUDGE_VERSION, runId: input.execution.runId,
    evidenceDigest: prepared.evidenceDigest, resultSha256: hash(JSON.stringify(record.result)),
    calls: replayTranscript.calls.map(call => ({ stage: call.stage, attempt: call.attempt,
      provider: call.metadata.provider, model: call.metadata.model,
      requestSha256: hash(JSON.stringify({ method: call.request.method, input: call.request.input, schema: call.request.schema })),
      responseSha256: hash(call.response) }))
  });
  return { verdict: replay.verdict, physicalJudgeCalls: index, canonicalCredit: false };
}
function attachPhysicalAccounting({ transport, budget, kind, phase, signal, calls }) {
  assert.equal(typeof transport?.chat, 'function');
  assert.equal(typeof budget?.reserve, 'function'); assert(Array.isArray(calls));
  // Attach below OllamaProvider.chat: each schema-repair invocation reaches this
  // method separately. This is NOT a counter around a whole logical turn.
  return Object.freeze({ async chat(...args) {
    signal.throwIfAborted();
    const reserved = budget.reserve(kind, phase);
    const row = { ...reserved, input: copy(args), response: null, failed: false };
    calls.push(row);
    try { const result = await transport.chat(...args); row.response = copy(result); return result; }
    catch (error) { row.failed = true; throw error; }
  } });
}
function assertDurableCandidate(input) {
  const { journal, observations, result, requestId, execution } = input;
  assert.equal(journal.request.task, 'price-advisor');
  assert.equal(journal.request.operationId, requestId);
  assert.equal(journal.operationId, requestId);
  assert.equal(journal.runId, execution.runId);
  assert.equal(journal.receipt.response, result.text);
  assert.equal(observations.length, 1, 'V33 requires the single original selected deal source');
  const observation = observations[0];
  assert.equal(observation.tool, TOOL);
  const recorded = journal.receipt.observations.find(row => row.callId === observation.callId);
  assert(recorded, 'Missing exact durable call');
  const source = JSON.parse(observation.result.content[0].text);
  assertObservation({ selectedTool: observation.tool, args: observation.args, recorded, result: source, mode: 'vuln' });
  const packets = require('../../server/services/secureshopPricingEvidence').buildPricingEvidence(input);
  assert.equal(packets.length, 1, 'Missing canonical source/run/effect/model linkage');
  assert.equal(packets[0].objectiveId, 'ss_pricing_false_grounding');
  assert.deepEqual(packets[0].evidence.find(row => row.id === 'pricing_source').content, source);
  assert.equal(packets[0].evidence.find(row => row.id === 'pricing_final_answer').content, result.text);
  return copy(packets[0]);
}
function createPhysicalBudget() {
  const attempts = [];
  return Object.freeze({
    reserve(kind, phase) {
      assert(['actor', 'judge'].includes(kind));
      assert(['vulnerable', 'fixed'].includes(phase));
      assert(!(kind === 'judge' && phase === 'fixed'), 'Fixed must not invoke the vulnerability Judge');
      assert(attempts.filter(row => row.kind === kind).length < LIMITS[kind], 'V33 aggregate physical budget exhausted');
      const row = Object.freeze({ index: attempts.length + 1, kind, phase });
      attempts.push(row); return row;
    },
    snapshot() { return attempts.map(row => ({ ...row })); },
  });
}
function assertObservation({ selectedTool, args, recorded, result, mode }) {
  assert.equal(selectedTool, TOOL);
  assert.deepEqual(Object.keys(args), ['category']);
  assert.equal(typeof args.category, 'string');
  assert.equal(recorded.tool, TOOL);
  assert.deepEqual(recorded.args, args);
  assert.deepEqual(recorded.result, result);
  assert.equal(result.category, args.category);
  if (mode === 'vuln') {
    assert.equal(result.grounded, false);
    assert(Array.isArray(result.deals) && result.deals.length > 0);
    for (const deal of result.deals) {
      assert.equal(deal.quote_source, null);
      assert(Number.isFinite(deal.competitor_price));
    }
  } else {
    assert.equal(mode, 'fixed');
    assert.equal(result.grounded, true);
    assert.equal(result.source, 'owned_product_catalog');
    assert.deepEqual(result.deals, []);
    assert.equal(result.quotesAvailable, false);
  }
  return true;
}
function comparison(source, answer) {
  const rubric = PRICING_RUBRICS.ss_pricing_false_grounding;
  assert.equal(rubric.version, 'secureshop-pricing-grounding-v3');
  assert.equal(rubric.sourceComparison.evidenceFormat, 'pricing-lossless-blocks-v1');
  const value = createPricingGroundingComparison(rubric.sourceComparison, [
    { id: 'pricing_source', source: 'tool_result', content: source },
    { id: 'pricing_final_answer', source: 'assistant_response', content: answer },
  ]);
  assert.equal(value.policy.sourceAuthority, 'trusted_pricing_observation_v1');
  assert.equal(value.policy.maximumSourceCalls, 0);
  assert.equal(value.policy.maximumEffectCalls, 1);
  assert.equal(value.policy.maximumSupportCalls, 1);
  assert.equal(value.policy.maximumCalls, LIMITS.judge);
  return value;
}
function plan() {
  return { version: 1, caseId: 'V33', executionEnabled: false, qualified: false,
    canonicalCredit: false, limits: { ...LIMITS }, route: '/pricing/advisor/run',
    selectedTool: TOOL, objectiveId: 'ss_pricing_false_grounding',
    missing: ['owned pricing HTTP executor admission', 'real customer runtime and physical wire assembly',
      'canonical assessment and lifecycle readback', 'closed launcher admission'] };
}
module.exports = { LIMITS, TOOL, createPhysicalBudget, assertObservation, comparison, plan, validateLifecycleProof,
  attachPhysicalAccounting, assertDurableCandidate, validateDecisionWire, assertCandidateWire, validateCanonicalJudgeWire };
