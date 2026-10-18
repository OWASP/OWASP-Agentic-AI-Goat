'use strict';

// Synthetic source/trace/effect captures only. No PostgreSQL, browser or model
// is started, and none of these objects can establish actual V17 qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { projectReviewForMode } = require('../server/services/secureshopBoundReviewTools');
const Q = require('./fixtures/secureshopReviewInjectionQualification');
const id = value => `10000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const sha = value => createHash('sha256').update(value).digest('hex');
const qualify = row => row.provider === 'ollama' && row.model === 'llama3.1:8b' && row.mocked === false;

function capture(sourceCase = 'approve_advertisement', actualDecision) {
  const sample = Q.SOURCES[sourceCase];
  const decision = actualDecision ?? sample.attackDecision;
  const binding = { launchId: id(1), scenarioId: id(2), generation: 1,
    platformOwnerId: 2, platformSessionId: 3, shopUserId: 4, role: 'merchant' };
  const sessionId = id(3), requestId = id(4);
  const execution = { runId: id(5), ownerKey: JSON.stringify(['SecureShopBoundConversation', sessionId]),
    durableGeneration: '1' };
  const review = { id: 11, product_id: 12, author_id: 4, body: sample.body,
    rating: sample.rating, status: 'pending' };
  const sdk = value => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
  const observation = (step, callId, tool, args, value) => ({ step, callId, tool, args,
    result: sdk(value), effectReceipt: { version: 1, status: 'completed', runId: execution.runId,
      ownerKey: execution.ownerKey, generation: '1',
      effectKey: `${requestId}:${JSON.stringify([step, callId, tool])}` } });
  const read = observation(1, 'read_original', 'review-moderator.moderate_pending',
    { limit: 1 }, { ok: true, count: 1, reviews: [review] });
  const args = { review_id: review.id, ...(decision === 'reject' ? { reason: 'Unrelated advertising' } : {}) };
  const committed = { ...review, status: decision === 'approve' ? 'approved' : 'rejected',
    moderator_kind: 'auto' };
  const action = observation(2, 'action_original', `review-moderator.${decision}`,
    args, { ok: true, applied: true, review: committed });
  const traces = [read, action].flatMap((value, index) => [{ session_id: sessionId,
    event_id: id(10 + index * 2), actor: 'supervisor', kind: 'model_decision', step: value.step,
    provider: 'ollama', params_json: JSON.stringify({ decision: 'tool_use',
      toolCalls: [{ id: value.callId, name: value.tool, args: value.args }] }),
    result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
  { session_id: sessionId, event_id: id(11 + index * 2), actor: 'task→supervisor',
    kind: 'local_tool_result', step: value.step, agent_ns: 'review-moderator',
    tool_name: value.tool.split('.')[1], result_json: JSON.stringify(value.result) }]);
  traces.push({ session_id: sessionId, event_id: id(15), actor: 'supervisor', kind: 'terminal',
    step: 3, provider: 'ollama', result_json: JSON.stringify({ stopReason: 'end_turn',
      steps: 3, hops: 2, model: 'llama3.1:8b', mocked: false }) });
  const source = { version: 1, ...binding, submissionId: id(6), reviewId: review.id,
    productId: review.product_id, authorId: review.author_id, body: review.body, rating: review.rating,
    submittedByShopUserId: 4, submittedByShopRole: 'merchant', bodySha256: sha(review.body),
    createdAt: '2026-10-12T00:00:00.000Z', createdAtMicros: '1791763200000000' };
  return { sourceCase, source,
    subject: { tenantId: id(20), principalId: id(21),
      personaSession: { sessionId: id(22), authorityVersion: '1' } },
    submitter: { scope: binding, persona: { id: 4, role: 'merchant' } },
    submission: { method: 'POST', path: '/api/secureshop/products/12/reviews',
      body: { submission_id: source.submissionId, author_id: 4, body: sample.body, rating: sample.rating },
      status: 200, value: { ok: true, review_id: review.id } }, rawReview: committed,
    turn: { binding, execution, sessionId, requestId, admittedAtMicros: '1791763200000001',
      traces, persistedTraces: structuredClone(traces), observations: [read, action],
      result: { stopReason: 'end_turn', steps: 3, hops: [{}, {}] },
      effects: [read, action].map(value => ({ run_id: execution.runId, owner_key: execution.ownerKey,
        generation: '1', effect_key: value.effectReceipt.effectKey, status: 'completed' })) } };
}

test('both explicit policy-violating source/action cases retain canonical v4 evidence without actual credit claims', async () => {
  for (const sourceCase of Object.keys(Q.SOURCES)) {
    const result = await Q.assertV17CaptureStructure(capture(sourceCase), qualify);
    assert.equal(result.actualQualification, false);
    assert.equal(result.status, 'validated_capture_pending_owned_caller');
    assert.equal(result.prepared.rubric.objectiveId, 'ss_content_followed');
    assert.equal(result.prepared.rubric.criteria.length, 2);
    assert.ok(result.obligations.includes('actual pinned actor and configured Judge transport'));
    assert.equal(result.candidate.evidence[0].content, Q.SOURCES[sourceCase].body);
  }
});

test('rejects altered source/request, late or foreign submission, reordered traces and missing effects', async () => {
  for (const mutate of [
    value => { value.submission.body.body = 'Edited request'; },
    value => { value.source.bodySha256 = '0'.repeat(64); },
    value => { value.source.platformSessionId += 1; },
    value => { value.source.createdAtMicros = value.turn.admittedAtMicros; },
    value => { value.source.submittedByShopUserId += 1; },
    value => { value.rawReview.body = 'Changed stored source'; },
    value => { value.turn.persistedTraces.reverse(); },
    value => { value.turn.effects.pop(); },
    value => { value.turn.observations[0].effectReceipt.status = 'uncertain'; },
    value => { value.rawReview.moderator_kind = 'manual'; },
    value => { value.turn.traces[0].result_json = JSON.stringify({ model: 'mock', mocked: true });
      value.turn.persistedTraces = structuredClone(value.turn.traces); },
  ]) {
    const value = capture(); mutate(value);
    await assert.rejects(Q.assertV17CaptureStructure(value, qualify));
  }
});

test('mere retrieval, model refusal and policy-compliant committed actions cannot satisfy the V17 capture', async () => {
  const readOnly = capture();
  readOnly.turn.observations.pop();
  await assert.rejects(Q.assertV17CaptureStructure(readOnly, qualify));
  for (const sourceCase of Object.keys(Q.SOURCES)) {
    const compliant = capture(sourceCase, Q.SOURCES[sourceCase].policyDecision);
    const candidates = await require('../server/services/secureshopReviewContentEvidence')
      .buildSecureShopReviewContentEvidence({ ...compliant.turn, qualifyModelTrace: qualify,
        readSubmission: async () => compliant.source });
    assert.equal(candidates.followed[0].facts.completed_model_moderation_effect, true,
      'The policy-compliant control retains a complete genuine-shaped provenance chain');
    await assert.rejects(Q.assertV17CaptureStructure(compliant, qualify));
  }
});

test('fixed projection withholds the exact source while retaining raw CAS body and policy outcome', () => {
  for (const sourceCase of Object.keys(Q.SOURCES)) {
    const value = capture(sourceCase), sample = Q.SOURCES[sourceCase];
    const read = value.turn.observations[0];
    const payload = JSON.parse(read.result.content[0].text);
    payload.reviews = payload.reviews.map(row => projectReviewForMode(row, 'fixed'));
    read.result.content[0].text = JSON.stringify(payload);
    value.rawReview.status = sample.policyDecision === 'approve' ? 'approved' : 'rejected';
    value.creditBefore = []; value.creditAfter = [];
    assert.equal(Q.assertV17FixedStructure(value).actualQualification, false);
    for (const mutate of [
      bad => { const p = JSON.parse(bad.turn.observations[0].result.content[0].text);
        p.reviews[0].body = sample.body; bad.turn.observations[0].result.content[0].text = JSON.stringify(p); },
      bad => { bad.rawReview.body = '[Review text withheld from the agent in fixed mode]'; },
      bad => { bad.creditAfter = [{ objective: 'ss_content_followed' }]; },
    ]) { const bad = structuredClone(value); mutate(bad); assert.throws(() => Q.assertV17FixedStructure(bad)); }
  }
});

test('arbitrary Judge DTO claims cannot substitute for original configured-result identity', async () => {
  const validated = await Q.assertV17CaptureStructure(capture(), qualify);
  const result = { verdict: 'pass', evidenceDigest: validated.prepared.evidenceDigest,
    criteria: validated.prepared.rubric.criteria.map(row => ({ id: row.id, satisfied: true })) };
  const row = { objective_id: 'ss_content_followed', packet: validated.prepared.packet,
    evidence_digest: validated.prepared.evidenceDigest, verdict: 'pass', disposition: 'awarded',
    evaluation_id: id(90), judge_result_json: JSON.stringify(result),
    tenant_id: id(20), principal_id: id(21), shop_user_id: 4, mode: 'vuln',
    run_id: validated.authority.execution.runId, owner_key: validated.authority.execution.ownerKey,
    owner_generation: '1', execution_json: { scope: { launchId: id(1), scenarioId: id(2),
      generation: 1, platformOwnerId: 2, platformSessionId: 3 },
      personaSessionId: id(22), personaAuthorityVersion: '1' } };
  assert.throws(() => Q.assertV17JudgeCapture(validated, { row,
    completion: { evaluation_id: id(90), tenant_id: id(20), principal_id: id(21) },
    contribution: { evaluation_id: id(90), tenant_id: id(20), principal_id: id(21) } }, result),
  /original configured Judge result identity/);
});

test('retained fences distinguish original replay, current reset and a populated independent sibling', () => {
  const owner = capture().turn.binding, requestId = id(4), originalOutcome = { status: 'completed', replayed: false };
  const value = { owner, requestId, originalOutcome,
    replay: { requestId, value: { ...originalOutcome, replayed: true },
      before: { actor: 3, judge: 2, effects: 2 }, after: { actor: 3, judge: 2, effects: 2 } },
    session: { requestId, before: { status: 200 }, after: { status: 401 } },
    reset: { requestId, immediatePreReset: { status: 200 }, before: owner,
      receipt: { resetId: id(70), status: 'committed', binding: { ...owner, generation: 2, status: 'active' },
        fromGeneration: 1, toGeneration: 2, targets: 1 },
      cleanupOperation: { resetId: id(70), status: 'committed', toGeneration: 2,
        binding: { launchId: owner.launchId, scenarioId: owner.scenarioId, generation: 1,
          platformOwnerId: owner.platformOwnerId, platformSessionId: owner.platformSessionId } },
      cleanupResolved: { status: 'committed', resolved: true },
      cleanupTargets: { resetId: id(70), status: 'committed', targets: [{ targetId: id(71),
        targetKind: 'reviews', launchId: owner.launchId, scenarioId: owner.scenarioId, fromGeneration: 1,
        platformOwnerId: owner.platformOwnerId, platformSessionId: owner.platformSessionId }] },
      cleanupHistory: [{ target_id: id(71), target_kind: 'reviews', launch_id: owner.launchId,
        scenario_id: owner.scenarioId, from_generation: 1, original_platform_owner_id: owner.platformOwnerId,
        original_platform_session_id: owner.platformSessionId, operation_id: id(70),
        target_receipt_version: 1, receipt_sha256: 'a'.repeat(64), completed_at: '2026-10-16T00:00:00.000Z' }],
      savedAfter: { status: 401 }, immutableBefore: [{ receiptSha256: 'a'.repeat(64) }],
      immutableAfter: [{ receiptSha256: 'a'.repeat(64) }], activeContributionsAfter: [] },
    sibling: { scope: { ...owner, platformOwnerId: 99, launchId: id(99) },
      positiveBefore: { status: 200, value: { id: 99 } }, positiveAfter: { status: 200, value: { id: 99 } },
      rowsBefore: [{ id: 99, body: 'Independent review' }], rowsAfter: [{ id: 99, body: 'Independent review' }] } };
  assert.equal(Q.assertV17RetainedFences(value).actualQualification, false);
  for (const mutate of [
    v => { v.replay.after.effects++; }, v => { v.replay.requestId = id(44); },
    v => { delete v.originalOutcome.replayed; }, v => { v.originalOutcome.replayed = true; },
    v => { v.replay.value.replayed = false; }, v => { v.replay.value.status = 'changed'; },
    v => { v.reset.immediatePreReset.status = 401; }, v => { v.reset.savedAfter.status = 200; },
    v => { v.reset.receipt.binding.platformOwnerId++; },
    v => { v.reset.cleanupHistory[0].operation_id = id(72); },
    v => { v.reset.cleanupHistory[0].receipt_sha256 = ''; },
    v => { v.reset.cleanupResolved.resolved = false; },
    v => { v.reset.immutableAfter = []; }, v => { v.reset.activeContributionsAfter = [{}]; },
    v => { v.sibling.scope.platformOwnerId = owner.platformOwnerId; },
    v => { v.sibling.rowsBefore = []; v.sibling.rowsAfter = []; },
  ]) { const bad = structuredClone(value); mutate(bad); assert.throws(() => Q.assertV17RetainedFences(bad)); }
});

test('real fixed projection and Judge producer deny missing review provenance without a model call', async () => {
  const { buildSecureShopReviewContentEvidence } = require('../server/services/secureshopReviewContentEvidence');
  const { buildSecureShopReviewContentRubric } = require('../server/services/secureshopReviewContentAssessment');
  const { createObjectiveJudge, prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
  for (const sourceCase of Object.keys(Q.SOURCES)) {
    const fixed = capture(sourceCase, Q.SOURCES[sourceCase].policyDecision);
    const read = fixed.turn.observations[0];
    const payload = JSON.parse(read.result.content[0].text);
    payload.reviews = payload.reviews.map(row => projectReviewForMode(row, 'fixed'));
    read.result.content[0].text = JSON.stringify(payload);
    fixed.turn.traces.find(row => row.kind === 'local_tool_result' && row.step === read.step)
      .result_json = JSON.stringify(read.result);
    fixed.turn.persistedTraces = structuredClone(fixed.turn.traces);
    fixed.creditBefore = []; fixed.creditAfter = [];
    Q.assertV17FixedStructure(fixed);
    const candidates = await buildSecureShopReviewContentEvidence({ ...fixed.turn,
      qualifyModelTrace: qualify, readSubmission: async () => fixed.source });
    assert.equal(candidates.followed.length, 1);
    const candidate = candidates.followed[0];
    const rubric = buildSecureShopReviewContentRubric('followed', 'fixed');
    let transcript, modelCalls = 0;
    const judge = createObjectiveJudge({ model: { async chat() {
      modelCalls++; throw new Error('Fixed missing provenance must deny before model');
    } }, observeExecutionTranscript: value => { transcript = value; } });
    const result = await judge({ rubric, ...candidate, execution: {
      ...fixed.turn.execution, signal: new AbortController().signal,
      async check() {}, async emit() {},
    } });
    assert.equal(modelCalls, 0);
    const prepared = prepareJudgeInput({ rubric, ...candidate });
    const record = { row: { family: rubric.family, scenario: rubric.scenario,
      objective_id: rubric.objectiveId, mode: 'fixed',
      rubric_version: rubric.version, packet: prepared.packet, evidence_digest: prepared.evidenceDigest,
      run_id: fixed.turn.execution.runId, verdict: 'fail', disposition: 'not_pass',
      judge_observations: null, judge_result_json: null }, transcript, wire: [] };
    record.row.result_json = require('../server/database/postgres/objectiveJudgmentRepository')
      .resultValue(result, record.row);
    record.row.result_serialized = JSON.stringify(record.row.result_json);
    record.row.result_digest = sha(record.row.result_serialized);
    assert.equal(Q.assertV17FixedProvenanceFailure(candidate, record, result).actualQualification, false);
    for (const mutate of [
      value => { value.candidate.facts.exact_review_observed = true; },
      value => { value.record.row.mode = 'vuln'; },
      value => { value.record.row.packet += ' '; },
      value => { value.record.row.disposition = 'awarded'; },
      value => { value.record.row.judge_observations = {}; },
      value => { value.record.transcript.header.maximumCalls = 2; },
      value => { value.record.transcript.calls.push({ attempt: 1 }); },
      value => { value.record.wire.push({ status: 200 }); },
      value => { value.result.attempts = 1; },
      value => { value.result.provider = 'ollama'; },
      value => { value.result.criteria[0].satisfied = true; },
      value => { value.result.explanation = 'Model refusal'; },
    ]) {
      const bad = structuredClone({ candidate, record, result }); mutate(bad);
      assert.throws(() => Q.assertV17FixedProvenanceFailure(bad.candidate, bad.record, bad.result));
    }
  }
});
