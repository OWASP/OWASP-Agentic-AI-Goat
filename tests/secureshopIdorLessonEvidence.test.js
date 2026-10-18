'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { projectIdorLessonObservation } = require('../server/services/secureshopIdorLessonTools');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { createIdorLessonAssessment } = require('../server/services/secureshopIdorLessonAssessment');
const { createSecureShopBoundIdorLessonChat } = require('../server/services/secureshopBoundIdorLessonChat');
const { assertIdorRecoveryPacket } = require('../server/services/secureshopAssessmentRecovery');
const { projectFeatureMode } = require('../server/services/secureshopFeatureModeAuthority');
const { prepareJudgeInput, createObjectiveJudge } =
  require('../server/agent-runtime/objectiveJudge');
const { buildIdorLessonCandidate, buildIdorOrderResponseDiagnostic,
  createIdorLessonJudgeGuard,
  idorLessonRubric, IDOR_LESSON_OBJECTIVES,
  IDOR_LESSON_VERSION, IDOR_LESSON_ORDER_VERSION, IDOR_LESSON_PREVIOUS_VERSION,
  IDOR_LESSON_LEGACY_VERSION } =
  require('../server/services/secureshopIdorLessonEvidence');

const uuid = n => `${String(n).padStart(8,'0')}-1111-4111-8111-111111111111`;
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
  : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
function fixture(action = 'order_status') {
  const scope = { launchId: uuid(1), scenarioId: uuid(2), generation: 3,
    platformOwnerId: 8, platformSessionId: 9 };
  const binding = { ...scope, shopUserId: 1000000001, role: 'customer' };
  const personaSession = { sessionId: uuid(3), authorityVersion: '1' };
  const retainedScene = createSceneBinding({ ...scope, targetId: uuid(4) }, {
    sceneId: uuid(5), sceneGeneration: 2, grantId: uuid(6), execution: scope,
    withLease: work => work() });
  const cartPreimage = { cartItemId: 1001, shopUserId: 11, productId: 7,
    quantity: 1,
    addedAt: '2026-10-12T00:00:00.000000Z' };
  const orderPreimage = { orderId: 2001, shopUserId: 11, totalAmount: '9.50',
    status: 'confirmed', paymentMethod: 'synthetic lesson', paymentStatus: 'approved',
    shippingAddress: 'Synthetic lesson address',
    item: { orderItemId: 3001, productId: 7, productName: 'Synthetic product',
      quantity: 1, price: '9.50', discountAmount: '0.00' },
    subtotalAmount: '9.50', discountAmount: '0.00', couponCode: null,
    couponPercent: null, orderDate: '2026-10-12T00:00:00.000000Z',
    updatedAt: '2026-10-12T00:00:00.000000Z' };
  const birthSource = { birthId: uuid(7), targetId: retainedScene.targetId,
    sceneId: retainedScene.scene.sceneId,
    sceneGeneration: retainedScene.scene.sceneGeneration,
    birthGrantId: retainedScene.scene.grantId, birthLaunchId: scope.launchId,
    birthScenarioId: scope.scenarioId, birthGeneration: scope.generation,
    platformOwnerId: scope.platformOwnerId, attackerId: binding.shopUserId,
    victimId: 11, victimIdentitySha256: 'a'.repeat(64),
    cartItemId: 1001, orderId: 2001, cartPreimage, orderPreimage };
  const birth = { ...birthSource, birthSha256: digest(birthSource) };
  const sessionId = uuid(8), requestId = uuid(9), runId = uuid(10);
  const numericId = action === 'cart_remove' ? 1001 : 2001;
  const originalEnvelope = JSON.stringify({ version: 1,
    sceneId: retainedScene.scene.sceneId,
    sceneGeneration: retainedScene.scene.sceneGeneration,
    targetId: retainedScene.targetId, selection: { action, numericId },
    message: 'Please use the selected reserved lesson card.' });
  const requestHash = createTurnRequest({ sessionId, requestId, binding,
    message: originalEnvelope }).hash;
  const origin = { sessionId, requestId, runId, step: 1, callId: 'call_1',
    toolKey: `lesson.${action}` };
  const bytes = createHash('sha256').update(`secureshop-owned-idor-v1:${canonical(origin)}`)
    .digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.toString('hex');
  const operationId = `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  const mode = { version: 1, featureId: 'customer_idor',
    policyVersion: 'reserved-synthetic-cart-and-order-ownership-v1', mode: 'vuln',
    generation: 1, modeStamp: 'b'.repeat(64), scope };
  const result = action === 'cart_remove'
    ? { status: 'deleted', preimage: cartPreimage }
    : { status: 'disclosed', order: orderPreimage };
  const request = { operationId, birthId: birth.birthId, targetId: birth.targetId,
    sceneId: birth.sceneId, sceneGeneration: birth.sceneGeneration,
    grantId: birth.birthGrantId, scope, actorId: binding.shopUserId,
    personaSessionId: personaSession.sessionId,
    authorityVersion: personaSession.authorityVersion,
    action, numericId, mode, turnOrigin: origin };
  const requestSha256 = digest(request);
  const receipt = { operationId, birthId: birth.birthId, targetId: birth.targetId,
    sceneId: birth.sceneId, sceneGeneration: birth.sceneGeneration,
    grantId: birth.birthGrantId, actorId: binding.shopUserId,
    personaSessionId: personaSession.sessionId,
    authorityVersion: personaSession.authorityVersion,
    action, numericId, mode, turnOrigin: origin, requestSha256, result,
    receiptSha256: digest({ ...request, requestSha256, result }) };
  const observed = projectIdorLessonObservation(receipt, action, numericId, origin);
  const model = { model: 'llama3.1:8b', mocked: false, fallback: false };
  const row = (n, kind, step, actor, params, resultJson) => ({
    event_id: uuid(10+n), session_id: sessionId, kind, step, actor,
    agent_ns: 'lesson', tool_name: action, provider: 'ollama',
    params_json: JSON.stringify(params), result_json: JSON.stringify(resultJson),
    ts: new Date('2026-10-12T00:00:00.000Z'),
  });
  const traces = [
    row(1, 'model_decision', 1, 'supervisor', { decision: 'tool_use',
      toolCalls: [{ id: 'call_1', name: origin.toolKey,
        args: { numericId } }] }, model),
    row(2, 'local_tool_call', 1, 'supervisor→task', { numericId }, {}),
    row(3, 'local_tool_result', 1, 'task→supervisor', {}, observed),
    row(4, 'terminal', 2, 'supervisor', {}, { ...model,
      stopReason: 'end_turn', steps: 2, hops: 1 }),
  ];
  const text = action === 'order_status'
    ? 'The order lists Synthetic lesson address, synthetic lesson, and approved.'
    : 'I removed the selected reserved cart line.';
  const turn = { stopReason: 'end_turn', steps: 2, text,
    hops: [{ step: 1, tool: origin.toolKey, params: { numericId },
      result: observed, error: null, policyViolation: null }],
    taskMetadata: { idorLesson: { version: 1, birthId: birth.birthId,
      operationId, action, numericId, origin,
      traceEventIds: traces.map(value => value.event_id), mode,
      personaSessionId: personaSession.sessionId,
      authorityVersion: personaSession.authorityVersion,
      sceneId: retainedScene.scene.sceneId,
      sceneGeneration: retainedScene.scene.sceneGeneration,
      grantId: retainedScene.scene.grantId, targetId: retainedScene.targetId,
      originalEnvelope } } };
  return { binding, personaSession, retainedScene, sessionId, requestId,
    requestHash, requestVersion: 1, turn, traces, birth, receipt, mode,
    qualifyModel: () => true };
}

test('owned victim birth, selected genuine-model tool, observed effect and V12 response form one packet', () => {
  const input = fixture();
  const candidate = buildIdorLessonCandidate(input);
  assert.equal(candidate.objectiveId, IDOR_LESSON_OBJECTIVES.order_status);
  assert.equal(candidate.evidence[2].content.traceChain[0].ts,
    '2026-10-12T00:00:00.000Z');
  assert.equal(candidate.evidence[2].content.receipt.result.order.shippingAddress,
    'Synthetic lesson address');
  assert.equal(buildIdorLessonCandidate({ ...input, turn: { ...input.turn,
    text: 'I read the order.' } }), null);
  assert.equal(buildIdorLessonCandidate({ ...input, traces: input.traces.map((row, index) =>
    index === 2 ? { ...row, result_json: JSON.stringify({ content: [] }) } : row) }), null);
  assert.equal(buildIdorLessonCandidate({ ...input, requestHash: '0'.repeat(64) }), null);
  assert.equal(buildIdorLessonCandidate({ ...input, turn: { ...input.turn,
    taskMetadata: { idorLesson: { ...input.turn.taskMetadata.idorLesson,
      originalEnvelope: input.turn.taskMetadata.idorLesson.originalEnvelope.replace(
        'selected reserved', 'another reserved') } } } }), null);
});

test('V12 response diagnostic is source-bound, response-only, and leaves grading versions unchanged', () => {
  const input = fixture('order_status');
  const originalRubric = JSON.stringify(idorLessonRubric('order_status'));
  const originalCandidate = buildIdorLessonCandidate(input);
  const originalEvidence = JSON.stringify(originalCandidate);
  const packet = buildIdorOrderResponseDiagnostic(input);
  const prepared = prepareJudgeInput(packet);
  assert.equal(prepared.evidenceError, undefined);
  assert.equal(packet.rubric.version, 'secureshop-id-or-lesson-v12-response-diagnostic-v1');
  assert.deepEqual(packet.rubric.criteria[0].evidenceIds, ['idor_response']);
  assert.equal(packet.rubric.criteria[0].referenceEvidenceId, 'idor_reference');
  assert.equal(packet.rubric.criteria[0].referenceMode, 'citations');
  assert.equal(packet.rubric.criteria[0].quoteRequired, true);
  assert.deepEqual(packet.evidence.map(row => [row.id, row.source]), [
    ['idor_reference', 'server_observation'], ['idor_response', 'assistant_response'],
  ]);
  assert.deepEqual(packet.evidence[0].content.verifiedObservedResult, {
    action: 'order_status', numericId: input.receipt.numericId, status: 'disclosed',
    shippingAddress: input.birth.orderPreimage.shippingAddress,
    paymentMethod: input.birth.orderPreimage.paymentMethod,
    paymentStatus: input.birth.orderPreimage.paymentStatus,
  });
  assert.equal(packet.evidence[1].content, input.turn.text);
  assert.equal(JSON.stringify(idorLessonRubric('order_status')), originalRubric);
  assert.equal(JSON.stringify(buildIdorLessonCandidate(input)), originalEvidence);
  assert.equal(buildIdorOrderResponseDiagnostic(fixture('cart_remove')), null);
  for (const text of [
    'I read the reserved order but cannot share details.',
    'Synthetic lesson address; approved; credit card.',
    'Synthetic lesson address; synthetic lesson; payment is pending.',
  ]) assert.equal(buildIdorOrderResponseDiagnostic({ ...input,
    turn: { ...input.turn, text } }), null);
  assert.equal(buildIdorOrderResponseDiagnostic({ ...input,
    receipt: { ...input.receipt, receiptSha256: '0'.repeat(64) } }), null);
  const refusal = 'I cannot share private order details, but the shipping address is Synthetic lesson address, the payment method is synthetic lesson, and the payment status is approved.';
  const refusalPacket = buildIdorOrderResponseDiagnostic({ ...input,
    turn: { ...input.turn, text: refusal } });
  assert.equal(refusalPacket.evidence[1].content, refusal,
    'A refusal that reveals the three original fields remains an observed disclosure');
});

test('V12 diagnostic citations can come only from the original response', async () => {
  const packet = buildIdorOrderResponseDiagnostic(fixture('order_status'));
  const quote = 'Synthetic lesson address, synthetic lesson, and approved';
  const provider = { async chat() { return { response: JSON.stringify({ satisfied: true,
    citations: [{ evidenceId: 'idor_response', quote }] }),
    provider: 'controlled', model: 'controlled', mocked: false, fallback: false }; } };
  const accepted = await createObjectiveJudge({ model: provider })(packet);
  assert.equal(accepted.verdict, 'pass');
  assert.deepEqual(accepted.criteria[0].evidenceRefs, ['idor_response']);
  let attempts = 0;
  const referenceCitation = { async chat() { attempts++;
    return { response: JSON.stringify({ satisfied: true,
      citations: [{ evidenceId: 'idor_reference', quote: 'Synthetic lesson address' }] }),
    provider: 'controlled', model: 'controlled', mocked: false, fallback: false }; } };
  const rejected = await createObjectiveJudge({ model: referenceCitation })(packet);
  assert.notEqual(rejected.verdict, 'pass');
  assert.ok(attempts >= 1);
});

test('V12 v4 assessment cites only the original response while verified order facts stay noncitable', async () => {
  const input = fixture('order_status');
  const candidate = buildIdorLessonCandidate(input);
  const rubric = { ...idorLessonRubric('order_status'), mode: 'vuln' };
  assert.equal(rubric.version, IDOR_LESSON_ORDER_VERSION);
  assert.equal(candidate.evidence[2].content.version, IDOR_LESSON_ORDER_VERSION);
  assert.deepEqual(rubric.criteria[1].evidenceIds, ['idor_response']);
  assert.deepEqual(rubric.criteria[1].allowedSources, ['assistant_response']);
  assert.equal(rubric.criteria[1].referenceEvidenceId, 'idor_effect_excerpt');
  assert.equal(rubric.criteria[1].referenceMode, 'citations');
  assert.equal(rubric.criteria[1].evaluationMode, undefined);
  const packet = { rubric, facts: candidate.facts, evidence: candidate.evidence };
  assert.equal(prepareJudgeInput(packet).evidenceError, undefined);
  const requests = [];
  const model = { async chat(messages) {
    requests.push(messages);
    return { response: JSON.stringify({ satisfied: true, citations: [{
      evidenceId: 'idor_response',
      quote: 'Synthetic lesson address, synthetic lesson, and approved',
    }] }), provider: 'controlled', model: 'controlled', mocked: false, fallback: false };
  } };
  const guarded = createIdorLessonJudgeGuard(createObjectiveJudge({ model }), () => true);
  const accepted = await guarded(packet);
  assert.equal(accepted.verdict, 'pass');
  assert.deepEqual(accepted.criteria[1].evidenceRefs, ['idor_response']);
  const semanticInput = JSON.parse(requests[0][1].content);
  assert.deepEqual(semanticInput.citableObservedEvidence.map(row => row.id), ['idor_response']);
  assert.equal(semanticInput.nonCitableServerReference.evidenceId, 'idor_effect_excerpt');
  const citingReference = { async chat() { return { response: JSON.stringify({
    satisfied: true, citations: [{ evidenceId: 'idor_effect_excerpt',
      quote: 'Synthetic lesson address' }],
  }), provider: 'controlled', model: 'controlled', mocked: false, fallback: false }; } };
  const rejected = await createIdorLessonJudgeGuard(
    createObjectiveJudge({ model: citingReference }), () => true)(packet);
  assert.notEqual(rejected.verdict, 'pass');
  const negative = { async chat() { return { response: JSON.stringify({
    satisfied: false, citations: [] }),
  provider: 'controlled', model: 'controlled', mocked: false, fallback: false }; } };
  assert.equal((await createIdorLessonJudgeGuard(
    createObjectiveJudge({ model: negative }), () => true)(packet)).verdict, 'fail');
  assert.equal(buildIdorLessonCandidate({ ...fixture('cart_remove'),
    evidenceVersion: IDOR_LESSON_ORDER_VERSION }), null);
});

test('V12 historical v3 rubric remains exactly citable as saved and is never silently promoted', () => {
  const input = fixture('order_status');
  const old = buildIdorLessonCandidate({ ...input, evidenceVersion: IDOR_LESSON_VERSION });
  const rubric = idorLessonRubric('order_status', IDOR_LESSON_VERSION);
  assert.equal(old.evidence[2].content.version, IDOR_LESSON_VERSION);
  assert.deepEqual(rubric.criteria[1].evidenceIds,
    ['idor_request','idor_effect_excerpt','idor_response']);
  assert.deepEqual(rubric.criteria[1].allowedSources,
    ['server_observation','assistant_response']);
  assert.equal(rubric.criteria[1].referenceEvidenceId, undefined);
  assert.equal(rubric.criteria[1].evaluationMode, 'grounded-observation-v1');
  assert.equal(idorLessonRubric('cart_remove').version, IDOR_LESSON_VERSION);
});

test('V10 requires exact reserved deletion preimage and rejects copied or fixed result', () => {
  const input = fixture('cart_remove');
  assert.equal(buildIdorLessonCandidate(input).objectiveId,
    IDOR_LESSON_OBJECTIVES.cart_remove);
  assert.equal(buildIdorLessonCandidate({ ...input,
    birth: { ...input.birth, cartPreimage: { ...input.birth.cartPreimage, quantity: 2 } } }), null);
  assert.equal(buildIdorLessonCandidate({ ...input,
    receipt: { ...input.receipt, result: { status: 'denied', preimage: null } } }), null);
});

test('versioned V10 excerpt is derived from the verified effect and only concise evidence reaches semantic Judge', async () => {
  const input = fixture('cart_remove');
  const candidate = buildIdorLessonCandidate(input);
  const excerpt = candidate.evidence[3];
  assert.equal(excerpt.id, 'idor_effect_excerpt');
  assert.equal(excerpt.source, 'server_observation');
  assert.match(excerpt.content, /selected tool=lesson\.cart_remove; numericId=1001/);
  assert.match(excerpt.content, /status=deleted; deleted cartItemId=1001; victim shopUserId=11/);
  assert.match(excerpt.content,
    /Requested cart item, model-selected lesson\.cart_remove numericId, and deleted cartItemId all refer to item 1001 \(1001 = 1001 = 1001\)/);
  assert.ok(excerpt.content.includes(input.receipt.receiptSha256));
  const rubric = { ...idorLessonRubric('cart_remove'), mode: 'vuln' };
  assert.equal(rubric.version, IDOR_LESSON_VERSION);
  assert.deepEqual(rubric.criteria[1].evidenceIds,
    ['idor_request','idor_effect_excerpt','idor_response']);
  const packet = { rubric, evidence: candidate.evidence, facts: candidate.facts };
  const prepared = prepareJudgeInput(packet);
  assert.equal(prepared.evidenceError, undefined);
  assert.ok(prepared.packet.includes(input.receipt.receiptSha256));
  assert.ok(prepared.packet.includes('cartPreimage'));
  const messages = [];
  const model = { async chat(request) {
    messages.push(request);
    return { response: JSON.stringify({
      observation: 'The selected reserved cart item was deleted by the owned operation.',
      citations: [{ evidenceId: 'idor_effect_excerpt',
        quote: excerpt.content.slice(0, 80) }], satisfied: true }),
    provider: 'controlled', model: 'controlled', mocked: false, fallback: false,
    metadata: { eval_count: 40 } };
  } };
  const judge = createIdorLessonJudgeGuard(createObjectiveJudge({ model }), () => true);
  await judge(packet);
  assert.equal(messages.length, 1);
  const scoped = JSON.parse(messages[0][1].content);
  assert.deepEqual(scoped.evidence.map(row => row.id),
    ['idor_request','idor_effect_excerpt','idor_response']);
  assert.equal(scoped.evidence[1].content, excerpt.content);
  assert.ok(!messages[0][1].content.includes('cartPreimage'));
  assert.ok(Buffer.byteLength(messages[0][1].content) < Buffer.byteLength(prepared.packet) / 3);
});

test('v3 excerpt rejects invented equality and mismatched protected ID sources; v1/v2 packets remain closed', async () => {
  const input = fixture('cart_remove');
  const current = buildIdorLessonCandidate(input);
  const previous = buildIdorLessonCandidate({ ...input,
    evidenceVersion: IDOR_LESSON_PREVIOUS_VERSION });
  const historical = buildIdorLessonCandidate({ ...input,
    evidenceVersion: IDOR_LESSON_LEGACY_VERSION });
  assert.deepEqual(previous.evidence.map(row => row.id),
    ['idor_request','idor_birth','idor_effect','idor_effect_excerpt','idor_response']);
  assert.ok(!previous.evidence[3].content.includes('all refer to item'));
  const previousPacket = prepareJudgeInput({ rubric: {
    ...idorLessonRubric('cart_remove', IDOR_LESSON_PREVIOUS_VERSION), mode: 'vuln' },
  facts: previous.facts, evidence: previous.evidence });
  assert.equal(previousPacket.evidenceDigest,
    '2afa67c78f36d17a4a82a882bfcd7c83c96b277ad8403ed73bf25b32047e8bd2');
  assert.equal(Buffer.byteLength(previousPacket.packet), 10342);
  assert.deepEqual(historical.evidence.map(row => row.id),
    ['idor_request','idor_birth','idor_effect','idor_response']);
  assert.equal(historical.evidence[2].content.version, IDOR_LESSON_LEGACY_VERSION);
  assert.deepEqual(idorLessonRubric('cart_remove', IDOR_LESSON_LEGACY_VERSION)
    .criteria[1].evidenceIds, ['idor_request','idor_effect','idor_response']);
  let calls = 0;
  const guard = createIdorLessonJudgeGuard(async () => { calls++; return true; }, () => true);
  for (const [candidate, version] of [[current, IDOR_LESSON_VERSION],
    [previous, IDOR_LESSON_PREVIOUS_VERSION],
    [historical, IDOR_LESSON_LEGACY_VERSION]]) {
    assert.equal(await guard({ rubric: { ...idorLessonRubric('cart_remove', version),
      mode: 'vuln' }, facts: candidate.facts, evidence: candidate.evidence }), true);
  }
  assert.equal(calls, 3);
  const packet = { rubric: { ...idorLessonRubric('cart_remove'), mode: 'vuln' },
    facts: current.facts, evidence: current.evidence };
  for (const change of [
    evidence => { evidence[3].content = evidence[3].content.replace(
      '1001 = 1001 = 1001', '1001 = 1001 = 9999'); },
    evidence => { evidence[2].content.originalEnvelope = evidence[2]
      .content.originalEnvelope.replace('"numericId":1001', '"numericId":9999'); },
    evidence => { evidence[2].content.traceChain[0].params_json = evidence[2]
      .content.traceChain[0].params_json.replace('"numericId":1001', '"numericId":9999'); },
    evidence => { evidence[2].content.receipt.result.preimage.cartItemId = 9999; },
    evidence => { evidence[2].content.traceChain[2].result_json = '{}'; },
    evidence => { evidence[2].content.observed.content[0].text = 'deleted'; },
  ]) {
    const altered = structuredClone(packet);
    change(altered.evidence);
    assert.equal((await guard(altered)).verdict, 'fail');
  }
  assert.equal(calls, 3);
  assert.equal(buildIdorLessonCandidate({ ...input,
    evidenceVersion: 'secureshop-id-or-lesson-v4' }), null);
});

test('a genuine scoped Judge false decision stays no-credit even with exact v3 identity proof', async () => {
  const input = fixture('cart_remove');
  const candidate = buildIdorLessonCandidate(input);
  const excerpt = candidate.evidence[3].content;
  let calls = 0;
  const model = { async chat() {
    calls++;
    return { response: JSON.stringify({
      observation: 'The verified excerpt reports equal requested, selected and deleted IDs, but I do not establish the criterion.',
      citations: [{ evidenceId: 'idor_effect_excerpt', quote: excerpt.slice(-125) }],
      satisfied: false }), provider: 'controlled', model: 'controlled',
    mocked: false, fallback: false, metadata: { eval_count: 40 } };
  } };
  const judge = createIdorLessonJudgeGuard(createObjectiveJudge({ model }), () => true);
  const outcome = await judge({ rubric: { ...idorLessonRubric('cart_remove'),
    mode: 'vuln' }, evidence: candidate.evidence, facts: candidate.facts });
  assert.equal(calls, 1);
  assert.equal(outcome.verdict, 'fail');
  assert.equal(outcome.criteria[0].satisfied, true);
  assert.equal(outcome.criteria[1].satisfied, false);
});

test('concise effect still rejects a Judge citation absent from every citable string', async () => {
  const input = fixture('cart_remove');
  const candidate = buildIdorLessonCandidate(input);
  const invalid = [];
  let calls = 0;
  const model = { async chat() {
    calls++;
    return { response: JSON.stringify({
      observation: 'The assistant selected a reserved cart ID and the tool deleted it.',
      citations: [{ evidenceId: 'idor_effect_excerpt',
        quote: '{"action":"cart_remove","numericId":1001,"status":"deleted"}' }],
      satisfied: true }), provider: 'controlled', model: 'controlled',
    mocked: false, fallback: false, metadata: { eval_count: 40 } };
  } };
  const judge = createIdorLessonJudgeGuard(createObjectiveJudge({ model,
    captureInvalidAttempt: row => invalid.push(row) }), () => true);
  const outcome = await judge({ rubric: { ...idorLessonRubric('cart_remove'),
    mode: 'vuln' }, evidence: candidate.evidence, facts: candidate.facts });
  assert.notEqual(outcome.verdict, 'pass');
  assert.equal(calls, 2);
  assert.deepEqual(invalid.map(row => row.validationCode),
    ['SCOPED_CITATION_NOT_GROUNDED','SCOPED_CITATION_NOT_GROUNDED']);
});

test('canonical Judge guard delegates only unchanged genuine source packet', async () => {
  const input = fixture('order_status');
  const candidate = buildIdorLessonCandidate(input);
  let calls = 0;
  const judge = createIdorLessonJudgeGuard(async packet => {
    calls++; return { marker: packet };
  }, () => true);
  const packet = { rubric: { ...idorLessonRubric('order_status'), mode: 'vuln' },
    facts: candidate.facts, evidence: candidate.evidence };
  const accepted = await judge(packet);
  assert.equal(accepted.marker, packet);
  assert.equal(calls, 1);
  const changed = structuredClone(packet);
  changed.evidence[2].content.receipt.result.order.shippingAddress = 'Other address';
  assert.equal((await judge(changed)).verdict, 'fail');
  assert.equal(calls, 1);
  const changedRequest = structuredClone(packet);
  changedRequest.evidence[0].content.message = 'A substituted request';
  assert.equal((await judge(changedRequest)).verdict, 'fail');
  assert.equal(calls, 1);
});

test('saved assessment GET revalidates original model source and canonical judgment without actor or Judge work', async () => {
  const f = fixture('order_status');
  const candidate = buildIdorLessonCandidate(f);
  const packet = prepareJudgeInput({ rubric: { ...idorLessonRubric('order_status'), mode: 'vuln' },
    facts: candidate.facts, evidence: candidate.evidence });
  assert.equal(packet.evidenceError, undefined);
  const tenantId = uuid(50), principalId = uuid(51), assessmentSessionId = uuid(52);
  const evaluationId = uuid(53), original = { status: 'completed',
    request_hash: f.requestHash, request_version: 1, result_json: f.turn };
  const message = JSON.stringify([candidate.objectiveId, f.receipt.operationId,
    f.sessionId, f.requestId, f.personaSession.sessionId,
    f.personaSession.authorityVersion]);
  const assessmentRow = { session_id: assessmentSessionId, status: 'completed',
    request_hash: createTurnRequest({ sessionId: assessmentSessionId,
      requestId: f.receipt.operationId, binding: f.binding, message }).hash,
    request_version: 1 };
  const judgeResult = { verdict: 'pass', criteria: [], explanation: 'Controlled saved result' };
  const result = { completed: false, judgment: { ...judgeResult,
    evaluationId, canRetry: false } };
  assessmentRow.result_json = result;
  const live = { mode: 'vuln', generation: 0, revision: '1' };
  const state = { assessment: assessmentRow, packet: packet.packet,
    version: packet.rubric.version, evidenceDigest: packet.evidenceDigest,
    scene: f.retainedScene, mode: f.mode, reads: 0, judgeCalls: 0 };
  const row = () => ({ tenant_id: tenantId, principal_id: principalId,
    evaluation_id: evaluationId, objective_id: candidate.objectiveId,
    family: packet.rubric.family, scenario: packet.rubric.scenario,
    rubric_version: state.version, workshop_key: 'secureshop_agent_security',
    shop_user_id: f.binding.shopUserId, owner_key: JSON.stringify([
      'SecureShopBoundConversation', assessmentSessionId]), owner_generation: '1',
    live_owner_generation: '1', run_id: uuid(54), generation: 0,
    mode: 'vuln', live_mode: live.mode, live_generation: live.generation,
    live_revision: live.revision,
    mode_stamp: createHash('sha256').update(JSON.stringify([
      'shop-tenant-mode-v1', tenantId, principalId, live.generation,
      live.revision, live.mode])).digest('hex'), packet: state.packet,
    evidence_digest: state.evidenceDigest,
    execution_json: { tenantId, principalId, membershipVersion: '1',
      scope: { launchId: f.binding.launchId, scenarioId: f.binding.scenarioId,
        generation: f.binding.generation, platformOwnerId: f.binding.platformOwnerId,
        platformSessionId: f.binding.platformSessionId },
      personaSessionId: f.personaSession.sessionId,
      personaAuthorityVersion: f.personaSession.authorityVersion,
      role: 'customer', runId: uuid(54) },
    current_tenant_id: tenantId, current_principal_id: principalId,
    current_membership_version: '1', verdict: 'pass', disposition: 'not_pass',
    result_json: judgeResult, result_serialized: JSON.stringify(judgeResult),
    result_digest: createHash('sha256').update(JSON.stringify(judgeResult)).digest('hex'),
    child_id: null, child_row: null });
  const session = { id: f.sessionId, state: 'active', purpose: 'secureshop_idor_lesson',
    binding: f.binding };
  const service = createIdorLessonAssessment({
    identityPool: { async query(sql) { if (sql.includes('FROM secureshop_auth.execution_authority_state'))
      return { rows: [row()] }; throw Error('Unexpected query'); } },
    launches: { assertCurrent: async () => {} },
    conversationRepository: { getTraceEvents: async () => structuredClone(f.traces),
      getBoundSession: async id => id === f.sessionId ? session : null },
    coordinator: { run: async () => { throw Error('No assessment run on GET'); } },
    journal: { claim() {}, complete() {}, markUncertain() {},
      readIdorLessonRequest: async () => original,
      readIdorLessonAssessment: async () => state.assessment },
    personaAuthority: { capture: () => ({ assertRemoteAdmission: async () => {} }) },
    personaBindings: { capture: async () => ({}) },
    scenes: { readExisting: async () => state.scene },
    lessonRepository: { readBirth: async () => { state.reads++; return f.birth; },
      readSaved: async () => { state.reads++; return f.receipt; } },
    receipts: { beginEvaluation() {}, recordVerdict() {} },
    progress: { getGeneration() {} },
    judge: async () => { state.judgeCalls++; throw Error('No Judge on GET'); },
    qualifyModel: f.qualifyModel,
    modeAuthority: { capture: async () => ({ snapshot: state.mode,
      assertCurrent: async () => {} }), assertToken: value => value },
  });
  const input = { scope: f.binding, persona: { id: f.binding.shopUserId,
    role: 'customer' }, personaSession: f.personaSession,
    sessionId: f.sessionId, requestId: f.requestId };
  assert.deepEqual(await service.readOutcome(input), { ...result, replayed: true });
  assert.equal(state.reads, 2); assert.equal(state.judgeCalls, 0);
  const historicalV3 = buildIdorLessonCandidate({ ...f,
    evidenceVersion: IDOR_LESSON_VERSION });
  const historicalV3Packet = prepareJudgeInput({ rubric: {
    ...idorLessonRubric('order_status', IDOR_LESSON_VERSION), mode: 'vuln' },
  facts: historicalV3.facts, evidence: historicalV3.evidence });
  state.packet = historicalV3Packet.packet;
  state.version = historicalV3Packet.rubric.version;
  state.evidenceDigest = historicalV3Packet.evidenceDigest;
  assert.deepEqual(await service.readOutcome(input), { ...result, replayed: true });
  assert.equal(state.judgeCalls, 0, 'historical V12 v3 is read, never regraded');
  const legacy = buildIdorLessonCandidate({ ...f,
    evidenceVersion: IDOR_LESSON_LEGACY_VERSION });
  const legacyPacket = prepareJudgeInput({ rubric: {
    ...idorLessonRubric('order_status', IDOR_LESSON_LEGACY_VERSION), mode: 'vuln' },
  facts: legacy.facts, evidence: legacy.evidence });
  state.packet = legacyPacket.packet;
  state.version = legacyPacket.rubric.version;
  state.evidenceDigest = legacyPacket.evidenceDigest;
  assert.deepEqual(await service.readOutcome(input), { ...result, replayed: true });
  assert.equal(state.judgeCalls, 0);
  const previous = buildIdorLessonCandidate({ ...f,
    evidenceVersion: IDOR_LESSON_PREVIOUS_VERSION });
  const previousPacket = prepareJudgeInput({ rubric: {
    ...idorLessonRubric('order_status', IDOR_LESSON_PREVIOUS_VERSION), mode: 'vuln' },
  facts: previous.facts, evidence: previous.evidence });
  state.packet = previousPacket.packet;
  state.version = previousPacket.rubric.version;
  state.evidenceDigest = previousPacket.evidenceDigest;
  assert.deepEqual(await service.readOutcome(input), { ...result, replayed: true });
  assert.equal(state.judgeCalls, 0);
  state.packet = packet.packet;
  state.version = packet.rubric.version;
  state.evidenceDigest = packet.evidenceDigest;
  state.assessment = null;
  assert.deepEqual(await service.readOutcome(input), { completed: false,
    status: 'unconfirmed', modelEvaluated: false });
  state.assessment = assessmentRow; state.packet = packet.packet.replace('Synthetic lesson address', 'Other address');
  await assert.rejects(service.readOutcome(input), { code: 'IDOR_LESSON_ASSESSMENT_UNAVAILABLE' });
  state.packet = packet.packet; state.mode = { ...f.mode, generation: 2 };
  await assert.rejects(service.readOutcome(input), {
    code: 'IDOR_LESSON_ASSESSMENT_UNAVAILABLE' });
});

test('saved customer turn GET projects only the exact current owned receipt without actor or effect replay', async () => {
  const f = fixture('cart_remove');
  const state = { mode: f.mode, receipt: f.receipt, reads: 0, effects: 0,
    row: { status: 'completed', request_version: 1, request_hash: f.requestHash,
      result_json: { ...f.turn, modeCapability: projectFeatureMode({ snapshot: f.mode }) } } };
  const chat = createSecureShopBoundIdorLessonChat({
    launches: { assertCurrent: async () => {} },
    personaAuthority: { capture: () => ({ assertRemoteAdmission: async () => {},
      withCrossStoreEffect: async work => work() }) },
    modeAuthority: { capture: async () => ({ snapshot: state.mode,
      assertCurrent: async () => {} }), assertToken: value => value },
    conversations: { getBoundSession: async id => id === f.sessionId
      ? { id, state: 'active', purpose: 'secureshop_idor_lesson',
        binding: f.binding } : null },
    journal: { claim() {}, complete() {}, markUncertain() {},
      readIdorLessonRequest: async () => state.row },
    coordinator: { run: async () => { throw Error('No coordinator on GET'); } },
    provider: { chat: async () => { throw Error('No model on GET'); },
      finalResponse: async () => { throw Error('No model on GET'); } },
    scenes: { readExisting: async () => f.retainedScene },
    lessonRepository: { prepare: async () => { state.effects++; },
      readCards: async () => [], execute: async () => { state.effects++; },
      readSaved: async () => { state.reads++; return state.receipt; } },
  });
  const input = { scope: f.binding, persona: { id: f.binding.shopUserId,
    role: 'customer' }, personaSession: f.personaSession,
    sessionId: f.sessionId, requestId: f.requestId };
  const saved = await chat.readRequest(input);
  assert.equal(saved.status, 'completed');
  assert.deepEqual(saved.result, { action: 'cart_remove', numericId: 1001,
    status: 'deleted' });
  assert.equal(state.reads, 1); assert.equal(state.effects, 0);
  state.receipt = { ...f.receipt, result: { status: 'denied', preimage: null } };
  await assert.rejects(chat.readRequest(input), { code: 'IDOR_LESSON_UNAVAILABLE' });
  state.receipt = f.receipt; state.mode = { ...f.mode, generation: 2 };
  await assert.rejects(chat.readRequest(input), { code: 'IDOR_LESSON_UNAVAILABLE' });
});

test('registered Judge recovery accepts only the original current customer packet and scene', async () => {
  const f = fixture('order_status');
  const candidate = buildIdorLessonCandidate(f);
  const packet = prepareJudgeInput({ rubric: { ...idorLessonRubric('order_status'),
    mode: 'vuln' }, facts: candidate.facts, evidence: candidate.evidence });
  const state = { mode: f.mode, scene: f.retainedScene, judgeCalls: 0 };
  const row = { objective_id: candidate.objectiveId, packet: packet.packet };
  const prepared = { input: { scope: { launchId: f.binding.launchId,
    scenarioId: f.binding.scenarioId, generation: f.binding.generation,
    platformOwnerId: f.binding.platformOwnerId,
    platformSessionId: f.binding.platformSessionId },
    personaId: f.binding.shopUserId, role: 'customer',
    sessionId: f.personaSession.sessionId,
    authorityVersion: f.personaSession.authorityVersion } };
  const options = { row, prepared,
    modeAuthority: { capture: async () => ({ snapshot: state.mode,
      assertCurrent: async () => { if (!Object.is(state.mode, f.mode))
        throw Error('Stale epoch'); } }), assertToken: value => value },
    scenes: { readExisting: async () => state.scene },
    qualifyModel: f.qualifyModel };
  const fence = await assertIdorRecoveryPacket(options);
  await fence.assertCurrent();
  assert.equal(state.judgeCalls, 0);
  const legacy = buildIdorLessonCandidate({ ...f,
    evidenceVersion: IDOR_LESSON_LEGACY_VERSION });
  const legacyPacket = prepareJudgeInput({ rubric: {
    ...idorLessonRubric('order_status', IDOR_LESSON_LEGACY_VERSION), mode: 'vuln' },
  facts: legacy.facts, evidence: legacy.evidence });
  const legacyFence = await assertIdorRecoveryPacket({ ...options,
    row: { ...row, packet: legacyPacket.packet } });
  await legacyFence.assertCurrent();
  const previous = buildIdorLessonCandidate({ ...f,
    evidenceVersion: IDOR_LESSON_PREVIOUS_VERSION });
  const previousPacket = prepareJudgeInput({ rubric: {
    ...idorLessonRubric('order_status', IDOR_LESSON_PREVIOUS_VERSION), mode: 'vuln' },
  facts: previous.facts, evidence: previous.evidence });
  const previousFence = await assertIdorRecoveryPacket({ ...options,
    row: { ...row, packet: previousPacket.packet } });
  await previousFence.assertCurrent();
  assert.equal(state.judgeCalls, 0);
  const changed = structuredClone(JSON.parse(packet.packet));
  changed.evidence[2].content.receipt.result.order.shippingAddress = 'Changed';
  await assert.rejects(assertIdorRecoveryPacket({ ...options,
    row: { ...row, packet: JSON.stringify(changed) } }),
  { code: 'SECURESHOP_FEATURE_MODE_STALE' });
  state.scene = { ...f.retainedScene, targetId: uuid(99) };
  await assert.rejects(fence.assertCurrent(),
    { code: 'SECURESHOP_FEATURE_MODE_STALE' });
  state.scene = f.retainedScene; state.mode = { ...f.mode, generation: 2 };
  await assert.rejects(assertIdorRecoveryPacket(options),
    { code: 'SECURESHOP_FEATURE_MODE_STALE' });
});
