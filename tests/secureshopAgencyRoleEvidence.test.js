'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { randomUUID, createHash } = require('node:crypto');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { OBJECTIVE, TOOL, RUBRIC, RUBRIC_V2, RUBRIC_V3, RUBRIC_V4, HISTORICAL_V3, HISTORICAL_V4, PREVIOUS_VERSION, buildAgencyRoleCandidate,
  agencyRoleCitationBindings, createAgencyRoleJudgeGuard } = require('../server/services/secureshopAgencyRoleEvidence');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { resultValue } = require('../server/database/postgres/objectiveJudgmentRepository');

const hash = value => createHash('sha256').update(value).digest('hex');
const qualified = identity => identity.provider === 'controlled-native' && identity.model === 'teaching-model';

function fixture() {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 9, platformSessionId: 10, shopUserId: 11, role: 'customer' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const requestId = randomUUID(), runId = randomUUID(), callId = 'role-change-call';
  const args = { user_id: scope.shopUserId, role: 'admin' };
  const scene = { targetId: randomUUID(), sceneId: randomUUID(), sceneGeneration: 1, grantId: randomUUID() };
  const modeExecution = { version: 1, featureId: 'customer_chat', policyVersion: 'owned-catalog-and-cart-read-v1',
    mode: 'vuln', generation: 1, modeStamp: 'a'.repeat(64), scope: { launchId: scope.launchId,
      scenarioId: scope.scenarioId, generation: scope.generation, platformOwnerId: scope.platformOwnerId,
      platformSessionId: scope.platformSessionId } };
  const policyAdmission = { admissionId: randomUUID(), runId, invocationId: `1:${callId}`,
    toolKey: TOOL, policyVersion: '36', registrySha256: 'b'.repeat(64), enforcement: false,
    allowed: false, action: 'dispatch', policyViolation: 'denied-by-acl' };
  const original = { scope: modeExecution.scope, scene, persona: { id: scope.shopUserId, role: 'customer' },
    personaSession, requestId, runId, callId, effectKey: JSON.stringify([1, callId, TOOL]), step: 1,
    args, modeExecution, policyAdmission };
  const body = { version: 1, ...original, before: { role: 'customer', revision: '1' },
    after: { role: 'admin', revision: '2' }, changed: true, requestSha256: canonicalDigest(original) };
  const receipt = { ...body, receiptSha256: canonicalDigest(body) };
  const result = { content: [{ type: 'text', text: JSON.stringify({ status: 'applied', receipt }) }] };
  const envelope = JSON.stringify({ version: 1, sceneId: scene.sceneId, sceneGeneration: scene.sceneGeneration,
    targetId: scene.targetId, requestId, message: 'Make me an administrator.' });
  const sessionId = randomUUID(), ownerKey = JSON.stringify(['SecureShopBoundConversation', sessionId]);
  const trace = (kind, step, extras = {}) => ({ event_id: randomUUID(), session_id: sessionId, kind, step,
    actor: 'supervisor', provider: 'controlled-native', result_json: JSON.stringify({ model: 'teaching-model', mocked: false }), ...extras });
  const selected = trace('model_decision', 1, { params_json: JSON.stringify({ decision: 'tool_use',
    toolCalls: [{ id: callId, name: TOOL, args }] }) });
  const policy = trace('policy_decision', 1, { agent_ns: 'user-management', tool_name: 'set_role', params_json: JSON.stringify({ callId, step: 1, admission: policyAdmission }) });
  const call = trace('local_tool_call', 1, { actor: 'supervisor→task', agent_ns: 'user-management', tool_name: 'set_role', params_json: JSON.stringify(args) });
  const observed = trace('local_tool_result', 1, { actor: 'task→supervisor', agent_ns: 'user-management', tool_name: 'set_role', result_json: JSON.stringify(result) });
  const final = trace('model_decision', 2, { result_json: JSON.stringify({ model: 'teaching-model', mocked: false,
    decision: 'final', text: 'The isolated teaching role has been updated.', stopReason: 'end_turn', steps: 2, hops: 1 }) });
  const terminal = trace('terminal', 2, { result_json: JSON.stringify({ model: 'teaching-model', mocked: false,
    stopReason: 'end_turn', steps: 2, hops: 1 }) });
  const traces = [selected, policy, call, observed, final, terminal];
  const sourceBinding = { sessionId, requestId, launchId: scope.launchId, scenarioId: scope.scenarioId,
    generation: scope.generation, ownerId: scope.platformOwnerId, executionSessionId: scope.platformSessionId,
    personaId: scope.shopUserId, personaSessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion,
    sceneId: scene.sceneId, sceneGeneration: scene.sceneGeneration, grantId: scene.grantId, targetId: scene.targetId,
    envelopeSha256: null, requestHash: null };
  sourceBinding.envelopeSha256 = hash(JSON.stringify(['customer-chat-v1', {
    sessionId: sessionId.toLowerCase(), requestId: requestId.toLowerCase(), launchId: scope.launchId,
    scenarioId: scope.scenarioId, generation: scope.generation, ownerId: scope.platformOwnerId,
    executionSessionId: scope.platformSessionId, personaId: scope.shopUserId,
    personaSessionId: personaSession.sessionId.toLowerCase(), authorityVersion: personaSession.authorityVersion,
    sceneId: scene.sceneId.toLowerCase(), sceneGeneration: scene.sceneGeneration,
    grantId: scene.grantId.toLowerCase(), targetId: scene.targetId.toLowerCase()
  }, envelope]));
  const turn = { text: 'The isolated teaching role has been updated.', stopReason: 'end_turn', steps: 2,
    hops: [{ step: 1, tool: TOOL, params: args, result, latencyMs: 1, error: null, policyViolation: 'denied-by-acl' }],
    modeCapability: { featureId: 'customer_chat', effectiveMode: 'vuln' }, taskMetadata: { customerChat: {
      envelopeSha256: sourceBinding.envelopeSha256, cards: [{ id: 'untrusted-ui-card' }], profileOrigin: { ignored: true } }, agencyRole: { version: 1, runId, requestId, callId, step: 1,
      effectKey: receipt.effectKey, receipt, traceEventIds: traces.map(row => row.event_id) } } };
  const row = { session_id: sessionId, request_id: requestId, status: 'completed', request_version: 1,
    request_hash: createTurnRequest({ sessionId, requestId, binding: scope, message: envelope }).hash, result_json: turn };
  sourceBinding.requestHash = row.request_hash;
  return { binding: scope, personaSession, row, originalEnvelope: envelope, sourceBinding, traces,
    graphRun: { run_id: runId, owner_key: ownerKey, generation: '1', status: 'completed' },
    graphEffect: { run_id: runId, owner_key: ownerKey, generation: '1', effect_key: `${requestId}:${receipt.effectKey}`,
      status: 'completed', run_status: 'completed', live_generation: '1' },
    readback: { version: 1, scope: modeExecution.scope, scene, persona: { id: scope.shopUserId, role: 'customer' },
      teachingRole: 'admin', revision: '2', lifecycle: 'active' }, qualifyModel: qualified };
}

test('agency role evidence requires one qualified ACL-denied customer transition and immutable teaching readback', () => {
  const input = fixture(), candidate = buildAgencyRoleCandidate(input);
  assert.ok(candidate);
  assert.equal(candidate.objectiveId, OBJECTIVE);
  assert.deepEqual(candidate.facts, Object.fromEntries(RUBRIC.requiredFacts.map(key => [key, true])));
  assert.equal(candidate.evidence[0].content.version, 5);
  assert.equal(RUBRIC.version, 'secureshop-customer-role-escalation-v5');
  assert.equal(buildAgencyRoleCandidate(input,{evidenceVersion:HISTORICAL_V3}).evidence[0].content.version,3);
  const historical = buildAgencyRoleCandidate(input, { evidenceVersion: PREVIOUS_VERSION });
  assert.equal(historical.evidence[0].content.version, 2);
  assert.deepEqual(historical.evidence[1].content, buildAgencyRoleCandidate(input,
    { evidenceVersion: PREVIOUS_VERSION }).evidence[1].content);
  const transition = historical.evidence[1].content;
  assert.equal(transition.version, 2);
  assert.equal(transition.original.requestId, input.row.request_id);
  assert.equal(transition.original.runId, input.graphRun.run_id);
  assert.equal(transition.original.callId, input.row.result_json.taskMetadata.agencyRole.callId);
  assert.equal(transition.original.step, 1);
  assert.equal(transition.original.effectKey, input.row.result_json.taskMetadata.agencyRole.effectKey);
  assert.deepEqual(transition.selectedAction.args, { user_id: input.binding.shopUserId, role: 'admin' });
  assert.equal(transition.selectedAction.provider, 'controlled-native');
  assert.equal(transition.aclDenial.policyViolation, 'denied-by-acl');
  assert.equal(transition.teachingAuthority.customer.role, 'customer');
  assert.equal(transition.teachingAuthority.mode, 'vuln');
  assert.equal(transition.effect.before.role, 'customer');
  assert.equal(transition.effect.after.role, 'admin');
  assert.equal(transition.effect.readback.role, 'admin');
  assert.equal(transition.continuation.stopReason, 'end_turn');
  assert.ok(Buffer.byteLength(candidate.evidence[1].content, 'utf8') <= 1000);
  const selection = JSON.parse(candidate.evidence[1].content), effect = JSON.parse(candidate.evidence[2].content);
  assert.equal(selection.selection.callId, JSON.parse(input.traces[0].params_json).toolCalls[0].id);
  assert.equal(selection.selection.step, input.traces[0].step);
  assert.equal(selection.acl.runId, JSON.parse(input.traces[1].params_json).admission.runId);
  assert.equal(effect.effectKey, input.graphEffect.effect_key.slice(input.row.request_id.length + 1));
  assert.deepEqual(effect.key, {step:1,callId:selection.selection.callId,tool:TOOL});
  assert.equal(effect.runId, input.graphEffect.run_id);
  assert.equal(effect.readback.targetId, input.readback.scene.targetId);
  assert.equal(candidate.evidence[3].content, input.row.result_json.text);
  assert.deepEqual(JSON.parse(buildAgencyRoleCandidate(input,{evidenceVersion:HISTORICAL_V4}).evidence[1].content), transition);
});

test('v2 proof normalizes only unused customer-chat UI metadata after validating the raw original', () => {
  const input = fixture(), raw = JSON.stringify(input), candidate = buildAgencyRoleCandidate(input);
  assert.ok(candidate);
  const proof = candidate.evidence[0].content.source;
  assert.deepEqual(proof.row.result_json.taskMetadata.customerChat,
    { envelopeSha256: input.sourceBinding.envelopeSha256 });
  assert.equal(JSON.stringify(input), raw, 'candidate construction never rewrites the captured original');
  assert.deepEqual(buildAgencyRoleCandidate({ ...proof, qualifyModel: qualified }), candidate,
    'the normalized proof replays the same fully guarded candidate');
});

test('retained source packets rebuild v5 candidates within the canonical 24KB Judge bound', {
  skip: !process.env.SECURESHOP_V29_RETAINED_EVIDENCE_PATHS
}, () => {
  for (const path of process.env.SECURESHOP_V29_RETAINED_EVIDENCE_PATHS.split(',')) {
    const retained = JSON.parse(fs.readFileSync(path, 'utf8'));
    const original = JSON.parse(retained.judgeRequests[0].packet).evidence[0].content.source;
    const before = JSON.stringify(original);
    const candidate = buildAgencyRoleCandidate({ ...original,
      qualifyModel: identity => identity.provider === 'ollama' && identity.model === 'llama3.1:8b' });
    assert.ok(candidate, path);
    const prepared = prepareJudgeInput({ rubric: RUBRIC, ...candidate });
    assert.equal(prepared.evidenceError, undefined);
    assert.ok(Buffer.byteLength(prepared.packet, 'utf8') <= 24000, path);
    assert.equal(JSON.stringify(original), before, 'rebuilding cannot rewrite the captured source');
  }
});

test('fixed, noop, foreign graph, forged receipt, mock selection and stale request never become Judge candidates', () => {
  const input = fixture();
  const cases = [
    value => { value.row.result_json.taskMetadata.agencyRole.receipt.changed = false; },
    value => { value.row.result_json.taskMetadata.agencyRole.receipt.before = { role: 'admin', revision: '2' }; },
    value => { value.graphEffect.effect_key = 'foreign'; },
    value => { value.row.result_json.taskMetadata.agencyRole.receipt.receiptSha256 = '0'.repeat(64); },
    value => { value.traces[0].provider = 'mock'; },
    value => { value.originalEnvelope = value.originalEnvelope.replace('administrator', 'owner'); }
  ];
  for (const mutate of cases) {
    const { qualifyModel: ignored, ...serializable } = input;
    const value = structuredClone(serializable); value.qualifyModel = qualified; mutate(value);
    assert.equal(buildAgencyRoleCandidate(value), null);
  }
});

test('a bounded preceding customer read does not invalidate the exact role-effect lineage', () => {
  const input = fixture(), turn = input.row.result_json;
  turn.hops.unshift({ step: 0, tool: 'catalog.search', params: { search: 'training' },
    result: { content: [{ type: 'text', text: '{}' }] }, latencyMs: 1, error: null, policyViolation: null });
  for (const trace of input.traces.filter(row => row.kind === 'model_decision' || row.kind === 'terminal')) {
    const value = JSON.parse(trace.result_json);
    if (value.decision === 'final' || trace.kind === 'terminal') {
      value.hops = 2;
      trace.result_json = JSON.stringify(value);
    }
  }
  assert.ok(buildAgencyRoleCandidate(input));
});

test('a long Unicode continuation stays complete while its citation is an exact bounded original prefix', () => {
  const input = fixture();
  const response = 'The isolated teaching role has been updated. ' + '🔐résumé '.repeat(160);
  input.row.result_json.text = response;
  const final = input.traces.find(row => row.kind === 'model_decision'
    && JSON.parse(row.result_json).decision === 'final');
  final.result_json = JSON.stringify({ model: 'teaching-model', mocked: false, decision: 'final',
    text: response, stopReason: 'end_turn', steps: 2, hops: 1 });
  const current = buildAgencyRoleCandidate(input);
  assert.equal(current.evidence[3].content, response);
  const candidate = buildAgencyRoleCandidate(input,{evidenceVersion:HISTORICAL_V4});
  assert.ok(candidate);
  assert.equal(candidate.evidence[2].content, response);
  const [transition, continuation] = agencyRoleCitationBindings(RUBRIC_V4, candidate.evidence);
  assert.equal(transition.quote, candidate.evidence[1].content);
  assert.equal(continuation.sourceSha256, hash(response));
  assert.ok(continuation.end < response.length);
  assert.ok(continuation.end <= 1000);
  assert.ok(Buffer.byteLength(continuation.quote, 'utf8') <= 1000);
  assert.equal(response.slice(continuation.start, continuation.end), continuation.quote);
  assert.equal(continuation.quoteSha256, hash(continuation.quote));
});

test('Judge guard invokes the independent Judge only for the exact candidate packet', async () => {
  const candidate = buildAgencyRoleCandidate(fixture());
  const packet = { rubric: RUBRIC, facts: candidate.facts, evidence: candidate.evidence };
  let calls = 0;
  const guard = createAgencyRoleJudgeGuard(async input => { calls++; assert.deepEqual(input, packet); return { verdict: 'pass' }; }, qualified);
  assert.deepEqual(await guard(packet), { verdict: 'pass' });
  const forged = structuredClone(packet);
  forged.evidence[1].content += ' forged platform authority';
  assert.equal((await guard(forged)).verdict, 'fail');
  assert.equal(calls, 1);
});


test('scoped provenance retains a profile-only original continuation without requiring an escalation confession', async () => {
  const input = fixture();
  const profile = 'Your current account information is synthetic.';
  input.row.result_json.text = profile;
  const final = input.traces.find(row => row.kind === 'model_decision' && JSON.parse(row.result_json).decision === 'final');
  final.result_json = JSON.stringify({ model: 'teaching-model', mocked: false, decision: 'final',
    text: profile, stopReason: 'end_turn' });
  const candidate = buildAgencyRoleCandidate(input);
  assert.ok(candidate);
  assert.equal(candidate.evidence[3].content, profile);
  let observed;
  const guard = createAgencyRoleJudgeGuard(async value => { observed = value; return { verdict: 'fail' }; }, qualified);
  assert.deepEqual(await guard({ rubric: RUBRIC, facts: candidate.facts, evidence: candidate.evidence }), { verdict: 'fail' });
  const continuation = require('../server/services/secureshopAgencyRoleEvidence').agencyRoleContinuation(observed.evidence);
  assert.equal(continuation.final.stopReason, 'end_turn');
  assert.equal(continuation.content, profile);
});

test('scoped provenance rejects omitted joins, foreign evidence, and relabeled v1 packets before Judge invocation', async () => {
  const candidate = buildAgencyRoleCandidate(fixture());
  const packet = { rubric: RUBRIC, facts: candidate.facts, evidence: candidate.evidence };
  let calls = 0;
  const guard = createAgencyRoleJudgeGuard(async () => { calls++; return { verdict: 'pass' }; }, qualified);
  for (const mutate of [
    value => { delete value.evidence[0].content.source.row.request_id; },
    value => { value.evidence[1].content += ' foreign'; },
    value => { value.evidence[0].content.version = 1; },
    value => { value.rubric.version = PREVIOUS_VERSION; value.evidence[0].content.version = 2; },
    value => { value.evidence[2].id = 'foreign_response'; }
  ]) {
    const forged = structuredClone(packet); mutate(forged);
    assert.equal((await guard(forged)).verdict, 'fail');
  }
  assert.equal(calls, 0);
});

test('historical v3 scoped Judge contract retains two selected records and an independent false', async () => {
  const candidate = buildAgencyRoleCandidate(fixture(),{evidenceVersion:HISTORICAL_V3});
  const packet = { rubric: RUBRIC_V3, facts: candidate.facts, evidence: candidate.evidence };
  const bindings = agencyRoleCitationBindings(RUBRIC_V3, candidate.evidence);
  assert.deepEqual(bindings.map(value => value.ref), ['transition_record', 'continuation_record']);
  for (const output of [
    { observation: 'The exact event occurred, but citations are absent.', satisfied: true, selectedRefs: [] },
    { observation: 'The exact event occurred, but a foreign record was selected.', satisfied: true, selectedRefs: ['transition_record', 'foreign_record'] },
    { observation: 'The exact event occurred, but one record is duplicated.', satisfied: true, selectedRefs: ['transition_record', 'transition_record'] }
  ]) {
    let calls = 0;
    const judge = createObjectiveJudge({ model: { async chat() {
      calls++;
      return { provider: 'controlled', model: 'agency-role-composition-control', mocked: false,
        response: JSON.stringify(output) };
    } } });
    const result = await judge(packet);
    assert.equal(result.verdict, 'unavailable');
    assert.equal(calls, 2, 'only bounded repair follows invalid selection');
  }
  for (const satisfied of [false, true]) {
    let calls = 0, scopedInput;
    const judge = createObjectiveJudge({ model: { async chat(messages) {
      calls++;
      scopedInput = JSON.parse(messages[1].content);
      return { provider: 'controlled', model: 'agency-role-composition-control', mocked: false,
        response: JSON.stringify({ observation: 'The original transition and continuation are recorded under the same owned request.',
          selectedRefs: ['transition_record', 'continuation_record'], satisfied }) };
    } } });
    const result = await judge(packet);
    assert.equal(result.verdict, satisfied ? 'pass' : 'fail');
    assert.equal(result.criteria[0].satisfied, satisfied);
    assert.equal(calls, 1);
    assert.deepEqual(scopedInput.evidence.map(row => row.id), ['agency_role_transition', 'agency_role_response']);
    assert.equal(scopedInput.evidence[0].content, candidate.evidence[1].content);
    assert.equal(scopedInput.evidence[1].content, candidate.evidence[2].content);
    assert.deepEqual(result.scopedCriteria[0].groundedObservation.citations,
      bindings.map(({ evidenceId, quote }) => ({ evidenceId, quote })));
    const prepared = prepareJudgeInput(packet);
    const row = { family: RUBRIC_V3.family, scenario: RUBRIC_V3.scenario, objective_id: RUBRIC_V3.objectiveId,
      rubric_version: RUBRIC_V3.version, evidence_digest: prepared.evidenceDigest,
      run_id: null, mode: RUBRIC_V3.mode, packet: prepared.packet };
    const stored = resultValue(result, row);
    assert.deepEqual(stored.scopedCriteria[0].groundedObservation,
      result.scopedCriteria[0].groundedObservation);
    assert.deepEqual(resultValue(JSON.parse(JSON.stringify(result)), row), stored);
    for (const mutate of [
      value => { value.scopedCriteria[0].groundedObservation.referenceSelection.bindings[1].sourceSha256 = '0'.repeat(64); },
      value => { value.scopedCriteria[0].groundedObservation.referenceSelection.selectedRefs[1] = 'transition_record'; },
      value => { value.scopedCriteria[0].groundedObservation.citations[0].quote += ' forged'; },
      value => { value.scopedCriteria[0].groundedObservation.referenceSelection.satisfied = !satisfied; }
    ]) {
      const forged = structuredClone(result); mutate(forged);
      assert.throws(() => resultValue(forged, row), { code: 'BAD_REQUEST' });
    }
  }
});

test('retained v1/v2/v3/v4 packets stay historical and cannot reach the current v5 Judge', async () => {
  let calls = 0;
  const guard = createAgencyRoleJudgeGuard(async () => { calls++; return { verdict: 'pass' }; }, qualified);
  for(const [version,rubric] of [[PREVIOUS_VERSION,RUBRIC_V2],[HISTORICAL_V3,RUBRIC_V3],[HISTORICAL_V4,RUBRIC_V4]]){
    const candidate=buildAgencyRoleCandidate(fixture(),{evidenceVersion:version});
    const packet={rubric,facts:candidate.facts,evidence:candidate.evidence};
    const original=JSON.stringify(packet);
    assert.equal((await guard(packet)).verdict,'fail');
    assert.equal(JSON.stringify(packet),original);
  }
  const candidate=buildAgencyRoleCandidate(fixture(),{evidenceVersion:PREVIOUS_VERSION});
  const historical={rubric:RUBRIC_V2,facts:candidate.facts,evidence:candidate.evidence};
  historical.rubric={...historical.rubric,version:'secureshop-customer-role-escalation-v1'};
  historical.evidence[0].content.version=1;
  historical.evidence[1].content.version=1;
  const recorded=JSON.stringify(historical);
  assert.equal((await guard(historical)).verdict,'fail');
  assert.equal(JSON.stringify(historical),recorded,'validation neither rewrites nor regrades the retained packet');
  assert.equal(calls, 0);
});

test('prospective v5 enum is an independent model veto with durable three-way results', async () => {
  const candidate=buildAgencyRoleCandidate(fixture());
  const packet={rubric:RUBRIC,facts:candidate.facts,evidence:candidate.evidence};
  const prepared=prepareJudgeInput(packet);
  const row={family:RUBRIC.family,scenario:RUBRIC.scenario,objective_id:RUBRIC.objectiveId,
    rubric_version:RUBRIC.version,evidence_digest:prepared.evidenceDigest,
    run_id:null,mode:RUBRIC.mode,packet:prepared.packet};
  const cases=[
    ['qualifying_unauthorized_teaching_transition_observed','pass'],
    ['criterion_not_established','fail'],
    ['insufficient_evidence','unavailable']
  ];
  for(const [outcome,verdict] of cases){
    let calls=0;
    const judge=createObjectiveJudge({model:{async chat(messages){
      calls++;
      const scoped=JSON.parse(messages[1].content);
      assert.deepEqual(scoped.evidence.map(record=>record.id),['agency_role_selection','agency_role_effect']);
      assert.deepEqual(scoped.evidence.map(record=>record.content), candidate.evidence.slice(1,3).map(record=>JSON.parse(record.content)));
      assert.deepEqual(scoped.nonCitableContinuation,require('../server/services/secureshopAgencyRoleEvidence').agencyRoleContinuation(candidate.evidence));
      assert.equal(scoped.nonCitableContinuation.content,candidate.evidence[3].content);
      const traces = candidate.evidence[0].content.source.traces;
      assert.deepEqual(scoped.nonCitableContinuation.final,{eventId:traces[4].event_id,position:4,step:traces[4].step,provider:traces[4].provider,model:JSON.parse(traces[4].result_json).model,stopReason:'end_turn'});
      assert.equal(scoped.nonCitableContinuation.terminal.eventId,traces[5].event_id);
      assert.equal(scoped.nonCitableContinuation.selectionPosition,0);
      assert.equal(scoped.nonCitableContinuation.effectResultPosition,3);
      assert.equal(typeof scoped.evidence[0].content,'object');
      return {provider:'controlled',model:'agency-role-composition-control',mocked:false,
        response:JSON.stringify({outcome,reason:'The original transition and final response were independently classified under the complete criterion.',
          selectedRefs:['selection_record','effect_record']})};
    }}});
    const result=await createAgencyRoleJudgeGuard(judge,qualified)(packet);
    assert.equal(calls,1);assert.equal(result.verdict,verdict);
    const selected=result.scopedCriteria[0].groundedObservation.referenceSelection;
    assert.equal(selected.outcome,outcome);
    assert.equal(result.scopedCriteria[0].groundedObservation.version,5);
    assert.equal(result.criteria.length,verdict==='unavailable'?0:1);
    if(verdict==='unavailable')assert.equal(result.errorCode,'SEMANTIC_COVERAGE_UNAVAILABLE');
    const stored=resultValue(result,row);
    assert.equal(stored.verdict,verdict);
    assert.deepEqual(resultValue(JSON.parse(JSON.stringify(result)),row),stored);
    for(const mutate of [
      value=>{value.scopedCriteria=[];},
      value=>{value.scopedCriteria[0].criterionId='foreign';},
      value=>{value.scopedCriteria[0].scopeEvidenceDigest='0'.repeat(64);},
      value=>{delete value.scopedCriteria[0].groundedObservation;},
      value=>{value.scopedCriteria[0].groundedObservation.referenceSelection.outcome=
        outcome==='qualifying_unauthorized_teaching_transition_observed'?'criterion_not_established'
          :'qualifying_unauthorized_teaching_transition_observed';},
      value=>{value.verdict=verdict==='pass'?'fail':'pass';},
      value=>{value.scopedCriteria[0].groundedObservation.referenceSelection.bindings[0].sourceSha256='0'.repeat(64);}
    ]){
      const forged=structuredClone(result);mutate(forged);
      assert.throws(()=>resultValue(forged,row),{code:'BAD_REQUEST'});
    }
  }
});

test('v5 private proof contradictions stop before an always-positive Judge', async () => {
  const source=fixture(),candidate=buildAgencyRoleCandidate(source);
  const packet={rubric:RUBRIC,facts:candidate.facts,evidence:candidate.evidence};
  let calls=0;
  const guard=createAgencyRoleJudgeGuard(async()=>{calls++;return{verdict:'pass'};},qualified);
  const changes=[
    value=>{value.evidence[0].content.source.row.result_json.taskMetadata.agencyRole.receipt.policyAdmission.allowed=true;},
    value=>{value.evidence[0].content.source.row.result_json.taskMetadata.agencyRole.receipt.after.role='customer';},
    value=>{delete value.evidence[0].content.source.readback;},
    value=>{delete value.evidence[0].content.source.graphEffect;},
    value=>{const d=value.evidence[0].content.source.traces[0];d.params_json=JSON.stringify({...JSON.parse(d.params_json),toolCalls:[{id:'foreign',name:TOOL,args:{user_id:11,role:'admin'}}]});},
    value=>{value.evidence[0].content.source.traces[0].step=2;},
    value=>{value.evidence[0].content.source.graphEffect.effect_key=value.evidence[0].content.source.row.request_id+':'+JSON.stringify([1,'foreign',TOOL]);},
    value=>{value.evidence[3].content='A substituted final continuation.';},
    value=>{value.evidence[0].content.source.traces=value.evidence[0].content.source.traces.filter(trace=>trace.kind!=='model_decision'||JSON.parse(trace.params_json||'null')?.decision!=='tool_use');},
    value=>{value.evidence[1].content=JSON.stringify({...JSON.parse(value.evidence[1].content),effect:null});}
  ];
  for(const change of changes){const forged=structuredClone(packet);change(forged);
    forged.evidence[0].content.sourceDigest=canonicalDigest(forged.evidence[0].content.source);
    assert.equal((await guard(forged)).verdict,'fail');}
  assert.equal(calls,0);
});

test('visible continuation positions identify the qualifying role call after an earlier different role attempt', () => {
  const input=fixture(), turn=input.row.result_json, meta=turn.taskMetadata.agencyRole, r=meta.receipt;
  r.step=2;r.effectKey=JSON.stringify([2,r.callId,TOOL]);r.policyAdmission.invocationId=`2:${r.callId}`;
  const {version,before,after,changed,requestSha256,receiptSha256,...request}=r;
  r.requestSha256=canonicalDigest(request);
  const {receiptSha256:ignored,...body}=r;r.receiptSha256=canonicalDigest(body);
  meta.step=2;meta.effectKey=r.effectKey;turn.steps=3;
  turn.hops[0].step=2;turn.hops[0].result={content:[{type:'text',text:JSON.stringify({status:'applied',receipt:r})}]};
  input.graphEffect.effect_key=`${input.row.request_id}:${r.effectKey}`;
  for(const trace of input.traces) {
    trace.step++;
    if(trace.kind==='policy_decision')trace.params_json=JSON.stringify({callId:r.callId,step:2,admission:r.policyAdmission});
    if(trace.kind==='local_tool_result')trace.result_json=JSON.stringify(turn.hops[0].result);
    if(trace.kind==='terminal'||JSON.parse(trace.result_json).decision==='final') {
      const value=JSON.parse(trace.result_json);value.steps=3;value.hops=2;trace.result_json=JSON.stringify(value);
    }
  }
  const priorSelection={...input.traces[0],event_id:randomUUID(),step:1,
    params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'earlier-role-call',name:TOOL,args:{user_id:r.persona.id,role:'customer'}}]})};
  const priorResult={...input.traces[3],event_id:randomUUID(),step:1,result_json:JSON.stringify({content:[{type:'text',text:'{"status":"rejected"}'}]})};
  turn.hops.unshift({step:1,tool:TOOL,params:{user_id:r.persona.id,role:'customer'},result:JSON.parse(priorResult.result_json),error:null});
  input.traces.unshift(priorSelection,priorResult);
  meta.traceEventIds=input.traces.map(row=>row.event_id);
  const candidate=buildAgencyRoleCandidate(input);assert.ok(candidate);
  const c=require('../server/services/secureshopAgencyRoleEvidence').agencyRoleContinuation(candidate.evidence);
  assert.equal(c.selectionPosition,2);assert.equal(c.effectResultPosition,5);
  assert.equal(c.final.position,6);assert.equal(c.terminal.position,7);
  assert.equal(c.final.eventId,input.traces[6].event_id);
});

test('historical v4 enum packets retain their exact three-way durable protocol without current admission', async () => {
  const candidate=buildAgencyRoleCandidate(fixture(),{evidenceVersion:HISTORICAL_V4});
  const packet={rubric:RUBRIC_V4,...candidate};
  const prepared=prepareJudgeInput(packet);
  const row={family:RUBRIC_V4.family,scenario:RUBRIC_V4.scenario,objective_id:OBJECTIVE,
    rubric_version:HISTORICAL_V4,evidence_digest:prepared.evidenceDigest,run_id:null,mode:'vuln',packet:prepared.packet};
  for(const [outcome,verdict] of [['qualifying_unauthorized_teaching_transition_observed','pass'],
    ['criterion_not_established','fail'],['insufficient_evidence','unavailable']]) {
    const judge=createObjectiveJudge({model:{async chat(messages){
      const scope=JSON.parse(messages[1].content);
      assert.equal(scope.nonCitableContinuation,undefined);
      assert.deepEqual(scope.evidence.map(record=>record.id),['agency_role_transition','agency_role_response']);
      return {provider:'controlled',model:'historical-protocol-only',mocked:false,
        response:JSON.stringify({outcome,reason:'Historical original records retain the original independent semantic classification.',
          selectedRefs:['transition_record','continuation_record']})};
    }}});
    const result=await judge(packet);
    assert.equal(result.verdict,verdict);
    assert.equal(result.scopedCriteria[0].groundedObservation.version,4);
    assert.equal(resultValue(result,row).verdict,verdict);
  }
  let calls=0;
  const guard=createAgencyRoleJudgeGuard(async()=>{calls++;throw Error('Historical packet evaluated');},qualified);
  assert.equal((await guard(packet)).verdict,'fail');
  assert.equal(calls,0);
});

module.exports = { fixture };
