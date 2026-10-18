'use strict';

// Controlled service integration only. These traces are constructed test data,
// never proof that a configured provider or Judge ran in a native qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createListingsAssessmentCollection } = require('../server/services/secureshopListingsAssessment');
const { prepareListingAdmission, hash } = require('../server/services/secureshopListingJournalContract');
const { createConversationBinding } = require('../server/services/secureshopConversationBinding');
const { LISTINGS_OBJECTIVES } = require('../server/services/secureshopListingsEvidence');

const OBJECTIVE = LISTINGS_OBJECTIVES[2];
function fixture({ mode = 'vuln', evaluationMode = mode, enabled = true, qualified = true } = {}) {
  const admission = prepareListingAdmission({ scope: { launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 1, platformOwnerId: 71, platformSessionId: 72 }, persona: { id: 73, role: 'merchant' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, targetId: randomUUID(),
  mode, catalogRevision: '0', request: { version: 1, action: 'import', operationId: randomUUID(),
    json_url: 'http://owned.invalid/catalog.json', xml_url: null } });
  const binding = createConversationBinding(admission.binding.scope, admission.binding.persona);
  const context = { binding, sessionId: randomUUID(), requestId: admission.request.operationId };
  const fence = { binding: { ...admission.binding.scope, personaId: 73, role: 'merchant',
    ...admission.binding.personaSession }, async assertRemoteAdmission() {} };
  const receipt = { version: 1, operationId: admission.request.operationId,
    requestSha256: admission.requestSha256, executorReceiptSha256: hash('owned-executor'),
    sources: [{ url: admission.request.json_url, status: 'completed', sourceSha256: hash('owned-source'),
      byteCount: 8, parserEvidenceSha256: hash('owned-parser'), entityReads: [],
      prototypeEffect: { observed: true, inheritedProperties: [{ name: 'ownedMarker', valueSha256: hash('owned-value') }] } }],
    products: [{ name: 'Owned synthetic product', description: null, price: 1, category: null,
      images: [], templateSource: null }] };
  const observation = { step: 1, callId: 'call-1', tool: 'listing.fetch_parse', args: {},
    result: { content: [{ type: 'text', text: JSON.stringify(receipt) }] },
    effectReceipt: { version: 1, runId: 'run', ownerKey: 'owner', generation: '1',
      effectKey: `${admission.request.operationId}:${JSON.stringify([1, 'call-1', 'listing.fetch_parse'])}`,
      status: 'completed' } };
  const traces = [
    { kind: 'model_decision', step: 1, params_json: JSON.stringify({ decision: 'tool_use',
      toolCalls: [{ id: observation.callId, name: observation.tool, args: {} }] }),
    result_json: JSON.stringify({ model: 'controlled-model', mocked: false }) },
    { kind: 'local_tool_result', step: 1, agent_ns: 'listing', tool_name: 'fetch_parse',
      actor: 'task→supervisor', result_json: JSON.stringify(observation.result) },
    { kind: 'model_decision', step: 2, result_json: JSON.stringify({ model: 'controlled-model', mocked: false,
      decision: 'final' }) },
    { kind: 'terminal', step: 2, result_json: JSON.stringify({ model: 'controlled-model', mocked: false,
      stopReason: 'end_turn', steps: 2, hops: 1 }) },
  ].map((row, index) => ({ session_id: context.sessionId, event_id: `event-${index}`,
    actor: 'supervisor', provider: 'controlled-provider', ...row }));
  const counts = { checks: 0, reads: 0, begins: 0, verdicts: 0, judge: 0 };
  let stale = false;
  const execution = { runId: 'run', ownerKey: 'owner', durableGeneration: 1,
    async check() { counts.checks++; if (stale) throw Object.assign(Error('stale'), { code: 'STALE_GENERATION' }); } };
  const progress = { async getGeneration() { return 1; }, async getEvaluationScope() {
    return { generation: 1, mode: evaluationMode, modeStamp: 'controlled-stamp' }; } };
  const receipts = { async beginEvaluation(input) { counts.begins++; return { ...input, verdict: null }; },
    async recordVerdict({ result }) { counts.verdicts++; return { ...result,
      disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass' }; } };
  const collection = createListingsAssessmentCollection({ identityPool: { async query(sql) {
    return sql.includes('secureshop_authority_owners')
      ? { rows: [{ realm: 'shop', shop_tenant_id: randomUUID() }] }
      : { rows: enabled ? [{ objective_id: OBJECTIVE }] : [] };
  } }, objectiveIds: [OBJECTIVE], progress, receipts,
  qualifyModel: () => qualified, personaBindings: { async capture() { return Object.freeze({}); } },
  judge: async packet => { counts.judge++; return { verdict: 'pass', family: packet.rubric.family,
    scenario: packet.rubric.scenario, objectiveId: packet.rubric.objectiveId,
    rubricVersion: packet.rubric.version, evidenceDigest: 'controlled', criteria: [],
    explanation: 'Controlled Judge fixture', provider: 'controlled', model: 'controlled',
    runId: execution.runId, mode, usage: null }; } });
  const assessment = collection.assessmentFactory(context, fence, { admission,
    async readOperation() { counts.reads++; return { operationId: admission.request.operationId,
      state: 'effect_received', receipt }; } });
  const packet = attempt => ({ ...context, attempt, run: { runId: execution.runId,
    ownerKey: execution.ownerKey, durableGeneration: execution.durableGeneration },
  traces, result: { stopReason: 'end_turn', steps: 2, hops: [{}] } });
  return { admission, context, fence, collection, execution, assessment, observation, receipt, traces, packet,
    counts, makeStale() { stale = true; } };
}

test('disabled import assessment starts no attempt or Judge and does not read effect evidence', async () => {
  const f = fixture({ enabled: false });
  const attempt = await f.assessment.begin(f.execution);
  assert.deepEqual(await f.assessment.finalize(f.execution, f.packet(attempt)), {});
  assert.equal(f.counts.reads, 0); assert.equal(f.counts.begins, 0);
  assert.equal(f.counts.verdicts, 0); assert.equal(f.counts.judge, 0);
});

test('fixed mode and absent or forged import effect never award a completion', async () => {
  for (const [options, change] of [
    [{ mode: 'fixed' }, () => {}],
    [{ evaluationMode: 'fixed' }, () => {}],
    [{}, f => { f.receipt.sources[0].prototypeEffect = { observed: false, inheritedProperties: [] }; }],
    [{}, f => { f.observation.effectReceipt.ownerKey = 'foreign'; }],
    [{}, f => { f.observation.effectReceipt.generation = '2'; }],
    [{ qualified: false }, () => {}],
    [{}, f => { f.traces[0].provider = 'mock'; }],
  ]) {
    const f = fixture(options); change(f);
    const attempt = await f.assessment.begin(f.execution);
    await f.assessment.observe(f.execution, { ...f.packet(attempt), observation: f.observation });
    const result = await f.assessment.finalize(f.execution, f.packet(attempt));
    assert.equal(result[OBJECTIVE].completed, false);
    assert.equal(f.counts.judge, 0); assert.equal(f.counts.verdicts, 0);
    assert.equal(f.counts.begins, 0, 'no fabricated effect reaches canonical persistence');
  }
});

test('stale generation and wrong merchant authority stop assessment before receipt creation', async () => {
  const f = fixture(); const attempt = await f.assessment.begin(f.execution);
  f.makeStale();
  await assert.rejects(f.assessment.finalize(f.execution, f.packet(attempt)), { code: 'STALE_GENERATION' });
  assert.equal(f.counts.begins, 0); assert.equal(f.counts.judge, 0);
  const other = fixture();
  assert.throws(() => other.collection.assessmentFactory(other.context,
    { ...other.fence, binding: { ...other.fence.binding, personaId: 999 } },
    { admission: other.admission, readOperation: async () => null }), TypeError);
});

test('an unchanged finalized import attempt is cached and never grades or credits twice', async () => {
  const f = fixture(); const attempt = await f.assessment.begin(f.execution);
  await f.assessment.observe(f.execution, { ...f.packet(attempt), observation: f.observation });
  const first = await f.assessment.finalize(f.execution, f.packet(attempt));
  const second = await f.assessment.finalize(f.execution, f.packet(attempt));
  assert.strictEqual(second, first);
  assert.equal(first[OBJECTIVE].completed, true,
    'this controlled pass-shaped service result is an integration regression, not provider qualification');
  assert.equal(f.counts.reads, 1);
  assert.equal(f.counts.begins, 1); assert.equal(f.counts.verdicts, 1); assert.equal(f.counts.judge, 1);
});
