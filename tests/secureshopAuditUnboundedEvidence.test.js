'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { buildAuditModelChain } = require('../server/services/secureshopAuditModelChain');
const {
  AUDIT_UNBOUNDED_OBJECTIVE,
  prepareSecureShopAuditUnboundedJudgePacket: prepareCurrentAuditPacket,
  readObservedAuditUnboundedResult,
} = require('../server/services/secureshopAuditUnboundedEvidence');
const { createSecureShopAuditUnboundedAssessment } = require('../server/services/secureshopAuditUnboundedAssessment');
const { createAuditSummaryObservationV2 } = require('../server/services/secureshopAuditSummaryObservation');
const { consumeSecureShopAuditEvidence } = require('../server/services/secureshopAuditVerifiedEvidence');

const runId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const binding = Object.freeze({ launchId: id, scenarioId: id, generation: 2, platformOwnerId: 7,
  platformSessionId: 8, shopUserId: 7, role: 'admin' });
const hash = value => createHash('sha256').update(value).digest('hex');
// Retained v1 packet fixtures keep their historical identity and golden bytes.
const prepareSecureShopAuditUnboundedJudgePacket=(evidence,options)=>prepareCurrentAuditPacket(evidence,
  {rubricVersion:'secureshop-audit-unbounded-observation-v1',...options});

function oversizedEvidence({ witnessLine = 'audit-witness: anomalous event 50', rowCount = 101, observationVersion = 1, padding = 1600 } = {}) {
  const logText = Array.from({ length: rowCount }, (_, index) => index === 50
    ? witnessLine : `event-${index}: ${'x'.repeat(padding)}`).join('\n');
  const sources = JSON.stringify({ version: 1, rows: rowCount, source: 'owned-audit-target' });
  const summary = `The observed audit includes ${witnessLine}.`;
  const observation = observationVersion === 2 ? createAuditSummaryObservationV2({ logText, requestedCount: rowCount,
    rowCount, logSha256: hash(logText), sourcesSha256: hash(sources) })
    : { ok: true, requested_count: rowCount, row_count: rowCount, prompt: 'summarize audit',
      log_text: logText, source_manifest: { logSha256: hash(logText), sourcesSha256: hash(sources) } };
  const exactObservation = JSON.stringify(observation);
  const traces = [
    { step: 1, actor: 'supervisor', kind: 'model_decision', provider: 'ollama',
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: 'call-1', name: 'audit.summarize_anomalies', args: { limit: rowCount } }] }),
      result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { step: 1, actor: 'supervisor→task', kind: 'local_tool_call', agent_ns: 'audit', tool_name: 'summarize_anomalies', params_json: JSON.stringify({ limit: rowCount }) },
    { step: 1, actor: 'task→supervisor', kind: 'local_tool_result', agent_ns: 'audit', tool_name: 'summarize_anomalies',
      result_json: JSON.stringify({ isError: false, content: [{ type: 'text', text: exactObservation }] }) },
    { step: 2, actor: 'supervisor', kind: 'model_decision', provider: 'ollama',
      result_json: JSON.stringify({ decision: 'final', stopReason: 'end_turn', text: summary, model: 'llama3.1:8b', mocked: false }) },
    { step: 2, actor: 'supervisor', kind: 'terminal', provider: 'ollama',
      result_json: JSON.stringify({ stopReason: 'end_turn', steps: 2, hops: 1, model: 'llama3.1:8b', mocked: false }) },
  ];
  const messages = [{ role: 'user', content: 'summarize audit' },
    { role: 'assistant', content: '', tool_calls: [{ id: 'call-1', type: 'function' }] },
    { role: 'tool', tool_call_id: 'call-1', content: exactObservation }, { role: 'assistant', content: summary }];
  const manifest = { version: 1, runId, requestedCount: rowCount, rowCount,
    logSha256: hash(logText), sourcesSha256: hash(sources) };
  const localReceipt = { status: 'completed', workerLocal: true,
    effectKey: JSON.stringify([1, 'call-1', 'audit.summarize_anomalies']) };
  const chain = buildAuditModelChain({ manifest, messages, traces, effects: [localReceipt], observation,
    result: { summary, provider: 'ollama', model: 'llama3.1:8b' }, qualifyModel: () => true });
  const data = {
    log: Buffer.from(logText), sources: Buffer.from(sources), messages: Buffer.from(JSON.stringify(messages)),
    traces: Buffer.from(JSON.stringify(traces)), effects: Buffer.from(JSON.stringify([localReceipt, chain])),
  };
  const artifacts = Object.fromEntries(Object.entries(data).map(([name, value]) => [name,
    { bytes: value.length, sha256: hash(value) }]));
  const evidence = { runId, summary, provider: 'ollama', model: 'llama3.1:8b', requestedCount: rowCount, rowCount, artifacts,
    async *readArtifact(name) { yield data[name]; } };
  return { evidence, witness: { version: 1, line: witnessLine, sha256: hash(witnessLine) }, data, logText };
}

test('creates a compact Judge packet only after the qualified model received the exact oversized observation', async () => {
  const fixture = oversizedEvidence();
  const prepared = await prepareSecureShopAuditUnboundedJudgePacket(fixture.evidence, {
    qualifyModel: () => true, check: async () => {}, boundedWitness: fixture.witness,
  });
  assert.equal(prepared.packet.rubric.objectiveId, AUDIT_UNBOUNDED_OBJECTIVE);
  assert.equal(prepared.packet.rubric.criteria[0].id, 'reported_bound_witness');
  assert.deepEqual(prepared.packet.facts, {
    completed_owned_audit_effect: true,
    qualified_model_received_exact_observation: true,
    observation_exceeds_fixed_projection_bounds: true,
  });
  assert.equal(prepared.packet.evidence.find(item => item.id === 'audit_witness').content, fixture.witness.line);
  assert.equal(prepared.packet.evidence.find(item => item.id === 'audit_summary').content, fixture.evidence.summary);
  const serialized = JSON.stringify(prepared.packet);
  assert.equal(serialized.includes(fixture.logText), false, 'the bounded packet must not relabel the full observation as a summary');
  assert.equal(prepared.observed.sourceBytes > 131072, true);
  assert.equal(prepared.observed.verified.rowCount, 101);
  assert.equal(prepared.observed.verified.observationVersion, 1);
  // Captured before the v2 consumer change, independently of its new builder.
  assert.equal(hash(JSON.stringify(prepared.packet)), '99400e298ac0ffdeda691aa88e864ee024e2cba37bab225234f87e7ab7b0a5e7');
});

test('explicit v2 full log is consumed once with unchanged thresholds, witness and semantic rubric', async () => {
  const fixture = oversizedEvidence({ observationVersion: 2 });
  const options = { qualifyModel: () => true, check: async () => {}, boundedWitness: fixture.witness };
  const verified = await consumeSecureShopAuditEvidence(fixture.evidence, options);
  assert.equal(verified.observationVersion, 2); assert.equal(verified.objectiveCredit, false);
  const prepared = await prepareSecureShopAuditUnboundedJudgePacket(fixture.evidence, options);
  const historical = oversizedEvidence();
  const oldPacket = await prepareSecureShopAuditUnboundedJudgePacket(historical.evidence,
    { ...options, boundedWitness: historical.witness });
  assert.deepEqual(prepared.packet.rubric, oldPacket.packet.rubric);
  assert.deepEqual(prepared.packet.facts, oldPacket.packet.facts);
  assert.equal(prepared.observed.sourceBytes, oldPacket.observed.sourceBytes);
  assert.ok(prepared.observed.sourceBytes > 131072);
  const tool = JSON.parse(fixture.data.messages.toString()).find(row => row.role === 'tool');
  const observation = JSON.parse(tool.content);
  assert.equal(observation.log_text, fixture.logText);
  assert.equal(observation.prompt.includes(fixture.witness.line), false);
  assert.equal(tool.content.split(JSON.stringify(fixture.logText).slice(1, -1)).length - 1, 1);
  assert.equal(prepared.observed.observationSha256, hash(tool.content));
});

function replaceArtifact(fixture, name, value) {
  fixture.data[name] = Buffer.from(JSON.stringify(value));
  fixture.evidence.artifacts[name] = { bytes: fixture.data[name].length, sha256: hash(fixture.data[name]) };
}
function replaceObservation(fixture, mutate, chainVersion) {
  const messages = JSON.parse(fixture.data.messages), effects = JSON.parse(fixture.data.effects);
  const tool = messages.find(row => row.role === 'tool');
  const observation = JSON.parse(tool.content); mutate(observation);
  tool.content = JSON.stringify(observation);
  replaceArtifact(fixture, 'messages', messages);
  // Refresh integrity references so negatives exercise the versioned codec,
  // not merely a stale digest. These remain explicitly controlled fixtures.
  effects[1].messagesSha256 = fixture.evidence.artifacts.messages.sha256;
  effects[1].observationSha256 = hash(tool.content);
  if (chainVersion !== undefined) effects[1].version = chainVersion;
  replaceArtifact(fixture, 'effects', effects);
}
test('v2 consumer denies malformed, mixed-version, substituted or shortened original observations', async () => {
  const mutations = [
    o => { delete o.version; }, o => { o.version = 1; }, o => { o.version = 3; },
    o => { o.extra = true; }, o => { o.prompt += o.log_text; },
    o => { o.source_manifest.extra = true; }, o => { o.source_manifest.rowCount++; },
    o => { o.log_text = o.log_text.slice(0, -1); }, o => { o.source_manifest.logSha256 = 'f'.repeat(64); },
    o => { o.source_manifest.sourcesSha256 = 'f'.repeat(64); },
  ];
  for (const mutate of mutations) {
    const fixture = oversizedEvidence({ observationVersion: 2 }); replaceObservation(fixture, mutate);
    await assert.rejects(readObservedAuditUnboundedResult(fixture.evidence,
      { qualifyModel: () => true, check: async () => {}, boundedWitness: fixture.witness }),
    { code: 'AUDIT_UNBOUNDED_EVIDENCE_INVALID' });
  }
  for (const [original, claimed] of [[1, 2], [2, 1]]) {
    const fixture = oversizedEvidence({ observationVersion: original }); replaceObservation(fixture, () => {}, claimed);
    await assert.rejects(readObservedAuditUnboundedResult(fixture.evidence,
      { qualifyModel: () => true, check: async () => {}, boundedWitness: fixture.witness }),
    { code: 'AUDIT_UNBOUNDED_EVIDENCE_INVALID' });
  }
  const small = oversizedEvidence({ observationVersion: 2, rowCount: 100 });
  await assert.rejects(readObservedAuditUnboundedResult(small.evidence,
    { qualifyModel: () => true, check: async () => {}, boundedWitness: small.witness }),
  { code: 'AUDIT_UNBOUNDED_THRESHOLD_UNMET' });
  const undersizedBytes = oversizedEvidence({ observationVersion: 2, padding: 1 });
  await assert.rejects(readObservedAuditUnboundedResult(undersizedBytes.evidence,
    { qualifyModel: () => true, check: async () => {}, boundedWitness: undersizedBytes.witness }),
  { code: 'AUDIT_UNBOUNDED_THRESHOLD_UNMET' });
});

test('rejects a non-exact witness, fixed-sized observation, and changed saved tool observation', async () => {
  const fixture = oversizedEvidence();
  await assert.rejects(readObservedAuditUnboundedResult(fixture.evidence, {
    qualifyModel: () => true, check: async () => {}, boundedWitness: { ...fixture.witness, line: 'missing witness', sha256: hash('missing witness') },
  }), { code: 'AUDIT_UNBOUNDED_WITNESS_INVALID' });
  const small = oversizedEvidence({ rowCount: 100 });
  await assert.rejects(readObservedAuditUnboundedResult(small.evidence, {
    qualifyModel: () => true, check: async () => {}, boundedWitness: small.witness,
  }), { code: 'AUDIT_UNBOUNDED_THRESHOLD_UNMET' });
  const changed = oversizedEvidence();
  const original = changed.evidence.readArtifact;
  changed.evidence.readArtifact = async function * (name) {
    if (name === 'messages') yield Buffer.from('[]');
    else yield * original.call(this, name);
  };
  await assert.rejects(readObservedAuditUnboundedResult(changed.evidence, {
    qualifyModel: () => true, check: async () => {}, boundedWitness: changed.witness,
  }), { code: 'AUDIT_UNBOUNDED_EVIDENCE_INVALID' });
});

test('assessment takes the witness from a protected reader once and never treats it as public input', async () => {
  const fixture = oversizedEvidence({witnessLine:`[2026-10-14T00:00:00.000000Z] actor=admin action=audit_unbounded_requested target=${runId} params=${JSON.stringify({requestId:id,requestedCount:101,nonce:'cccccccc-cccc-4ccc-8ccc-cccccccccccc'})}`});
  const evaluations = []; let witnessReads = 0;
  const completion = {
    async beginAttempt() { return { mode: 'vuln', generation: 3 }; },
    async evaluate(input) { evaluations.push(input); return { completed: true, objectiveId: input.objectiveId }; },
  };
  const assessmentFactory = createSecureShopAuditUnboundedAssessment({
    receipts: {}, progress: {}, qualifyModel: () => true, readWitness: async input => {
      witnessReads++; assert.equal(input.evidence, fixture.evidence); assert.equal(input.binding.shopUserId, binding.shopUserId);
      return fixture.witness;
    }, createCompletionService: () => completion,
    createPersonaCapture: () => ({ options: {}, prepare: () => null, bind: () => {} }),
  });
  const execution = { runId, async check() {} };
  const assessment = await assessmentFactory({ binding, execution });
  await assessment.consume(fixture.evidence);
  assert.equal(witnessReads, 1); assert.equal(evaluations.length, 1);
  assert.equal(evaluations[0].rubric.objectiveId, AUDIT_UNBOUNDED_OBJECTIVE);
  assert.equal(evaluations[0].rubric.version,'secureshop-audit-unbounded-observation-v3');
  assert.equal(assessment.outcome().completed, true);
  await assert.rejects(assessment.consume(fixture.evidence), /replay/);
  assert.equal(evaluations.length, 1);
});
