'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { buildAuditModelChain } = require('../server/services/secureshopAuditModelChain');
const { createSecureShopAuditAssessment } = require('../server/services/secureshopAuditAssessment');

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const binding = Object.freeze({ launchId: id, scenarioId: id, generation: 2, platformOwnerId: 7,
  platformSessionId: 8, shopUserId: 7, role: 'admin' });
const hash = value => createHash('sha256').update(value).digest('hex');

function verifiedEvidence() {
  const summary = 'Suspicious content was described without claiming an administrative action.';
  const observation = { ok: true, requested_count: 2, row_count: 1, prompt: 'audit prompt', log_text: 'recorded event',
    source_manifest: { logSha256: hash('recorded event'), sourcesSha256: 's'.repeat(64) } };
  const exact = JSON.stringify(observation);
  const traces = [
    { step: 1, actor: 'supervisor', kind: 'model_decision', provider: 'ollama', params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: 'call-1', name: 'audit.summarize_anomalies', args: { limit: 2 } }] }), result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false }) },
    { step: 1, actor: 'supervisor→task', kind: 'local_tool_call', agent_ns: 'audit', tool_name: 'summarize_anomalies', params_json: JSON.stringify({ limit: 2 }) },
    { step: 1, actor: 'task→supervisor', kind: 'local_tool_result', agent_ns: 'audit', tool_name: 'summarize_anomalies', result_json: JSON.stringify({ isError: false, content: [{ type: 'text', text: exact }] }) },
    { step: 2, actor: 'supervisor', kind: 'model_decision', provider: 'ollama', result_json: JSON.stringify({ decision: 'final', stopReason: 'end_turn', text: summary, model: 'llama3.1:8b', mocked: false }) },
    { step: 2, actor: 'supervisor', kind: 'terminal', provider: 'ollama', result_json: JSON.stringify({ stopReason: 'end_turn', steps: 2, hops: 1, model: 'llama3.1:8b', mocked: false }) },
  ];
  const messages = [{ role: 'user', content: 'audit' }, { role: 'tool', content: exact }, { role: 'assistant', content: summary }];
  const manifest = { version: 1, runId: id, requestedCount: 2, rowCount: 1, logSha256: hash('recorded event'), sourcesSha256: 's'.repeat(64) };
  const effects = [{ status: 'completed', workerLocal: true, effectKey: JSON.stringify([1, 'call-1', 'audit.summarize_anomalies']) }];
  const chain = buildAuditModelChain({ manifest, messages, traces, effects, observation, result: { summary, provider: 'ollama', model: 'llama3.1:8b' }, qualifyModel: () => true });
  const data = { log: Buffer.from('recorded event'), sources: Buffer.from('sources'), messages: Buffer.from('messages'), traces: Buffer.from('traces'), effects: Buffer.from(JSON.stringify([effects[0], chain])) };
  const artifacts = Object.fromEntries(Object.entries(data).map(([name, value]) => [name, { bytes: value.length,
    sha256: name === 'effects' ? hash(value) : name === 'log' ? manifest.logSha256 : name === 'sources' ? manifest.sourcesSha256 : chain[`${name}Sha256`] }]));
  return { runId: id, summary, provider: 'ollama', model: 'llama3.1:8b', requestedCount: 2, rowCount: 1, artifacts,
    async *readArtifact(name) { yield data[name]; } };
}

function fixture({ stale = false, judgeVerdict = 'pass', scopeValue = { generation: 3, mode: 'vuln', modeStamp: 'fixture' }, personaBindings } = {}) {
  const events = []; let staleNow = stale; let judgeCalls = 0; let recordCalls = 0; let captured,personaToken;
  const execution = { runId: id, ownerKey: 'owner-audit', durableGeneration: '3', async check() {
    events.push('check'); if (staleNow) throw Object.assign(new Error('stale generation'), { code: 'STALE_GENERATION' });
  } };
  const receipts = {
    async beginEvaluation(input, token) { events.push('beginEvaluation'); captured = input; personaToken=token; return { ...input, generation: 3, verdict: null }; },
    async recordVerdict({ result }) { events.push('recordVerdict'); recordCalls++; return { ...captured, generation: 3, verdict: result.verdict, result, disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass' }; },
  };
  const progress = { async getGeneration() { return 3; }, async getEvaluationScope() { events.push('scope'); return scopeValue; } };
  const judge = async input => { judgeCalls++; events.push('judge'); return { family: input.rubric.family, scenario: input.rubric.scenario,
    objectiveId: input.rubric.objectiveId, rubricVersion: input.rubric.version, evidenceDigest: 'digest', mode: input.rubric.mode,
    verdict: judgeVerdict, criteria: [], explanation: 'controlled Judge', provider: 'fixture', model: 'fixture' }; };
  const assessmentFactory = createSecureShopAuditAssessment({ receipts, progress, judge, qualifyModel: () => true, personaBindings });
  return { execution, assessmentFactory, events, captured: () => captured, personaToken:()=>personaToken,
    get judgeCalls() { return judgeCalls; }, get recordCalls() { return recordCalls; }, stale() { staleNow = true; } };
}

test('begin captures owner/launch/generation before evidence and consumes one verified result', async () => {
  const f = fixture();
  const assessment = await f.assessmentFactory({ binding, execution: f.execution });
  assert.throws(() => assessment.outcome(), /did not complete/);
  assert.deepEqual(f.events.slice(0, 2), ['check', 'scope']);
  assert.equal(f.captured(), undefined);
  await assessment.consume(verifiedEvidence());
  const outcome = assessment.outcome();
  assert.equal(outcome.completed, true);
  assert.equal(f.captured().instanceScope.launchId, binding.launchId);
  assert.equal(f.captured().instanceScope.generation, binding.generation);
  assert.equal(f.captured().instanceScope.platformOwnerId, binding.platformOwnerId);
  assert.equal(f.judgeCalls, 1); assert.equal(f.recordCalls, 1);
  assert.ok(f.events.indexOf('beginEvaluation') < f.events.indexOf('judge'));
});

test('assessment evidence is single-use and no outcome exists before consume', async () => {
  const f = fixture(); const assessment = await f.assessmentFactory({ binding, execution: f.execution });
  const evidence = verifiedEvidence();
  await assessment.consume(evidence);
  await assert.rejects(assessment.consume(evidence), /replay/);
  assert.equal(f.judgeCalls, 1); assert.equal(f.recordCalls, 1);
});

test('stale execution prevents Judge and credit persistence', async () => {
  const f = fixture(); const assessment = await f.assessmentFactory({ binding, execution: f.execution });
  f.stale();
  await assert.rejects(assessment.consume(verifiedEvidence()), { code: 'STALE_GENERATION' });
  assert.equal(f.judgeCalls, 0); assert.equal(f.recordCalls, 0);
  assert.throws(() => assessment.outcome(), /did not complete/);
});

test('wrong persona or execution identity is rejected before assessment state', async () => {
  const f = fixture();
  await assert.rejects(f.assessmentFactory({ binding: { ...binding, role: 'customer' }, execution: f.execution }), TypeError);
  await assert.rejects(f.assessmentFactory({ binding, execution: { ...f.execution, runId: '' } }), TypeError);
});

test('missing or unsupported canonical mode metadata blocks assessment admission', async () => {
  for (const scopeValue of [{ generation: 3 }, { generation: 3, mode: 'strict', modeStamp: 'fixture' }]) {
    const f = fixture({ scopeValue });
    await assert.rejects(f.assessmentFactory({ binding, execution: f.execution }), /grading mode or generation is unavailable/);
    assert.equal(f.judgeCalls, 0);
  }
});

test('candidate assessment captures one private persona token and checks the current fence',async()=>{
  const token=Object.freeze({private:'persona-evaluation'});let captureCalls=0,fenceChecks=0;
  const personaBindings={async capture(input){captureCalls++;assert.equal(input.personaId,7);assert.equal(input.role,'admin');return token;}};
  const fence={binding:{...binding,personaId:7,role:'admin',sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',authorityVersion:'4'},
    async assertRemoteAdmission(){fenceChecks++;}};
  const f=fixture({personaBindings});
  const assessment=await f.assessmentFactory({binding,execution:f.execution},fence);
  await assessment.consume(verifiedEvidence());
  assert.equal(captureCalls,1);assert.equal(f.personaToken(),token);assert.ok(fenceChecks>=3);
  assert.equal(Object.hasOwn(assessment.outcome(),'personaEvaluation'),false);
});

test('candidate assessment rejects absent authority and revocation before Judge work',async()=>{
  const f=fixture({personaBindings:{async capture(){return{private:true};}}});
  await assert.rejects(f.assessmentFactory({binding,execution:f.execution}),/persona authority/i);
  const revoked=fixture({personaBindings:{async capture(){return{private:true};}}});
  let revokedNow=false;const fence={binding:{...binding,personaId:7,role:'admin',sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',authorityVersion:'4'},
    async assertRemoteAdmission(){if(revokedNow)throw Object.assign(new Error('revoked'),{code:'SHOP_AUTH_REVOKED'});}};
  const assessment=await revoked.assessmentFactory({binding,execution:revoked.execution},fence);revokedNow=true;
  await assert.rejects(assessment.consume(verifiedEvidence()),{code:'SHOP_AUTH_REVOKED'});
  assert.equal(revoked.judgeCalls,0);assert.equal(revoked.recordCalls,0);
});
