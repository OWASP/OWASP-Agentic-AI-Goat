'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const runner = require('./fixtures/ragObjectivePlanActual8b');

const sha = value => createHash('sha256').update(value).digest('hex');
const source = fs.readFileSync(path.join(runner.ROOT, 'tests/fixtures/ragObjectivePlanActual8b.js'), 'utf8');
// This immutable declaration belongs to the retained semantic-gate-failed run
// (attack_true_positive). Reading it is not current-runtime admission or qualification.
const historicalBytes = fs.readFileSync(path.join(runner.ROOT, runner.RUN_PATH));
const historicalRun = JSON.parse(historicalBytes);
const HISTORICAL_RUN_SHA256 = '0e3f2d15cfb82b8ee8e988f92e1239bdd1a6abd60952d81a992753a3abd17292';

test('historical failed-run declaration preserves its sealed bounds and four fixed cases', () => {
  assert.equal(sha(historicalBytes), HISTORICAL_RUN_SHA256);
  const admission = { run: historicalRun };
  assert.equal(admission.run.bounds.cases, 4);
  assert.equal(admission.run.bounds.maximumCallsPerCase, 6);
  assert.equal(admission.run.bounds.maximumStructuralRepairsPerCase, 1);
  assert.equal(admission.run.bounds.maximumInferenceCalls, 24);
  assert.equal(admission.run.bounds.maximumHttpCalls, 25);
  assert.deepEqual(admission.run.cases.map(item => item.id), [
    'attack_true_positive',
    'clean_task_false_positive_guard',
    'generic_refusal_without_same_group_recognition',
    'quoted_training_warning_is_not_injection',
  ]);
});

test('historical admission rejects the changed current checkout before network access', () => {
  const currentPackageSha256 = sha(fs.readFileSync(path.join(runner.ROOT, 'package.json')));
  assert.notEqual(currentPackageSha256, historicalRun.runtimePins.packageJsonSha256);
  const drift = Object.entries(historicalRun.sourcePins)
    .map(([relative, expected]) => ({ relative, expected, actual: sha(fs.readFileSync(path.join(runner.ROOT, relative))) }))
    .find(item => item.actual !== item.expected);
  assert(drift, 'the historical source pins must reject the current checkout');
  const originalFetch = global.fetch;
  let fetches = 0;
  global.fetch = async () => { fetches += 1; throw Error('unexpected network'); };
  try {
    assert.throws(() => runner.loadRun(runner.ROOT), error => {
      assert.equal(error.code, 'ERR_ASSERTION');
      assert.equal(error.actual, drift.actual);
      assert.equal(error.expected, drift.expected);
      return true;
    });
    assert.equal(fetches, 0);
  } finally { global.fetch = originalFetch; }
});

test('declared packets preserve full evidence but exclude fixture labels and notes', () => {
  // Packet construction checks the sealed input hashes independently of runtime admission.
  const admission = { run: historicalRun };
  const rows = runner.declarations(runner.ROOT, admission);
  assert.equal(rows.length, 4);
  for (const row of rows) {
    const packet = runner.diagnosticPacket(row);
    assert.deepEqual(Object.keys(packet).sort(), [
      'effects', 'objective', 'provenance', 'response', 'responseBoundary', 'source', 'trustedTask',
    ]);
    assert.equal(Object.hasOwn(packet, 'expectedVerdict'), false);
    assert.equal(Object.hasOwn(packet, 'derivationNote'), false);
    assert.equal(Object.hasOwn(packet, 'hashes'), false);
    assert.equal(packet.provenance.actualCapture, false);
    assert.equal(packet.provenance.kind, 'controlled_counterfactual');
    assert.equal(sha(packet.source), row.declaration.sourceSha256);
    assert.equal(sha(packet.response), row.declaration.responseSha256);
  }
});

test('source-stage wire is source-only and structural repair cannot request reinterpretation', () => {
  const base = {
    version: 'rag-objective-plan-diagnostic-v1',
    objective: 'rag_query_injection',
    stage: 'source_candidate',
    question: 'Select the source candidate.',
    repair: false,
    evidence: { objective: 'rag_query_injection', source: 'SOURCE_SENTINEL', provenance: {} },
    sourceCatalogue: [{ id: 's1', content: 'SOURCE_SENTINEL' }],
    responseCatalogue: [],
    candidate: null,
    outputSchema: { type: 'object' },
  };
  const first = runner.messagesFor(base);
  assert.match(first[0].content, /Do not decide objective credit/);
  assert.doesNotMatch(JSON.stringify(first), /RESPONSE_SENTINEL|expectedVerdict|derivationNote/);
  assert.deepEqual(JSON.parse(first[1].content).responseCatalogue, []);
  const repaired = runner.messagesFor({ ...base, repair: true });
  assert.match(repaired[0].content, /invalid JSON or closed-schema shape/);
  assert.match(repaired[0].content, /do not revise semantic meaning/);
});

test('launcher is Judge-only, stops at the first failed semantic gate, and saves partial wire state', () => {
  const imports = source.split('\n').filter(line => line.includes('require(')).join('\n');
  assert.doesNotMatch(imports, /objectiveJudge|objectiveJudgmentRepository|completion|database\//);
  assert.doesNotMatch(imports, /actorProvider|actorModel|executeTool|toolCall/);
  assert.match(source, /profile: 'manual24'/);
  assert.match(source, /if \(!current\.semanticMatch\)[\s\S]*?break;/);
  assert.match(source, /record: \(\) => \{ state\.calls = wire\.calls; save\(\); \}/);
  assert.match(source, /finally \{[\s\S]*?overall\.abort\(\); wire\.close\(\);/);
  assert.match(source, /creditAuthorized: false/);
});

test('wire-body and reconstructed-text hashes are independently verified', () => {
  const text = '{"answer":"supported","responseEvidenceIds":["r1"]}';
  const raw = JSON.stringify({ model: 'llama3.1:8b', done: true,
    message: { role: 'assistant', content: text } });
  const sent = { response: raw, responseSha256: sha(raw) };
  const record = { response: text, responseSha256: sha(text) };
  assert.notEqual(sent.responseSha256, record.responseSha256);
  assert.equal(runner.assertRecordedResponse(sent, record), text);
  assert.throws(() => runner.assertRecordedResponse({ ...sent, responseSha256: sha('tampered') }, record));
  assert.throws(() => runner.assertRecordedResponse(sent, { ...record, responseSha256: sha('tampered') }));
});

test('outer HTTP bound permits the transport-admitted 25th call only', () => {
  assert.doesNotThrow(() => runner.assertWithinHttpBudget(25, 25));
  assert.throws(() => runner.assertWithinHttpBudget(26, 25), /budget exhausted/);
});

test('invalid invocation is rejected before any network access', async () => {
  const originalFetch = global.fetch;
  let fetches = 0;
  global.fetch = async () => { fetches += 1; throw Error('unexpected network'); };
  try {
    await assert.rejects(runner.main({ extra: true }));
    assert.equal(fetches, 0);
  } finally {
    global.fetch = originalFetch;
  }
});

test('private result writes are atomic, durable, and owner-only', () => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'rag-objective-plan-')));
  const output = path.join(directory, 'result.json');
  const state = { status: 'partial', calls: [{ status: 'pending' }] };
  const save = runner.privateWriter(output, state);
  save();
  assert.deepEqual(JSON.parse(fs.readFileSync(output, 'utf8')), state);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  assert.equal(fs.existsSync(output + '.tmp'), false);
  fs.rmSync(directory, { recursive: true, force: true });
});
