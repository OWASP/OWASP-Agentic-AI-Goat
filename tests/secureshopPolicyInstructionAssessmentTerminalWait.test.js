'use strict';
// Intended destination after the V30 hold: tests/secureshopPolicyInstructionAssessmentTerminalWait.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..'); // destination tests/ directory
const source = fs.readFileSync(path.join(ROOT, 'tests/postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');

function actualMethod() {
  const scope = source.slice(source.indexOf('async function qualifyPolicyInstruction('));
  const waitStart = scope.indexOf('  const wait = async (predicate, label, timeout = 120000) => {');
  const waitEnd = scope.indexOf('  const posts =', waitStart);
  const methodStart = scope.indexOf('    async waitAutomaticAssessment() {');
  const methodEnd = scope.indexOf('    async credit({ evaluationId: id }) {', methodStart);
  assert(waitStart >= 0 && waitEnd > waitStart && methodStart >= 0 && methodEnd > methodStart);
  const waitSource = scope.slice(waitStart, waitEnd);
  const methodSource = scope.slice(methodStart, methodEnd);
  assert.match(methodSource, /rows\.length === 1 && rows\[0\]\.verdict != null && rows\[0\]\.evaluated_at != null/);
  assert.match(methodSource, /assert\.equal\(row\.verdict, 'pass'\); assert\.equal\(row\.disposition, 'awarded'\)/);
  return { waitSource, methodSource };
}

async function run(states) {
  const { waitSource, methodSource } = actualMethod();
  let now = 0, reads = 0;
  const wait = new Function('sleep', 'Date', `${waitSource}; return wait;`)(
    async () => { now += 60000; }, { now: () => now });
  const judgments = async () => states[Math.min(reads++, states.length - 1)];
  const facts = { original: true }, evidence = [{ id: 'original', content: true }];
  const proof = { provider: 'ollama', model: 'pinned' };
  const runtime = { readConfiguredJudgeProvenance: () => proof,
    prepareJudgeInput: () => ({ facts, evidence }) };
  const method = new Function('wait', 'judgments', 'assert', 'judgeResults', 'require',
    'candidateInputs', 'RUBRIC', 'buildPolicyInstructionCandidate', `let evaluationId;
      return ({${methodSource}}).waitAutomaticAssessment;`)(
    wait, judgments, assert, new Map([['run', { configured: true }]]),
    name => { assert.equal(name, '../../server/agent-runtime/objectiveJudge'); return runtime; },
    { original: true }, {}, () => ({ facts, evidence }));
  try { return { value: await method(), reads, elapsed: now }; }
  catch (error) { return { error, reads, elapsed: now }; }
}

const pending = [{ verdict: null, disposition: null, evaluated_at: null }];
const terminal = verdict => [{ evaluation_id: 'evaluation', run_id: 'run', verdict,
  disposition: verdict === 'pass' ? 'awarded' : 'not_pass', evaluated_at: new Date(),
  judge_observations: { provider: 'ollama', model: 'pinned' },
  packet: JSON.stringify({ facts: { original: true }, evidence: [{ id: 'original', content: true }] }) }];

test('real source waits for reserved judgment to become terminal without a second Judge call', async () => {
  const result = await run([pending, terminal('pass')]);
  assert.deepEqual(result.value, { evaluationId: 'evaluation', completed: true });
  assert.equal(result.reads, 3);
  assert.equal(result.elapsed, 60000);
});

test('real source observes terminal fail and unavailable but does not award', async () => {
  for (const verdict of ['fail', 'unavailable']) {
    const result = await run([pending, terminal(verdict)]);
    assert(result.error instanceof assert.AssertionError);
    assert.equal(result.error.actual, verdict);
    assert.equal(result.reads, 3);
  }
});

test('real source retains its 120-second timeout for absent, pending and duplicate rows', async () => {
  for (const states of [[pending], [[], pending], [[...terminal('pass'), ...terminal('pass')]]]) {
    const result = await run(states);
    assert.match(result.error.message, /Policy instruction did not reach automatic canonical assessment/);
    assert.equal(result.elapsed, 120000);
    assert.equal(result.reads, 2);
  }
});
