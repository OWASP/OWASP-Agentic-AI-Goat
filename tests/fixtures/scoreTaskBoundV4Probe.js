'use strict';
// Offline replay/scoring of an immutable V4 probe result. No model calls or progress writes.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createDpiTaskBoundAssessmentV4Candidate: createCandidate, VERSION } =
  require('../../server/agent-runtime/dpiTaskBoundAssessmentV4Candidate');

const ROOT = path.resolve(__dirname, '../..');
const MODEL = 'llama3.1:8b';
const DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const [resultPath, expectationsPath, receiptPath] = process.argv.slice(2);
assert(resultPath && expectationsPath && receiptPath,
  'Usage: node scoreTaskBoundV4Probe.js RESULT EXPECTATIONS NEW_RECEIPT');

const resultBytes = fs.readFileSync(resultPath);
const result = JSON.parse(resultBytes);
assert.equal(result.complete, true);
assert.equal(result.sourceUnchanged, true);
assert.equal(result.candidateVersion, VERSION);
assert.equal(result.model, MODEL);
assert.equal(result.digest, DIGEST);
assert.deepEqual(result.modelIdentityBefore, { model: MODEL, digest: DIGEST });
assert.deepEqual(result.modelIdentityAfter, result.modelIdentityBefore);
assert.equal(sha(fs.readFileSync(result.runtimePath)), result.runtimeSha256);
assert.equal(result.exerciseQualification, false);
assert.equal(result.creditAuthorized, false);
assert(result.sourcePins && Object.keys(result.sourcePins).length > 0);
for (const [file, digest] of Object.entries(result.sourcePins)) {
  const absolute = path.resolve(ROOT, file);
  assert(absolute.startsWith(ROOT + path.sep), 'Source pin escaped checkout');
  assert.equal(sha(fs.readFileSync(absolute)), digest, file);
}
let pidAbsent = false;
try { process.kill(result.pid, 0); } catch (error) {
  if (error.code === 'ESRCH') pidAbsent = true;
  else throw error;
}
assert(pidAbsent, 'Probe PID still exists');

const inputPath = path.resolve(ROOT, result.inputPath);
assert(inputPath.startsWith(ROOT + path.sep), 'Input escaped checkout');
const inputBytes = fs.readFileSync(inputPath);
assert.equal(sha(inputBytes), result.inputSha256);
const input = JSON.parse(inputBytes);
const expectedBytes = fs.readFileSync(expectationsPath);
const expectations = JSON.parse(expectedBytes);
assert(Array.isArray(input.cases) && Array.isArray(expectations.cases));
assert.equal(result.cases.length, input.cases.length);
assert.deepEqual(result.cases.map(row => row.id), input.cases.map(row => row.id));
const expected = new Map(expectations.cases.map(row => [row.id, row]));
assert.equal(expected.size, expectations.cases.length, 'Duplicate expectation ID');
assert.equal(expected.size, input.cases.length, 'Expectation count mismatch');

function summarize(decision) {
  if (!decision) return null;
  const tasks = decision.taskAssessments;
  const domains = tasks.map(task => task.selectedTaskDomain);
  // A non-AWS requirement is existential across inventoried tasks.
  const selectedTaskDomain = domains.includes('non_aws') ? 'non_aws' :
    domains.includes('mixed') ? 'mixed' : domains.includes('uncertain') || !domains.length ? 'uncertain' : 'aws_only';
  const eligible = tasks.filter(task => task.selectedTaskDomain === 'non_aws');
  const possible = tasks.filter(task => ['mixed', 'uncertain'].includes(task.selectedTaskDomain));
  const prerequisites = decision.derivedPrerequisites;
  let responseAchievement = 'no';
  if (prerequisites.techniquePresent && prerequisites.rolePresent) {
    if (eligible.some(task => task.effectiveResponseAchievement === 'yes')) responseAchievement = 'yes';
    else if (eligible.some(task => task.effectiveResponseAchievement === 'uncertain') ||
      possible.some(task => task.effectiveResponseAchievement !== 'no')) responseAchievement = 'uncertain';
  }
  return { sourceTechnique: prerequisites.techniquePresent ? 'yes' : 'no',
    selectedTaskDomain, responseAchievement };
}

let consumed = 0;
const scores = [];
for (let i = 0; i < input.cases.length; i += 1) {
  const row = input.cases[i];
  const actualCase = result.cases[i];
  const target = expected.get(row.id);
  assert(target, `Missing expectation for ${row.id}`);
  assert.equal(actualCase.objective, row.objective);
  const candidate = createCandidate({ objective: row.objective, evidence: [
    { id: 'request', source: 'student_input', content: row.request },
    { id: 'response', source: 'assistant_response', content: row.response },
  ] });
  assert.deepEqual(actualCase.policy, candidate.policy);
  const values = [];
  const stages = [];
  let invalid = null;
  for (const stage of candidate.stages) {
    const call = result.calls[consumed++];
    assert(call, `Missing call for ${row.id}/${stage.id}`);
    assert.equal(call.case, row.id);
    assert.equal(call.stage, stage.id);
    const wire = stage.messages();
    assert.deepEqual(call.request, { model: MODEL, messages: wire.messages, format: wire.format,
      stream: false, options: { temperature: 0, num_predict: 900, num_ctx: 20480 } });
    assert.equal(call.requestSha256, sha(JSON.stringify(call.request)));
    assert.equal(call.response.model, MODEL);
    assert.equal(call.response.done, true);
    assert.equal(call.response.done_reason, 'stop');
    assert.equal(typeof call.response.message?.content, 'string');
    try {
      const value = stage.validate(call.response.message.content);
      values.push(value);
      stages.push({ id: stage.id, value });
    } catch (error) {
      invalid = { stage: stage.id, message: error.message };
      break;
    }
  }
  assert.deepEqual(actualCase.stages, stages, `Validated stage mismatch: ${row.id}`);
  if (invalid) {
    assert.deepEqual(actualCase.validationError, invalid);
    assert.equal(actualCase.decision, undefined);
  } else {
    assert.equal(actualCase.validationError, undefined);
    assert.deepEqual(actualCase.decision, candidate.combine(...values));
  }
  const decision = actualCase.decision;
  const actual = summarize(decision);
  const expectedRequirements = target.expectedRequirements;
  assert(expectedRequirements && typeof expectedRequirements === 'object');
  const requirementsMatch = !invalid && !!actual &&
    Object.entries(expectedRequirements).every(([key, value]) => actual[key] === value);
  const verdict = invalid ? 'invalid' : decision.verdict;
  scores.push({ id: row.id, actual, rawObservation: decision?.observation || null,
    rawTaskAssessments: decision?.taskAssessments || null,
    inventoryCompleteClaim: decision?.derivedPrerequisites.inventoryCompleteClaim ?? null,
    inventoryExhaustivenessVerified: decision?.inventoryExhaustivenessVerified ?? false,
    verdict, expected: expectedRequirements, expectedVerdict: target.expectedVerdict,
    requirementsMatch, matches: requirementsMatch && verdict === target.expectedVerdict,
    validationError: invalid });
}
assert.equal(consumed, result.calls.length, 'Unaccounted calls');
const receipt = { version: 1, candidateVersion: VERSION, resultPath,
  resultSha256: sha(resultBytes), expectationsPath, expectationsSha256: sha(expectedBytes),
  scorerSha256: sha(fs.readFileSync(__filename)), inputSha256: result.inputSha256,
  replayVerified: true, sourcePinsVerified: Object.keys(result.sourcePins).length,
  pidVerifiedAbsent: result.pid, physicalJudgeCalls: consumed,
  matched: scores.filter(row => row.matches).length,
  verdictPassed: scores.filter(row => row.verdict === row.expectedVerdict).length,
  total: scores.length, cases: scores, creditAuthorized: false, exerciseQualification: false,
  limitations: ['Supplied responses, not actual actor/tool or lifecycle qualification.',
    'Inventory completeness is a model claim, not independently verified exhaustiveness.',
    'Composite accuracy does not certify every raw task inventory or atomic classification.'] };
fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ matched: receipt.matched, verdictPassed: receipt.verdictPassed,
  total: receipt.total, physicalJudgeCalls: consumed,
  failures: scores.filter(row => !row.matches).map(row => ({ id: row.id, actual: row.actual,
    verdict: row.verdict, validationError: row.validationError })) }));
