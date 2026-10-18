'use strict';
// Offline replay/scoring; never sends model calls or writes application progress.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createDpiTaskBoundAssessmentV3Candidate: createCandidate } = require('../../server/agent-runtime/dpiTaskBoundAssessmentV3Candidate');
const ROOT = path.resolve(__dirname, '../..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const [resultPath, expectationsPath, receiptPath] = process.argv.slice(2);
assert(resultPath && expectationsPath && receiptPath);
const resultBytes = fs.readFileSync(resultPath);
const result = JSON.parse(resultBytes);
assert.equal(result.complete, true); assert.equal(result.sourceUnchanged, true);
assert.deepEqual(result.modelIdentityBefore, result.modelIdentityAfter);
assert.equal(result.modelIdentityBefore.model, 'llama3.1:8b');
assert.equal(result.modelIdentityBefore.digest, '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
for (const [file, digest] of Object.entries(result.sourcePins)) assert.equal(sha(fs.readFileSync(path.join(ROOT, file))), digest, file);
assert.equal(sha(fs.readFileSync(process.execPath)), result.runtimeSha256);
let absent = false;
try { process.kill(result.pid, 0); } catch (error) { if (error.code === 'ESRCH') absent = true; else throw error; }
assert(absent, 'Probe PID still exists');
const inputBytes = fs.readFileSync(path.join(ROOT, result.inputPath));
assert.equal(sha(inputBytes), result.inputSha256);
const input = JSON.parse(inputBytes);
assert.deepEqual(result.cases.map(row => row.id), input.cases.map(row => row.id));
const expectedBytes = fs.readFileSync(expectationsPath);
const expected = new Map(JSON.parse(expectedBytes).cases.map(row => [row.id, row]));
let consumed = 0;
const scores = [];
for (let i = 0; i < input.cases.length; i++) {
  const row = input.cases[i], actualCase = result.cases[i], target = expected.get(row.id);
  assert(target);
  const candidate = createCandidate({ objective: row.objective, evidence: [
    { id: 'request', source: 'student_input', content: row.request },
    { id: 'response', source: 'assistant_response', content: row.response },
  ] });
  assert.deepEqual(actualCase.policy, candidate.policy);
  const values = [];
  let invalid = null;
  for (const stage of candidate.stages) {
    const call = result.calls[consumed++]; assert(call);
    assert.equal(call.case, row.id); assert.equal(call.stage, stage.id);
    const wire = stage.messages();
    assert.deepEqual(call.request, { model: result.model, messages: wire.messages, format: wire.format, stream: false,
      options: { temperature: 0, num_predict: 900, num_ctx: 20480 } });
    assert.equal(call.requestSha256, sha(JSON.stringify(call.request)));
    assert.equal(call.response.model, result.model); assert.equal(call.response.done, true); assert.equal(call.response.done_reason, 'stop');
    try { values.push(stage.validate(call.response.message.content)); }
    catch (error) { invalid = { stage: stage.id, message: error.message }; break; }
  }
  if (invalid) assert.deepEqual(actualCase.validationError, invalid);
  else assert.deepEqual(actualCase.decision, candidate.combine(...values));
  const decision = actualCase.decision;
  let actual = null;
  if (decision) {
    const observation = decision.observation, prerequisites = decision.derivedPrerequisites;
    // The historical fixture's responseAchievement includes task scope and role prerequisites.
    // Preserve raw atomics separately; do not rewrite a model observation to fit the fixture.
    let objectiveResponseAchievement = decision.effectiveResponseAchievement;
    if (!prerequisites.taskPresent || !prerequisites.rolePresent || observation.selectedTaskDomain === 'aws_only') objectiveResponseAchievement = 'no';
    else if (objectiveResponseAchievement !== 'no' && ['mixed', 'uncertain'].includes(observation.selectedTaskDomain)) objectiveResponseAchievement = 'uncertain';
    actual = { sourceTechnique: prerequisites.techniquePresent ? 'yes' : 'no',
      selectedTaskDomain: observation.selectedTaskDomain, responseAchievement: objectiveResponseAchievement };
  }
  const requirementsMatch = !!actual && Object.entries(target.expectedRequirements).every(([key, value]) => actual[key] === value);
  scores.push({ id: row.id, actual, rawObservation: decision?.observation || null,
    effectiveResponseAchievement: decision?.effectiveResponseAchievement || null,
    verdict: decision?.verdict || 'invalid', expected: target.expectedRequirements, expectedVerdict: target.expectedVerdict,
    requirementsMatch, matches: requirementsMatch && decision?.verdict === target.expectedVerdict, validationError: invalid });
}
assert.equal(consumed, result.calls.length, 'Unaccounted calls');
const receipt = { version: 1, resultPath, resultSha256: sha(resultBytes), expectationsPath, expectationsSha256: sha(expectedBytes),
  scorerSha256: sha(fs.readFileSync(__filename)), inputSha256: result.inputSha256,
  replayVerified: true, sourcePinsVerified: Object.keys(result.sourcePins).length, pidVerifiedAbsent: result.pid,
  physicalJudgeCalls: consumed, matched: scores.filter(row => row.matches).length,
  verdictPassed: scores.filter(row => row.verdict === row.expectedVerdict).length, total: scores.length,
  cases: scores, creditAuthorized: false, exerciseQualification: false,
  limitations: ['Supplied responses, not actual actor/tool or lifecycle qualification.',
    'Model observations are retained; final composite accuracy does not certify every raw atomic classification.'] };
fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ matched: receipt.matched, verdictPassed: receipt.verdictPassed, total: receipt.total,
  physicalJudgeCalls: consumed, failures: scores.filter(row => !row.matches).map(row => ({ id: row.id, actual: row.actual, verdict: row.verdict })) }));
