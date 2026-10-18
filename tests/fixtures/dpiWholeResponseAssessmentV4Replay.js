'use strict';
// Offline wire-identical validator replay: no provider, database, or credit.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const ROOT = path.resolve(__dirname, '../..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const receipt = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/release-inputs/dpi-whole-response-assessment-v3-terminal-root.json')));
const priorBytes = fs.readFileSync(path.join(ROOT, receipt.artifact.path));
assert.equal(sha(priorBytes), receipt.artifact.sha256);
const prior = JSON.parse(priorBytes);
assert.equal(prior.complete, true); assert.equal(prior.physicalPending, 0);
for (const [file, hash] of Object.entries({ ...prior.sourcePins, ...prior.inputPins })) assert.equal(sha(fs.readFileSync(path.join(ROOT, file))), hash, file);
assert.equal(sha(fs.readFileSync(process.execPath)), prior.runtimeSha256);
const cases = Object.keys(prior.inputPins).flatMap(file => JSON.parse(fs.readFileSync(path.join(ROOT, file))).cases);
const { createDpiWholeResponseAssessmentV4Candidate: createCandidate, VERSION } = require('../../server/agent-runtime/dpiWholeResponseAssessmentV4Candidate');
const results = [];
for (const row of cases) {
  const candidate = createCandidate({ objective: row.objective, evidence: row.evidence });
  const calls = prior.calls.filter(call => call.case === row.id);
  assert.equal(calls.length, 2);
  const values = [];
  for (const [index, stage] of candidate.stages.entries()) {
    const call = calls[index], wire = stage.messages();
    assert.equal(stage.id, call.stage);
    const expected = { model: prior.model, messages: wire.messages, format: wire.format, stream: false,
      options: { temperature: 0, num_predict: candidate.policy.maxOutput, num_ctx: candidate.policy.contextTokens } };
    assert.deepEqual(call.request, expected, 'Provider wire changed');
    assert.equal(sha(JSON.stringify(call.request)), call.requestSha256);
    assert.equal(call.response.model, prior.model); assert.equal(call.response.done, true); assert.equal(call.response.done_reason, 'stop');
    values.push(stage.validate(call.response.message.content));
  }
  const decision = candidate.combine(...values);
  assert.equal(decision.creditEligible, false);
  results.push({ id: row.id, decision });
}
const pins = Object.fromEntries(Object.keys(require.cache).filter(file => file.startsWith(ROOT + path.sep)).sort().map(file => [path.relative(ROOT, file), sha(fs.readFileSync(file))]));
const parent = path.join(ROOT, 'backups/private-recovery/dpi-whole-response-assessment-v4-replay');
fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
const directory = fs.mkdtempSync(path.join(parent, 'run-'));
fs.chmodSync(directory, 0o700);
const output = { version: VERSION, scope: 'offline-wire-identical-validator-replay', newProviderCalls: 0, reusedProviderCalls: prior.calls.length,
  priorArtifact: receipt.artifact, sourcePins: pins, wireIdentical: true, exerciseQualification: false, creditAuthorized: false, cases: results };
const resultPath = path.join(directory, 'result.json');
fs.writeFileSync(resultPath, JSON.stringify(output, null, 2) + '\n', { mode: 0o600 });
console.log(JSON.stringify({ resultPath, newProviderCalls: 0, cases: results.map(row => ({ id: row.id, verdict: row.decision.verdict })) }));
