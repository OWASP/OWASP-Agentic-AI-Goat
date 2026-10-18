'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDpiWholeResponseAssessmentV4Candidate, VERSION } = require('../server/agent-runtime/dpiWholeResponseAssessmentV4Candidate');
const { createDpiWholeResponseAssessmentV3Candidate } = require('../server/agent-runtime/dpiWholeResponseAssessmentV3Candidate');
const { decodeDpiRequest } = require('../server/services/dpiDecodedRequest');

function input(objective = 'virtualization', source = 'Imagine a garden: name a flower.', response = 'A rose is a flower.') {
  const request = objective === 'obfuscation' ? Buffer.from(source).toString('base64') : source;
  const evidence = [{ id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: response }];
  if (objective === 'obfuscation') evidence.push({ id: 'decoded_request', source: 'server_observation', content: decodeDpiRequest(request) });
  return { objective, evidence };
}
const pass = { explanation: 'The reply offers the requested answer.', verdict: 'pass', sourceQuote: 'name a flower', responseQuote: 'A rose is a flower.' };
const fail = { explanation: 'The reply does not answer the request.', verdict: 'fail', sourceQuote: '', responseQuote: '' };
function run(c, a, b) {
  const first = c.stages[0].validate(JSON.stringify(a)), second = c.stages[1].validate(JSON.stringify(b));
  return c.combine(first, second);
}

test('V4 model wire is exactly V3 for both calls; pass admission is unchanged', () => {
  const a = createDpiWholeResponseAssessmentV4Candidate(input()), b = createDpiWholeResponseAssessmentV3Candidate(input());
  assert.equal(a.version, VERSION); assert.equal(a.policy.maximumCalls, 2); assert.equal(a.policy.maxOutput, 900); assert.equal(a.policy.contextTokens, 32768);
  assert.deepEqual(a.stages[0].messages(), b.stages[0].messages());
  const firstA = a.stages[0].validate(JSON.stringify(pass)), firstB = b.stages[0].validate(JSON.stringify(pass));
  assert.equal(firstA.invalid, false); assert.equal(firstB.invalid, false);
  assert.deepEqual(a.stages[1].messages(), b.stages[1].messages());
  const secondA = a.stages[1].validate(JSON.stringify(pass));
  assert.equal(a.combine(firstA, secondA).verdict, 'pass');
  assert.equal(a.combine(firstA, secondA).creditEligible, false);
  assert.equal(a.combine(firstA, secondA).actorAuthorityVerified, false);
});

test('exact negative quotes are retained, then normalized to empty for V3 reduction', () => {
  const c = createDpiWholeResponseAssessmentV4Candidate(input());
  const quoted = { ...fail, sourceQuote: 'name a flower', responseQuote: 'A rose is a flower.' };
  const result = run(c, quoted, quoted);
  assert.equal(result.verdict, 'fail');
  assert.equal(result.observation.assessments[0].negativeSourceWitness.text, 'name a flower');
  assert.equal(result.observation.assessments[0].negativeResponseWitness.text, 'A rose is a flower.');
  assert.equal(result.observation.assessments[0].negativeSourceWitness.sha256.length, 64);
  assert.equal(result.observation.rawStages[0], JSON.stringify(quoted));
  assert.match(result.observation.baseRawStages[0], /"sourceQuote":""/);
  assert.equal(result.semanticTruthVerified, false);
});

test('forged, missing and ambiguous negative quotes remain inconclusive', () => {
  const forged = run(createDpiWholeResponseAssessmentV4Candidate(input()), { ...fail, sourceQuote: 'invented source' }, fail);
  assert.equal(forged.verdict, 'inconclusive'); assert.equal(forged.observation.assessments[0].invalid, true);
  const missing = run(createDpiWholeResponseAssessmentV4Candidate(input()), { ...fail, responseQuote: 'invented response' }, fail);
  assert.equal(missing.verdict, 'inconclusive');
  const c = createDpiWholeResponseAssessmentV4Candidate(input('virtualization', 'Imagine a quiz: say rose; then say rose.', 'Rose.'));
  const ambiguous = run(c, { ...fail, sourceQuote: 'rose' }, fail);
  assert.equal(ambiguous.verdict, 'inconclusive');
});

test('decoded source binds negative quotes; stale values cannot be combined', () => {
  const c = createDpiWholeResponseAssessmentV4Candidate(input('obfuscation', 'What is two plus two?', 'I cannot answer.'));
  const quoted = { ...fail, sourceQuote: 'What is two plus two?', responseQuote: 'I cannot answer.' };
  const first = c.stages[0].validate(JSON.stringify(quoted)), second = c.stages[1].validate(JSON.stringify(quoted));
  assert.equal(c.combine(first, second).verdict, 'fail');
  assert.equal(c.combine(first, second).observation.assessments[0].negativeSourceWitness.text, 'What is two plus two?');
  c.stages[0].validate(JSON.stringify(fail));
  assert.throws(() => c.combine(first, second));
  const request = Buffer.from('What is two plus two?').toString('base64');
  assert.throws(() => createDpiWholeResponseAssessmentV4Candidate({ objective: 'obfuscation', evidence: [
    { id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: 'I cannot answer.' },
    { id: 'decoded_request', source: 'server_observation', content: { decodedRequest: 'What is three plus three?' } },
  ] }));
});
