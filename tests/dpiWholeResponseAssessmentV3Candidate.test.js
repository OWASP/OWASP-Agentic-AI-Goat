'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDpiWholeResponseAssessmentV3Candidate, VERSION } = require('../server/agent-runtime/dpiWholeResponseAssessmentV3Candidate');
const { decodeDpiRequest } = require('../server/services/dpiDecodedRequest');

function candidate(objective = 'virtualization', source = 'Imagine a quiz: name the capital of France and name the capital of Japan.', response = 'Paris is the capital of France. Tokyo is the capital of Japan.') {
  const request = objective === 'obfuscation' ? Buffer.from(source).toString('base64') : source;
  const evidence = [{ id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: response }];
  if (objective === 'obfuscation') evidence.push({ id: 'decoded_request', source: 'server_observation', content: decodeDpiRequest(request) });
  return createDpiWholeResponseAssessmentV3Candidate({ objective, evidence });
}
const pass = (sourceQuote, responseQuote) => ({ explanation: 'The reply offers an answer to the selected request.', verdict: 'pass', sourceQuote, responseQuote });
const fail = { explanation: 'No qualifying offered answer is shown.', verdict: 'fail', sourceQuote: '', responseQuote: '' };
function run(c, first, second) {
  const a = c.stages[0].validate(JSON.stringify(first)), b = c.stages[1].validate(JSON.stringify(second));
  return c.combine(a, b);
}

test('objective-specific prompts expose only the relevant criterion and flat explanation-first schema', () => {
  const virtual = candidate(), encoded = candidate('obfuscation', 'What is two plus two?', 'Four.');
  assert.equal(virtual.version, VERSION); assert.equal(virtual.policy.maximumCalls, 2); assert.equal(virtual.policy.maxOutput, 900); assert.equal(virtual.policy.contextTokens, 32768);
  const vw = virtual.stages[0].messages(), ew = encoded.stages[0].messages();
  assert.deepEqual(Object.keys(vw.format.properties), ['explanation', 'verdict', 'sourceQuote', 'responseQuote']);
  assert.equal(Object.hasOwn(vw.format, 'anyOf'), false);
  assert.match(vw.messages[0].content, /pass means the learner succeeded/);
  assert.match(ew.messages[0].content, /An AWS-only answer is NOT learner success/);
  assert.equal(Object.hasOwn(JSON.parse(vw.messages[1].content), 'objective'), false);
  assert.equal(Object.hasOwn(JSON.parse(ew.messages[1].content), 'objective'), false);
  assert.equal(JSON.parse(ew.messages[1].content).serverDecodedRequest, 'What is two plus two?');
  assert.match(vw.messages[0].content, /USER REQUEST, not the assistant reply/);
  assert.match(vw.messages[0].content, /reply need not repeat that framing/);
  assert.match(vw.messages[0].content, /correctness is not part of this objective/);
  assert.doesNotMatch(vw.messages[0].content, /serverDecodedRequest/);
  assert.match(ew.messages[0].content, /serverDecodedRequest/);
  assert.match(ew.messages[0].content, /factually correct answer/);
  assert.doesNotMatch(ew.messages[0].content, /hypothetical/);
  const initial = virtual.stages[0].validate(JSON.stringify(fail));
  assert.notEqual(vw.messages[0].content, virtual.stages[1].messages().messages[0].content);
  assert.deepEqual(JSON.parse(virtual.stages[1].messages().messages[1].content), JSON.parse(vw.messages[1].content));
  assert.doesNotMatch(virtual.stages[1].messages().messages[1].content, /No qualifying offered answer is shown/);
  assert.ok(initial);
});

test('two valid pass witnesses can select different compound components without task inventory', () => {
  const c = candidate();
  const result = run(c, pass('name the capital of France', 'Paris is the capital of France.'),
    pass('name the capital of Japan', 'Tokyo is the capital of Japan.'));
  assert.equal(result.verdict, 'pass'); assert.equal(result.observation.assessments.length, 2);
  assert.equal(result.observation.rawStages.length, 2);
  assert.match(result.observation.rawStages[0], /"explanation"/);
  assert.equal(result.creditEligible, false); assert.equal(result.actorAuthorityVerified, false); assert.equal(result.semanticTruthVerified, false);
});

test('invalid or absent witness, malformed explanation, disagreement and uncertainty abstain', () => {
  assert.equal(run(candidate(), fail, fail).verdict, 'fail');
  assert.equal(run(candidate(), fail, pass('name the capital of France', 'Paris is the capital of France.')).verdict, 'inconclusive');
  assert.equal(run(candidate(), { ...fail, verdict: 'inconclusive' }, fail).verdict, 'inconclusive');
  const invalid = run(candidate(), pass('invented task', 'Paris is the capital of France.'), pass('name the capital of Japan', 'Tokyo is the capital of Japan.'));
  assert.equal(invalid.verdict, 'inconclusive'); assert.equal(invalid.observation.assessments[0].invalid, true);
  assert.equal(run(candidate(), { ...pass('name the capital of France', 'Paris is the capital of France.'), explanation: '' },
    pass('name the capital of Japan', 'Tokyo is the capital of Japan.')).verdict, 'inconclusive');
  assert.equal(run(candidate(), { ...pass('name the capital of France', 'Paris is the capital of France.'), extra: 1 },
    pass('name the capital of Japan', 'Tokyo is the capital of Japan.')).verdict, 'inconclusive');
});

test('decoded evidence, selected quotes and stale outputs retain V1 admission', () => {
  const c = candidate('obfuscation', 'What is two plus two?', 'Four.');
  assert.equal(run(c, pass('What is two plus two?', 'Four.'), pass('What is two plus two?', 'Four.')).verdict, 'pass');
  const old = c.stages[0].validate(JSON.stringify(fail)), second = c.stages[1].validate(JSON.stringify(fail));
  assert.equal(c.combine(old, second).verdict, 'fail');
  c.stages[0].validate(JSON.stringify({ ...fail, verdict: 'inconclusive' }));
  assert.throws(() => c.combine(old, second));
  const request = Buffer.from('What is two plus two?').toString('base64');
  assert.throws(() => createDpiWholeResponseAssessmentV3Candidate({ objective: 'obfuscation', evidence: [
    { id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: 'Four.' },
    { id: 'decoded_request', source: 'server_observation', content: { decodedRequest: 'What is three plus three?' } },
  ] }));
});
