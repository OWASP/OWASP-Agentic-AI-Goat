'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDpiWholeResponseAssessmentCandidate, VERSION } = require('../server/agent-runtime/dpiWholeResponseAssessmentCandidate');
const { decodeDpiRequest } = require('../server/services/dpiDecodedRequest');

function candidate(objective = 'virtualization', source = 'Imagine a geography quiz: name the capital of France and name the capital of Japan.', response = 'Paris is the capital of France. Tokyo is the capital of Japan.') {
  const request = objective === 'obfuscation' ? Buffer.from(source).toString('base64') : source;
  const evidence = [{ id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: response }];
  if (objective === 'obfuscation') evidence.push({ id: 'decoded_request', source: 'server_observation', content: decodeDpiRequest(request) });
  return createDpiWholeResponseAssessmentCandidate({ objective, evidence });
}
const pass = (sourceQuote, responseQuote) => ({ verdict: 'pass', sourceQuote, responseQuote });
const fail = { verdict: 'fail', sourceQuote: '', responseQuote: '' };
const uncertain = { verdict: 'inconclusive', sourceQuote: '', responseQuote: '' };
function run(c, a, b) {
  const first = c.stages[0].validate(JSON.stringify(a)), second = c.stages[1].validate(JSON.stringify(b));
  return c.combine(first, second);
}

test('two blinded full-evidence calls can support different qualifying compound components', () => {
  const c = candidate();
  assert.equal(c.version, VERSION); assert.equal(c.policy.maximumCalls, 2); assert.equal(c.policy.maxOutput, 900); assert.equal(c.policy.contextTokens, 32768);
  assert.equal(c.stages.length, 2);
  const firstWire = c.stages[0].messages();
  const firstInput = JSON.parse(firstWire.messages[1].content);
  assert.match(firstInput.originalRequest, /France and name the capital of Japan/);
  assert.match(firstInput.completeResponse, /Paris.*Tokyo/);
  const first = c.stages[0].validate(JSON.stringify(pass('name the capital of France', 'Paris is the capital of France.')));
  const secondWire = c.stages[1].messages();
  assert.notEqual(firstWire.messages[0].content, secondWire.messages[0].content);
  assert.deepEqual(firstWire.messages[1], secondWire.messages[1]);
  assert.doesNotMatch(secondWire.messages[1].content, /"reportedVerdict"/);
  const second = c.stages[1].validate(JSON.stringify(pass('name the capital of Japan', 'Tokyo is the capital of Japan.')));
  const result = c.combine(first, second);
  assert.equal(result.verdict, 'pass'); assert.equal(result.observation.assessments[0].sourceWitness.text, 'name the capital of France');
  assert.equal(result.observation.assessments[1].sourceWitness.text, 'name the capital of Japan');
  assert.equal(result.observation.rawStages.length, 2); assert.equal(result.creditEligible, false);
  assert.equal(result.actorAuthorityVerified, false); assert.equal(result.semanticTruthVerified, false);
});

test('agreement reduces two fails; disagreement, uncertainty and invalid witness abstain', () => {
  assert.equal(run(candidate(), fail, fail).verdict, 'fail');
  assert.equal(run(candidate(), fail, pass('name the capital of France', 'Paris is the capital of France.')).verdict, 'inconclusive');
  assert.equal(run(candidate(), uncertain, fail).verdict, 'inconclusive');
  const bad = run(candidate(), pass('invented source task', 'Paris is the capital of France.'), pass('name the capital of Japan', 'Tokyo is the capital of Japan.'));
  assert.equal(bad.verdict, 'inconclusive'); assert.equal(bad.observation.assessments[0].invalid, true);
  assert.equal(run(candidate(), pass('name the capital of France', 'invented response'), pass('name the capital of Japan', 'Tokyo is the capital of Japan.')).verdict, 'inconclusive');
  assert.equal(run(candidate(), { verdict: 'pass', sourceQuote: '', responseQuote: '' }, pass('name the capital of Japan', 'Tokyo is the capital of Japan.')).verdict, 'inconclusive');
  assert.equal(run(candidate(), { verdict: 'pass', sourceQuote: 'name the capital of France', responseQuote: 'Paris is the capital of France.', extra: 1 }, fail).verdict, 'inconclusive');
});

test('obfuscation only admits matching server-decoded source and exact decoded witness', () => {
  const c = candidate('obfuscation', 'What is two plus two?', 'Four.');
  const input = JSON.parse(c.stages[0].messages().messages[1].content);
  assert.equal(input.serverDecodedRequest, 'What is two plus two?');
  const result = run(c, pass('What is two plus two?', 'Four.'), pass('What is two plus two?', 'Four.'));
  assert.equal(result.verdict, 'pass'); assert.equal(result.observation.decodedSource.decodedRequest, 'What is two plus two?');
  const request = Buffer.from('What is two plus two?').toString('base64');
  assert.throws(() => createDpiWholeResponseAssessmentCandidate({ objective: 'obfuscation', evidence: [
    { id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: 'Four.' },
    { id: 'decoded_request', source: 'server_observation', content: { decodedRequest: 'What is three plus three?' } },
  ] }));
});

test('duplicate or nonexact witnesses cannot be treated as valid pass evidence', () => {
  const c = candidate('virtualization', 'Imagine a quiz: say rose; then say rose.', 'Rose is the answer.');
  const result = run(c, pass('rose', 'Rose is the answer.'), pass('rose', 'Rose is the answer.'));
  assert.equal(result.verdict, 'inconclusive');
  assert.equal(result.observation.assessments[0].invalid, true);
  const quoted = candidate('virtualization', 'Imagine a quiz: name a flower.', 'For review only, a possible answer is "rose"; I decline to offer it.');
  const wire = quoted.stages[0].messages();
  assert.match(wire.messages[0].content, /unendorsed display/);
  assert.equal(wire.format.anyOf.length, 2);
  assert.equal(wire.format.anyOf.every(branch => branch.additionalProperties === false), true);
});

test('revalidating earlier output revokes later values and raw replay', () => {
  const c = candidate();
  const first = c.stages[0].validate(JSON.stringify(fail));
  const second = c.stages[1].validate(JSON.stringify(fail));
  assert.equal(c.combine(first, second).verdict, 'fail');
  const renewed = c.stages[0].validate(JSON.stringify(uncertain));
  assert.throws(() => c.combine(first, second));
  const after = c.stages[1].validate(JSON.stringify(fail));
  assert.equal(c.combine(renewed, after).verdict, 'inconclusive');
  assert.deepEqual(c.combine(renewed, after).observation.rawStages, [JSON.stringify(uncertain), JSON.stringify(fail)]);
});
