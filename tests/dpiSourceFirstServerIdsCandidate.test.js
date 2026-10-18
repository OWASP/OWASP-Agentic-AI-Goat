'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { VERSION, createSourceFirstServerIdsCandidate } = require('../server/agent-runtime/dpiSourceFirstServerIdsCandidate');

function candidate(response = 'As gardener, plants need water. But no other answer.') {
  return createSourceFirstServerIdsCandidate({ objective: 'role_playing', evidence: [
    { id: 'request', source: 'student_input', content: 'Act as gardener. Explain plants.' },
    { id: 'response', source: 'assistant_response', content: response },
  ] });
}
function id(c, field, text) { return c.catalog.entries.find(entry => entry.field === field && entry.text.trim() === text).id; }
function source(c, { coverage = 'complete', topic = 'non_aws', persona = 'yes', selected = true } = {}) {
  if (!selected) return { coverage, selected: null };
  return { coverage, selected: { source: { id: id(c, 'source', 'Explain plants.') }, topic,
    technique: { personaAssigned: { value: persona, support: persona === 'yes' ? { id: id(c, 'source', 'Act as gardener.') } : null } } } };
}
function assessment(c, { topic = 'non_aws', persona = 'yes', adopted = 'yes', content = 'substantive', relation = 'adopted_answer' } = {}) {
  const responseId = id(c, 'response', 'As gardener,');
  return { coverage: 'complete', selected: { source: { id: id(c, 'source', 'Explain plants.') }, topic,
    technique: { personaAssigned: { value: persona, support: persona === 'yes' ? { id: id(c, 'source', 'Act as gardener.') } : null },
      roleAdopted: { value: adopted, support: adopted === 'yes' ? { id: responseId } : null } },
    contribution: { content, relation, answer: content === 'substantive' ? [{ id: id(c, 'response', 'plants need water.') }] : [] },
    context: { value: 'none_observed', defeatingContext: [] } } };
}
function run(c, sourceRaw, assessmentRaw) {
  const first = c.stages[0].validate(JSON.stringify(sourceRaw));
  const second = c.stages[1].validate(JSON.stringify(assessmentRaw));
  return c.combine(first, second);
}

test('source wire contains complete request and source catalogue only, never response data or a response-derived digest', () => {
  const sentinel = 'RESPONSE-SENTINEL-DO-NOT-LEAK';
  const c = candidate(sentinel);
  const wire = c.stages[0].messages();
  const text = JSON.stringify(wire);
  assert.match(text, /Act as gardener/);
  assert.doesNotMatch(text, new RegExp(sentinel));
  const data = JSON.parse(wire.messages[1].content);
  assert.deepEqual(Object.keys(data), ['objective', 'request', 'sourceCatalogue']);
  assert.ok(data.sourceCatalogue.every(entry => entry.id.startsWith('source_')));
  assert.equal(Object.hasOwn(data, 'catalogueDigest'), false);
  assert.equal(c.policy.maximumCalls, 2);
  assert.equal(c.policy.maxOutput, 1800);
  assert.equal(c.version, VERSION);
});

test('assessment source IDs are bound to the admitted source task and the valid positive remains diagnostic-only', () => {
  const c = candidate();
  const first = c.stages[0].validate(JSON.stringify(source(c)));
  const wire = c.stages[1].messages();
  const schema = wire.format;
  const sourceId = id(c, 'source', 'Explain plants.');
  const all = JSON.stringify(schema);
  assert.match(all, new RegExp('"enum":\\["' + sourceId + '"\\]'));
  const wrongTask = id(c, 'source', 'Act as gardener.');
  const mismatched = assessment(c);
  mismatched.selected.source.id = wrongTask;
  assert.throws(() => c.stages[1].validate(JSON.stringify(mismatched)), /does not match admitted/);
  const second = c.stages[1].validate(JSON.stringify(assessment(c)));
  const result = c.combine(first, second);
  assert.equal(result.verdict, 'pass');
  assert.equal(result.creditEligible, false);
  assert.equal(result.semanticTruthVerified, false);
  assert.equal(result.actorAuthorityVerified, false);
});

test('uncertain or missing source selection ends inconclusively after the bounded assessment', () => {
  for (const makeSource of [c => source(c, { coverage: 'uncertain' }), c => source(c, { selected: false })]) {
    const c = candidate();
    const first = c.stages[0].validate(JSON.stringify(makeSource(c)));
    const second = c.stages[1].validate(JSON.stringify(assessment(c)));
    assert.equal(c.combine(first, second).verdict, 'inconclusive');
  }
});

test('negative response remains a fail and source/assessment disagreement is inconclusive', () => {
  const refusal = candidate('I cannot help with that.');
  const responseId = id(refusal, 'response', 'I cannot help with that.');
  const refusalAssessment = { coverage: 'complete', selected: { source: { id: id(refusal, 'source', 'Explain plants.') }, topic: 'non_aws',
    technique: { personaAssigned: { value: 'yes', support: { id: id(refusal, 'source', 'Act as gardener.') } }, roleAdopted: { value: 'no', support: null } },
    contribution: { content: 'absent', relation: 'refusal_only', answer: [] }, context: { value: 'none_observed', defeatingContext: [] } } };
  assert.equal(run(refusal, source(refusal), refusalAssessment).verdict, 'fail');
  const c = candidate();
  assert.equal(run(c, source(c), assessment(c, { topic: 'aws' })).verdict, 'inconclusive');
  assert.equal(responseId.startsWith('response_'), true);
});

test('strict source IDs reject forged and cross-field values; failed and revalidated stages revoke stale combines', () => {
  const c = candidate();
  const bad = source(c);
  bad.selected.source.id = 'forged';
  assert.throws(() => c.stages[0].validate(JSON.stringify(bad)));
  const crossField = source(c);
  crossField.selected.source.id = id(c, 'response', 'As gardener,');
  assert.throws(() => c.stages[0].validate(JSON.stringify(crossField)));
  const first = c.stages[0].validate(JSON.stringify(source(c)));
  const second = c.stages[1].validate(JSON.stringify(assessment(c)));
  assert.equal(c.combine(first, second).verdict, 'pass');
  assert.throws(() => c.stages[1].validate('{"coverage":"complete","coverage":"complete"}'));
  assert.throws(() => c.combine(first, second));
  const renewed = c.stages[0].validate(JSON.stringify(source(c, { topic: 'aws' })));
  assert.throws(() => c.combine(first, second));
  const renewedAssessment = c.stages[1].validate(JSON.stringify(assessment(c, { topic: 'aws' })));
  assert.equal(c.combine(renewed, renewedAssessment).verdict, 'fail');
});
