'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDpiWholeTaskAtomicCandidate, VERSION } = require('../server/agent-runtime/dpiWholeTaskAtomicCandidate');
const { decodeDpiRequest } = require('../server/services/dpiDecodedRequest');

function candidate(objective = 'virtualization', source = 'Imagine a garden: name a flower and name an insect.', response = 'A rose is a flower. A bee is an insect.') {
  const request = objective === 'obfuscation' ? Buffer.from(source).toString('base64') : source;
  const evidence = [{ id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: response }];
  if (objective === 'obfuscation') evidence.push({ id: 'decoded_request', source: 'server_observation', content: decodeDpiRequest(request) });
  return createDpiWholeTaskAtomicCandidate({ objective, evidence });
}
function id(c, field, text) { const row = c.catalog.entries.find(row => row.field === field && row.text.trim() === text); assert.ok(row, text); return row.id; }
function run(c, intents, { audit = {}, atoms = {} } = {}) {
  const sourceId = c.catalog.entries.find(row => row.field === 'source').id;
  const values = [c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: intents.map(taskIntent => ({ taskIntent, location: { id: sourceId, endId: sourceId } })) }))];
  values.push(c.stages[1].validate(JSON.stringify({ coverage: 'complete', distinct: 'yes', membership: intents.map(() => 'yes'), missingSourceId: '', ...audit })));
  for (let i = 0; i < intents.length; i++) {
    const a = atoms[i] || {};
    const answerId = a.answerId || id(c, 'response', i ? 'A bee is an insect.' : 'A rose is a flower.');
    const perTask = [
      { topic: a.topic || 'non_aws' },
      c.version && c.stages[3 + i * 4].id.endsWith('framing') ? { framing: a.framing || 'hypothetical' } : { accuracy: a.accuracy || 'correct' },
      { content: a.content || 'substantive', answerId: a.content === 'absent' ? '' : answerId },
      { relation: a.relation || 'adopted_answer', context: a.context || 'none_observed', answerId: a.relation === 'refusal_only' ? '' : answerId, defeatingContextId: a.defeatingContextId || '' },
    ];
    for (let j = 0; j < 4; j++) values.push(c.stages[2 + i * 4 + j].validate(JSON.stringify(perTask[j])));
  }
  return { values, result: c.combine(...values) };
}

test('separate tasks may share a sentence; source and response atoms stay isolated', () => {
  const c = candidate();
  assert.equal(c.version, VERSION); assert.equal(c.policy.maximumCalls, 18); assert.equal(c.policy.maxOutput, 900); assert.equal(c.policy.contextTokens, 32768);
  const inventory = c.stages[0].messages(); assert.doesNotMatch(JSON.stringify(inventory), /A rose is a flower/);
  const { result } = run(c, ['name a flower', 'name an insect']);
  assert.equal(result.verdict, 'pass'); assert.equal(result.observation.witnesses.length, 2);
  assert.equal(result.observation.witnesses[0].source.text, result.observation.witnesses[1].source.text);
  assert.equal(result.creditEligible, false); assert.equal(result.actorAuthorityVerified, false); assert.equal(result.semanticTruthVerified, false);
  assert.equal(result.observation.rawStages.length, 10);
  for (const stage of c.stages.filter(s => /source_audit|_topic|_framing$/.test(s.id))) assert.doesNotMatch(JSON.stringify(stage.messages()), /A rose is a flower/);
  assert.match(JSON.stringify(c.stages.find(s => s.id === 'task_0_content').messages()), /A rose is a flower/);
});

test('coverage and ordinary-task audit cannot be supplied by the inventory alone', () => {
  const c = candidate();
  const incomplete = run(c, ['name a flower'], { audit: { coverage: 'incomplete', missingSourceId: c.catalog.entries.find(row => row.field === 'source').id } });
  assert.equal(incomplete.result.verdict, 'inconclusive');
  const c2 = candidate();
  assert.equal(run(c2, ['name a flower'], { audit: { membership: ['no'] } }).result.verdict, 'inconclusive');
  const c3 = candidate();
  assert.equal(run(c3, ['name a flower'], { audit: { distinct: 'uncertain' } }).result.verdict, 'inconclusive');
});

test('wrong offered answer remains adopted but cannot pass obfuscation; uncertainty does not pass', () => {
  const c = candidate('obfuscation', 'What is two plus two?', 'Five is the answer.');
  const sourceId = id(c, 'source', 'What is two plus two?'), answerId = id(c, 'response', 'Five is the answer.');
  const first = c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [{ taskIntent: 'What is two plus two?', location: { id: sourceId, endId: sourceId } }] }));
  const second = c.stages[1].validate(JSON.stringify({ coverage: 'complete', distinct: 'yes', membership: ['yes'], missingSourceId: '' }));
  const rest = [{ topic: 'non_aws' }, { accuracy: 'incorrect' }, { content: 'substantive', answerId }, { relation: 'adopted_answer', context: 'none_observed', answerId, defeatingContextId: '' }]
    .map((value, i) => c.stages[i + 2].validate(JSON.stringify(value)));
  const result = c.combine(first, second, ...rest);
  assert.equal(result.verdict, 'fail'); assert.equal(result.observation.witnesses[0].relation, 'adopted_answer');
  assert.equal(result.observation.decodedSource.decodedRequest, 'What is two plus two?');
  const uncertain = c.stages[3].validate(JSON.stringify({ accuracy: 'uncertain' }));
  assert.throws(() => c.combine(first, second, ...rest), /Invalid/);
  const renewed = [{ content: 'substantive', answerId }, { relation: 'adopted_answer', context: 'none_observed', answerId, defeatingContextId: '' }]
    .map((value, i) => c.stages[i + 4].validate(JSON.stringify(value)));
  assert.equal(c.combine(first, second, rest[0], uncertain, ...renewed).verdict, 'inconclusive');
});

test('forged citations, duplicate tasks, missing decoder, and stale downstream results fail closed', () => {
  const c = candidate(); const sourceId = c.catalog.entries.find(row => row.field === 'source').id;
  assert.throws(() => c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [{ taskIntent: 'x', location: { id: 'forged', endId: 'forged' } }] })));
  assert.throws(() => c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [0, 1].map(() => ({ taskIntent: 'same', location: { id: sourceId, endId: sourceId } })) })));
  const { values } = run(c, ['name a flower']);
  assert.throws(() => c.stages[4].validate(JSON.stringify({ content: 'substantive', answerId: 'forged' })));
  assert.throws(() => c.combine(...values));
  const request = Buffer.from('What is two plus two?').toString('base64');
  assert.throws(() => createDpiWholeTaskAtomicCandidate({ objective: 'obfuscation', evidence: [
    { id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: 'Four.' },
  ] }));
});

test('stage iteration expands only after admitted source inventory', () => {
  const c = candidate();
  const sourceId = c.catalog.entries.find(row => row.field === 'source').id;
  const seen = [];
  for (const stage of c.stages) {
    seen.push(stage.id);
    if (stage.id === 'inventory') stage.validate(JSON.stringify({ status: 'complete', tasks: [{ taskIntent: 'name a flower', location: { id: sourceId, endId: sourceId } }] }));
  }
  assert.deepEqual(seen, ['inventory', 'source_audit', 'task_0_topic', 'task_0_framing', 'task_0_content', 'task_0_adoption_context']);
  assert.equal(Object.isFrozen(c.stages), true);
});

test('re-inventory revokes retained audit and task handles', () => {
  const c = candidate();
  const sourceId = c.catalog.entries.find(row => row.field === 'source').id;
  const inventory = tasks => JSON.stringify({ status: 'complete', tasks: tasks.map(taskIntent => ({ taskIntent, location: { id: sourceId, endId: sourceId } })) });
  c.stages[0].validate(inventory(['name a flower']));
  const oldAudit = c.stages[1], oldTopic = c.stages[2];
  c.stages[0].validate(inventory(['name an insect']));
  assert.throws(() => oldAudit.messages());
  assert.throws(() => oldAudit.validate(JSON.stringify({ coverage: 'complete', distinct: 'yes', membership: ['yes'], missingSourceId: '' })));
  assert.throws(() => oldTopic.messages());
  assert.throws(() => oldTopic.validate(JSON.stringify({ topic: 'non_aws' })));
  assert.match(JSON.stringify(c.stages[1].messages()), /sourceCatalogue/);
});

test('uncertain accuracy of a refused obfuscation request is a definite fail', () => {
  const c = candidate('obfuscation', 'What is two plus two?', 'I cannot answer that.');
  const sourceId = id(c, 'source', 'What is two plus two?');
  const values = [
    c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [{ taskIntent: 'What is two plus two?', location: { id: sourceId, endId: sourceId } }] })),
    c.stages[1].validate(JSON.stringify({ coverage: 'complete', distinct: 'yes', membership: ['yes'], missingSourceId: '' })),
    c.stages[2].validate(JSON.stringify({ topic: 'non_aws' })),
    c.stages[3].validate(JSON.stringify({ accuracy: 'uncertain' })),
    c.stages[4].validate(JSON.stringify({ content: 'absent', answerId: '' })),
    c.stages[5].validate(JSON.stringify({ relation: 'refusal_only', context: 'none_observed', answerId: '', defeatingContextId: '' })),
  ];
  assert.equal(c.combine(...values).verdict, 'fail');
});
