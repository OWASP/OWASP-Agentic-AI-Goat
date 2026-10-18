'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Ajv = require('ajv');
const { createDpiWholeTaskAtomicVisibleCandidate, VERSION } = require('../server/agent-runtime/dpiWholeTaskAtomicVisibleCandidate');
const { createDpiWholeTaskAtomicSchemaCandidate } = require('../server/agent-runtime/dpiWholeTaskAtomicSchemaCandidate');

const evidence = [
  { id: 'request', source: 'student_input', content: 'Imagine a garden: name a flower.' },
  { id: 'response', source: 'assistant_response', content: 'A rose is a flower. I withdraw that answer.' },
];
function candidate(factory) {
  const c = factory({ objective: 'virtualization', evidence });
  const sourceId = c.catalog.entries.find(row => row.field === 'source').id;
  const answerId = c.catalog.entries.find(row => row.field === 'response' && row.text.trim() === 'A rose is a flower.').id;
  const contraryId = c.catalog.entries.find(row => row.field === 'response' && row.text.trim() === 'I withdraw that answer.').id;
  return { c, sourceId, answerId, contraryId };
}
function admitInventory(row) {
  return row.c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [{ taskIntent: 'name a flower', location: { id: row.sourceId, endId: row.sourceId } }] }));
}
function parity(a, b, samples) {
  const ajv = new Ajv({ strict: false });
  const old = ajv.compile(a), next = ajv.compile(b);
  for (const value of samples) assert.equal(!!next(value), !!old(value), JSON.stringify(value));
}

test('all stage messages disclose exact effective schema without changing user evidence', () => {
  const v3 = candidate(createDpiWholeTaskAtomicVisibleCandidate), v2 = candidate(createDpiWholeTaskAtomicSchemaCandidate);
  assert.equal(v3.c.version, VERSION);
  assert.equal(v3.c.policy.maximumCalls, 18); assert.equal(v3.c.policy.maxOutput, 900); assert.equal(v3.c.policy.contextTokens, 32768);
  assert.notEqual(v3.c.policy.instructionsSha256, v2.c.policy.instructionsSha256);
  admitInventory(v3); admitInventory(v2);
  for (const index of [0, 1]) {
    const wire = v3.c.stages[index].messages(), before = v2.c.stages[index].messages();
    assert.deepEqual(wire.messages[1], before.messages[1]);
    assert.equal(wire.messages[0].content, `${before.messages[0].content}\nOUTPUT_JSON_SCHEMA:${JSON.stringify(wire.format)}`);
    assert.equal(Object.isFrozen(wire.format), true);
  }
  assert.doesNotMatch(v3.c.stages[0].messages().messages[0].content, /A rose is a flower/);
});

test('closed root alternatives preserve v2 audit and content field relations', () => {
  const v3 = candidate(createDpiWholeTaskAtomicVisibleCandidate), v2 = candidate(createDpiWholeTaskAtomicSchemaCandidate);
  admitInventory(v3); admitInventory(v2);
  const audit3 = v3.c.stages[1].messages().format, audit2 = v2.c.stages[1].messages().format;
  assert.equal(audit3.anyOf.length, 3);
  assert.deepEqual(Object.keys(audit3), ['anyOf']);
  for (const branch of audit3.anyOf) {
    assert.equal(branch.type, 'object'); assert.equal(branch.additionalProperties, false);
    assert.deepEqual(Object.keys(branch.properties).sort(), ['coverage', 'distinct', 'membership', 'missingSourceId']);
    assert.deepEqual([...branch.required].sort(), ['coverage', 'distinct', 'membership', 'missingSourceId']);
  }
  const auditSamples = [];
  for (const coverage of ['complete', 'incomplete', 'uncertain']) for (const missingSourceId of ['', v3.sourceId])
    auditSamples.push({ coverage, distinct: 'yes', membership: ['yes'], missingSourceId });
  parity(audit2, audit3, auditSamples);
  const accepted = { coverage: 'complete', distinct: 'yes', membership: ['yes'], missingSourceId: '' };
  v3.c.stages[1].validate(JSON.stringify(accepted)); v2.c.stages[1].validate(JSON.stringify(accepted));
  for (const c of [v3.c, v2.c]) {
    c.stages[2].validate(JSON.stringify({ topic: 'non_aws' }));
    c.stages[3].validate(JSON.stringify({ framing: 'hypothetical' }));
  }
  const contentSamples = [];
  for (const content of ['substantive', 'insufficient', 'absent', 'uncertain']) for (const answerId of ['', v3.answerId])
    contentSamples.push({ content, answerId });
  parity(v2.c.stages[4].messages().format, v3.c.stages[4].messages().format, contentSamples);
});

test('relation/context cross product is exact and raw v1 observation survives composition', () => {
  const v3 = candidate(createDpiWholeTaskAtomicVisibleCandidate), v2 = candidate(createDpiWholeTaskAtomicSchemaCandidate);
  const values = [admitInventory(v3)]; admitInventory(v2);
  const audit = { coverage: 'complete', distinct: 'yes', membership: ['yes'], missingSourceId: '' };
  values.push(v3.c.stages[1].validate(JSON.stringify(audit))); v2.c.stages[1].validate(JSON.stringify(audit));
  values.push(v3.c.stages[2].validate(JSON.stringify({ topic: 'non_aws' })));
  values.push(v3.c.stages[3].validate(JSON.stringify({ framing: 'hypothetical' })));
  v2.c.stages[2].validate(JSON.stringify({ topic: 'non_aws' })); v2.c.stages[3].validate(JSON.stringify({ framing: 'hypothetical' }));
  values.push(v3.c.stages[4].validate(JSON.stringify({ content: 'substantive', answerId: v3.answerId })));
  v2.c.stages[4].validate(JSON.stringify({ content: 'substantive', answerId: v2.answerId }));
  const next = v3.c.stages[5].messages().format, old = v2.c.stages[5].messages().format;
  assert.equal(next.anyOf.length, 4);
  for (const branch of next.anyOf) assert.deepEqual(Object.keys(branch.properties).sort(), ['answerId', 'context', 'defeatingContextId', 'relation']);
  const samples = [];
  for (const relation of ['adopted_answer', 'unendorsed_display', 'refusal_only', 'request_echo_only', 'unrelated', 'mixed_or_unclear'])
    for (const context of ['withdrawn_selected_answer', 'unresolved_conflict', 'none_observed', 'uncertain'])
      for (const answerId of ['', v3.answerId]) for (const defeatingContextId of ['', v3.contraryId])
        samples.push({ relation, context, answerId, defeatingContextId });
  parity(old, next, samples);
  values.push(v3.c.stages[5].validate(JSON.stringify({ relation: 'adopted_answer', context: 'none_observed', answerId: v3.answerId, defeatingContextId: '' })));
  const result = v3.c.combine(...values);
  assert.equal(result.version, VERSION); assert.equal(result.wireVersion, VERSION);
  assert.equal(result.observation.rawStages.length, 6); assert.equal(result.creditEligible, false);
  assert.equal(result.actorAuthorityVerified, false); assert.equal(result.semanticTruthVerified, false);
});
