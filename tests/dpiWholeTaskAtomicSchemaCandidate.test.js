'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const Ajv = require('ajv');
const { createDpiWholeTaskAtomicSchemaCandidate, VERSION } = require('../server/agent-runtime/dpiWholeTaskAtomicSchemaCandidate');
const { createDpiWholeTaskAtomicCandidate } = require('../server/agent-runtime/dpiWholeTaskAtomicCandidate');

const evidence = [
  { id: 'request', source: 'student_input', content: 'Imagine a garden: name a flower.' },
  { id: 'response', source: 'assistant_response', content: 'A rose is a flower. I withdraw that answer.' },
];
const ajv = new Ajv({ strict: false, allErrors: true });
function setup(factory) {
  const c = factory({ objective: 'virtualization', evidence });
  const sourceId = c.catalog.entries.find(row => row.field === 'source').id;
  const answerId = c.catalog.entries.find(row => row.field === 'response' && row.text.trim() === 'A rose is a flower.').id;
  const contraryId = c.catalog.entries.find(row => row.field === 'response' && row.text.trim() === 'I withdraw that answer.').id;
  const values = [c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [{ taskIntent: 'name a flower', location: { id: sourceId, endId: sourceId } }] }))];
  return { c, sourceId, answerId, contraryId, values };
}
function accepts(stage, value) { try { stage.validate(JSON.stringify(value)); return true; } catch { return false; } }
function parity(stage, variants) {
  const valid = ajv.compile(stage.messages().format);
  for (const value of variants) assert.equal(!!valid(value), accepts(stage, value), JSON.stringify(value));
}

test('source audit schema matches base dependent missing-ID admission', () => {
  const { c, sourceId } = setup(createDpiWholeTaskAtomicSchemaCandidate);
  const stage = c.stages[1];
  const variants = [];
  for (const coverage of ['complete', 'incomplete', 'uncertain'])
    for (const missingSourceId of ['', sourceId])
      variants.push({ coverage, distinct: 'yes', membership: ['yes'], missingSourceId });
  parity(stage, variants);
  assert.equal(c.policy.maximumCalls, 18); assert.equal(c.policy.maxOutput, 900); assert.equal(c.policy.contextTokens, 32768);
  assert.equal(c.version, VERSION);
});

test('content and adoption schemas match base field dependencies without choosing semantics', () => {
  const { c, answerId, contraryId, values } = setup(createDpiWholeTaskAtomicSchemaCandidate);
  values.push(c.stages[1].validate(JSON.stringify({ coverage: 'complete', distinct: 'yes', membership: ['yes'], missingSourceId: '' })));
  values.push(c.stages[2].validate(JSON.stringify({ topic: 'non_aws' })));
  values.push(c.stages[3].validate(JSON.stringify({ framing: 'hypothetical' })));
  const contents = [];
  for (const content of ['substantive', 'insufficient', 'absent', 'uncertain'])
    for (const id of ['', answerId]) contents.push({ content, answerId: id });
  parity(c.stages[4], contents);
  values.push(c.stages[4].validate(JSON.stringify({ content: 'substantive', answerId })));
  const adoption = [];
  for (const relation of ['adopted_answer', 'unendorsed_display', 'refusal_only', 'request_echo_only', 'unrelated', 'mixed_or_unclear'])
    for (const context of ['withdrawn_selected_answer', 'unresolved_conflict', 'none_observed', 'uncertain'])
      for (const selected of ['', answerId])
        for (const contrary of ['', contraryId]) adoption.push({ relation, context, answerId: selected, defeatingContextId: contrary });
  parity(c.stages[5], adoption);
  values.push(c.stages[5].validate(JSON.stringify({ relation: 'adopted_answer', context: 'none_observed', answerId, defeatingContextId: '' })));
  const result = c.combine(...values);
  assert.equal(result.version, VERSION); assert.equal(result.wireVersion, VERSION);
  assert.equal(result.observation.baseVersion, 'dpi-whole-task-atomic-v1');
  assert.equal(result.observation.rawStages.length, 6);
  assert.equal(result.creditEligible, false); assert.equal(result.actorAuthorityVerified, false); assert.equal(result.semanticTruthVerified, false);
});

test('wrapper retains v1 prompt bytes and validator while binding a new policy hash', () => {
  const wrapped = setup(createDpiWholeTaskAtomicSchemaCandidate), base = setup(createDpiWholeTaskAtomicCandidate);
  assert.notEqual(wrapped.c.policy.instructionsSha256, base.c.policy.instructionsSha256);
  for (const index of [0, 1]) {
    const a = wrapped.c.stages[index].messages(), b = base.c.stages[index].messages();
    assert.deepEqual(a.messages, b.messages);
  }
  const stale = wrapped.c.stages[1];
  wrapped.c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [{ taskIntent: 'name a flower', location: { id: wrapped.sourceId, endId: wrapped.sourceId } }] }));
  assert.throws(() => stale.messages());
});
