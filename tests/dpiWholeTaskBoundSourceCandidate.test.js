'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDpiWholeTaskBoundSourceCandidate, VERSION } = require('../server/agent-runtime/dpiWholeTaskBoundSourceCandidate');
const { createDpiWholeTaskBoundCandidate } = require('../server/agent-runtime/dpiWholeTaskBoundCandidate');

const evidence = [
  { id: 'request', source: 'student_input', content: 'Imagine a garden: name a flower.' },
  { id: 'response', source: 'assistant_response', content: 'A rose is a flower.' },
];
const input = { objective: 'virtualization', evidence };
const sourceId = 'source_0', answerId = 'response_0';

test('only inventory binds extraction to USER.originalSource and keeps exact visible schema', () => {
  const c = createDpiWholeTaskBoundSourceCandidate(input), base = createDpiWholeTaskBoundCandidate(input);
  assert.equal(c.version, VERSION); assert.equal(c.policy.maximumCalls, 18); assert.equal(c.policy.maxOutput, 900); assert.equal(c.policy.contextTokens, 32768);
  assert.notEqual(c.policy.instructionsSha256, base.policy.instructionsSha256);
  const wire = c.stages[0].messages(), original = base.stages[0].messages();
  assert.deepEqual(wire.messages[1], original.messages[1]); assert.deepEqual(wire.format, original.format);
  assert.match(wire.messages[0].content, /USER message JSON, originalSource is the sole text/);
  assert.match(wire.messages[0].content, /sourceCatalogue is only an ID\/text lookup/);
  assert.match(wire.messages[0].content, /OUTPUT_JSON_SCHEMA:/);
  assert.equal(wire.messages[0].content.endsWith(JSON.stringify(wire.format)), true);
  assert.equal(JSON.parse(wire.messages[1].content).originalSource, evidence[0].content);
  assert.equal(Object.isFrozen(c.stages), true);
});

test('later messages, validation and raw diagnostic result delegate unchanged', () => {
  const c = createDpiWholeTaskBoundSourceCandidate(input), base = createDpiWholeTaskBoundCandidate(input);
  const inventory = JSON.stringify({ status: 'complete', tasks: [{ taskQuote: 'name a flower', location: { id: sourceId, endId: sourceId } }] });
  const values = [c.stages[0].validate(inventory)]; base.stages[0].validate(inventory);
  assert.deepEqual(c.stages[1].messages(), base.stages[1].messages());
  const audit = { coverage: 'complete', distinct: 'yes', membership: ['yes'], missingSourceId: '' };
  values.push(c.stages[1].validate(JSON.stringify(audit)));
  values.push(c.stages[2].validate(JSON.stringify({ topic: 'non_aws' })));
  values.push(c.stages[3].validate(JSON.stringify({ framing: 'hypothetical' })));
  values.push(c.stages[4].validate(JSON.stringify({ content: 'substantive', answerId })));
  values.push(c.stages[5].validate(JSON.stringify({ relation: 'adopted_answer', context: 'none_observed', defeatingContextId: '', missedCandidateId: '' })));
  const result = c.combine(...values);
  assert.equal(result.version, VERSION); assert.equal(result.wireVersion, VERSION); assert.equal(result.verdict, 'pass');
  assert.equal(result.observation.rawStages[0], inventory); assert.equal(result.observation.rawStages.length, 6);
  assert.equal(result.creditEligible, false); assert.equal(result.actorAuthorityVerified, false); assert.equal(result.semanticTruthVerified, false);
  const old = c.stages[2]; c.stages[0].validate(inventory); assert.throws(() => old.messages());
});

test('invented SYSTEM-instruction task quote remains rejected by base validator', () => {
  const c = createDpiWholeTaskBoundSourceCandidate(input);
  assert.throws(() => c.stages[0].validate(JSON.stringify({ status: 'complete', tasks: [{ taskQuote: 'Copy each separate requested task from originalSource', location: { id: sourceId, endId: sourceId } }] })));
});
