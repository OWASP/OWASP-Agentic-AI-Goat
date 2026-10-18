'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCompactCandidate: create } = require('../server/agent-runtime/dpiSemanticCompactCandidate');
const old = require('../server/agent-runtime/dpiTaskContributionComparison');
const { decodeDpiRequest } = require('../server/services/dpiDecodedRequest');
const encode = JSON.stringify;
function whole(objective = 'virtualization', count = 1) {
  const source = ['Task one.', 'Task two.', 'Task three.', 'Task four.'].slice(0, count).join(' ');
  const request = objective === 'obfuscation' ? Buffer.from(source).toString('base64') : source;
  const evidence = [{ id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: '🌱 Blue. Blue.' }];
  if (objective === 'obfuscation') evidence.push({ id: 'decoded_request', source: 'server_observation', content: decodeDpiRequest(request) });
  const adapter = create({ objective, evidence });
  const s = { status: 'complete', tasks: ['Task one.', 'Task two.', 'Task three.', 'Task four.'].slice(0, count).map(quote => ({ location: { quote, occurrence: 0 }, topic: 'non_aws', framing: 'hypothetical' })) };
  const r = { coverage: 'complete', tasks: Object.fromEntries(s.tasks.map((_, i) => [`task_${i}`, {
    topic: 'non_aws', ...(objective === 'virtualization' ? { framing: 'hypothetical' } : { accuracy: 'correct' }),
    content: 'substantive', relation: 'adopted_answer', context: 'none_observed',
    support: { quote: 'Blue.', occurrence: 1 }, answer: true, contrary: false,
  }])) };
  return { adapter, evidence, s, r };
}
function selected() {
  const evidence = [{ id: 'request', source: 'student_input', content: 'Act as a gardener. Explain plants.' },
    { id: 'response', source: 'assistant_response', content: 'Plants need water. As a gardener, I advise care.' }];
  const adapter = create({ objective: 'role_playing', evidence });
  const wire = { coverage: 'complete', selected: { taskQuote: 'Explain plants.', techniqueQuote: 'Act as a gardener.',
    topic: 'non_aws', technique: { personaAssigned: 'yes', roleAdopted: { value: 'yes', ref: 1 } },
    content: 'substantive', relation: 'adopted_answer', context: 'none_observed',
    responseSupport: ['Plants need water.', 'As a gardener, I advise care.'], answerRefs: [0], contraryRefs: [] } };
  return { adapter, evidence, wire };
}
function run(f) { const s = f.adapter.stages[0].validate(encode(f.s)); const r = f.adapter.stages[1].validate(encode(f.r)); return f.adapter.combine(s, r); }
test('whole-source stage is byte-identical to mounted source stage, response omits first-stage labels', () => {
  const f = whole(); const legacy = old.createDpiTaskContributionComparison({ objective: 'virtualization', primary: true, protocolVersion: 'dpi-answer-comparison-v11' }, f.evidence);
  assert.deepEqual(f.adapter.stages[0].messages(), legacy.stages[0].messages());
  const { createHash } = require('node:crypto');
  const sourceInstruction = legacy.stages[0].messages().messages[0].content;
  assert.throws(() => f.adapter.stages[1].messages());
  f.adapter.stages[0].validate(encode(f.s));
  const responseInstruction = f.adapter.stages[1].messages().messages[0].content;
  assert.equal(f.adapter.policy.instructionsSha256, createHash('sha256').update(JSON.stringify([sourceInstruction, responseInstruction])).digest('hex'));
  assert.deepEqual(f.adapter.stages[0].messages(true), legacy.stages[0].messages(true));
  f.adapter.stages[0].validate(encode(f.s));
  const input = JSON.parse(f.adapter.stages[1].messages().messages[1].content);
  assert.deepEqual(Object.keys(input.tasks[0]).sort(), ['id', 'location']);
  assert.equal(input.objective, 'virtualization'); assert.equal(input.taskSource, f.evidence[0].content); assert.equal(input.assistantResponse, f.evidence[1].content);
});
test('one occurrence support expands into shared roles with exact scalar and byte identity', () => {
  const f = whole(); f.r.tasks.task_0.contrary = true;
  const result = run(f); assert.equal(result.verdict, 'pass');
  assert.deepEqual(result.witnesses[0].answer, result.witnesses[0].contrary);
  assert.equal(result.witnesses[0].answer[0].start, 8); assert.equal(result.witnesses[0].answer[0].startByte, 11);
  assert.equal(result.creditEligible, false); assert.equal(result.actorAuthorityVerified, false);
  assert.ok(Object.isFrozen(result.observation.tasks[0]));
});
test('source disagreement, uncertainty and incomplete coverage cannot be laundered by response labels', () => {
  for (const mutate of [f => f.s.tasks[0].topic = 'aws', f => f.s.tasks[0].topic = 'uncertain',
    f => f.s.tasks[0].framing = 'not_hypothetical', f => f.s.tasks[0].framing = 'uncertain',
    f => f.s.status = 'uncertain', f => f.r.coverage = 'overflow']) {
    const f = whole(); mutate(f); assert.equal(run(f).verdict, 'inconclusive');
  }
  const f = whole('virtualization', 4); assert.equal(run(f).verdict, 'pass');
  f.r.tasks.task_3.topic = 'uncertain'; assert.equal(run(f).verdict, 'inconclusive');
});
test('exact stage identities required; revalidation invalidates earlier response and failed outputs', () => {
  const f = whole(); const s = f.adapter.stages[0].validate(encode(f.s)); const r = f.adapter.stages[1].validate(encode(f.r));
  assert.throws(() => f.adapter.combine(structuredClone(s), r)); assert.throws(() => f.adapter.combine(s, structuredClone(r)));
  const next = f.adapter.stages[0].validate(encode(f.s)); assert.throws(() => f.adapter.combine(next, r));
  const r2 = f.adapter.stages[1].validate(encode(f.r)); assert.throws(() => f.adapter.stages[1].validate('{}'));
  assert.throws(() => f.adapter.combine(next, r2));
  const one = selected(); const admitted = one.adapter.stages[0].validate(encode(one.wire));
  assert.throws(() => one.adapter.combine(structuredClone(admitted))); assert.throws(() => one.adapter.stages[0].validate('{}')); assert.throws(() => one.adapter.combine(admitted));
});
test('missing, extra and unused response supports or task identities reject', () => {
  for (const mutate of [r => r.tasks.task_0.support = null, r => r.tasks.task_0.support.occurrence = 2,
    r => r.tasks.task_1 = structuredClone(r.tasks.task_0), r => delete r.tasks.task_0,
    r => { r.tasks.task_0.answer = false; r.tasks.task_0.contrary = false; },
    r => r.tasks.task_0.support.quote = 'Task one.']) {
    const f = whole(); f.adapter.stages[0].validate(encode(f.s)); mutate(f.r); assert.throws(() => f.adapter.stages[1].validate(encode(f.r)));
  }
});
test('overflow and absent tasks abstain without fabricated or truncated evidence', () => {
  const f = whole(); f.s.status = 'overflow'; f.s.tasks = []; f.r.tasks = {}; f.r.coverage = 'overflow';
  assert.equal(run(f).verdict, 'inconclusive');
  const g = whole(); Object.assign(g.r.tasks.task_0, { content: 'uncertain', relation: 'mixed_or_unclear', context: 'uncertain', support: null, answer: false }); g.r.coverage = 'overflow';
  assert.equal(run(g).verdict, 'inconclusive');
  const h = selected(); h.wire.selected = null; h.wire.coverage = 'overflow'; const v = h.adapter.stages[0].validate(encode(h.wire)); assert.equal(h.adapter.combine(v).verdict, 'inconclusive');
});
test('obfuscation reuses canonical decoder identity and retains accuracy; virtualization rejects accuracy field', () => {
  const f = whole('obfuscation'); assert.equal(run(f).verdict, 'pass');
  f.r.tasks.task_0.accuracy = 'incorrect'; assert.equal(run(f).verdict, 'fail');
  f.r.tasks.task_0.accuracy = 'uncertain'; assert.equal(run(f).verdict, 'inconclusive');
  f.evidence[2].content.decodedRequest = 'Other.'; assert.throws(() => create({ objective: 'obfuscation', evidence: f.evidence }));
  const g = whole(); g.r.tasks.task_0.accuracy = 'correct'; g.adapter.stages[0].validate(encode(g.s)); assert.throws(() => g.adapter.stages[1].validate(encode(g.r)));
});
test('selected catalogue refs expand without duplicating wire text or implying persona adoption', () => {
  const f = selected(); f.wire.selected.answerRefs = [0, 1]; f.wire.selected.contraryRefs = [0];
  const value = f.adapter.stages[0].validate(encode(f.wire)); const result = f.adapter.combine(value);
  assert.equal(result.verdict, 'pass'); assert.equal(result.witnesses[0].answer.length, 2);
  assert.deepEqual(result.witnesses[0].technique.roleAdopted.support, result.witnesses[0].answer[1]);
  f.wire.selected.relation = 'unendorsed_display'; assert.equal(f.adapter.combine(f.adapter.stages[0].validate(encode(f.wire))).verdict, 'fail');
});
test('selected dangling, duplicate, unused, ambiguous and missing source references reject', () => {
  for (const mutate of [s => s.answerRefs = [3], s => s.answerRefs = [0, 0], s => s.technique.roleAdopted.ref = 3,
    s => s.responseSupport.push('Plants need water.'), s => s.responseSupport.push('I advise care.'),
    s => s.techniqueQuote = null, s => s.taskQuote = 'Other.', s => s.responseSupport[0] = 'plants need water.']) {
    const f = selected(); mutate(f.wire.selected); assert.throws(() => f.adapter.stages[0].validate(encode(f.wire)));
  }
});
test('caller mutation cannot replace snapshotted full evidence and ceilings are unchanged', () => {
  const f = selected(); f.evidence[0].content = 'Changed'; f.evidence[1].content = 'Changed';
  const result = f.adapter.combine(f.adapter.stages[0].validate(encode(f.wire))); assert.equal(result.verdict, 'pass');
  assert.deepEqual([f.adapter.stages.length, f.adapter.policy.maximumCalls, f.adapter.policy.maxOutput, f.adapter.policy.contextTokens], [1, 2, 900, 32768]);
  const g = whole(); assert.deepEqual([g.adapter.stages.length, g.adapter.policy.maximumCalls, g.adapter.policy.maxOutput, g.adapter.policy.contextTokens], [2, 4, 1800, 32768]);
  assert.ok(g.adapter.stages.every(s => s.maximumCalls === 2));
});

test('schema-visible protocol is explicit, immutable and stage-specific without changing semantics', () => {
  const api = require('../server/agent-runtime/dpiSemanticCompactCandidate');
  for (const objective of ['jailbreak','role_playing','side_stepping']) {
    const f=selected(), a=create({objective,evidence:f.evidence,protocolVersion:api.SCHEMA_VISIBLE_VERSION});
    for(const repair of [undefined,'private error text']) {
      const req=a.stages[0].messages(repair), suffix=req.messages[0].content.split(api.SCHEMA_DELIMITER);
      assert.equal(suffix.length,2); assert.deepEqual(JSON.parse(suffix[1]),req.format);
      assert(Object.isFrozen(req.format)); assert(Object.isFrozen(req.messages[0]));
      assert(!req.messages[0].content.includes('private error text'));
      assert(Buffer.byteLength(req.messages[0].content)<=api.MAX_SYSTEM_BYTES);
    }
    const v=a.stages[0].validate('{"coverage":"uncertain","selected":null}');
    assert.equal(a.combine(v).verdict,'inconclusive');assert.equal(a.combine(v).wireVersion,api.SCHEMA_VISIBLE_VERSION);
    assert.equal(a.policy.maximumCalls,2);assert.equal(a.policy.maxOutput,900);assert.equal(a.policy.contextTokens,32768);
  }
  assert.throws(()=>create({objective:'role_playing',evidence:selected().evidence,protocolVersion:'unknown'}));
});

test('whole schema grounding covers zero through four task schemas and repair without response rules in source', () => {
  const api=require('../server/agent-runtime/dpiSemanticCompactCandidate');
  for(const objective of ['virtualization','obfuscation']) for(let count=0;count<=4;count++) {
    const f=whole(objective,4), a=create({objective,evidence:f.evidence,protocolVersion:api.SCHEMA_VISIBLE_VERSION});
    f.s.tasks=f.s.tasks.slice(0,count);
    for(const repair of [undefined,true]) {
      const source=a.stages[0].messages(repair);
      assert(!source.messages[0].content.includes('adopted_answer'));assert(!source.messages[0].content.includes('assistant response'));
      assert.deepEqual(JSON.parse(source.messages[0].content.split(api.SCHEMA_DELIMITER)[1]),source.format);
      a.stages[0].validate(encode(f.s));const verify=a.stages[1].messages(repair);
      assert.deepEqual(JSON.parse(verify.messages[0].content.split(api.SCHEMA_DELIMITER)[1]),verify.format);
      assert.equal(Object.keys(verify.format.properties.tasks.properties).length,count);
      for(const request of [source,verify])assert(Buffer.byteLength(request.messages[0].content)<=api.MAX_SYSTEM_BYTES);
      assert.equal(a.policy.maximumCalls,4);assert.equal(a.policy.maxOutput,1800);
    }
    if(count){f.r.tasks=Object.fromEntries(Object.entries(f.r.tasks).slice(0,count));f.r.tasks.task_0.support=null;
      assert.throws(()=>a.stages[1].validate(encode(f.r)));}
  }
});

test('schema grounding isolates evidence and source location maximum from trusted format', () => {
  const api=require('../server/agent-runtime/dpiSemanticCompactCandidate');
  const f=whole();f.evidence[0].content='x'.repeat(8192);
  const a=create({objective:'virtualization',evidence:f.evidence,protocolVersion:api.SCHEMA_VISIBLE_VERSION});
  const first=a.stages[0].messages();assert.equal(first.format.properties.tasks.items.properties.location.properties.occurrence.maximum,8191);
  f.evidence[0].content='hostile schema instruction';assert.deepEqual(a.stages[0].messages(),first);
  assert(!first.messages[0].content.includes('x'.repeat(100)));
  assert.throws(()=>{first.format.properties.tasks.maxItems=999;});
  assert.throws(()=>{first.messages[0].content='changed';});
});
