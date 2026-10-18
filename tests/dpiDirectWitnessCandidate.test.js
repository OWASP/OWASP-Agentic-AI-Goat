'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const api = require('../server/agent-runtime/dpiDirectWitnessCandidate');
const previous = require('../server/agent-runtime/dpiSemanticDecisionCandidate');
const compact = require('../server/agent-runtime/dpiSemanticCompactCandidate');
const { decodeDpiRequest } = require('../server/services/dpiDecodedRequest');
const at = (quote, occurrence = 0) => ({ quote, occurrence });
function fixture(objective = 'role_playing', count = 1) {
  const selected = ['jailbreak', 'role_playing', 'side_stepping'].includes(objective);
  const source = selected ? 'Instruction. Task. Task.' : Array.from({ length: Math.max(count, 1) }, (_, i) => `Task ${i}.`).join(' ');
  const request = objective === 'obfuscation' ? Buffer.from(source).toString('base64') : source;
  const response = '🌱 e\u0301. Answer. Answer. Role. Correction.';
  const evidence = [{ id: 'request', source: 'student_input', content: request }, { id: 'response', source: 'assistant_response', content: response }];
  if (objective === 'obfuscation') evidence.push({ id: 'decoded_request', source: 'server_observation', content: decodeDpiRequest(request) });
  const adapter = api.createDirectWitnessCandidate({ objective, evidence });
  const technique = objective === 'jailbreak' ? { overrideRequested: { value: 'yes', support: at('Instruction.') } }
    : objective === 'role_playing' ? { personaAssigned: { value: 'yes', support: at('Instruction.') }, roleAdopted: { value: 'yes', support: at('Role.') } }
      : { awsContextExpansion: { value: 'yes', support: at('Instruction.') }, relevantCompetitorDetail: { value: 'yes', support: at('Role.') } };
  const task = { topic: 'non_aws', contribution: { content: 'substantive', relation: 'adopted_answer', answer: [at('Answer.', 1)] }, context: { value: 'none_observed', defeatingContext: [] } };
  const s = { status: 'complete', tasks: Array.from({ length: count }, (_, i) => ({ location: at(`Task ${i}.`), topic: 'non_aws', framing: 'hypothetical' })) };
  const wire = selected ? { coverage: 'complete', selected: { source: at('Task.', 1), ...task, technique } }
    : { coverage: 'complete', tasks: Object.fromEntries(s.tasks.map((_, i) => [`task_${i}`, { ...structuredClone(task), ...(objective === 'virtualization' ? { framing: 'hypothetical' } : { accuracy: 'correct' }) }])) };
  return { objective, selected, source, request, response, evidence, adapter, s, wire };
}
function run(f) { if (f.selected) return f.adapter.combine(f.adapter.stages[0].validate(JSON.stringify(f.wire))); const a = f.adapter.stages[0].validate(JSON.stringify(f.s)); return f.adapter.combine(a, f.adapter.stages[1].validate(JSON.stringify(f.wire))); }
test('explicit direct protocol preserves repeated occurrence and Unicode identity without guessed matches', () => {
  const f = fixture(), result = run(f);
  assert.equal(result.verdict, 'pass'); assert.equal(result.witnesses[0].source.start, f.source.lastIndexOf('Task.'));
  assert.equal(result.witnesses[0].answer[0].start, f.response.lastIndexOf('Answer.'));
  assert.equal(result.creditEligible, false); assert.equal(result.actorAuthorityVerified, false); assert.equal(result.semanticTruthVerified, false);
  f.wire.selected.contribution.answer = [at('e\u0301.')]; assert.equal(run(f).witnesses[0].answer[0].startByte, 5);
  f.wire.selected.contribution.answer = [at('é.')]; assert.throws(() => run(f), /occurrence missing/);
  const g = fixture(); g.evidence[1].content = 'aaa'; g.adapter = api.createDirectWitnessCandidate({ objective: g.objective, evidence: g.evidence });
  g.wire.selected.contribution.answer = [at('aa', 1)]; g.wire.selected.technique.roleAdopted.support = at('aa', 1);
  assert.equal(run(g).witnesses[0].answer[0].start, 1);
});
test('direct role schema rejects missing answer, defeating context and affirmative technique support', () => {
  for (const change of [t => t.contribution.answer = [], t => t.context.value = 'withdrawn_selected_answer', t => t.technique.roleAdopted.support = null,
    t => t.source.occurrence = 2, t => t.contribution.answer = [at('Task.')], t => t.technique.personaAssigned.support = at('Role.'),
    t => t.contribution.answer.push(at('Answer.', 1)), t => t.source.extra = true, t => t.answerRefs = [0]]) {
    const f = fixture(); change(f.wire.selected); assert.throws(() => run(f));
  }
});
test('same-task contrary and technique roles are independent; quoted material never implies adoption', () => {
  const f = fixture(); f.wire.selected.context = { value: 'withdrawn_selected_answer', defeatingContext: [at('Correction.')] };
  assert.equal(run(f).verdict, 'inconclusive');
  f.wire.selected.context = { value: 'none_observed', defeatingContext: [] };
  f.wire.selected.contribution.relation = 'unendorsed_display'; assert.equal(run(f).verdict, 'fail');
  f.wire.selected.technique.roleAdopted.value = 'no'; f.wire.selected.contribution.relation = 'adopted_answer'; assert.equal(run(f).verdict, 'fail');
  f.wire.selected.technique.roleAdopted.value = 'uncertain'; assert.equal(run(f).verdict, 'inconclusive');
  f.wire.selected = null; assert.equal(run(f).verdict, 'inconclusive');
});
test('whole-source coverage, source disagreements, all four arbitrary tasks and canonical decoding retained', () => {
  for (const objective of ['virtualization', 'obfuscation']) {
    const f = fixture(objective, 4); assert.equal(run(f).verdict, 'pass');
    f.s.tasks[3].topic = 'aws'; assert.equal(run(f).verdict, 'inconclusive'); f.s.tasks[3].topic = 'non_aws';
    f.wire.coverage = 'overflow'; assert.equal(run(f).verdict, 'inconclusive');
    const empty = fixture(objective, 0); assert.equal(run(empty).verdict, 'inconclusive');
  }
  const f = fixture('virtualization'); f.s.tasks[0].framing = 'not_hypothetical'; assert.equal(run(f).verdict, 'inconclusive');
  const g = fixture('obfuscation'); g.wire.tasks.task_0.accuracy = 'incorrect'; assert.equal(run(g).verdict, 'fail');
  g.evidence[2].content.decodedRequest = 'Wrong.'; assert.throws(() => api.createDirectWitnessCandidate({ objective: g.objective, evidence: g.evidence }));
});
test('distinct support ceiling counts shared roles once and rejects disjoint overflow', () => {
  const f = fixture('virtualization'); f.wire.tasks.task_0.context = { value: 'unresolved_conflict', defeatingContext: [at('Answer.', 1)] };
  const result = run(f); assert.equal(result.verdict, 'inconclusive'); assert.deepEqual(result.witnesses[0].answer, result.witnesses[0].contrary);
  f.wire.tasks.task_0.context.defeatingContext = [at('Correction.')]; assert.throws(() => run(f), /Combined response support/);
  const g = fixture(); g.wire.selected.contribution.answer = [at('Answer.', 0), at('Answer.', 1), at('e\u0301.'), at('Correction.')];
  assert.throws(() => run(g), /Combined response support/);
});
test('whole evidence and exact schema stay immutable, no response labels leak into source stage, unchanged ceilings', () => {
  for (const objective of previous.OBJECTIVES) for (const count of [0, 1, 2, 3, 4]) {
    const f = fixture(objective, count), a = f.adapter;
    assert.deepEqual([a.policy.maximumCalls, a.policy.maxOutput, a.policy.contextTokens], f.selected ? [2, 900, 32768] : [4, 1800, 32768]);
    if (!f.selected) a.stages[0].validate(JSON.stringify(f.s));
    for (const stage of a.stages) for (const repair of [false, true]) {
      const w = stage.messages(repair), system = w.messages[0].content;
      assert.deepEqual(JSON.parse(system.slice(system.lastIndexOf(api.DELIMITER) + api.DELIMITER.length)), w.format);
      assert.ok(Buffer.byteLength(system) <= api.MAX_SYSTEM_BYTES); assert.ok(Object.isFrozen(w.format)); assert.ok(Object.isFrozen(w.messages[1]));
      assert.equal(stage.maximumCalls, 2); assert.equal(stage.repairMessage('private error'), 'INVALID_DIRECT_WITNESS_OUTPUT');
    }
    const first = JSON.parse(a.stages[0].messages().messages[1].content);
    if (!f.selected) { assert.deepEqual(Object.keys(first), ['taskSource']); const second = JSON.parse(a.stages[1].messages().messages[1].content); assert.equal(second.taskSource, f.source); assert.equal(second.assistantResponse, f.response); for (const t of second.tasks) assert.deepEqual(Object.keys(t), ['id', 'location']); }
    else { assert.equal(first.request, f.request); assert.equal(first.response, f.response); }
  }
});
test('no forged/stale stage identity; failure revokes prior result; caller changes cannot alter evidence', () => {
  const f = fixture(); const a = f.adapter.stages[0].validate(JSON.stringify(f.wire)); f.evidence[1].content = 'Changed';
  assert.equal(f.adapter.combine(a).verdict, 'pass'); assert.throws(() => f.adapter.combine(structuredClone(a)));
  assert.throws(() => f.adapter.stages[0].validate('{}')); assert.throws(() => f.adapter.combine(a));
  const g = fixture('virtualization'); const s = g.adapter.stages[0].validate(JSON.stringify(g.s)), v = g.adapter.stages[1].validate(JSON.stringify(g.wire));
  assert.throws(() => g.adapter.combine(s, structuredClone(v)));
  const s2 = g.adapter.stages[0].validate(JSON.stringify(g.s)); assert.throws(() => g.adapter.combine(s2, v));
  const v2 = g.adapter.stages[1].validate(JSON.stringify(g.wire)); assert.throws(() => g.adapter.stages[1].validate('{}')); assert.throws(() => g.adapter.combine(s2, v2));
});
test('all deterministic facet combinations agree with retained decision semantics', () => {
  let compared = 0;
  for (const objective of previous.OBJECTIVES) {
    const f = fixture(objective), task = f.selected ? f.wire.selected : f.wire.tasks.task_0;
    // Unique citations allow comparison to the old selected reader without altering evidence.
    if (f.selected) { task.source = at('Instruction.'); task.contribution.answer = [at('Role.')]; }
    else task.contribution.answer = [at('Role.')];
    task.context.defeatingContext = [at('Role.')];
    for (const topic of ['aws', 'non_aws', 'uncertain']) for (const content of ['substantive', 'insufficient', 'absent', 'uncertain'])
      for (const relation of previous.RELATIONS) for (const context of ['none_observed', 'withdrawn_selected_answer', 'unresolved_conflict', 'uncertain'])
        for (const extra of (f.selected ? ['yes', 'no', 'uncertain'] : objective === 'virtualization' ? ['hypothetical', 'direct', 'uncertain'] : ['correct', 'incorrect', 'creative_fulfillment', 'uncertain'])) {
          Object.assign(task, { topic }); Object.assign(task.contribution, { content, relation }); task.context.value = context;
          if (f.selected) Object.values(task.technique).forEach(t => t.value = extra); else if (objective === 'virtualization') { task.framing = extra; f.s.tasks[0].framing = extra === 'direct' ? 'not_hypothetical' : extra; } else task.accuracy = extra;
          if (!f.selected) f.s.tasks[0].topic = topic;
          const actual = run(f), observation = structuredClone(actual.observation); observation.version = previous.VERSION;
          if (f.selected) { observation.tasks[0].source = { quote: 'Instruction.' }; observation.tasks[0].answer = [{ quote: 'Role.' }]; observation.tasks[0].contrary = [{ quote: 'Role.' }]; for (const t of Object.values(observation.tasks[0].technique)) if (t.support) t.support = { quote: t.support.quote }; }
          const expected = previous.validateObservation(observation, { objective, source: f.source, response: f.response, responseComplete: true });
          assert.deepEqual(actual.decisions, expected.decisions); assert.equal(actual.verdict, expected.verdict); compared++;
        }
  }
  assert.equal(compared, 4608);
});
test('historical compact default remains separate and does not opt into direct witness', () => {
  const f = fixture(); const old = compact.createCompactCandidate({ objective: f.objective, evidence: f.evidence });
  assert.equal(old.version, compact.VERSION); assert.ok(!old.stages[0].messages().messages[0].content.includes(api.VERSION));
  assert.throws(() => compact.createCompactCandidate({ objective: f.objective, evidence: f.evidence, protocolVersion: api.VERSION }));
});
