'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopConfigRepository } = require('../server/database/postgres/workshopConfigRepository');

function fixture({ missingBuilder = false, failObjectiveWrite = false } = {}) {
  const keys = ['xss_workshop', 'xss_email_builder', 'csrf_workshop'];
  let state = { revision: 7,
    exercises: keys.filter(key => !missingBuilder || key !== 'xss_email_builder').map(workshop_key => ({
      workshop_key, challenge_key: workshop_key, catalog_active: true, is_visible: false,
      show_hints: false, show_solutions: false, challenge_name: `Instructor ${workshop_key}`,
    })),
    objectives: keys.flatMap(workshop_key => [true, false].map((content, index) => ({
      workshop_key, objective_id: `${workshop_key}_${index}`, label: `Instructor label ${index}`,
      description: 'Instructor teaching text', catalog_active: true, is_enabled: false,
      hint_enabled: false, solution_enabled: false,
      hint_content: content ? { hints: ['Preserved hint'] } : null,
      solution_content: content ? { approach: 'Preserved solution' } : null,
    }))).concat([{ workshop_key: 'xss_workshop', objective_id: 'retired', catalog_active: false,
      is_enabled: false, hint_enabled: false, solution_enabled: false }]),
    legacy: [{ challenge_id: 'reflected', solutions_enabled: false }, { challenge_id: 'email', solutions_enabled: false }],
  };
  let saved;
  const calls = [];
  const client = { release() {}, async query(sql, args = []) {
    calls.push({ sql, args });
    if (sql === 'BEGIN') { saved = structuredClone(state); return { rows: [] }; }
    if (sql === 'ROLLBACK') { state = saved; return { rows: [] }; }
    if (sql === 'COMMIT') return { rows: [] };
    if (sql.startsWith('SELECT revision')) return { rows: [{ revision: state.revision }] };
    if (sql.startsWith('SELECT * FROM workshop_platform.exercises')) {
      return { rows: state.exercises.filter(row => row.workshop_key === args[0] && row.catalog_active) };
    }
    if (sql.startsWith('SELECT w.*')) return { rows: state.exercises.flatMap(exercise => state.objectives
      .filter(objective => objective.workshop_key === exercise.workshop_key && objective.catalog_active)
      .map(objective => ({ ...exercise, ...objective }))) };
    if (sql.startsWith('UPDATE workshop_platform.config_revision')) { state.revision++; return { rowCount: 1, rows: [] }; }
    if (sql.startsWith('INSERT INTO workshop_platform.revisions')) return { rows: [{ revision: state.revision }] };
    const table = sql.match(/^UPDATE workshop_platform\.(exercises|objectives|xss_legacy_solution_visibility)/)?.[1];
    if (table) {
      if (table === 'objectives' && failObjectiveWrite) throw Error('Controlled objective update failure');
      const field = sql.match(/SET\s+(\w+)=\$1/)[1];
      const legacy = table === 'xss_legacy_solution_visibility';
      if (!legacy) {
        assert.deepEqual(args[2], ['xss_workshop', 'xss_email_builder']);
        assert.match(sql, /workshop_key=ANY\(\$3::text\[\]\)/);
        assert.match(sql, /catalog_active=true/);
      }
      const contentField = sql.match(/AND \((hint_content|solution_content) IS NOT NULL OR \$1=false\)/)?.[1];
      let rowCount = 0;
      for (const row of state[legacy ? 'legacy' : table]) {
        if (!legacy && (!args[2].includes(row.workshop_key) || !row.catalog_active)) continue;
        if (contentField && args[0] && row[contentField] === null) continue;
        if (row[field] !== args[0]) { row[field] = args[0]; rowCount++; }
      }
      return { rowCount, rows: [] };
    }
    throw Error(`Unexpected query ${sql}`);
  } };
  return { service: createWorkshopConfigRepository({ connect: async () => client }),
    state: () => state, calls };
}

for (const [dimension, master, gate] of [
  ['active', 'is_visible', null], ['hints', 'show_hints', 'hint_enabled'],
  ['solutions', 'show_solutions', 'solution_enabled'], ['objectives', null, 'is_enabled'],
]) test(`XSS ${dimension} control commits both groups together and preserves siblings and teaching content`, async () => {
  const f = fixture(), before = structuredClone(f.state());
  const result = await f.service.setXssGroupControls(dimension, true, 19);
  assert.equal(result.changed, true); assert.equal(result.revision, 8);
  for (const key of ['xss_workshop', 'xss_email_builder']) {
    assert(result.exercises[key]);
    if (master) assert.equal(f.state().exercises.find(row => row.workshop_key === key)[master], true);
    if (gate) for (const row of f.state().objectives.filter(row => row.workshop_key === key && row.catalog_active)) {
      assert.equal(row[gate], gate === 'is_enabled' || row[gate === 'hint_enabled' ? 'hint_content' : 'solution_content'] !== null);
    }
  }
  assert.deepEqual(f.state().exercises.find(row => row.workshop_key === 'csrf_workshop'), before.exercises.find(row => row.workshop_key === 'csrf_workshop'));
  assert.deepEqual(f.state().objectives.filter(row => row.workshop_key === 'csrf_workshop' || !row.catalog_active), before.objectives.filter(row => row.workshop_key === 'csrf_workshop' || !row.catalog_active));
  assert.deepEqual(f.state().objectives.map(({ label, description, hint_content, solution_content }) => ({ label, description, hint_content, solution_content })),
    before.objectives.map(({ label, description, hint_content, solution_content }) => ({ label, description, hint_content, solution_content })));
  assert(f.calls.find(call => call.sql.endsWith('FOR UPDATE')));
  assert.equal(f.calls.filter(call => call.sql === 'BEGIN').length, 1);
  assert.equal(f.calls.filter(call => call.sql === 'COMMIT').length, 1);
  assert(f.state().legacy.every(row => row.solutions_enabled === (dimension === 'solutions')));
  assert.equal((await f.service.setXssGroupControls(dimension, true, 19)).changed, false);
  assert.equal(f.state().revision, 8, 'duplicate request is a no-op');
  await f.service.setXssGroupControls(dimension, false, 19);
  assert.equal(f.state().revision, 9);
  if (gate) assert(f.state().objectives.filter(row => ['xss_workshop', 'xss_email_builder'].includes(row.workshop_key)).every(row => row[gate] === false));
});

test('XSS group mutation rolls back both masters when objective mutation fails', async () => {
  const f = fixture({ failObjectiveWrite: true }), before = structuredClone(f.state());
  await assert.rejects(f.service.setXssGroupControls('hints', true, 19), /Controlled objective update failure/);
  assert.deepEqual(f.state(), before);
  assert(f.calls.some(call => call.sql === 'ROLLBACK'));
  assert(!f.calls.some(call => call.sql === 'COMMIT'));
});

test('missing or retired group prevents partial configuration writes', async () => {
  const f = fixture({ missingBuilder: true }), before = structuredClone(f.state());
  await assert.rejects(f.service.setXssGroupControls('active', true, 19), { code: 'NOT_FOUND' });
  assert.deepEqual(f.state(), before);
  assert(!f.calls.some(call => call.sql.startsWith('UPDATE')));
});

test('invalid group controls are rejected before connecting to the database', () => {
  const f = fixture();
  for (const [dimension, enabled] of [['hints', 'true'], ['arbitrary', true], ['__proto__', true]]) {
    assert.throws(() => f.service.setXssGroupControls(dimension, enabled, 19), { code: 'BAD_REQUEST' });
  }
  assert.deepEqual(f.calls, []);
});
