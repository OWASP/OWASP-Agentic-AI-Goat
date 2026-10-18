'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');

const root = path.resolve(__dirname, '..');
const candidatePath = path.join(root, 'db/postgres/identity-migrations/0066_dpi_teaching_copy_alignment.sql');
const migration36Path = path.join(root, 'db/postgres/identity-migrations/0036_dpi_teaching_scope.sql');
const migration43Path = path.join(root, 'db/postgres/identity-migrations/0043_dpi_evidence_guidance.sql');
const objectiveIds = [
  'system_prompt', 'jailbreak', 'multi_language', 'virtualization',
  'role_playing', 'side_stepping', 'obfuscation',
];

function stable(value) {
  return JSON.stringify(value);
}

function migrationSolutions(file) {
  const sql = fs.readFileSync(file, 'utf8');
  const pattern = /UPDATE workshop_platform\.objectives\s+SET solution_content=\$(\w+)\$([\s\S]*?)\$\1\$::jsonb[\s\S]*?objective_id='([^']+)'[\s\S]*?AND solution_content=\$(\w+)\$([\s\S]*?)\$\4\$::jsonb/g;
  const found = new Map();
  for (const match of sql.matchAll(pattern)) {
    found.set(match[3], { before: JSON.parse(match[5]), after: JSON.parse(match[2]) });
  }
  return found;
}

function candidateSolutions(sql) {
  const found = new Map();
  const pattern = /changed_(\d+) AS \(\n UPDATE workshop_platform\.objectives\n SET ([\s\S]*?)\n WHERE workshop_key='direct_prompt_injection' AND objective_id='([^']+)'([\s\S]*?)\n RETURNING 1\n\)/g;
  for (const match of sql.matchAll(pattern)) {
    const id = match[3];
    const target = new RegExp(`\\$dpi_${id}_new\\$([\\s\\S]*?)\\$dpi_${id}_new\\$::jsonb`).exec(match[2]);
    if (!target) continue;
    const predecessors = [];
    for (const item of `${match[2]}${match[4]}`.matchAll(new RegExp(`\\$dpi_${id}_pre_(\\d+)\\$([\\s\\S]*?)\\$dpi_${id}_pre_\\1\\$::jsonb`, 'g'))) {
      const value = JSON.parse(item[2]);
      if (!predecessors.some(existing => stable(existing) === stable(value))) predecessors.push(value);
    }
    found.set(id, { ordinal: Number(match[1]), target: JSON.parse(target[1]), predecessors, where: match[4] });
  }
  return found;
}

function candidateLabels(sql) {
  const found = new Map();
  const pattern = /changed_(\d+) AS \(\n UPDATE workshop_platform\.objectives\n SET ([\s\S]*?)\n WHERE workshop_key='direct_prompt_injection' AND objective_id='([^']+)'([\s\S]*?)\n RETURNING 1\n\)/g;
  for (const match of sql.matchAll(pattern)) {
    const id = match[3];
    const target = new RegExp(`\\$dpi_${id}_label_new\\$([\\s\\S]*?)\\$dpi_${id}_label_new\\$`).exec(match[2]);
    const before = new RegExp(`\\$dpi_${id}_label_old\\$([\\s\\S]*?)\\$dpi_${id}_label_old\\$`).exec(`${match[2]}${match[4]}`);
    assert(target && before, `${id} must have exact label CASE values`);
    found.set(id, { ordinal: Number(match[1]), target: target[1], before: before[1], where: match[4] });
  }
  return found;
}

test('immutable DPI copy migration retains historical targets and every reachable predecessor', () => {
  const sql = fs.readFileSync(candidatePath, 'utf8');
  // Retained qualified0066 checksum (also recorded in identity-0067 preparation).
  // Later default-copy migrations must not rewrite this historical target.
  assert.equal(require('node:crypto').createHash('sha256').update(sql).digest('hex'),'7bf8f4777be2cdc627544372567f77ce98fd8c8bfc1b52f8e5d7566c74334a3f');
  const migration36 = migrationSolutions(migration36Path);
  const migration43 = migrationSolutions(migration43Path);
  const candidate = candidateSolutions(sql);
  assert.deepEqual([...candidate.keys()], objectiveIds);

  for (const id of objectiveIds) {
    const row = candidate.get(id);
    assert.equal(typeof row.target.approach,'string');
    assert.match(row.where, /updated_by IS NULL/);

    const expected = [migration36.get(id).before, migration36.get(id).after];
    if (migration43.has(id)) expected.push(migration43.get(id).after);
    const expectedSet = new Set(expected.map(stable));
    const actualSet = new Set(row.predecessors.map(stable));
    assert.deepEqual(actualSet, expectedSet, `${id} must admit source-default and reachable migration histories`);
    assert.equal(row.predecessors.length, actualSet.size, `${id} predecessor guards must be unique`);
    assert(!actualSet.has(stable(row.target)), `${id} replay must not rewrite the current target`);
  }

  assert(!migration43.has('multi_language'), '0043 intentionally did not revise the multilingual solution');
  assert(!migration43.has('obfuscation'), '0043 revised only the obfuscation hint, not its solution');
});

test('DPI copy migration binds labels and increments revision only for real default changes', () => {
  const sql = fs.readFileSync(candidatePath, 'utf8');
  const schema = fs.readFileSync(path.join(root, 'db/postgres/identity-migrations/0002_workshop_platform.sql'), 'utf8');
  const candidate = candidateSolutions(sql);
  const labels = candidateLabels(sql);
  const currentLabels = new Map(WORKSHOP_OBJECTIVES.direct_prompt_injection.map(item => [item.id, item.text]));

  assert.equal(candidate.size, 7);
  assert.equal(labels.size, 8);
  assert.deepEqual([...new Set([...candidate.values(), ...labels.values()].map(item => item.ordinal))].sort((a, b) => a - b),
    Array.from({ length: 8 }, (_, index) => index));
  for (const [id, row] of labels) {
    assert.equal(row.target, currentLabels.get(id), `${id} label must equal the current catalog`);
    assert.match(row.where, /updated_by IS NULL/);
  }

  assert.match(sql, /^-- Candidate only:[\s\S]*\nWITH\n/);
  assert.doesNotMatch(sql, /(^|\n)\s*(?:BEGIN|COMMIT)\s*;/i,
    'the production migration loader owns the transaction boundary');
  assert.match(sql, /UPDATE workshop_platform\.config_revision\nSET revision=revision\+1,updated_at=now\(\)\nWHERE id=1 AND \(EXISTS\(SELECT 1 FROM changed_0\)[\s\S]*EXISTS\(SELECT 1 FROM changed_7\)\);\n$/);
  assert.equal((sql.match(/UPDATE workshop_platform\.config_revision/g) || []).length, 1);
  assert.equal((sql.match(/UPDATE workshop_platform\.objectives/g) || []).length, 8,
    'each objective row is updated at most once in the data-modifying CTE statement');
  assert.equal((sql.match(/solution_content=CASE WHEN/g) || []).length, 7);
  assert.equal((sql.match(/label=CASE WHEN/g) || []).length, 8);
  assert.doesNotMatch(sql, /\b(?:INSERT|DELETE|ALTER|DROP|TRUNCATE|CREATE)\b/i);
  assert.match(schema, /CREATE TABLE workshop_platform\.config_revision \(id integer PRIMARY KEY CHECK\(id=1\),revision integer NOT NULL DEFAULT 0,updated_at timestamptz NOT NULL DEFAULT now\(\)\);/);
  assert.match(schema, /CREATE TABLE workshop_platform\.objectives \([\s\S]*?label text NOT NULL[\s\S]*?hint_content jsonb,solution_content jsonb,updated_by integer REFERENCES identity\.users\(id\),updated_at timestamptz NOT NULL DEFAULT now\(\)/);

  const migrated = candidate.get('multi_language');
  const initial = { solution: migrated.predecessors[0], label: labels.get('multi_language').before, updatedBy: null, revision: 8 };
  const changed = applyCandidate(initial, migrated, labels.get('multi_language'));
  assert.deepEqual(changed, { solution: migrated.target, label: labels.get('multi_language').target, updatedBy: null, revision: 9 });
  assert.deepEqual(applyCandidate(changed, migrated, labels.get('multi_language')), changed, 'replay is a no-op');

  const custom = { solution: { title: 'Instructor copy' }, label: 'Instructor label', updatedBy: 41, revision: 8 };
  assert.deepEqual(applyCandidate(custom, migrated, labels.get('multi_language')), custom, 'custom row is preserved');
});

function applyCandidate(row, solutionUpdate, labelUpdate) {
  const next = structuredClone(row);
  let changed = false;
  if (next.updatedBy === null && solutionUpdate.predecessors.some(value => stable(value) === stable(next.solution))) {
    next.solution = structuredClone(solutionUpdate.target);
    changed = true;
  }
  if (next.updatedBy === null && next.label === labelUpdate.before) {
    next.label = labelUpdate.target;
    changed = true;
  }
  if (changed) next.revision += 1;
  return next;
}
