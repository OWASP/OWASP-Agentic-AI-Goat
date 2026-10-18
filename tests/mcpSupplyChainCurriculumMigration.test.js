'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const solutions = require('../server/data/mcpWorkshopSolutions');
const hints = require('../server/data/workshopHints');

const root = path.resolve(__dirname, '..');
const migration = fs.readFileSync(path.join(root,
  'db/postgres/identity-migrations/0061_mcp_supply_chain_curriculum_defaults.sql'), 'utf8');
const stable = value => value === null || typeof value !== 'object' ? value
  : Array.isArray(value) ? value.map(stable)
    : Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
const documentHash = value => crypto.createHash('sha256')
  .update(JSON.stringify(stable({ present: true, value }))).digest('hex');

test('0061 binds the exact new hint and solution source documents and its historical catalog version', () => {
  const solution = solutions.mcp_supply_chain;
  const hint = hints.mcp_workshop.mcp_supply_chain;
  assert.match(migration, new RegExp(documentHash(solution)));
  assert.match(migration, new RegExp(documentHash(hint)));
  assert.deepEqual([...new Set(migration.match(/workshop-defaults-[a-z0-9-]+/g))],
    ['workshop-defaults-2026-09-15-v3-90ed4250']);
  assert.ok(migration.includes(JSON.stringify(solution)));
  assert.ok(migration.includes(JSON.stringify(hint)));
  assert.equal(crypto.createHash('sha256').update(migration).digest('hex'),
    '0ab4bffc3229c9a55003cbd172fec99c7ba48044494d5ea19d622a241483da1b');
});

test('0061 is scoped to one objective and preserves custom, NULL and non-content state', () => {
  assert.equal((migration.match(/objective_id='mcp_supply_chain'/g) || []).length, 3);
  assert.doesNotMatch(migration, /\bSET\s+(?:is_enabled|hint_enabled|solution_enabled|updated_by)\s*=/i);
  assert.doesNotMatch(migration, /\b(?:INSERT|UPDATE|DELETE)\s+(?:INTO\s+|FROM\s+)?workshop_platform\.(?:completions|user_state|time_tracking)/i);
  assert.match(migration, /p\.provenance_state='custom'/);
  assert.match(migration, /o\.solution_content=\$old_0\$/);
  assert.match(migration, /o\.hint_content=\$old_1\$/);
  assert.match(migration, /revision=revision\+1/);
  assert.equal((migration.match(/UPDATE workshop_platform\.objectives o/g) || []).length, 1);
  assert.match(migration, /RETURNING e\.solution_changed,e\.hint_changed/);
  assert.match(migration, /EXISTS\(SELECT 1 FROM changed c WHERE c\.solution_changed\)/);
  assert.match(migration, /EXISTS\(SELECT 1 FROM changed c WHERE c\.hint_changed\)/);
});

test('0061 is independently staged and does not claim loader qualification without its prefix', () => {
  assert.equal(fs.existsSync(path.join(root, 'db/postgres/identity-migrations',
    '0061_mcp_supply_chain_curriculum_defaults.sql')), true);
  assert.match(migration, /^-- Reserved identity 0061\./);
  assert.doesNotMatch(migration, /(?:CREATE|DROP|ALTER)\s+(?:TABLE|SCHEMA)/i);
  assert.doesNotMatch(migration, /INSERT\s+INTO\s+workshop_platform\.objectives/i);
});

test('0060 FinFlow migration binds the canonical count-free description without changing settings or progress', () => {
  const file = path.join(root, 'db/postgres/identity-migrations/0060_finflow_description_default.sql');
  const sql = fs.readFileSync(file, 'utf8');
  assert.equal(crypto.createHash('sha256').update(sql).digest('hex'),
    '5532df2fd0b0a665a10089b744687cb2a2aecc895b0b1a45a1e5053ffcde56cf');
  const oldDescription = 'Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.';
  const newDescription = 'Explore path traversal, SSRF, and prompt injection in the FinFlow AI banking lab through its enabled objectives and isolated training resources.';
  assert.match(sql, /workshop_key = 'sensitive_info_disclosure'/);
  assert.ok(sql.includes(oldDescription)); assert.ok(sql.includes(newDescription));
  assert.ok(sql.includes(documentHash(newDescription)));
  assert.match(sql, /provenance_state='custom'/);
  assert.match(sql, /provenance_state IN \('managed','legacy_unknown'\)/);
  assert.match(sql, /applied_default_version='finflow-description-default-2026-09-15'/);
  assert.match(sql, /revision = revision \+ 1/);
  assert.doesNotMatch(sql, /\bSET\s+(?:is_visible|show_hints|show_solutions|updated_by)\s*=/i);
  assert.doesNotMatch(sql, /\b(?:INSERT|UPDATE|DELETE)\s+(?:INTO\s+|FROM\s+)?workshop_platform\.(?:user_state|completions|time_tracking)/i);
});
