'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const { solutions } = require('../../server/data/promptInjectionSolutions');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');

const root = path.resolve(__dirname, '../..');
const connectionString = process.env.PG_DPI_COPY_MIGRATION_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && !!connectionString;
const workshop = 'direct_prompt_injection';

// Derive historical defaults from immutable applied migrations, independently
// of the candidate SQL. Never infer successful SQL execution from a JS model.
async function histories() {
  const result = new Map();
  for (const filename of ['0036_dpi_teaching_scope.sql', '0043_dpi_evidence_guidance.sql']) {
    const sql = await fs.readFile(path.join(root, 'db/postgres/identity-migrations', filename), 'utf8');
    const pattern = /UPDATE workshop_platform\.objectives\s+SET solution_content=\$(\w+)\$([\s\S]*?)\$\1\$::jsonb[\s\S]*?objective_id='([^']+)'[\s\S]*?AND solution_content=\$(\w+)\$([\s\S]*?)\$\4\$::jsonb/g;
    for (const match of sql.matchAll(pattern)) {
      const previous = result.get(match[3]) || [];
      for (const text of [match[5], match[2]]) {
        const value = JSON.parse(text);
        if (!previous.some(item => JSON.stringify(item) === JSON.stringify(value))) previous.push(value);
      }
      result.set(match[3], previous);
    }
  }
  assert.equal(result.size, 7);
  return result;
}

test('DPI copy migration uses the real loader, rolls back atomically, preserves custom fields, and replays',
  { skip: !enabled, timeout: 60000 }, async () => {
    const database = decodeURIComponent(new URL(connectionString).pathname.slice(1));
    assert.match(database, /^dvaia_dpi_copy_[a-f0-9]{12}$/, 'owned disposable database required');
    const pool = new Pool({ connectionString, max: 1 });
    const stagedRoot = await fs.mkdtemp(path.join(
      process.env.DVAIA_ISOLATED_TEST_WORKSPACE || os.tmpdir(), 'dpi-copy-loader-'));
    const baselineDir = path.join(stagedRoot, 'baseline');
    const fullDir = path.join(stagedRoot, 'full');
    const failingDir = path.join(stagedRoot, 'failing');
    await Promise.all([baselineDir, fullDir, failingDir].map(directory => fs.mkdir(directory)));
    try {
      assert.equal((await pool.query('SELECT current_database() AS name')).rows[0].name, database);
      const baseNames = ['0001_identity.sql', '0002_workshop_platform.sql'];
      for (const name of baseNames) {
        const sql = await fs.readFile(path.join(root, 'db/postgres/identity-migrations', name), 'utf8');
        for (const directory of [baselineDir, fullDir, failingDir]) {
          await fs.writeFile(path.join(directory, name), sql);
        }
      }
      const candidateName = '0066_dpi_teaching_copy_alignment.sql';
      const candidate = await fs.readFile(path.join(root,
        'db/postgres/identity-migrations/0066_dpi_teaching_copy_alignment.sql'), 'utf8');
      assert.doesNotMatch(candidate, /(^|\n)\s*(?:BEGIN|COMMIT)\s*;/i,
        'migrate() owns the transaction boundary');
      await fs.writeFile(path.join(fullDir, candidateName), candidate);
      await fs.writeFile(path.join(failingDir, candidateName),
        `${candidate}\nDO $rollback$ BEGIN RAISE EXCEPTION 'loader rollback sentinel'; END $rollback$;\n`);
      assert.deepEqual(await migrate(pool, baselineDir), baseNames);
      assert.deepEqual(await migrate(pool, baselineDir), []);

      const predecessor = await histories();
      const oldLabels = new Map([
        ['interact', 'Interact with the AI assistant'],
        ['system_prompt', 'System Prompt Extraction: Extract hidden instructions'],
        ['jailbreak', 'Jailbreak: Bypass AI safety restrictions'],
        ['multi_language', 'Multi-Language Attack: Use language switching'],
        ['virtualization', 'Virtualization: Set scene to bypass filters'],
        ['role_playing', 'Role Playing: Adopt unauthorized personas'],
        ['side_stepping', 'Side Stepping: Make AI do forbidden actions'],
        ['obfuscation', 'Obfuscation: Use token smuggling techniques'],
      ]);
      await pool.query('INSERT INTO workshop_platform.exercises(workshop_key,challenge_key,challenge_name,ordinal) VALUES($1,$1,$1,0)', [workshop]);
      await pool.query('INSERT INTO identity.users(id,username,email,password) VALUES(77,$1,$2,$3)',
        ['copy-instructor', 'copy-instructor@example.invalid', '$2b$10$' + 'A'.repeat(53)]);
      const labels = WORKSHOP_OBJECTIVES.direct_prompt_injection;
      const rows = async () => (await pool.query('SELECT * FROM workshop_platform.objectives ORDER BY objective_id')).rows;
      const revision = async () => Number((await pool.query(
        'SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision);
      const candidateLedger = async () => (await pool.query(
        'SELECT name,checksum FROM dvaia_migrations.ledger WHERE name=$1', [candidateName])).rows;

      for (const mode of ['old0', 'old1', 'old2', 'customLabel', 'customSolution', 'customOwner', 'current']) {
        await pool.query('DELETE FROM workshop_platform.objectives');
        await pool.query('DELETE FROM dvaia_migrations.ledger WHERE name=$1', [candidateName]);
        for (const [index, entry] of labels.entries()) {
          const variants = predecessor.get(entry.id);
          const old = variants?.[Math.min(Number(mode.slice(-1)) || 0, variants.length - 1)] ?? null;
          const label = mode === 'current' ? entry.text : mode === 'customLabel' ? `Instructor: ${entry.id}` : oldLabels.get(entry.id);
          const content = mode === 'current' ? solutions[entry.id] ?? null : mode === 'customSolution' ? { instructor: entry.id } : old;
          await pool.query('INSERT INTO workshop_platform.objectives(workshop_key,objective_id,label,ordinal,solution_content,is_enabled) VALUES($1,$2,$3,$4,$5::jsonb,false)', [workshop, entry.id, label, index, JSON.stringify(content)]);
        }
        if (mode === 'customOwner') await pool.query('UPDATE workshop_platform.objectives SET updated_by=77');
        const before = await rows(), priorRevision = await revision();
        if (mode === 'old0') {
          await assert.rejects(migrate(pool, failingDir), /loader rollback sentinel/);
          assert.deepEqual(await rows(), before, 'failed candidate must roll back every row change');
          assert.equal(await revision(), priorRevision, 'failed candidate must roll back revision');
          assert.deepEqual(await candidateLedger(), [], 'failed candidate must not enter the ledger');
        }
        assert.deepEqual(await migrate(pool, fullDir), [candidateName]);
        const ledger = await candidateLedger();
        assert.deepEqual(ledger, [{ name: candidateName,
          checksum: createHash('sha256').update(candidate).digest('hex') }]);
        const after = await rows();
        for (const row of after) {
          const old = before.find(item => item.objective_id === row.objective_id);
          assert.equal(row.label, ['customLabel', 'customOwner'].includes(mode) ? old.label : labels.find(item => item.id === row.objective_id).text, `${mode}/${row.objective_id} label`);
          assert.deepEqual(row.solution_content, ['customSolution', 'customOwner'].includes(mode) ? old.solution_content : solutions[row.objective_id] ?? null, `${mode}/${row.objective_id} solution`);
          assert.equal(row.updated_by, old.updated_by);
          assert.equal(row.is_enabled, false, 'visibility must be preserved');
        }
        const increment = ['current', 'customOwner'].includes(mode) ? 0 : 1;
        assert.equal(await revision(), priorRevision + increment);
        assert.deepEqual(await migrate(pool, fullDir), []);
        assert.deepEqual(await rows(), after, `${mode} replay must preserve timestamps and content`);
        assert.equal(await revision(), priorRevision + increment);
      }
    } finally {
      await pool.end();
      await fs.rm(stagedRoot, { recursive: true, force: true });
    }
  });
