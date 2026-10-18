'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env.PG_MCP_SUPPLY_CHAIN_CURRICULUM_TEST_URL);
const migration = fs.readFileSync(path.resolve(__dirname,
  '../../db/postgres/identity-migrations/0061_mcp_supply_chain_curriculum_defaults.sql'), 'utf8');
const oldRoot = process.env.DVAIA_MCP_SUPPLY_CHAIN_BASELINE_ROOT;
const oldSolution = oldRoot
  ? require(path.join(oldRoot, 'server/data/mcpWorkshopSolutions')).mcp_supply_chain : null;
const oldHint = oldRoot
  ? require(path.join(oldRoot, 'server/data/workshopHints')).mcp_workshop.mcp_supply_chain : null;
const newSolution = require('../../server/data/mcpWorkshopSolutions').mcp_supply_chain;
const newHint = require('../../server/data/workshopHints').mcp_workshop.mcp_supply_chain;
const provenance = require('../../server/database/postgres/catalogDefaultProvenance');

async function schema(client) {
  await client.query(`CREATE SCHEMA workshop_platform;
    CREATE TABLE workshop_platform.config_revision(id integer PRIMARY KEY,revision integer NOT NULL,updated_at timestamptz NOT NULL DEFAULT now());
    INSERT INTO workshop_platform.config_revision VALUES(1,17,now());
    CREATE TABLE workshop_platform.objectives(
      workshop_key text NOT NULL,objective_id text NOT NULL,solution_content jsonb,hint_content jsonb,
      is_enabled boolean NOT NULL,hint_enabled boolean NOT NULL,solution_enabled boolean NOT NULL,
      updated_by integer,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(workshop_key,objective_id));
    CREATE TABLE workshop_platform.catalog_field_defaults(
      entity_kind text NOT NULL,workshop_key text NOT NULL,objective_id text NOT NULL,field_name text NOT NULL,
      provenance_state text NOT NULL,source_version text,source_hash text,source_document jsonb,
      applied_default_version text,applied_default_hash text,applied_default_document jsonb,
      observed_document jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(entity_kind,workshop_key,objective_id,field_name));
    CREATE TABLE workshop_platform.completions(user_id integer,workshop_key text,objective_id text,completed_at timestamptz);`);
}
async function objective(client, { solution = oldSolution, hint = oldHint,
  solutionState = 'legacy_unknown', hintState = 'legacy_unknown',
  solutionProvenance = true, hintProvenance = true } = {}) {
  await client.query(`INSERT INTO workshop_platform.objectives
    (workshop_key,objective_id,solution_content,hint_content,is_enabled,hint_enabled,solution_enabled,updated_by)
    VALUES('mcp_workshop','mcp_supply_chain',$1,$2,false,true,false,77)`, [solution, hint]);
  for (const [fieldName, value, state] of [
    ...(solutionProvenance ? [['solution_content', solution, solutionState]] : []),
    ...(hintProvenance ? [['hint_content', hint, hintState]] : []),
  ]) {
    const document = provenance.document(value); const hash = provenance.hashDocument(document);
    await client.query(`INSERT INTO workshop_platform.catalog_field_defaults
      (entity_kind,workshop_key,objective_id,field_name,provenance_state,
       source_version,source_hash,source_document,applied_default_version,applied_default_hash,
       applied_default_document,observed_document)
      VALUES('objective','mcp_workshop','mcp_supply_chain',$1,$2,'prior',$3,$4::jsonb,
       CASE WHEN $2='managed' THEN 'prior' ELSE NULL END,
       CASE WHEN $2='managed' THEN $3 ELSE NULL END,
       CASE WHEN $2='managed' THEN $4::jsonb ELSE NULL END,$4::jsonb)`,
    [fieldName, state, hash, JSON.stringify(document)]);
  }
  await client.query(`INSERT INTO workshop_platform.completions VALUES
    (81,'mcp_workshop','mcp_supply_chain',now())`);
}
async function state(client) {
  const objectiveRow = (await client.query(`SELECT solution_content,hint_content,is_enabled,hint_enabled,
    solution_enabled,updated_by FROM workshop_platform.objectives
    WHERE workshop_key='mcp_workshop' AND objective_id='mcp_supply_chain'`)).rows[0] || null;
  const provenance = (await client.query(`SELECT field_name,provenance_state,source_version,source_hash,
    applied_default_version,applied_default_hash FROM workshop_platform.catalog_field_defaults ORDER BY field_name`)).rows;
  const revision = (await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision;
  const completionCount = (await client.query('SELECT count(*)::int AS n FROM workshop_platform.completions')).rows[0].n;
  return { objectiveRow, provenance, revision, completionCount };
}

test('0061 semantic transition preserves populated state, replays empty, and rolls back atomically',
  { skip: !enabled || !oldRoot ? 'requires owned disposable PostgreSQL URL and exact baseline root' : false }, async () => {
    const pool = new Pool({ connectionString: process.env.PG_MCP_SUPPLY_CHAIN_CURRICULUM_TEST_URL, max: 1 });
    const client = await pool.connect();
    try {
      for (const provenanceState of ['managed', 'legacy_unknown']) {
        await client.query('BEGIN'); await schema(client);
        await objective(client, { solutionState: provenanceState, hintState: provenanceState });
        const before = await state(client); await client.query(migration); const changed = await state(client);
        assert.deepEqual(changed.objectiveRow.solution_content, newSolution);
        assert.deepEqual(changed.objectiveRow.hint_content, newHint);
        assert.deepEqual({ ...changed.objectiveRow, solution_content: null, hint_content: null },
          { ...before.objectiveRow, solution_content: null, hint_content: null });
        assert.equal(changed.completionCount, before.completionCount);
        assert.equal(changed.revision, before.revision + 1);
        assert.ok(changed.provenance.every(row => row.provenance_state === provenanceState));
        assert.ok(changed.provenance.every(row => row.source_version === 'workshop-defaults-2026-09-15-v3-90ed4250'));
        await client.query(migration); assert.deepEqual(await state(client), changed);
        await client.query('ROLLBACK');
      }

      for (const selected of ['solution', 'hint']) {
        await client.query('BEGIN'); await schema(client);
        await objective(client, selected === 'solution'
          ? { solutionState: 'managed', hintState: 'custom' }
          : { solutionState: 'custom', hintState: 'managed' });
        const before = await state(client); await client.query(migration); const changed = await state(client);
        assert.deepEqual(changed.objectiveRow.solution_content,
          selected === 'solution' ? newSolution : oldSolution);
        assert.deepEqual(changed.objectiveRow.hint_content,
          selected === 'hint' ? newHint : oldHint);
        assert.equal(changed.revision, before.revision + 1);
        assert.deepEqual({ ...changed.objectiveRow, solution_content: null, hint_content: null },
          { ...before.objectiveRow, solution_content: null, hint_content: null });
        await client.query('ROLLBACK');
      }

      await client.query('BEGIN'); await schema(client);
      await objective(client, { solution: null, solutionState: 'legacy_unknown', hintState: 'custom' });
      const nullBefore = await state(client); await client.query(migration);
      assert.deepEqual(await state(client), nullBefore);
      await client.query('ROLLBACK');

      await client.query('BEGIN'); await schema(client);
      await objective(client, { solutionState: 'managed', hintState: 'managed' });
      await client.query(`UPDATE workshop_platform.catalog_field_defaults SET applied_default_hash=$1
        WHERE field_name='solution_content'`, ['d'.repeat(64)]);
      await client.query(`UPDATE workshop_platform.catalog_field_defaults SET applied_default_document=$1::jsonb
        WHERE field_name='hint_content'`, [JSON.stringify({ present: true, value: { different: true } })]);
      const mismatchBefore = await state(client); await client.query(migration);
      assert.deepEqual(await state(client), mismatchBefore);
      await client.query('ROLLBACK');

      await client.query('BEGIN'); await schema(client);
      await objective(client, { solutionProvenance: false, hintProvenance: false });
      const absentBefore = await state(client); await client.query(migration); const absentAfter = await state(client);
      assert.deepEqual(absentAfter.objectiveRow.solution_content, newSolution);
      assert.deepEqual(absentAfter.objectiveRow.hint_content, newHint);
      assert.equal(absentAfter.provenance.length, 0);
      assert.equal(absentAfter.revision, absentBefore.revision + 1);
      await client.query('ROLLBACK');

      await client.query('BEGIN'); await schema(client);
      await client.query(migration);
      assert.equal((await state(client)).revision, 17, 'fresh pre-seed migration is an empty transition');
      await client.query('ROLLBACK');

      await client.query('BEGIN'); await schema(client);
      const customSolution = { instructor: 'preserved' };
      await objective(client, { solution: customSolution, hint: null,
        solutionState: 'custom', hintState: 'legacy_unknown' });
      const customBefore = await state(client); await client.query(migration);
      assert.deepEqual(await state(client), customBefore);
      await client.query('ROLLBACK');

      await client.query('BEGIN'); await schema(client); await objective(client);
      const rollbackBefore = await state(client); await client.query(migration); await client.query('ROLLBACK');
      await client.query('BEGIN'); await schema(client); await objective(client);
      assert.deepEqual(await state(client), rollbackBefore);
      await client.query('ROLLBACK');
    } finally { client.release(); await pool.end(); }
  });
