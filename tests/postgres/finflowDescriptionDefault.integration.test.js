'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const provenance = require('../../server/database/postgres/catalogDefaultProvenance');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && Boolean(process.env.PG_FINFLOW_DESCRIPTION_DEFAULT_TEST_URL);
const migration = fs.readFileSync(path.resolve(__dirname,
  '../../db/postgres/identity-migrations/0060_finflow_description_default.sql'), 'utf8');
const oldDescription = 'Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.';
const newDescription = 'Explore path traversal, SSRF, and prompt injection in the FinFlow AI banking lab through its enabled objectives and isolated training resources.';
const version = 'finflow-description-default-2026-09-15';
const newDocument = provenance.document(newDescription);
const newHash = provenance.hashDocument(newDocument);

async function createSchema(client) {
  await client.query(`DROP SCHEMA IF EXISTS workshop_platform CASCADE;
    CREATE SCHEMA workshop_platform;
    CREATE TABLE workshop_platform.config_revision(
      id integer PRIMARY KEY CHECK(id=1), revision integer NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
    INSERT INTO workshop_platform.config_revision VALUES(1,17,now());
    CREATE TABLE workshop_platform.exercises(
      workshop_key text PRIMARY KEY, challenge_description text NOT NULL,
      is_visible boolean NOT NULL, show_hints boolean NOT NULL, show_solutions boolean NOT NULL,
      updated_by integer, updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE workshop_platform.catalog_field_defaults(
      entity_kind text NOT NULL, workshop_key text NOT NULL, objective_id text NOT NULL DEFAULT '', field_name text NOT NULL,
      provenance_state text NOT NULL CHECK(provenance_state IN ('managed','custom','legacy_unknown')),
      source_version text, source_hash text, source_document jsonb,
      applied_default_version text, applied_default_hash text, applied_default_document jsonb,
      observed_document jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(entity_kind,workshop_key,objective_id,field_name),
      CHECK ((provenance_state='managed' AND applied_default_hash IS NOT NULL
        AND applied_default_document IS NOT NULL AND applied_default_version IS NOT NULL)
        OR provenance_state<>'managed'));
    CREATE TABLE workshop_platform.user_state(user_id integer,workshop_key text,generation integer,started_at timestamptz);
    CREATE TABLE workshop_platform.completions(user_id integer,workshop_key text,objective_id text,completed_at timestamptz);`);
}

async function seedCase(client, { description = oldDescription, state = 'legacy_unknown', provenanceRow = true } = {}) {
  await client.query(`INSERT INTO workshop_platform.exercises
    (workshop_key,challenge_description,is_visible,show_hints,show_solutions,updated_by)
    VALUES('sensitive_info_disclosure',$1,false,true,false,77)`, [description]);
  if (provenanceRow) {
    const document = provenance.document(description);
    const hash = provenance.hashDocument(document);
    await client.query(`INSERT INTO workshop_platform.catalog_field_defaults
      (entity_kind,workshop_key,objective_id,field_name,provenance_state,
       source_version,source_hash,source_document,applied_default_version,applied_default_hash,
       applied_default_document,observed_document)
      VALUES('exercise','sensitive_info_disclosure','','challenge_description',$1,
       'prior',$2,$3::jsonb,
       CASE WHEN $1='managed' THEN 'prior' ELSE NULL END,
       CASE WHEN $1='managed' THEN $2 ELSE NULL END,
       CASE WHEN $1='managed' THEN $3::jsonb ELSE NULL END,$3::jsonb)`,
    [state, hash, JSON.stringify(document)]);
  }
  await client.query(`INSERT INTO workshop_platform.user_state VALUES(81,'sensitive_info_disclosure',9,now());
    INSERT INTO workshop_platform.completions VALUES(81,'sensitive_info_disclosure','path_traversal',now());`);
}

async function snapshot(client) {
  const exercise = (await client.query(`SELECT challenge_description,is_visible,show_hints,show_solutions,updated_by
    FROM workshop_platform.exercises WHERE workshop_key='sensitive_info_disclosure'`)).rows[0] || null;
  const defaults = (await client.query(`SELECT provenance_state,source_version,source_hash,source_document,
    applied_default_version,applied_default_hash,applied_default_document,observed_document
    FROM workshop_platform.catalog_field_defaults WHERE entity_kind='exercise'
      AND workshop_key='sensitive_info_disclosure' AND objective_id='' AND field_name='challenge_description'`)).rows[0] || null;
  const revision = (await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision;
  const userState = (await client.query('SELECT user_id,workshop_key,generation FROM workshop_platform.user_state')).rows;
  const completions = (await client.query('SELECT user_id,workshop_key,objective_id FROM workshop_platform.completions')).rows;
  return { exercise, defaults, revision, userState, completions };
}

async function isolatedCase(client, options, verify) {
  await client.query('BEGIN');
  try {
    await createSchema(client); await seedCase(client, options); await verify();
  } finally { await client.query('ROLLBACK'); }
}

test('0060 exact-old transition, replay, seed reconciliation and rollback preserve unrelated state',
  { skip: !enabled ? 'requires owned disposable PostgreSQL URL' : false }, async () => {
    assert.equal(newHash, 'a002c709bb3138cfb0fb434a819be377498e86e0b2a1da629dd4a45bb76ab9df');
    const pool = new Pool({ connectionString: process.env.PG_FINFLOW_DESCRIPTION_DEFAULT_TEST_URL, max: 1 });
    const client = await pool.connect();
    try {
      for (const state of ['managed', 'legacy_unknown']) {
        await isolatedCase(client, { state }, async () => {
          const before = await snapshot(client); await client.query(migration); const changed = await snapshot(client);
          assert.equal(changed.exercise.challenge_description, newDescription);
          assert.deepEqual({ ...changed.exercise, challenge_description: null },
            { ...before.exercise, challenge_description: null });
          assert.deepEqual(changed.userState, before.userState); assert.deepEqual(changed.completions, before.completions);
          assert.equal(changed.revision, before.revision + 1);
          assert.equal(changed.defaults.provenance_state, 'managed');
          assert.equal(changed.defaults.source_version, version); assert.equal(changed.defaults.source_hash, newHash);
          assert.equal(changed.defaults.applied_default_version, version);
          assert.equal(changed.defaults.applied_default_hash, newHash);
          assert.deepEqual(changed.defaults.source_document, newDocument);
          assert.deepEqual(changed.defaults.applied_default_document, newDocument);
          assert.deepEqual(changed.defaults.observed_document, newDocument);
          await client.query(migration); assert.deepEqual(await snapshot(client), changed);
          const decision = await provenance.reconcileField(client, { entityKind: 'exercise',
            workshopKey: 'sensitive_info_disclosure', fieldName: 'challenge_description',
            sourceValue: newDescription, sourceVersion: version });
          assert.deepEqual(decision, { changed: false, decision: 'record' });
          assert.deepEqual(await snapshot(client), changed);
        });
      }

      for (const options of [
        { state: 'custom' },
        { state: 'custom', description: 'Instructor-authored FinFlow description' },
        { state: 'legacy_unknown', description: '' },
      ]) await isolatedCase(client, options, async () => {
        const before = await snapshot(client); await client.query(migration);
        assert.deepEqual(await snapshot(client), before);
      });

      await isolatedCase(client, { provenanceRow: false }, async () => {
        const before = await snapshot(client); await client.query(migration); const migrated = await snapshot(client);
        assert.equal(migrated.exercise.challenge_description, newDescription);
        assert.equal(migrated.defaults, null); assert.equal(migrated.revision, before.revision + 1);
        const decision = await provenance.reconcileField(client, { entityKind: 'exercise',
          workshopKey: 'sensitive_info_disclosure', fieldName: 'challenge_description',
          sourceValue: newDescription, sourceVersion: version });
        assert.deepEqual(decision, { changed: false, decision: 'preserve_unknown' });
        const reconciled = await snapshot(client);
        assert.equal(reconciled.defaults.provenance_state, 'legacy_unknown');
        assert.equal(reconciled.defaults.source_hash, newHash);
        assert.deepEqual(reconciled.defaults.observed_document, newDocument);
      });

      await client.query('BEGIN'); await createSchema(client); await seedCase(client, { state: 'managed' });
      const before = await snapshot(client); await client.query('SAVEPOINT before_migration');
      await client.query(migration); await client.query('ROLLBACK TO SAVEPOINT before_migration');
      assert.deepEqual(await snapshot(client), before); await client.query('ROLLBACK');
    } finally { client.release(); await pool.end(); }
  });
